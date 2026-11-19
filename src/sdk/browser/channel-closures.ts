import type { KeyWayChannel } from "./create-keyway";
import { channelFinished, channelKey, closedBy, needsFeeReserve, outPointKey, waitingOnChain } from "./settlement-sweep";
import { FINISHED, type ForceCloseOnChain, type SettleResult } from "./watchtower-settle";
import type { WatchedChannel } from "./watchtower-store";

/**
 * What the in-page watchtower has seen happen to a channel on-chain, kept apart from what the node says about it.
 *
 * Fiber 0.10.1's browser node learns of a close the peer put on-chain only from a check it runs every five minutes
 * (`CHECK_CHANNELS_SHUTDOWN_INTERVAL`, fiber/network.rs), so a reopened wallet's node can call a channel ready
 * while its funding cell is already spent. And it never finishes a force-closed channel: it keeps
 * `WAITING_ONCHAIN_SETTLEMENT` until it has a settlement record for the close, which only a build with the
 * `watchtower` feature writes (`has_unresolved_onchain_tlcs`, fiber/onchain_tlc_reconcile.rs; fiber-wasm builds
 * without it). The page's watchtower reads the chain itself, so the SDK goes by what it found: a channel whose
 * funding a commitment spent is shown as closing, not ready, and one it has established as finished stops holding
 * the fee reserve.
 *
 * A finished channel's watchtower record is removed in the end, so the verdict is kept here, where it outlives the
 * page. It stays open to correction for as long as anything can correct it: until the node itself reports the
 * channel closed by the same transaction, every pass reads the chain again, and a pass that finds the funding cell
 * live, another closing transaction, or something still to settle takes the verdict back. After that, the
 * transaction the verdict rests on is still asked about before anything is done on its strength; if the chain no
 * longer has it buried, the verdict is taken out of storage (`revokeVerdict`), the channel shows as closing again,
 * and the watchtower's record, a copy of which is kept here from the moment it was removed, goes back to the
 * watchtower so it can claim again.
 */
export type ChannelClosure = {
  channelId: string;
  /** The funding cell as Fiber names it (`channel_outpoint`). A record speaks only for a channel on this cell. */
  fundingOutPoint: string;
  /** The commitment transaction that spent the funding cell. */
  closingTx: string;
  /**
   * Set once nothing is left for the user to claim: the watchtower's status (one of FINISHED) and the transaction
   * it rests on, which was FINAL_DEPTH blocks deep when this was written (and is asked about again every time the
   * fee reserve is about to be released on it, and every ten minutes otherwise: `createReserveGate`).
   */
  finished?: { status: string; evidence: string };
  /**
   * The watchtower's record of the channel (its settlement key and data), kept from the moment a verdict removed it
   * from the watchtower's own store. If the verdict is ever taken back, the record is put back and the watchtower
   * can claim again. Absent for a channel whose record an earlier SDK had already removed: that one can only be
   * followed on-chain (`recordChainVerdict`).
   */
  record?: WatchedChannel;
  seenAt: number;
};

export type ClosureStore = {
  list(): Promise<ChannelClosure[]>;
  put(closure: ChannelClosure): Promise<void>;
  remove(channelId: string): Promise<void>;
};

const STORE = "closures";

/**
 * The closures, in an IndexedDB database next to the node's own (its name starts with the node's database prefix,
 * so the encrypted node backup carries it to a new device with the channels). A database of its own, so an older
 * SDK reading the same node's watchtower database finds that one as it expects it.
 */
export function openClosureStore(databasePrefix: string): ClosureStore {
  const name = `${databasePrefix}-keyway-closures`;
  function open(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(name, 1);
      request.onupgradeneeded = () => request.result.createObjectStore(STORE, { keyPath: "channelId" });
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error ?? new Error("Could not open the channel closures"));
    });
  }
  async function run<T>(mode: IDBTransactionMode, work: (store: IDBObjectStore) => IDBRequest<T>): Promise<T> {
    const database = await open();
    try {
      return await new Promise<T>((resolve, reject) => {
        const transaction = database.transaction(STORE, mode);
        const request = work(transaction.objectStore(STORE));
        // A write is done when its transaction is: a reader that follows then finds it.
        transaction.oncomplete = () => resolve(request.result);
        transaction.onerror = () => reject(transaction.error ?? new Error("Could not use the channel closures"));
        transaction.onabort = () => reject(transaction.error ?? new Error("Could not use the channel closures"));
      });
    } finally {
      database.close();
    }
  }
  return {
    list: () => run("readonly", (store) => store.getAll() as IDBRequest<ChannelClosure[]>),
    put: async (closure) => { await run("readwrite", (store) => store.put(closure)); },
    remove: async (channelId) => { await run("readwrite", (store) => store.delete(channelId)); },
  };
}

/** The closure recorded for a channel as the node lists it: same channel, on the same funding cell. */
export function closureOf(closures: readonly ChannelClosure[], channel: { channel_id?: unknown; channel_outpoint?: unknown }): ChannelClosure | undefined {
  const id = channelKey(channel.channel_id);
  const outPoint = outPointKey(channel.channel_outpoint);
  if (id === undefined || outPoint === undefined) return undefined;
  return closures.find((closure) => closure.channelId === id && closure.fundingOutPoint === outPoint);
}

/**
 * A channel as the SDK presents it, given what the in-page watchtower has seen of its close (`closureOf`). Once a
 * commitment has spent the funding cell the channel can carry no more payments, whatever the node says: it is
 * closing, with nothing to send or receive, until nothing is left to claim, and closed after that. So it reads
 * the same before and after the node notices the close, and stays in the list of open channels while the user's
 * share is still to be claimed. A verdict reached on another closing transaction than the one the node has seen
 * close the channel (a reorganization replaced it) says nothing about this close: the channel stays closing.
 *
 * The same goes for a channel the node itself reports closed by force and still waiting for its settlement, when
 * nothing has been recorded about it (the first start after an upgrade, a first pass that failed, closures that
 * can't be read): Fiber's browser node keeps that state for good, whether or not the user's share has been
 * claimed, so it is no evidence that anything is finished. Only a standing verdict makes such a channel closed.
 */
export function withClosure(channel: KeyWayChannel, closure: Pick<ChannelClosure, "finished" | "closingTx"> | undefined): KeyWayChannel {
  const closing = (finished: boolean): KeyWayChannel => ({ ...channel, status: finished ? "closed" : "closing", canSend: 0n, canReceive: 0n });
  if (!closure) return waitingOnChain(channel.raw as never) ? closing(false) : channel;
  const nodeClosing = closedBy(channel.raw as never);
  const verdict = closure.finished !== undefined && (nodeClosing === undefined || nodeClosing === closure.closingTx);
  return closing(verdict || channelFinished(channel.raw as never));
}

/**
 * The node's channels (all of them, closed ones included) as the SDK lists them: each corrected by its closure,
 * and closed ones left out unless asked for.
 */
export function presentChannels(channels: KeyWayChannel[], closures: readonly ChannelClosure[], includeClosed: boolean): KeyWayChannel[] {
  const presented = channels.map((channel) => withClosure(channel, closureOf(closures, channel.raw as never)));
  return includeClosed ? presented : presented.filter((channel) => channel.status !== "closed");
}

/**
 * Keeps the closures in step with one watchtower result for a channel, and ends the watch once the channel is
 * finished for good and the node agrees it is closed.
 *
 * - A commitment spent the funding cell: recorded at once, before anything else is asked of the chain, so the
 *   channel stops showing as ready, now and after a reload.
 * - A status in FINISHED whose transaction is buried (`isBuried`): the verdict is written.
 * - The watchtower's record is removed only once there is a verdict and the node reports the channel closed by the
 *   same transaction (`nodeClosedBy`), and a copy of it is kept with the verdict first (`endWatch`). Until then
 *   every pass reads the chain again, and what it finds wins: the funding cell live, or spent by something that is
 *   no commitment, forgets the closure; another commitment starts it over; a live commitment cell with something
 *   still to settle (`unsettled`) takes the verdict back; a finished status resting on another transaction than the
 *   verdict's replaces it, once that one is buried.
 *
 * Returns true when this result finished the channel.
 */
export async function recordSettleResult(options: {
  result: SettleResult;
  /** The channel's funding cell as the node lists it (`channel_outpoint`). */
  fundingOutPoint: string;
  /** The transaction the node says closed the channel, if it reports it closed (settlement-sweep.ts `closedBy`). */
  nodeClosedBy?: string;
  closures: ClosureStore;
  watchtower: WatchRecords;
  isBuried: (txHash: string) => Promise<boolean>;
  now?: number;
}): Promise<boolean> {
  const { result, closures } = options;
  const channelId = channelKey(result.channelId);
  const fundingOutPoint = outPointKey(options.fundingOutPoint);
  const closingTx = channelKey(result.closingTx);
  // Without both there is nothing a record could be matched to later: nothing is written, and the watch goes on.
  if (channelId === undefined || fundingOutPoint === undefined) return false;
  const known = (await closures.list()).find((closure) => closure.channelId === channelId);
  if (closingTx === undefined) {
    // "open", or a close that isn't a commitment: nothing here says the channel is force-closed (any more),
    // whatever was recorded before. Other statuses (the indexer is behind, say) decide nothing.
    if (known && (result.status === "open" || result.status === "closed cooperatively")) await closures.remove(channelId);
    return false;
  }
  const same = known !== undefined && known.fundingOutPoint === fundingOutPoint && known.closingTx === closingTx;
  const closure: ChannelClosure = {
    channelId, fundingOutPoint, closingTx, seenAt: same ? known.seenAt : options.now ?? Date.now(),
    // The kept copy of the watchtower's record belongs to the channel, whatever closed it.
    ...(known?.record ? { record: known.record } : {}),
  };
  let finished = same && !result.unsettled ? known.finished : undefined;
  // The chain now rests the same conclusion on another transaction (a reorganization replaced the claim, say):
  // the old verdict is void, and the new transaction has its own depth to reach.
  if (finished && FINISHED.has(result.status) && result.evidence && channelKey(result.evidence) !== channelKey(finished.evidence)) finished = undefined;
  // The observation first: whatever fails after this, the channel no longer reads as ready.
  if (!same || Boolean(known.finished) !== Boolean(finished)) await closures.put(closure);
  let finishedNow = false;
  // A claim just sent (txHash) is never the end: the pass after it reads what the chain made of it.
  if (!finished && !result.txHash && FINISHED.has(result.status) && result.evidence && await options.isBuried(result.evidence)) {
    finished = { status: result.status, evidence: result.evidence };
    // The verdict before the record goes: were the record removed and the verdict lost, nothing would release the reserve.
    await closures.put({ ...closure, finished });
    finishedNow = true;
  }
  if (finished && options.nodeClosedBy === closingTx) await endWatch({ closure: { ...closure, finished }, closures, watchtower: options.watchtower });
  return finishedNow;
}

/** The watchtower's records, as far as the closures need them (watchtower-store.ts). */
export type WatchRecords = {
  get(channelId: string): Promise<WatchedChannel | undefined>;
  remove(channelId: string): Promise<void>;
  restore(channel: WatchedChannel): Promise<void>;
};

/**
 * Ends the watch of a channel finished for good: the watchtower's record is removed from its store, after a copy
 * has been put with the verdict. The copy is what lets the watchtower act again if the verdict is ever taken back
 * (`revokeVerdict`); a copy already kept is not replaced by what the store holds now (the node handed the channel
 * over again at a later start, possibly with less than the watchtower had gathered).
 */
export async function endWatch(options: { closure: ChannelClosure; closures: ClosureStore; watchtower: WatchRecords }): Promise<void> {
  const { closure, closures, watchtower } = options;
  if (!closure.record) {
    const record = await watchtower.get(closure.channelId);
    if (record) await closures.put({ ...closure, record });
  }
  await watchtower.remove(closure.channelId);
}

/**
 * Takes a verdict back for good: the transaction it rested on is no longer buried (a reorganization deeper than
 * FINAL_DEPTH, or the verdict was written on a wrong answer). The stored closure loses its `finished`, so the
 * channel shows as closing again and holds the reserve after a reload too, and the watchtower gets its record back
 * (`restoreWatch`), so the next pass reads the chain and claims whatever is the user's again.
 *
 * What it can't do: for a channel whose record an earlier SDK removed without keeping a copy, and which Fiber
 * doesn't hand over again (it does so only for Channel V2 channels, at each start), there is no key left to
 * claim with. That channel is then only followed on-chain: it shows as closing and holds the reserve until the
 * chain shows nothing left under its commitment lock (`recordChainVerdict`).
 */
export async function revokeVerdict(options: { closure: ChannelClosure; closures: ClosureStore; watchtower: Pick<WatchRecords, "restore"> }): Promise<void> {
  const { closure, closures, watchtower } = options;
  const stored = (await closures.list()).find((item) => item.channelId === closure.channelId);
  // Only the verdict that was found wanting: one written since, on other evidence, has its own check to face.
  if (!stored?.finished || stored.closingTx !== closure.closingTx || stored.finished.evidence !== closure.finished?.evidence) return;
  const { finished: _revoked, ...rest } = stored;
  await closures.put(rest);
  await restoreWatch({ closures: [rest], watchtower });
}

/**
 * Gives the watchtower back the record of every channel that is force-closed, not finished, and whose record is
 * kept here: after a verdict was taken back, the watch has to start again. Run at the start of every pass too, so
 * a restore that failed is tried again. Nothing in a record the watchtower already holds is replaced; the kept copy
 * only fills in what that record lacks (watchtower-store.ts `restore`).
 */
export async function restoreWatch(options: { closures: readonly ChannelClosure[]; watchtower: Pick<WatchRecords, "restore"> }): Promise<void> {
  for (const closure of options.closures) {
    if (closure.record && !closure.finished) await options.watchtower.restore(closure.record);
  }
}

/**
 * What the chain alone says about a channel the watchtower holds no record of: that it is force-closed, and, when
 * everything below holds, that it is finished.
 *
 * An earlier SDK removed a channel's record as soon as it found the channel settled, and wrote nothing down; Fiber
 * hands only Channel V2 channels over again at a start. Such a channel would read as ready until the node noticed
 * the close, and would then hold the fee reserve for good.
 *
 * - A commitment transaction spent the funding cell: recorded, so the channel shows as closing, whatever the node
 *   still says (as `recordSettleResult` does for a channel with a record). The funding cell live again, or spent
 *   by a cooperative close, forgets it.
 * - Finished: without the record nothing can be claimed and nobody can tell whose the funds under the commitment
 *   lock are, so only one thing counts: nothing is left there. The verdict is written when the node itself reports
 *   the channel closed by force and waiting, the commitment found is the closing transaction the node names, the
 *   commitment cell and every successor are spent with none left (`follow`, watchtower-settle.ts
 *   `forceCloseSettled`), and the transaction that spent the last one is buried (`isBuried`). Anything less, a live
 *   cell under the lock or a transaction not yet deep enough, writes no verdict.
 *
 * Returns true when it wrote the verdict.
 */
export async function recordChainVerdict(options: {
  /** The channel as the node lists it. */
  channel: { channel_id?: unknown; channel_outpoint?: unknown; shutdown_transaction_hash?: unknown; state: { state_name: string; state_flags?: unknown } };
  follow: (fundingOutPoint: string) => Promise<ForceCloseOnChain>;
  closures: ClosureStore;
  isBuried: (txHash: string) => Promise<boolean>;
  now?: number;
}): Promise<boolean> {
  const { channel, closures } = options;
  const channelId = channelKey(channel.channel_id);
  const fundingOutPoint = outPointKey(channel.channel_outpoint);
  if (channelId === undefined || fundingOutPoint === undefined) return false;
  const seen = await options.follow(fundingOutPoint);
  const closingTx = channelKey(seen.closingTx);
  const known = (await closures.list()).find((closure) => closure.channelId === channelId);
  if (closingTx === undefined) {
    // The funding cell is live again, or a cooperative close spent it: nothing says the channel is force-closed.
    // A closure that carries the kept copy of the watchtower's record is never dropped on this answer (it may be
    // a stale one, and the copy is the only place the channel's keys still are): it loses its verdict, which
    // sends the record back to the watchtower at the next pass, and the pass over that record decides from there.
    if (known && seen.notForceClosed) {
      if (known.record) {
        if (known.finished) {
          const { finished: _dropped, ...rest } = known;
          await closures.put(rest);
        }
      } else await closures.remove(channelId);
    }
    return false;
  }
  const same = known !== undefined && known.fundingOutPoint === fundingOutPoint && known.closingTx === closingTx;
  const closure: ChannelClosure = {
    channelId, fundingOutPoint, closingTx, seenAt: same ? known.seenAt : options.now ?? Date.now(),
    ...(known?.record ? { record: known.record } : {}),
  };
  // The observation first, as for a channel with a record. A verdict about another close is dropped with it.
  if (!same) await closures.put(closure);
  // The verdict: only for a channel the node itself reports closed by force and waiting, by this transaction.
  const evidence = channelKey(seen.settledBy);
  if (!waitingOnChain(channel) || closedBy(channel) !== closingTx || evidence === undefined) return false;
  if (same && known.finished?.evidence === evidence) return false;
  if (!await options.isBuried(evidence)) return false;
  await closures.put({ ...closure, finished: { status: "settled", evidence } });
  return true;
}

/** How long an answer that a verdict's transaction is buried is reused before the chain is asked again. */
const RECHECK_AFTER = 10 * 60_000;

/**
 * Whether the fee reserve may still be needed (`needed`), and whether a finished closure still stands (`holds`).
 *
 * The reserve is released only when every channel is finished: by the node's own account, or because the node
 * reports it closed and a verdict for the same channel, funding cell and closing transaction says nothing is left
 * to claim. Before the reserve goes on the strength of a verdict, the transaction the verdict rests on is asked
 * about once more: if it is no longer buried (a deep reorganization, or a wrong answer when the verdict was
 * written), the verdict doesn't count. `needed({ fresh: true })`, which the sweep uses when it decides whether to
 * move the reserve, asks the chain every time; otherwise an answer had in the last ten minutes, and since the last
 * `reset` (each start), is used, which is enough to notice that the reserve may be due and to drop a channel Fiber
 * hands over again. A
 * channel being opened keeps the reserve too: the node lists it only once the peer has answered. If anything can't
 * be read, the reserve stays.
 *
 * A verdict found wanting is not just passed over: `revoke` takes it out of storage (`revokeVerdict`), so the
 * channel reads as closing again, here and after a reload, and the watchtower looks at it again. Only the chain's
 * own answer does that; an RPC that can't be reached keeps the reserve and leaves the verdict for the next ask.
 */
export function createReserveGate(deps: {
  /** Every channel the node knows, closed ones included. */
  listChannels(): Promise<Array<Parameters<typeof needsFeeReserve>[0][number]>>;
  listClosures(): Promise<ChannelClosure[]>;
  isBuried(txHash: string): Promise<boolean>;
  /** Whether a channel open is in progress. */
  opening(): boolean;
  /** Takes back, in storage, a verdict whose transaction the chain no longer has buried. */
  revoke?(closure: ChannelClosure): Promise<void>;
  now?(): number;
}) {
  /** When each verdict was last borne out by the chain. */
  const stood = new Map<string, number>();
  async function holds(closure: ChannelClosure, fresh = false): Promise<boolean> {
    if (!closure.finished) return false;
    const key = `${closure.channelId}:${closure.closingTx}:${closure.finished.evidence}`;
    // An answer is reused only for a while: a page left open for days asks again, so a verdict that stops holding
    // is taken back, and its channel watched again, even while another channel keeps the sweep from asking.
    const last = stood.get(key);
    if (!fresh && last !== undefined && (deps.now ?? Date.now)() - last < RECHECK_AFTER) return true;
    stood.delete(key);
    let buried: boolean;
    try {
      buried = await deps.isBuried(closure.finished.evidence);
    } catch {
      // Not an answer: nothing is released on it, and nothing is taken back.
      return false;
    }
    if (!buried) {
      await deps.revoke?.(closure).catch((error) => console.warn(`[keyway] could not take back the verdict for channel ${closure.channelId}; it is asked about again before anything rests on it`, error));
      return false;
    }
    stood.set(key, (deps.now ?? Date.now)());
    return true;
  }
  async function needed(options: { fresh?: boolean } = {}): Promise<boolean> {
    if (deps.opening()) return true;
    const channels = await deps.listChannels();
    if (!needsFeeReserve(channels)) return false;
    let closures: ChannelClosure[];
    try {
      closures = await deps.listClosures();
    } catch (error) {
      console.warn("[keyway] could not read what the watchtower has seen; the fee reserve stays for now", error);
      return true;
    }
    // Still needed even if every verdict stands: no need to ask the chain.
    if (needsFeeReserve(channels, closures)) return true;
    const standing: ChannelClosure[] = [];
    for (const closure of closures) {
      // Only the verdicts the release would rest on: those of channels the node reports closed by the same transaction.
      const relied = channels.some((channel) => !channelFinished(channel) && closureOf([closure], channel) && closedBy(channel) === closure.closingTx);
      if (relied && await holds(closure, options.fresh)) standing.push(closure);
    }
    return needsFeeReserve(channels, standing);
  }
  /**
   * Whether a channel is finished for good: a verdict that still stands, and the node reporting the channel closed
   * by the same transaction. Fiber hands such a channel to the watchtower again at every start; it needs no
   * second look, only dropping again.
   */
  async function settledForGood(closure: ChannelClosure | undefined, channel: Parameters<typeof closedBy>[0]): Promise<boolean> {
    return closure?.finished !== undefined && closedBy(channel) === closure.closingTx && await holds(closure);
  }
  return {
    needed, holds, settledForGood,
    /** Forgets every answer had so far: the chain may have changed while the node was stopped. */
    reset: () => stood.clear(),
  };
}
