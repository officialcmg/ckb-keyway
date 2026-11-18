import type { KeyWayChannel } from "./create-keyway";
import { channelFinished, channelKey, closedBy, needsFeeReserve, outPointKey } from "./settlement-sweep";
import { FINISHED, type SettleResult } from "./watchtower-settle";

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
 * live, another closing transaction, or something still to settle takes the verdict back.
 */
export type ChannelClosure = {
  channelId: string;
  /** The funding cell as Fiber names it (`channel_outpoint`). A record speaks only for a channel on this cell. */
  fundingOutPoint: string;
  /** The commitment transaction that spent the funding cell. */
  closingTx: string;
  /**
   * Set once nothing is left for the user to claim: the watchtower's status (one of FINISHED) and the transaction
   * it rests on, which was FINAL_DEPTH blocks deep when this was written (and is asked about again, once a
   * session, before the fee reserve is released on it: `createReserveGate`).
   */
  finished?: { status: string; evidence: string };
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
 * share is still to be claimed.
 */
export function withClosure(channel: KeyWayChannel, closure: Pick<ChannelClosure, "finished"> | undefined): KeyWayChannel {
  if (!closure) return channel;
  const finished = Boolean(closure.finished) || channelFinished(channel.raw as never);
  return { ...channel, status: finished ? "closed" : "closing", canSend: 0n, canReceive: 0n };
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
 *   same transaction (`nodeClosedBy`). Until then every pass reads the chain again, and what it finds wins:
 *   the funding cell live, or spent by something that is no commitment, forgets the closure; another commitment
 *   starts it over; a live commitment cell with something still to settle (`unsettled`) takes the verdict back.
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
  watchtower: { remove(channelId: string): Promise<void> };
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
  const closure: ChannelClosure = { channelId, fundingOutPoint, closingTx, seenAt: same ? known.seenAt : options.now ?? Date.now() };
  let finished = same && !result.unsettled ? known.finished : undefined;
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
  if (finished && options.nodeClosedBy === closingTx) await options.watchtower.remove(channelId);
  return finishedNow;
}

/**
 * Whether the fee reserve may still be needed (`needed`), and whether a finished closure still stands (`holds`).
 *
 * The reserve is released only when every channel is finished: by the node's own account, or because the node
 * reports it closed and a verdict for the same channel, funding cell and closing transaction says nothing is left
 * to claim. Before the reserve goes on the strength of a verdict, the transaction the verdict rests on is asked
 * about once more (once per session): if it is no longer buried (a deep reorganization, or a wrong answer when the
 * verdict was written), the verdict doesn't count. A channel being opened keeps the reserve too: the node lists it
 * only once the peer has answered. If anything can't be read, the reserve stays.
 */
export function createReserveGate(deps: {
  /** Every channel the node knows, closed ones included. */
  listChannels(): Promise<Array<Parameters<typeof needsFeeReserve>[0][number]>>;
  listClosures(): Promise<ChannelClosure[]>;
  isBuried(txHash: string): Promise<boolean>;
  /** Whether a channel open is in progress. */
  opening(): boolean;
}) {
  const stood = new Set<string>();
  async function holds(closure: ChannelClosure): Promise<boolean> {
    if (!closure.finished) return false;
    const key = `${closure.channelId}:${closure.closingTx}:${closure.finished.evidence}`;
    if (stood.has(key)) return true;
    if (!await deps.isBuried(closure.finished.evidence).catch(() => false)) return false;
    stood.add(key);
    return true;
  }
  async function needed(): Promise<boolean> {
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
      if (relied && await holds(closure)) standing.push(closure);
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
  return { needed, holds, settledForGood };
}
