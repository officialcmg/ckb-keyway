import type { KeyWayChannel } from "./create-keyway";
import { channelKey, outPointKey } from "./settlement-sweep";
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
 * A finished channel's watchtower record is removed, so the verdict is kept here, where it outlives the page.
 */
export type ChannelClosure = {
  channelId: string;
  /** The funding cell as Fiber names it (`channel_outpoint`). A record speaks only for a channel on this cell. */
  fundingOutPoint: string;
  /** The commitment transaction that spent the funding cell. */
  closingTx: string;
  /**
   * Set once nothing is left for the user to claim: the watchtower's status (one of FINISHED) and the transaction
   * it rests on, which was FINAL_DEPTH blocks deep when this was written.
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
 * commitment has spent the funding cell the channel can carry no more payments: it is closing (closed, once nothing
 * is left to claim) with nothing to send or receive, even while the node still reports it as ready. A channel the
 * node itself reports closed is left as the node reports it.
 */
export function withClosure(channel: KeyWayChannel, closure: Pick<ChannelClosure, "finished"> | undefined): KeyWayChannel {
  if (!closure || channel.status === "closed") return channel;
  return { ...channel, status: closure.finished ? "closed" : "closing", canSend: 0n, canReceive: 0n };
}

/**
 * Keeps the closures in step with one watchtower result for a channel, and ends the watch once the channel is
 * finished for good.
 *
 * - A commitment spent the funding cell: recorded, so the channel stops showing as ready, now and after a reload.
 * - A status in FINISHED whose transaction is buried (`isBuried`): the verdict is written first, then the
 *   watchtower record is removed. Until it is buried the record stays and the next pass asks again, so a
 *   reorganization that brings the commitment cell back still finds everything needed to claim from it.
 * - The funding cell is live after all (a reorganization undid the close): an unfinished closure is forgotten.
 *
 * A finished closure is never changed again. Returns true when this result finished the channel.
 */
export async function recordSettleResult(options: {
  result: SettleResult;
  /** The channel's funding cell as the node lists it (`channel_outpoint`). */
  fundingOutPoint: string;
  closures: ClosureStore;
  watchtower: { remove(channelId: string): Promise<void> };
  isBuried: (txHash: string) => Promise<boolean>;
  now?: number;
}): Promise<boolean> {
  const { result, closures } = options;
  const channelId = channelKey(result.channelId);
  const fundingOutPoint = outPointKey(options.fundingOutPoint);
  // Without both there is nothing a record could be matched to later: nothing is written, and the watch goes on.
  if (channelId === undefined || fundingOutPoint === undefined) return false;
  const known = (await closures.list()).find((closure) => closure.channelId === channelId);
  if (known?.finished && known.fundingOutPoint === fundingOutPoint) {
    // Written, but the page went away before the record was removed (or the node handed the channel over again).
    await options.watchtower.remove(channelId);
    return false;
  }
  if (!result.closingTx) {
    // "open", or a close that isn't a commitment: nothing here says the channel is force-closed (any more).
    if (known && (result.status === "open" || result.status === "closed cooperatively")) await closures.remove(channelId);
    return false;
  }
  const closure: ChannelClosure = { channelId, fundingOutPoint, closingTx: result.closingTx, seenAt: known?.seenAt ?? options.now ?? Date.now() };
  // A claim just sent (txHash) is never the end: the pass after it reads what the chain made of it.
  const finished = !result.txHash && FINISHED.has(result.status) && result.evidence && await options.isBuried(result.evidence)
    ? { status: result.status, evidence: result.evidence }
    : undefined;
  if (finished) {
    // The verdict first: were the record removed and the verdict then lost, nothing would ever release the reserve.
    await closures.put({ ...closure, finished });
    await options.watchtower.remove(channelId);
    return true;
  }
  if (!known || known.fundingOutPoint !== fundingOutPoint || known.closingTx !== closure.closingTx) await closures.put(closure);
  return false;
}
