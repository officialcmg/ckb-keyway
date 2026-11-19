import * as ccc from "@ckb-ccc/core";
import type { KeyWayRecovery } from "./account-lock";
import type { KeyWayApiClient } from "./api-client";
import type { RequestEmailCode } from "./email-code";
import { KeyWaySigner } from "./keyway-signer";
import { FEE_RESERVE, MIN_PLAIN_CELL } from "./settlement-sweep";

export { FEE_RESERVE, needsFeeReserve } from "./settlement-sweep";

/**
 * Whether the node's key already holds a plain cell the watchtower can use for fees.
 *
 * The indexer that lists the key's cells can lag the chain, and still list a reserve cell that a sweep has
 * returned to the user; a channel opened on its word would get no reserve. So a listed cell counts only if the node
 * itself says it is live, with the node's transaction pool taken into account: a cell that a transaction still on
 * its way spends (a sweep sent before a reload, of which this page remembers nothing) doesn't count either. A cell
 * the node doesn't have yet counts only while the transaction that creates it is on its way in (the change of this
 * page's own claim or sweep, which the client lists from its cache). Cells this page's own unconfirmed sends have
 * spent are never listed (ccc leaves them out). When the node can't be asked, the cell isn't counted: at worst a
 * second reserve is sent, which comes back with the first.
 */
export async function hasFeeReserve(client: ccc.Client, lock: ccc.ScriptLike): Promise<boolean> {
  for await (const cell of client.findCellsByLock(lock, undefined, true)) {
    if (cell.cellOutput.type || cell.outputData !== "0x" || cell.cellOutput.capacity < MIN_PLAIN_CELL) continue;
    if (await reserveCellStands(client, cell.outPoint).catch(() => false)) return true;
  }
  return false;
}

async function reserveCellStands(client: ccc.Client, outPoint: ccc.OutPoint): Promise<boolean> {
  if (await client.getCellLiveNoCache(outPoint, false, true)) return true;
  const created = await client.getTransactionNoCache(outPoint.txHash);
  return created?.status === "pending" || created?.status === "proposed";
}

/**
 * Sends the fee reserve from the user's account to their node's key. The user approved it in the
 * channel-open dialog, so the signer here approves only this exact transaction. It goes through KeyWay's
 * ordinary signing, so it counts toward the user's daily email-confirmation amount like any other send.
 */
export async function sendFeeReserve(options: {
  authToken: string;
  ckbPublicKey: string;
  recovery?: KeyWayRecovery;
  api: KeyWayApiClient;
  requestEmailCode?: RequestEmailCode;
  client: ccc.Client;
  lock: ccc.ScriptLike;
}): Promise<string> {
  let expected: string | undefined;
  const signer = new KeyWaySigner(options.authToken, options.ckbPublicKey, {
    approveCkbTransaction: (preview) => expected !== undefined && preview.transactionHash === expected,
    approveCkbMessage: () => false,
    requestEmailCode: options.requestEmailCode ?? (() => Promise.resolve(undefined)),
  }, options.client, options.api, options.recovery);
  const transaction = ccc.Transaction.from({ outputs: [{ lock: options.lock, capacity: FEE_RESERVE }] });
  await transaction.completeInputsByCapacity(signer);
  await transaction.completeFeeBy(signer);
  await signer.prepareTransaction(transaction);
  expected = transaction.hash();
  return signer.sendTransaction(transaction);
}

/**
 * Whether a reserve this page sent (transaction `txHash`, the reserve at its output 0) still stands although the
 * node key's view of the chain doesn't list it yet: on its way in (pending), or committed and live but not indexed.
 * Not if the node key's own client has already spent it (a sweep returning it), or the chain doesn't know it.
 */
export async function sentReserveStands(options: { client: ccc.Client; viewer: ccc.Client; txHash: ccc.HexLike }): Promise<boolean> {
  const outPoint = ccc.OutPoint.from({ txHash: options.txHash, index: 0 });
  if (await options.viewer.cache.isUnusable(outPoint)) return false;
  const found = await options.client.getTransactionNoCache(options.txHash);
  if (found?.status === "pending" || found?.status === "proposed") return true;
  if (found?.status !== "committed") return false;
  return Boolean(await options.viewer.getCellLiveNoCache(outPoint, false));
}

/**
 * The fee reserve around a channel open: checked before it, sent once the funding transaction is on-chain.
 * `reserveClient`: the client that sends from the node's key, if there is one in the page. It knows which of the
 * key's cells its own unconfirmed sends (a sweep returning the reserve) have already spent; the account's client
 * would still count a reserve that is on its way out, and the new channel would open without one.
 */
export function createFeeReserve(options: Omit<Parameters<typeof sendFeeReserve>[0], "lock"> & { lock: () => Promise<ccc.ScriptLike>; reserveClient?: ccc.Client }) {
  /** The reserve this page last sent, until the node key's view of the chain lists it. */
  let sent: string | undefined;
  return {
    /** Whether this open must also send the reserve, because the node's key doesn't hold one yet. */
    async needed(): Promise<boolean> {
      const viewer = options.reserveClient ?? options.client;
      if (await hasFeeReserve(viewer, await options.lock())) {
        sent = undefined;
        return false;
      }
      // The account's client sent it, so the node key's client can't know of it until it is indexed: a second
      // channel opened right after the first must not send a second reserve.
      if (sent === undefined) return true;
      return !await sentReserveStands({ client: options.client, viewer, txHash: sent }).catch(() => false);
    },
    /**
     * Waits for the funding transaction, so the reserve can't spend the same cells, then sends the reserve.
     * The channel is already open by then, so a failure is reported and the next open tries again.
     */
    async send(fundingTxHash: string | undefined): Promise<string | undefined> {
      try {
        if (fundingTxHash) await options.client.waitTransaction(fundingTxHash, 0, 180_000);
        const lock = await options.lock();
        for (let attempt = 0; ; attempt++) {
          try {
            return sent = await sendFeeReserve({ ...options, lock });
          } catch (error) {
            // The indexer can still list the funding transaction's inputs for a few seconds after it lands.
            if (attempt >= 3 || !/Resolve|Dead|Unknown/i.test(error instanceof Error ? error.message : "")) throw error;
            await new Promise((resolve) => setTimeout(resolve, 5_000));
          }
        }
      } catch (error) {
        console.warn("[keyway] the channel opened, but its fee reserve wasn't sent; the next channel open adds it", error);
        return undefined;
      }
    },
  };
}
