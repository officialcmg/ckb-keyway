import * as ccc from "@ckb-ccc/core";
import type { KeyWayApiClient } from "./api-client";
import type { RequestEmailCode } from "./email-code";
import { KeyWaySigner } from "./keyway-signer";
import { FEE_RESERVE, MIN_PLAIN_CELL } from "./settlement-sweep";

export { FEE_RESERVE, needsFeeReserve } from "./settlement-sweep";

/** Whether the node's key already holds a plain cell the watchtower can use for fees. */
export async function hasFeeReserve(client: ccc.Client, lock: ccc.ScriptLike): Promise<boolean> {
  for await (const cell of client.findCellsByLock(lock, undefined, true)) {
    if (!cell.cellOutput.type && cell.outputData === "0x" && cell.cellOutput.capacity >= MIN_PLAIN_CELL) return true;
  }
  return false;
}

/**
 * Sends the fee reserve from the user's account to their node's key. The user approved it in the
 * channel-open dialog, so the signer here approves only this exact transaction. It goes through KeyWay's
 * ordinary signing, so it counts toward the user's daily email-confirmation amount like any other send.
 */
export async function sendFeeReserve(options: {
  authToken: string;
  ckbPublicKey: string;
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
  }, options.client, options.api);
  const transaction = ccc.Transaction.from({ outputs: [{ lock: options.lock, capacity: FEE_RESERVE }] });
  await transaction.completeInputsByCapacity(signer);
  await transaction.completeFeeBy(signer);
  await signer.prepareTransaction(transaction);
  expected = transaction.hash();
  return signer.sendTransaction(transaction);
}

/** The fee reserve around a channel open: checked before it, sent once the funding transaction is on-chain. */
export function createFeeReserve(options: Omit<Parameters<typeof sendFeeReserve>[0], "lock"> & { lock: () => Promise<ccc.ScriptLike> }) {
  return {
    /** Whether this open must also send the reserve, because the node's key doesn't hold one yet. */
    async needed(): Promise<boolean> {
      return !await hasFeeReserve(options.client, await options.lock());
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
            return await sendFeeReserve({ ...options, lock });
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
