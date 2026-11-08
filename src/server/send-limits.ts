import * as ccc from "@ckb-ccc/core";
import { currentLock, KeyWayAccountSigner, secp256k1Lock } from "../sdk/browser/account-lock.ts";
import {
  chainOnSendLimit,
  decodeSendLimitSettings,
  encodeSendLimitSettings,
  isSendLimitCell,
  recordEntriesBytes,
  SEND_LIMIT_MAGIC,
  SEND_LIMIT_RECORD_MAGIC,
  SEND_LIMIT_SPARE,
  sendLimitInputIndex,
  setSendLimitRecord,
  type SendLimitHead,
  type SendLimitSettings,
} from "../sdk/browser/send-limits.ts";
import { serializeTransaction } from "./funding-transaction.ts";
import { loadLitAction } from "./lit-actions.ts";
import type { TransactionStatus } from "./pending-transactions.ts";
import type { ReadyWallet } from "./user-wallet.ts";

/**
 * The server's side of the send limits the policy Action enforces (research/send-limits/README.md): planning a
 * transaction with the Action's own rules, finding the account's newest send-limit cell, and building the
 * transactions that turn limits on or change them.
 */

export type SendLimitKind = "exempt" | "legacy" | "chained" | "unchained" | "genesis";
export type SendLimitPlan = {
  transactionHash: ccc.Hex;
  limits: SendLimitKind;
  needsCode: boolean;
  outflow: { ckb: string; tokens: Array<{ asset: string; amount: string }> };
  totals?: Record<string, string>;
  record?: ccc.Hex;
  /** The send-limit input, whose witness carries the record. */
  recordIndex?: number;
};

/** Limit kinds whose code the Action emails to the address bound in the send-limit cell. */
export const LIT_CODE_KINDS: SendLimitKind[] = ["chained", "unchained", "genesis"];

type Planner = (params: Record<string, unknown>) => Promise<unknown>;

// The Action's source, run here in its keyless "plan" mode: the same rules Lit applies, with no Lit run. A stand-in
// Lit global refuses any key use, so planning can never sign.
const PLAN_LIT = { Actions: {
  getPrivateKey: async () => { throw new Error("Planning has no key"); },
  getLitActionPrivateKey: async () => { throw new Error("Planning has no key"); },
} };
let compiled: Promise<Planner> | undefined;
async function localAction(): Promise<Planner> {
  const source = await loadLitAction("sign-ckb-transaction");
  return new Function("Lit", "ethers", "fetch", `${source}\nreturn main;`)(PLAN_LIT, {}, globalThis.fetch.bind(globalThis)) as Planner;
}

/** How planning runs; tests replace `run` with the Action under the fake Lit runtime. */
export const sendLimitPlanner: { run: Planner } = {
  run: async (params) => {
    // A failed load (a transient file error) isn't kept, so the next preview tries again.
    compiled ??= localAction().catch((error) => { compiled = undefined; throw error; });
    return (await compiled)(params);
  },
};

/** Whether this transaction needs the code under the account's send limits, and the record it must carry. */
export async function planSendLimits(wallet: Pick<ReadyWallet, "litPkpId" | "litPublicKey">, transaction: ccc.Transaction): Promise<SendLimitPlan> {
  const result = await sendLimitPlanner.run({ mode: "plan", pkpId: wallet.litPkpId, publicKey: wallet.litPublicKey, transaction: serializeTransaction(transaction) }) as Partial<SendLimitPlan> | undefined;
  if (!result || result.transactionHash !== transaction.hash() || typeof result.needsCode !== "boolean" || !["exempt", "legacy", "chained", "unchained", "genesis"].includes(String(result.limits))) {
    throw new Error("Send limits couldn't be checked");
  }
  if (result.record !== undefined && !/^0x([0-9a-f]{2})+$/.test(result.record)) throw new Error("Send limits couldn't be checked");
  return result as SendLimitPlan;
}

/** Puts a plan's record on the send-limit input, if the transaction spends one. */
export function applySendLimitRecord(transaction: ccc.Transaction, plan: Pick<SendLimitPlan, "record" | "recordIndex">): void {
  if (!plan.record) return;
  if (!Number.isInteger(plan.recordIndex) || plan.recordIndex! < 0 || plan.recordIndex! >= transaction.inputs.length) throw new Error("Send limits couldn't be checked");
  setSendLimitRecord(transaction, plan.recordIndex!, plan.record);
}

/** The record a send-limit cell's creating transaction carries, if any (a genesis has none). */
function recordOf(transaction: ccc.Transaction): ccc.Hex | undefined {
  for (let i = 0; i < transaction.witnesses.length; i++) {
    try {
      const inputType = transaction.getWitnessArgsAt(i)?.inputType;
      if (inputType?.startsWith(SEND_LIMIT_RECORD_MAGIC)) return inputType;
    } catch { /* not WitnessArgs */ }
  }
  return undefined;
}

/**
 * The account's newest send-limit cell: the one a pending transaction created that no later pending transaction
 * spends, or the live one on chain. A cell from a transaction the node doesn't know yet (its client is still
 * sending it) is waited for briefly, then skipped. Undefined when limits were never turned on.
 */
export async function sendLimitHead(
  client: ccc.Client,
  wallet: Pick<ReadyWallet, "litPublicKey">,
  pending: Array<{ transaction: ccc.Transaction; status: TransactionStatus; signedAt?: number }>,
  statusOf: (hash: string) => Promise<TransactionStatus | undefined> = async (hash) => (await client.getTransaction(hash))?.status,
): Promise<SendLimitHead | undefined> {
  const secp = await secp256k1Lock(client, wallet.litPublicKey);
  const limitOutput = (transaction: ccc.Transaction) => transaction.outputs.findIndex((output, i) => isSendLimitCell(output, transaction.outputsData[i], secp));
  // A send-limit transaction signed moments ago that the node doesn't know yet: its client may still be sending it,
  // so give it a few seconds before building on what came before it.
  const inPool = (status: TransactionStatus | undefined) => status === "pending" || status === "proposed" || status === "committed";
  const known = await Promise.all(pending.map(async ({ transaction, status, signedAt }) => {
    if (inPool(status) || limitOutput(transaction) === -1) return { transaction, status };
    // Only one signed moments ago can still be on its way; an older one was never sent.
    if (signedAt !== undefined && Date.now() - signedAt > JUST_SIGNED_MS) return { transaction, status };
    for (let attempt = 0; attempt < 6; attempt++) {
      await new Promise((resolve) => setTimeout(resolve, 500));
      const now = await statusOf(transaction.hash()).catch(() => undefined);
      if (inPool(now)) return { transaction, status: now! };
    }
    return { transaction, status };
  }));
  // Only transactions the node holds spend anything; one that never reached it doesn't.
  const live = known.filter(({ status }) => inPool(status));
  const spent = new Set(live.flatMap(({ transaction }) => transaction.inputs.map((input) => `${input.previousOutput.txHash}:${input.previousOutput.index}`)));
  const head = (transaction: ccc.Transaction, index: number): SendLimitHead => ({
    outPoint: { txHash: transaction.hash(), index },
    cellOutput: transaction.outputs[index],
    outputData: ccc.hexFrom(transaction.outputsData[index]),
    recordEntriesBytes: recordEntriesBytes(recordOf(transaction) ?? "0x"),
  });
  for (const { transaction } of [...live].reverse()) {
    const index = limitOutput(transaction);
    if (index !== -1 && !spent.has(`${transaction.hash()}:${index}`)) return head(transaction, index);
  }
  // Anyone can plant a look-alike at the address; the real one was made by a transaction that spent one of the key's
  // own cells (any input), which needs its signature. As in the Action, that is read from the key's own lock history
  // in the block that holds the cell, so every candidate costs the same two lookups however its transaction was
  // made. The newest comes first (every chained send makes the real one the newest), and planted cells can't stretch
  // the search past a fixed number of candidates: running out of them is an error, never "no send limits".
  const history = new Map<bigint, Promise<Set<string>>>();
  const spentByKeyIn = (block: bigint) => {
    let inputs = history.get(block);
    if (!inputs) {
      const key = { script: secp, scriptType: "lock" as const, scriptSearchMode: "exact" as const, filter: { blockRange: [block, block + 1n] as [bigint, bigint] } };
      inputs = client.findTransactionsPaged(key, "asc", MAX_BLOCK_HISTORY).then(({ transactions }) => {
        // A full page can't be read past here; outsiders can only fill it by giving this key that many cells in one block.
        if (transactions.length >= MAX_BLOCK_HISTORY) throw new Error("A block holds too much of this account's history to check");
        return new Set(transactions.filter(({ isInput }) => isInput).map(({ txHash }) => txHash));
      });
      history.set(block, inputs);
    }
    return inputs;
  };
  let scanned = 0;
  let candidates = 0;
  const filter = { script: { codeHash: TYPE_ID_CODE_HASH, hashType: "type" as const, args: "0x" }, outputData: SEND_LIMIT_MAGIC, outputDataSearchMode: "prefix" as const };
  for await (const cell of client.findCellsOnChain({ script: secp, scriptType: "lock", scriptSearchMode: "exact", filter }, "desc", 32)) {
    if (++scanned > MAX_SCANNED) throw new Error("This account has too many look-alike send-limit cells to check");
    if (!isSendLimitCell(cell.cellOutput, cell.outputData, secp) || spent.has(`${cell.outPoint.txHash}:${Number(cell.outPoint.index)}`)) continue;
    if (++candidates > MAX_CANDIDATES) throw new Error("This account has too many look-alike send-limit cells to check");
    const created = await client.getTransaction(cell.outPoint.txHash);
    if (!created || created.blockNumber === undefined) continue;
    if ((await spentByKeyIn(created.blockNumber)).has(cell.outPoint.txHash)) {
      return { outPoint: { txHash: cell.outPoint.txHash, index: Number(cell.outPoint.index) }, cellOutput: cell.cellOutput, outputData: cell.outputData, recordEntriesBytes: recordEntriesBytes(recordOf(created.transaction) ?? "0x") };
    }
  }
  return undefined;
}

const TYPE_ID_CODE_HASH = "0x00000000000000000000000000000000000000000000000000545950455f4944";
/** How long after signing a transaction the node doesn't know yet is waited for: its client is sending it. */
const JUST_SIGNED_MS = 10_000;
/** Send-limit-shaped cells the search checks, newest first, two lookups each. Planting more costs about 11k CKB. */
const MAX_CANDIDATES = 64;
/** Cells the search may read, should a node return more than the send-limit-shaped ones it was asked for. */
const MAX_SCANNED = 512;
/** Entries of the key's history read from one block, as in the Action. */
const MAX_BLOCK_HISTORY = 1024;
const FEE_RATE = 1_500n;

/** The capacity a send-limit cell with this data occupies, in shannons. */
export function sendLimitCapacity(lock: ccc.Script, data: ccc.HexLike): bigint {
  const output = ccc.CellOutput.from({ lock, type: ccc.Script.from({ codeHash: TYPE_ID_CODE_HASH, hashType: "type", args: `0x${"00".repeat(32)}` }), capacity: 0n }, data);
  return output.capacity;
}

/**
 * The transaction that turns limits on: the oldest plain cell at the key's secp256k1 address as input 0, the new
 * cell as output 0 (its Type ID from input 0), more of the account's plain cells as needed, and change back to the
 * account. The fingerprint is zero until the Action returns it with the code; the code is for this transaction
 * with the fingerprint zeroed, so filling it in afterwards keeps the code valid.
 */
export async function buildSendLimitGenesis(client: ccc.Client, wallet: Pick<ReadyWallet, "litPublicKey" | "recovery">, settings: Omit<SendLimitSettings, "fingerprint">): Promise<ccc.Transaction> {
  const secp = await secp256k1Lock(client, wallet.litPublicKey);
  let oldest: ccc.Cell | undefined;
  for await (const cell of client.findCellsOnChain({ script: secp, scriptType: "lock", scriptSearchMode: "exact", filter: { scriptLenRange: [0, 1], outputDataLenRange: [0, 1] } }, "asc", 1)) { oldest = cell; break; }
  if (!oldest) throw new Error("Turning send limits on needs a plain CKB cell at the account's secp256k1 address");
  // The Action requires the oldest committed plain cell; one a pending send already spent can't be used yet.
  if (await client.cache.isUnusable(oldest.outPoint)) throw new Error("Wait for your pending send to confirm, then turn send limits on");
  const data = encodeSendLimitSettings({ ...settings, fingerprint: ccc.hexFrom(new Uint8Array(32)) });
  const input = ccc.CellInput.from({ previousOutput: oldest.outPoint, cellOutput: oldest.cellOutput, outputData: oldest.outputData });
  const type = ccc.Script.from({ codeHash: TYPE_ID_CODE_HASH, hashType: "type", args: ccc.hashTypeId(input, 0) });
  const transaction = ccc.Transaction.from({
    inputs: [input],
    outputs: [{ lock: secp, type, capacity: sendLimitCapacity(secp, data) + SEND_LIMIT_SPARE }],
    outputsData: [data],
  });
  const signer = new KeyWayAccountSigner(client, wallet.litPublicKey, wallet.recovery);
  await transaction.addCellDepsOfKnownScripts(client, ccc.KnownScript.Secp256k1Blake160);
  await transaction.completeFeeChangeToLock(signer, await currentLock(client, wallet.litPublicKey, wallet.recovery), FEE_RATE);
  await signer.prepareTransaction(transaction);
  return transaction;
}

/** The genesis with the fingerprint the Action returned put into the new cell's data. */
export function withFingerprint(transaction: ccc.Transaction, fingerprint: ccc.HexLike): void {
  const settings = decodeSendLimitSettings(transaction.outputsData[0]);
  transaction.outputsData[0] = encodeSendLimitSettings({ ...settings, fingerprint: ccc.hexFrom(fingerprint) });
}

/**
 * The transaction that changes the limits: it spends the newest send-limit cell and creates its successor with the
 * new settings, paying the fee from the cell's spare CKB (or, if the new data needs more room, from the account's
 * plain cells). The fingerprint never changes.
 */
export async function buildSendLimitChange(client: ccc.Client, wallet: Pick<ReadyWallet, "litPublicKey" | "recovery">, head: SendLimitHead, settings: Omit<SendLimitSettings, "fingerprint">): Promise<ccc.Transaction> {
  const before = decodeSendLimitSettings(head.outputData);
  const data = encodeSendLimitSettings({ ...settings, fingerprint: before.fingerprint });
  const cellOutput = ccc.CellOutput.from(head.cellOutput);
  const transaction = ccc.Transaction.from({ outputs: [], outputsData: [] });
  chainOnSendLimit(transaction, head);
  transaction.outputsData[0] = data;
  const signer = new KeyWayAccountSigner(client, wallet.litPublicKey, wallet.recovery);
  await transaction.addCellDepsOfKnownScripts(client, ccc.KnownScript.Secp256k1Blake160);
  await signer.prepareTransaction(transaction);
  const occupied = sendLimitCapacity(cellOutput.lock, data);
  const fee = (BigInt(transaction.toBytes().length + 4) * FEE_RATE + 999n) / 1000n;
  if (occupied + fee <= cellOutput.capacity) {
    transaction.outputs[0].capacity = cellOutput.capacity - fee;
    return transaction;
  }
  transaction.outputs[0].capacity = occupied + SEND_LIMIT_SPARE;
  await transaction.completeFeeChangeToLock(signer, await currentLock(client, wallet.litPublicKey, wallet.recovery), FEE_RATE);
  await signer.prepareTransaction(transaction);
  if (sendLimitInputIndex(transaction, head) === -1) throw new Error("The send-limit change lost its input");
  return transaction;
}
