import * as ccc from "@ckb-ccc/core";
import { JsonRpcTransformers, type JsonRpcCellOutput, type JsonRpcOutPoint, type JsonRpcTransaction } from "@ckb-ccc/core/advanced";
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
  // The cells and the history must come from the same node, as in the Action: a node that fails retries the whole
  // search on the next.
  let lastError: unknown;
  for (const url of RPC_URLS) {
    try {
      return await liveSendLimitCellAt(url, secp, spent);
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError ?? new Error("CKB RPC is unavailable");
}

/**
 * The newest live send-limit cell this key made at its secp256k1 address, read the way the Action reads it.
 * Anyone can plant a look-alike there; the real one was made by a transaction that spent one of the key's own cells
 * (any input), which needs its signature. That is read from the key's own lock history in just the blocks that hold
 * the candidates, in batches, so the whole search is a few requests however many look-alikes there are, within the
 * Action's own bound of 16 pages. Past that it's an error, never "no send limits"; so is an indexer that is behind
 * its chain, whose empty answer could hide the real cell.
 */
async function liveSendLimitCellAt(url: string, secp: ccc.Script, spent: Set<string>): Promise<SendLimitHead | undefined> {
  const [indexer, tip] = await rpcBatch(url, [{ method: "get_indexer_tip", params: [] }, { method: "get_tip_header", params: [] }]) as Array<{ block_number?: string; number?: string; timestamp?: string }>;
  if (typeof tip.number !== "string" || typeof tip.timestamp !== "string" || typeof indexer.block_number !== "string") throw new Error("CKB RPC returned an invalid tip");
  if (BigInt(tip.number) - BigInt(indexer.block_number) > MAX_INDEXER_LAG) throw new Error("CKB RPC's indexer is behind the chain");
  if (Date.now() - Number(BigInt(tip.timestamp)) > MAX_TIP_AGE_MS) throw new Error("CKB RPC's chain is behind the network");
  const lockKey = (filter: Record<string, unknown>) => ({ script: JsonRpcTransformers.scriptFrom(secp), script_type: "lock", script_search_mode: "exact", filter });
  const filter = { script: { code_hash: TYPE_ID_CODE_HASH, hash_type: "type", args: "0x" }, output_data: SEND_LIMIT_MAGIC, output_data_filter_mode: "prefix" };
  const candidates: Array<{ outPoint: ccc.OutPoint; cellOutput: ccc.CellOutput; outputData: ccc.Hex; block: bigint }> = [];
  let cursor: string | undefined;
  for (let pages = 1; ; pages++) {
    // Nodes that ignore the data filter return other Type ID cells too; those are passed over, up to a page bound.
    if (pages > MAX_PAGES) throw new Error("This account has too many look-alike send-limit cells to check");
    const page = await rpc(url, "get_cells", [lockKey(filter), "asc", ccc.numToHex(PAGE_SIZE), ...(cursor ? [cursor] : [])]) as { objects?: unknown; last_cursor?: string };
    if (!Array.isArray(page.objects)) throw new Error("CKB RPC returned an invalid get_cells page");
    for (const object of page.objects as Array<{ out_point: JsonRpcOutPoint; output: JsonRpcCellOutput; output_data?: string; block_number: string }>) {
      const outputData = ccc.hexFrom(object.output_data ?? "0x");
      const cellOutput = JsonRpcTransformers.cellOutputTo(object.output);
      if (!isSendLimitCell(cellOutput, outputData, secp)) continue;
      // Look-alikes anyone plants count toward no cap: only the page bound limits how many are read.
      candidates.push({ outPoint: JsonRpcTransformers.outPointTo(object.out_point), cellOutput, outputData, block: BigInt(object.block_number) });
    }
    if (page.objects.length < PAGE_SIZE || !page.last_cursor) break;
    cursor = page.last_cursor;
  }
  const live = candidates.filter(({ outPoint }) => !spent.has(`${outPoint.txHash}:${Number(outPoint.index)}`));
  if (live.length === 0) return undefined;

  // A full page of a block's history is read on from its cursor, so cells outsiders give the key in the same block
  // can't hide its own entry; only past MAX_HISTORY_PAGES full pages (CKB the outsider gave away) is it an error.
  let pending: Array<{ block: bigint; cursor?: string }> = [...new Set(live.map(({ block }) => block))].map((block) => ({ block }));
  const madeByKey = new Set<string>();
  for (let round = 0; pending.length > 0; round++) {
    if (round >= MAX_HISTORY_PAGES) throw new Error("A block holds too much of this account's history to check");
    const next: typeof pending = [];
    for (let at = 0; at < pending.length; at += BATCH_SIZE) {
      const slice = pending.slice(at, at + BATCH_SIZE);
      const calls = slice.map(({ block, cursor }) => ({
        method: "get_transactions",
        params: [lockKey({ block_range: [ccc.numToHex(block), ccc.numToHex(block + 1n)] }), "asc", ccc.numToHex(MAX_BLOCK_HISTORY), ...(cursor ? [cursor] : [])],
      }));
      (await rpcBatch(url, calls) as Array<{ objects?: Array<{ tx_hash?: string; io_type?: string }>; last_cursor?: string }>).forEach((result, i) => {
        if (!Array.isArray(result.objects)) throw new Error("CKB RPC returned an invalid get_transactions page");
        for (const entry of result.objects) if (entry.io_type === "input" && typeof entry.tx_hash === "string") madeByKey.add(entry.tx_hash.toLowerCase());
        if (result.objects.length >= MAX_BLOCK_HISTORY) {
          if (typeof result.last_cursor !== "string") throw new Error("CKB RPC returned an invalid get_transactions page");
          next.push({ ...slice[i], cursor: result.last_cursor });
        }
      });
    }
    pending = next;
  }
  // The indexer lists cells oldest first; every chained send makes the real one the newest.
  const real = live.filter(({ outPoint }) => madeByKey.has(outPoint.txHash)).at(-1);
  if (!real) return undefined;
  const [found] = await rpcBatch(url, [{ method: "get_transaction", params: [real.outPoint.txHash] }]) as Array<{ transaction?: JsonRpcTransaction }>;
  const creator = found.transaction ? JsonRpcTransformers.transactionTo(found.transaction) : undefined;
  if (!creator || creator.hash() !== real.outPoint.txHash) throw new Error("CKB RPC returned the wrong transaction");
  return { outPoint: { txHash: real.outPoint.txHash, index: Number(real.outPoint.index) }, cellOutput: real.cellOutput, outputData: real.outputData, recordEntriesBytes: recordEntriesBytes(recordOf(creator) ?? "0x") };
}

/** How the search reaches CKB nodes; tests replace `fetch` with a fake chain. */
export const sendLimitRpc: { fetch: (url: string, init: { method: string; headers: Record<string, string>; body: string; redirect: "error" }) => Promise<Response> } = {
  fetch: (url, init) => globalThis.fetch(url, init),
};

async function post(url: string, payload: unknown): Promise<unknown> {
  const response = await sendLimitRpc.fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload), redirect: "error" });
  if (!response.ok) throw new Error(`CKB RPC returned HTTP ${response.status}`);
  return response.json();
}

/** One JSON-RPC call's result; an error or a missing result fails it. */
async function rpc(url: string, method: string, params: unknown[]): Promise<unknown> {
  const reply = await post(url, { id: 0, jsonrpc: "2.0", method, params }) as { result?: unknown } | null;
  if (!reply?.result) throw new Error(`CKB RPC didn't answer ${method}`);
  return reply.result;
}

/** One JSON-RPC batch, each call's result in order; any error or missing result fails the batch. */
async function rpcBatch(url: string, calls: Array<{ method: string; params: unknown[] }>): Promise<unknown[]> {
  const replies = await post(url, calls.map((call, id) => ({ id, jsonrpc: "2.0", ...call }))) as Array<{ id?: unknown; result?: unknown }>;
  if (!Array.isArray(replies)) throw new Error("CKB RPC returned an invalid batch");
  const results = new Array<unknown>(calls.length);
  for (const reply of replies) if (Number.isInteger(reply?.id) && (reply.id as number) >= 0 && (reply.id as number) < calls.length && reply.result) results[reply.id as number] = reply.result;
  for (let i = 0; i < calls.length; i++) if (results[i] === undefined) throw new Error("CKB RPC left a call in the batch unanswered");
  return results;
}

const TYPE_ID_CODE_HASH = "0x00000000000000000000000000000000000000000000000000545950455f4944";
/** The nodes the Action reads (its RPC_URLS), over HTTP so history lookups can go in batches. */
const RPC_URLS = ["https://testnet.ckb.dev/", "https://testnet.ckbapp.dev/"];
/** How long after signing a transaction the node doesn't know yet is waited for: its client is sending it. */
const JUST_SIGNED_MS = 10_000;
/** Indexer pages of send-limit-shaped cells, as in the Action: from 4096 such cells (each at least 130 CKB) it's an error. */
const PAGE_SIZE = 256;
const MAX_PAGES = 16;
/** History lookups in one request. */
const BATCH_SIZE = 256;
/** Entries of the key's history in one page, and full pages read from one block, as in the Action. */
const MAX_BLOCK_HISTORY = 1024;
const MAX_HISTORY_PAGES = 4;
/** Blocks an indexer may be behind its chain tip before its answer isn't believed, as in the Action. */
const MAX_INDEXER_LAG = 3n;
/** How old a node's tip may be before its chain is taken to have stalled, as in the Action. */
const MAX_TIP_AGE_MS = 10 * 60_000;
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
