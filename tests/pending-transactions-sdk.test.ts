// Back-to-back sends from fresh clients (another tab, a reload, another device): every send is signed through
// KeyWay, which lists the account's pending transactions; each signer loads them before it picks inputs.
import assert from "node:assert/strict";
import test from "node:test";
import * as ccc from "@ckb-ccc/core";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { secp256k1Lock } from "../src/sdk/browser/account-lock.ts";
import type { KeyWayApiClient } from "../src/sdk/browser/api-client.ts";
import { KeyWaySigner } from "../src/sdk/browser/keyway-signer.ts";
import { PendingTransactions } from "../src/sdk/browser/pending-transactions.ts";
import { encodeSendLimitSettings, sendLimitInputIndex, type SendLimitHead } from "../src/sdk/browser/send-limits.ts";

const CKB = 100_000_000n;
const publicKey = ccc.hexFrom(secp256k1.getPublicKey(secp256k1.utils.randomSecretKey(), true));
const stranger = ccc.Script.from({ codeHash: `0x${"99".repeat(32)}`, hashType: "type", args: "0x" });
const typeId = ccc.Script.from({ codeHash: "0x00000000000000000000000000000000000000000000000000545950455f4944", hashType: "type", args: `0x${"42".repeat(32)}` });

/** A chain of committed cells every client reads from the indexer; pending transactions are only on the server. */
function chain(cells: ccc.Cell[]) {
  const client = () => {
    const fresh = new ccc.ClientPublicTestnet({ url: "https://testnet.ckb.dev/" });
    Object.assign(fresh, {
      findSingletonCellByType: async () => undefined,
      findCellsOnChain: async function* (key: ccc.ClientIndexerSearchKeyLike) {
        const search = ccc.ClientIndexerSearchKey.from(key);
        for (const cell of cells) {
          if (!cell.cellOutput.lock.eq(search.script)) continue;
          const [min, max] = search.filter?.scriptLenRange ?? [0n, 1n << 64n];
          const typeLength = BigInt(cell.cellOutput.type ? cell.cellOutput.type.toBytes().length : 0);
          if (search.filter?.scriptLenRange && (typeLength < min || typeLength >= max)) continue;
          yield cell;
        }
      },
      getCell: async (outPoint: ccc.OutPointLike) => cells.find((cell) => cell.outPoint.eq(ccc.OutPoint.from(outPoint))),
    });
    return fresh;
  };
  return { client };
}

/** KeyWay's server as far as signing goes: it approves, "signs" (returns the transaction) and lists what it signed. */
function server(initialHead?: SendLimitHead) {
  const signed: ccc.Transaction[] = [];
  let head = initialHead;
  const api = {
    pendingTransactions: async () => ({ transactions: signed.map((tx) => JSON.parse(ccc.stringify(tx))), ...(head ? { sendLimit: head } : {}) }),
    signTransaction: async (_token: string, body: Record<string, unknown>) => {
      const transaction = ccc.Transaction.from(body.transaction as ccc.TransactionLike);
      if (body.operation === "preview") return { preview: { transactionHash: transaction.hash() }, confirmationNonce: crypto.randomUUID(), requiresEmailCode: false };
      signed.push(transaction);
      if (head) {
        const index = sendLimitInputIndex(transaction, head);
        if (index !== -1) {
          const out = transaction.outputs.findIndex((output) => output.type?.eq(typeId));
          head = { outPoint: { txHash: transaction.hash(), index: out }, cellOutput: transaction.outputs[out], outputData: ccc.hexFrom(transaction.outputsData[out]), recordEntriesBytes: 49 };
        }
      }
      return { transaction: JSON.parse(ccc.stringify(transaction)) };
    },
  } as unknown as KeyWayApiClient;
  return { api, signed };
}

const handlers = { approveCkbTransaction: () => true, approveCkbMessage: () => false, requestEmailCode: async () => undefined };

async function send(signer: KeyWaySigner, amount: bigint) {
  const tx = ccc.Transaction.from({ outputs: [{ lock: stranger, capacity: amount }] });
  await tx.completeInputsByCapacity(signer);
  await tx.completeFeeBy(signer, 1_000n);
  return signer.signOnlyTransaction(tx);
}

let nextHash = 1;
const cell = (lock: ccc.Script, capacity: bigint, type?: ccc.Script, outputData: ccc.Hex = "0x") =>
  ccc.Cell.from({ outPoint: { txHash: `0x${(nextHash++).toString(16).padStart(64, "0")}`, index: 0 }, cellOutput: { lock, capacity, type }, outputData });

test("a fresh client skips the cells another client's pending send spent and uses its change", async () => {
  const secp = await secp256k1Lock(new ccc.ClientPublicTestnet(), publicKey);
  const funds = cell(secp, 1_000n * CKB);
  const world = chain([funds]);
  const { api, signed } = server();
  // Two tabs, each with its own CCC client and cache.
  const first = new KeyWaySigner("token", publicKey, handlers, world.client(), api);
  const one = await send(first, 100n * CKB);
  assert.ok(one.inputs[0].previousOutput.eq(funds.outPoint));
  // Without the list, the second tab would pick `funds` again and the node would refuse it.
  const second = new KeyWaySigner("token", publicKey, handlers, world.client(), api);
  const two = await send(second, 100n * CKB);
  assert.ok(!two.inputs.some((input) => input.previousOutput.eq(funds.outPoint)), "the spent cell is skipped");
  assert.ok(two.inputs.some((input) => input.previousOutput.txHash === one.hash()), "the first send's change is spent");
  // And a third client right after both.
  const third = new KeyWaySigner("token", publicKey, handlers, world.client(), api);
  const three = await send(third, 100n * CKB);
  assert.ok(three.inputs.some((input) => input.previousOutput.txHash === two.hash()));
  assert.equal(signed.length, 3);
});

test("with limits on, every send chains on the newest send-limit cell, across clients", async () => {
  const secp = await secp256k1Lock(new ccc.ClientPublicTestnet(), publicKey);
  const data = encodeSendLimitSettings({ fingerprint: `0x${"11".repeat(32)}`, tokensUnlimited: false, ckb: 100n * CKB, tokens: new Map() });
  const limitCell = cell(secp, 174n * CKB, typeId, data);
  const world = chain([cell(secp, 1_000n * CKB), limitCell]);
  const head = { outPoint: { txHash: limitCell.outPoint.txHash, index: 0 }, cellOutput: limitCell.cellOutput, outputData: data, recordEntriesBytes: 0 };
  const { api } = server(head);
  const first = new KeyWaySigner("token", publicKey, handlers, world.client(), api);
  const one = await send(first, 50n * CKB);
  const index = sendLimitInputIndex(one, head);
  assert.notEqual(index, -1, "the send spends the send-limit cell");
  assert.ok(one.outputs.some((output, i) => output.type?.eq(typeId) && one.outputsData[i] === data), "and creates its unchanged successor");
  assert.ok(ccc.bytesFrom(one.getWitnessArgsAt(index)!.inputType!).length >= 6 + 49, "with room for the record");
  // The CCC fee covers the added cell: the fee rate holds with the record's room counted.
  assert.ok(await one.getFee(world.client()) >= one.estimateFee(1_000n));

  // The same page right away, and another client: both build on the first send's pending cell.
  const again = await send(first, 10n * CKB);
  assert.equal(again.inputs[sendLimitInputIndex(again, { outPoint: { txHash: one.hash(), index: one.outputs.findIndex((o) => o.type?.eq(typeId)) } })]?.previousOutput.txHash, one.hash());
  const other = new KeyWaySigner("token", publicKey, handlers, world.client(), api);
  const two = await send(other, 10n * CKB);
  assert.ok(two.inputs.some((input) => input.previousOutput.txHash === again.hash() && input.previousOutput.index === BigInt(again.outputs.findIndex((o) => o.type?.eq(typeId)))));
});

test("pending transactions are marked in the order they were signed, and a failed load keeps sending possible", async () => {
  const secp = await secp256k1Lock(new ccc.ClientPublicTestnet(), publicKey);
  const funds = cell(secp, 1_000n * CKB);
  const parent = ccc.Transaction.from({ inputs: [{ previousOutput: funds.outPoint }], outputs: [{ lock: secp, capacity: 900n * CKB }], outputsData: ["0x"] });
  const child = ccc.Transaction.from({ inputs: [{ previousOutput: { txHash: parent.hash(), index: 0 } }], outputs: [{ lock: secp, capacity: 800n * CKB }], outputsData: ["0x"] });
  const client = chain([funds]).client();
  const pending = new PendingTransactions(async () => ({ transactions: [parent, child].map((tx) => JSON.parse(ccc.stringify(tx))) }), client);
  await pending.refresh(true);
  assert.equal(await client.cache.isUnusable({ txHash: parent.hash(), index: 0 }), true, "the parent's output is spent by the child");
  assert.equal(await client.cache.isUnusable(funds.outPoint), true);
  const found: ccc.Cell[] = [];
  for await (const live of client.findCells({ script: secp, scriptType: "lock", scriptSearchMode: "exact" })) found.push(live);
  assert.deepEqual(found.map((live) => live.outPoint.txHash), [child.hash()]);

  let calls = 0;
  const failing = new PendingTransactions(async () => { calls++; throw new Error("KeyWay is unavailable"); }, chain([]).client());
  assert.deepEqual((await failing.refresh(true)).transactions, []);
  await failing.refresh();
  assert.equal(calls, 1, "loads again only after a moment");
});
