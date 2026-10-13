import assert from "node:assert/strict";
import test from "node:test";
import * as ccc from "@ckb-ccc/core";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { formatCkbSignature } from "../src/server/funding-transaction.ts";
import { describeTransaction, type KnownScripts } from "../src/server/transaction-policy.ts";
import { parseThreshold } from "../src/server/general-signing.ts";

const client = new ccc.ClientPublicTestnet();
const CKB = 100_000_000n;
const info = (codeHash: string) => ({ codeHash: ccc.hexFrom(codeHash), hashType: "type", cellDeps: [] }) as unknown as ccc.ScriptInfo;
const SECP = `0x${"9b".repeat(32)}`;
const known: KnownScripts = {
  xudt: info(`0x${"25".repeat(32)}`),
  sudt: info(`0x${"26".repeat(32)}`),
  dao: info(`0x${"82".repeat(32)}`),
  wallets: [{ name: "standard", info: info(SECP) }],
  quiet: [],
};
const lock = (byte: string) => ccc.Script.from({ codeHash: SECP, hashType: "type", args: `0x${byte.repeat(20)}` });
const own = lock("11");
const alice = lock("22");
const contract = ccc.Script.from({ codeHash: `0x${"77".repeat(32)}`, hashType: "type", args: "0x" });
const xudt = ccc.Script.from({ codeHash: known.xudt.codeHash, hashType: "type", args: `0x${"aa".repeat(32)}` });
const dao = ccc.Script.from({ codeHash: known.dao.codeHash, hashType: "type", args: "0x" });
const spore = ccc.Script.from({ codeHash: "0x685a60219309029d01310311dba953d67029170ca4848a4ff638e57002130a0d", hashType: "data1", args: `0x${"5e".repeat(32)}` });
const mystery = ccc.Script.from({ codeHash: `0x${"9f".repeat(32)}`, hashType: "type", args: "0x" });

type Cell = { lock: ccc.Script; capacity: bigint; type?: ccc.Script; data?: ccc.Hex };
const u128 = (value: bigint) => ccc.hexFrom(ccc.numLeToBytes(value, 16));

function build(inputs: Cell[], outputs: Cell[]) {
  const transaction = ccc.Transaction.from({
    inputs: inputs.map((_, index) => ({ previousOutput: { txHash: `0x${index.toString(16).padStart(64, "0")}`, index: 0 } })),
    outputs: outputs.map((cell) => ({ lock: cell.lock, capacity: cell.capacity, type: cell.type })),
    outputsData: outputs.map((cell) => cell.data ?? "0x"),
    witnesses: [ccc.hexFrom(ccc.WitnessArgs.from({ lock: `0x${"00".repeat(65)}` }).toBytes())],
  });
  const inputCells = inputs.map((cell) => ({ cellOutput: ccc.CellOutput.from({ lock: cell.lock, capacity: cell.capacity, type: cell.type }), outputData: cell.data ?? "0x" as ccc.Hex }));
  return describeTransaction(transaction, inputCells, own, known, client);
}

test("describes a plain CKB transfer, its recipient and the fee", () => {
  const fee = 1_000n;
  const { preview, outflowShannons } = build(
    [{ lock: own, capacity: 1_000n * CKB }],
    [{ lock: alice, capacity: 100n * CKB }, { lock: own, capacity: 900n * CKB - fee }],
  );
  assert.equal(preview.sendingCkb, "100");
  assert.equal(preview.feeCkb, "0.00001");
  assert.equal(outflowShannons, 100n * CKB + fee);
  assert.equal(preview.recipients.length, 1);
  assert.equal(preview.recipients[0].kind, "wallet");
  assert.equal(preview.recipients[0].ckb, "100");
  assert.match(preview.recipients[0].address, /^ckt1/);
  assert.equal(preview.otherSigners, 0);
});

test("receiving tokens doesn't count as tokens leaving", () => {
  const { tokensLeaving } = build(
    [{ lock: own, capacity: 500n * CKB }, { lock: alice, capacity: 200n * CKB, type: xudt, data: u128(10n) }],
    [{ lock: own, capacity: 200n * CKB, type: xudt, data: u128(10n) }, { lock: own, capacity: 500n * CKB - 2_000n }],
  );
  assert.equal(tokensLeaving, false);
});

test("refuses a fee above the size-based cap but accepts a generous normal one", () => {
  assert.throws(() => build([{ lock: own, capacity: 1_000n * CKB }], [{ lock: alice, capacity: 990n * CKB }]), /above the KeyWay limit/);
  const { preview } = build([{ lock: own, capacity: 1_000n * CKB }], [{ lock: alice, capacity: 1_000n * CKB - 50_000n }]);
  assert.equal(preview.feeCkb, "0.0005");
});

test("reports token amounts leaving the account and who receives them", () => {
  const { preview, tokensLeaving } = build(
    [{ lock: own, capacity: 200n * CKB, type: xudt, data: u128(1_000n) }, { lock: own, capacity: 500n * CKB }],
    [
      { lock: alice, capacity: 143n * CKB, type: xudt, data: u128(250n) },
      { lock: own, capacity: 143n * CKB, type: xudt, data: u128(750n) },
      { lock: own, capacity: 414n * CKB - 2_000n },
    ],
  );
  assert.deepEqual(preview.tokens.map(({ standard, amount }) => ({ standard, amount })), [{ standard: "xUDT", amount: "-250" }]);
  assert.equal(preview.recipients[0].tokens[0].amount, "250");
  assert.equal(preview.recipients[0].ckb, "143");
  assert.equal(tokensLeaving, true);
});

test("recognizes a Nervos DAO deposit", () => {
  const { preview } = build(
    [{ lock: own, capacity: 2_000n * CKB }],
    [{ lock: own, capacity: 1_000n * CKB, type: dao, data: "0x0000000000000000" }, { lock: own, capacity: 1_000n * CKB - 3_000n }],
  );
  assert.deepEqual(preview.dao, [{ action: "deposit", amountCkb: "1000" }]);
  assert.equal(preview.sendingCkb, "0");
});

test("shows an NFT leaving the account and flags unrecognized scripts", () => {
  const { preview } = build(
    [{ lock: own, capacity: 300n * CKB, type: spore, data: "0x01" }, { lock: own, capacity: 500n * CKB, type: mystery }],
    [{ lock: alice, capacity: 300n * CKB, type: spore, data: "0x01" }, { lock: contract, capacity: 500n * CKB - 4_000n, type: mystery }],
  );
  assert.equal(preview.nfts[0].kind, "Spore");
  assert.equal(preview.nfts[0].change, "sent");
  assert.equal(preview.unrecognized.length, 1);
  assert.equal(preview.unrecognized[0].cells, 2);
  assert.equal(preview.recipients.find((recipient) => recipient.kind === "contract")?.ckb, "499.99996");
});

test("counts inputs that other people must sign", () => {
  const { preview } = build(
    [{ lock: own, capacity: 200n * CKB }, { lock: alice, capacity: 100n * CKB }],
    [{ lock: alice, capacity: 150n * CKB }, { lock: own, capacity: 150n * CKB - 1_000n }],
  );
  assert.equal(preview.otherSigners, 1);
  assert.equal(preview.sendingCkb, "50.00001");
});

test("signatures over CCC's message hash verify with CCC's verifyMessage", () => {
  const privateKey = secp256k1.utils.randomSecretKey();
  const publicKey = ccc.hexFrom(secp256k1.getPublicKey(privateKey, true));
  const message = "Log in to Acme Pay";
  const digest = ccc.bytesFrom(ccc.messageHashCkbSecp256k1(message));
  const raw = secp256k1.sign(digest, privateKey, { prehash: false, format: "recovered" });
  const signature = formatCkbSignature({
    recoveryParam: raw[0] as 0 | 1,
    r: ccc.hexFrom(raw.slice(1, 33)),
    s: ccc.hexFrom(raw.slice(33, 65)),
  });
  assert.equal(ccc.verifyMessageCkbSecp256k1(message, signature, publicKey), true);
});

test("validates email-confirmation thresholds", () => {
  assert.equal(parseThreshold(null), null);
  assert.equal(parseThreshold("10000000000"), 10_000_000_000n);
  assert.throws(() => parseThreshold("0"), /greater than zero/);
  assert.throws(() => parseThreshold(5), /whole number/);
});

test("RUSD's own token contract is read as a token, and shown in RUSD", () => {
  const rusd = ccc.Script.from({ codeHash: "0x1142755a044bf2ee358cba9f2da187ce928c91cd4dc8692ded0337efa677d21a", hashType: "type", args: "0x878fcc6f1f08d48e87bb1c3b3d5083f23f8a39c5d5c764f253b55b998526439b" });
  const { preview, tokenOutflows } = build(
    [{ lock: own, capacity: 142n * CKB, type: rusd, data: u128(60n * CKB) }, { lock: own, capacity: 1_000n * CKB }],
    [{ lock: alice, capacity: 142n * CKB, type: rusd, data: u128(25n * CKB) }, { lock: own, capacity: 142n * CKB, type: rusd, data: u128(35n * CKB) }, { lock: own, capacity: 858n * CKB - 1_000n }],
  );
  assert.equal(preview.unrecognized.length, 0);
  assert.equal(preview.tokens[0].amountText, "-25 RUSD");
  assert.deepEqual(tokenOutflows, [{ asset: rusd.hash(), amount: 25n * CKB }]);
});

test("cells with a type script KeyWay can't read count as tokens leaving, per cell", () => {
  const { tokensLeaving, tokenOutflows } = build(
    [{ lock: own, capacity: 200n * CKB, type: mystery }, { lock: own, capacity: 1_000n * CKB }],
    [{ lock: alice, capacity: 200n * CKB, type: mystery }, { lock: own, capacity: 1_000n * CKB - 1_000n }],
  );
  assert.equal(tokensLeaving, true);
  assert.deepEqual(tokenOutflows, [{ asset: mystery.hash(), amount: 1n }]);
});
