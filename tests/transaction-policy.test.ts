import assert from "node:assert/strict";
import test from "node:test";
import * as ccc from "@ckb-ccc/core";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { secp256k1Lock, type KeyWayRecovery } from "../src/sdk/browser/account-lock.ts";
import { formatCkbSignature, previewFundingTransaction, serializeTransaction } from "../src/server/funding-transaction.ts";
import { describeTransaction, previewGeneralTransaction, previewSummaryLines, type KnownScripts } from "../src/server/transaction-policy.ts";
import { parseThreshold } from "../src/server/general-signing.ts";
import type { ReadyWallet } from "../src/server/user-wallet.ts";

const client = new ccc.ClientPublicTestnet();
const CKB = 100_000_000n;
const info = (codeHash: string) => ({ codeHash: ccc.hexFrom(codeHash), hashType: "type", cellDeps: [] }) as unknown as ccc.ScriptInfo;
const SECP = `0x${"9b".repeat(32)}`;
const TYPE_ID = "0x00000000000000000000000000000000000000000000000000545950455f4944";
const UNIQUE = `0x${"2c".repeat(32)}`;
const known: KnownScripts = {
  xudt: info(`0x${"25".repeat(32)}`),
  sudt: info(`0x${"26".repeat(32)}`),
  dao: info(`0x${"82".repeat(32)}`),
  wallets: [{ name: "standard", info: info(SECP) }],
  quiet: [info(TYPE_ID), info(UNIQUE)],
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

function build(inputs: Cell[], outputs: Cell[], recovery?: KeyWayRecovery) {
  const transaction = ccc.Transaction.from({
    inputs: inputs.map((_, index) => ({ previousOutput: { txHash: `0x${index.toString(16).padStart(64, "0")}`, index: 0 } })),
    outputs: outputs.map((cell) => ({ lock: cell.lock, capacity: cell.capacity, type: cell.type })),
    outputsData: outputs.map((cell) => cell.data ?? "0x"),
    witnesses: [ccc.hexFrom(ccc.WitnessArgs.from({ lock: `0x${"00".repeat(65)}` }).toBytes())],
  });
  const inputCells = inputs.map((cell) => ({ cellOutput: ccc.CellOutput.from({ lock: cell.lock, capacity: cell.capacity, type: cell.type }), outputData: cell.data ?? "0x" as ccc.Hex }));
  return describeTransaction(transaction, inputCells, own, known, client, undefined, recovery);
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

test("names NFTs and tokens by their whole ID, and keeps tokens apart that a short ID would merge", () => {
  // Two xUDT tokens ground (in seconds) so their type script hashes share the old short form, 0xbdb681…72b5.
  const twinA = ccc.Script.from({ codeHash: known.xudt.codeHash, hashType: "type", args: `0x71d40e${"00".repeat(29)}` });
  const twinB = ccc.Script.from({ codeHash: known.xudt.codeHash, hashType: "type", args: `0xedc32b${"00".repeat(29)}` });
  assert.equal(twinA.hash(), "0xbdb681eee837511ca24e81fff9e2476fbcb402d5ef264a31c4fa30ef01da72b5");
  assert.equal(twinB.hash(), "0xbdb68117fdbb5becaaeaaa710e97c5e02cf34fa8eac6abafea610c90224472b5");
  // Two Spores whose IDs share their start and end.
  const sporeA = ccc.Script.from({ ...spore, args: `0x${"5e".repeat(14)}${"00".repeat(4)}${"5e".repeat(14)}` });
  const sporeB = ccc.Script.from({ ...spore, args: `0x${"5e".repeat(14)}${"ff".repeat(4)}${"5e".repeat(14)}` });
  const { preview } = build(
    [
      { lock: own, capacity: 300n * CKB, type: sporeA, data: "0x01" },
      { lock: own, capacity: 200n * CKB, type: twinA, data: u128(1_000n) },
      { lock: own, capacity: 200n * CKB, type: twinB, data: u128(7n) },
      { lock: own, capacity: 500n * CKB },
    ],
    [
      { lock: alice, capacity: 300n * CKB, type: sporeA, data: "0x01" },
      { lock: alice, capacity: 200n * CKB, type: twinA, data: u128(1_000n) },
      { lock: alice, capacity: 200n * CKB, type: twinB, data: u128(7n) },
      { lock: own, capacity: 300n * CKB, type: sporeB, data: "0x02" },
      { lock: own, capacity: 200n * CKB - 5_000n },
    ],
  );
  assert.deepEqual(preview.nfts, [{ kind: "Spore", id: sporeA.args, change: "sent" }, { kind: "Spore", id: sporeB.args, change: "minted" }]);
  const [recipient] = preview.recipients;
  assert.deepEqual(recipient.nfts, [`Spore ${sporeA.args}`]);
  assert.deepEqual(recipient.tokens.map(({ asset, amount }) => ({ asset, amount })), [{ asset: twinA.hash(), amount: "1000" }, { asset: twinB.hash(), amount: "7" }]);
  assert.deepEqual(recipient.tokens.map(({ amountText }) => amountText), [`1000 of token ${twinA.hash()}`, `7 of token ${twinB.hash()}`]);
  const lines = previewSummaryLines(preview);
  assert.ok(lines.includes(`Spore ${sporeA.args}: sent`), lines.join("\n"));
  assert.ok(lines.includes(`Spore ${sporeB.args}: minted`), lines.join("\n"));
  assert.ok(lines.includes(`Token -1000 of token ${twinA.hash()} (xUDT ${twinA.hash()})`), lines.join("\n"));
  assert.ok(lines.includes(`Token -7 of token ${twinB.hash()} (xUDT ${twinB.hash()})`), lines.join("\n"));
  assert.ok(lines.every((line) => !line.includes("…")), lines.join("\n"));
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

test("with recovery on, the Omnilock and the old secp256k1 lock are both the user's", () => {
  const omni = ccc.Script.from({ codeHash: `0x${"f3".repeat(32)}`, hashType: "type", args: `0x00${"11".repeat(20)}01${"aa".repeat(32)}` });
  const transaction = ccc.Transaction.from({
    inputs: [0, 1].map((index) => ({ previousOutput: { txHash: `0x${index.toString(16).padStart(64, "0")}`, index: 0 } })),
    outputs: [{ lock: alice, capacity: 100n * CKB }, { lock: omni, capacity: 600n * CKB - 2_000n }],
    outputsData: ["0x", "0x"],
    witnesses: [ccc.hexFrom(ccc.WitnessArgs.from({ lock: `0x${"00".repeat(85)}` }).toBytes()), "0x"],
  });
  const inputCells = [[omni, 300n], [own, 400n]].map(([lock, ckb]) => ({ cellOutput: ccc.CellOutput.from({ lock: lock as ccc.Script, capacity: (ckb as bigint) * CKB }), outputData: "0x" as ccc.Hex }));
  const { preview, outflowShannons } = describeTransaction(transaction, inputCells, [omni, own], known, client);
  assert.equal(preview.sendingCkb, "100");
  assert.equal(outflowShannons, 100n * CKB + 2_000n);
  assert.equal(preview.otherSigners, 0);
  assert.deepEqual(preview.details.inputs.map(({ lock }) => lock), ["you", "you"]);
  assert.equal(preview.recipients.length, 1);
});

test("CKB moved under a type script the account doesn't control counts as leaving", () => {
  // Whoever wrote this type script decides when a cell under it can be spent again.
  const hostile = ccc.Script.from({ codeHash: `0x${"66".repeat(32)}`, hashType: "type", args: "0x" });
  const fee = 1_000n;
  const locked = build([{ lock: own, capacity: 500n * CKB }], [{ lock: own, capacity: 500n * CKB - fee, type: hostile }]);
  assert.equal(locked.outflowShannons, 500n * CKB);

  // A small cell of the type the account already holds vouches for no more CKB than it holds.
  const topped = build(
    [{ lock: own, capacity: 100n * CKB, type: hostile }, { lock: own, capacity: 400n * CKB }],
    [{ lock: own, capacity: 500n * CKB - fee, type: hostile }],
  );
  assert.equal(topped.outflowShannons, 400n * CKB);

  // Moving a cell under its own type, a plain self-transfer and a token change stay at the fee.
  assert.equal(build([{ lock: own, capacity: 100n * CKB, type: hostile }], [{ lock: own, capacity: 100n * CKB - fee, type: hostile }]).outflowShannons, fee);
  assert.equal(build([{ lock: own, capacity: 400n * CKB }], [{ lock: own, capacity: 400n * CKB - fee }]).outflowShannons, fee);
  assert.equal(build(
    [{ lock: own, capacity: 200n * CKB, type: xudt, data: u128(10n) }, { lock: own, capacity: 300n * CKB }],
    [{ lock: own, capacity: 300n * CKB, type: xudt, data: u128(10n) }, { lock: own, capacity: 200n * CKB - fee }],
  ).outflowShannons, fee);
});

test("a token balance of an unlisted type (or xUDT referenced by data hash) can't leave while an empty cell comes back", () => {
  const xudtByData = ccc.Script.from({ codeHash: "0x50bd8d6680b8b9cf98b73f3c08faf8b2a21914311954118ad6609be6e78a1b95", hashType: "data1", args: `0x${"cd".repeat(32)}` });
  const otherUdt = ccc.Script.from({ codeHash: `0x${"5a".repeat(32)}`, hashType: "type", args: `0x${"01".repeat(32)}` });
  for (const [token, amount] of [[xudtByData, 1_000n], [otherUdt, 1n]] as const) {
    // Someone else pays for the recipient's cell; an empty cell of the token comes back to the account.
    const { tokensLeaving, tokenOutflows } = build(
      [{ lock: own, capacity: 200n * CKB, type: token, data: u128(1_000n) }, { lock: alice, capacity: 300n * CKB }],
      [{ lock: own, capacity: 200n * CKB, type: token, data: u128(0n) }, { lock: alice, capacity: 300n * CKB - 2_000n, type: token, data: u128(1_000n) }],
    );
    assert.equal(tokensLeaving, true, token.codeHash);
    assert.deepEqual(tokenOutflows, [{ asset: token.hash(), amount }], token.codeHash);
  }
  // The same cell coming back unchanged isn't a transfer.
  const moved = build(
    [{ lock: own, capacity: 200n * CKB, type: otherUdt, data: u128(1_000n) }, { lock: own, capacity: 300n * CKB }],
    [{ lock: own, capacity: 200n * CKB, type: otherUdt, data: u128(1_000n) }, { lock: own, capacity: 300n * CKB - 2_000n }],
  );
  assert.deepEqual(moved.tokenOutflows, []);
});

test("Spore, Cluster, Type ID and Unique cells leaving the account count as assets, per cell, like the Lit Action", () => {
  const cluster = ccc.Script.from({ codeHash: "0x0bbe768b519d8ea7b96d58f1182eb7e6ef96c541fbd9526975077ee09f049058", hashType: "data1", args: `0x${"c1".repeat(32)}` });
  const typeId = ccc.Script.from({ codeHash: TYPE_ID, hashType: "type", args: `0x${"71".repeat(32)}` });
  const unique = ccc.Script.from({ codeHash: UNIQUE, hashType: "type", args: `0x${"81".repeat(20)}` });
  for (const type of [spore, cluster, typeId, unique]) {
    const { tokensLeaving, tokenOutflows } = build(
      [{ lock: own, capacity: 300n * CKB, type, data: "0x01" }, { lock: own, capacity: 1_000n * CKB }],
      [{ lock: alice, capacity: 300n * CKB, type, data: "0x01" }, { lock: own, capacity: 1_000n * CKB - 1_000n }],
    );
    assert.equal(tokensLeaving, true, type.codeHash);
    assert.deepEqual(tokenOutflows, [{ asset: type.hash(), amount: 1n }], type.codeHash);
  }
  // Kept by the account, moved between its own cells: nothing leaves.
  const kept = build(
    [{ lock: own, capacity: 300n * CKB, type: spore, data: "0x01" }, { lock: own, capacity: 1_000n * CKB }],
    [{ lock: own, capacity: 300n * CKB, type: spore, data: "0x01" }, { lock: own, capacity: 1_000n * CKB - 1_000n }],
  );
  assert.deepEqual(kept.tokenOutflows, []);
  // Not assets: Nervos DAO cells, the send-limit settings cell and the recovery list.
  const settings = ccc.Script.from({ codeHash: TYPE_ID, hashType: "type", args: `0x${"5e".repeat(32)}` });
  const list = ccc.Script.from({ codeHash: TYPE_ID, hashType: "type", args: `0x${"a1".repeat(32)}` });
  const recovery = { adminListTypeHash: list.hash() } as unknown as KeyWayRecovery;
  const quiet = build(
    [
      { lock: own, capacity: 1_000n * CKB, type: dao, data: "0x0000000000000000" },
      { lock: own, capacity: 200n * CKB, type: settings, data: "0x4b57534c01" },
      { lock: own, capacity: 200n * CKB, type: list, data: "0x01" },
    ],
    [{ lock: alice, capacity: 1_400n * CKB - 2_000n }],
    recovery,
  );
  assert.deepEqual(quiet.tokenOutflows, []);
  assert.equal(quiet.tokensLeaving, false);
});

/** An offline client that answers getCell from these cells, and counts how often it is asked. */
function chainOf(cells: ccc.Cell[]) {
  const reads = { count: 0 };
  const client = new ccc.ClientPublicTestnet({ url: "http://127.0.0.1:1/offline" });
  Object.assign(client, {
    getCell: async (outPoint: ccc.OutPointLike) => {
      reads.count++;
      return cells.find((cell) => cell.outPoint.eq(ccc.OutPoint.from(outPoint)));
    },
    findCells: async function* () {},
    findCellsOnChain: async function* () {},
  });
  return { client, reads };
}

const offlineKey = secp256k1.utils.randomSecretKey();
const offlineWallet = { litPkpId: `0x${"11".repeat(20)}`, litPublicKey: ccc.hexFrom(secp256k1.getPublicKey(offlineKey, true)), status: "ready" } as unknown as ReadyWallet;
const live = (index: number, lock: ccc.Script, capacity: bigint, type?: ccc.Script, data: ccc.Hex = "0x") =>
  ccc.Cell.from({ outPoint: { txHash: `0x${(index + 0x100).toString(16).padStart(64, "0")}`, index: 0 }, cellOutput: { lock, capacity, type }, outputData: data });
const json = <T>(value: T): T => JSON.parse(JSON.stringify(value));

test("a transaction's inputs are read from the chain, never from cell details the caller attached", async () => {
  const { client: probe } = chainOf([]);
  const mine = await secp256k1Lock(probe, offlineWallet.litPublicKey);
  const other = ccc.Script.from({ codeHash: mine.codeHash, hashType: mine.hashType, args: `0x${"77".repeat(20)}` });
  const token = await ccc.Script.fromKnownScript(probe, ccc.KnownScript.XUdt, `0x${"55".repeat(32)}`);
  const cells = [live(1, mine, 200n * CKB, token, u128(1_000n)), live(2, mine, 500n * CKB)];
  const { client, reads } = chainOf(cells);
  const clean = serializeTransaction(ccc.Transaction.from({
    inputs: cells.map(({ outPoint }) => ({ previousOutput: outPoint })),
    outputs: [{ lock: other, type: token, capacity: 143n * CKB }, { lock: mine, capacity: 557n * CKB - 10_000n }],
    outputsData: [u128(1_000n), "0x"],
    witnesses: [ccc.hexFrom(ccc.WitnessArgs.from({ lock: `0x${"00".repeat(65)}` }).toBytes()), "0x"],
  })) as { inputs: Array<Record<string, unknown>> };
  // The same out points, with the token input described as plain CKB.
  const forged = json(clean);
  forged.inputs[0].cellOutput = { lock: JSON.parse(ccc.stringify(mine)), capacity: ccc.numToHex(200n * CKB) };
  forged.inputs[0].outputData = "0x";

  const honest = await previewGeneralTransaction(offlineWallet, json(clean), client);
  reads.count = 0;
  const attempted = await previewGeneralTransaction(offlineWallet, forged, client);
  assert.ok(reads.count >= cells.length, "each input is looked up on chain");
  assert.equal(attempted.preview.transactionHash, honest.preview.transactionHash);
  assert.deepEqual(attempted.tokenOutflows, [{ asset: token.hash(), amount: 1_000n }]);
  assert.deepEqual(attempted.tokenOutflows, honest.tokenOutflows);
  assert.equal(attempted.outflowShannons, honest.outflowShannons);
  assert.deepEqual(previewSummaryLines(attempted.preview), previewSummaryLines(honest.preview));
});

test("a channel funding's inputs are read from the chain, never from cell details the caller attached", async () => {
  const { client: probe } = chainOf([]);
  const mine = await secp256k1Lock(probe, offlineWallet.litPublicKey);
  const peer = ccc.Script.from({ codeHash: mine.codeHash, hashType: mine.hashType, args: `0x${"77".repeat(20)}` });
  const channel = ccc.Script.from({ codeHash: "0x6c67887fe201ee0c7853f1682c0b77c0e6214044c156c7558269390a8afa6d7c", hashType: "type", args: `0x${"cc".repeat(20)}` });
  const cells = [live(3, mine, 2_000n * CKB), live(4, peer, 100n * CKB)];
  const { client } = chainOf(cells);
  const clean = serializeTransaction(ccc.Transaction.from({
    inputs: cells.map(({ outPoint }) => ({ previousOutput: outPoint })),
    outputs: [{ lock: channel, capacity: 1_600n * CKB }, { lock: mine, capacity: 500n * CKB - 10_000n }],
    outputsData: ["0x", "0x"],
    witnesses: [ccc.hexFrom(ccc.WitnessArgs.from({ lock: `0x${"00".repeat(65)}` }).toBytes()), "0x"],
  })) as { inputs: Array<Record<string, unknown>> };
  // The same out points, with capacity moved from the user's input to the peer's.
  const forged = json(clean);
  forged.inputs[0].cellOutput = { lock: JSON.parse(ccc.stringify(mine)), capacity: ccc.numToHex(1_100n * CKB) };
  forged.inputs[0].outputData = "0x";
  forged.inputs[1].cellOutput = { lock: JSON.parse(ccc.stringify(peer)), capacity: ccc.numToHex(1_000n * CKB) };
  forged.inputs[1].outputData = "0x";

  const honest = await previewFundingTransaction(offlineWallet, json(clean), client);
  const attempted = await previewFundingTransaction(offlineWallet, forged, client);
  assert.equal(honest.preview.amountCkb, "1500");
  assert.deepEqual(attempted.preview, honest.preview);
});
