import assert from "node:assert/strict";
import test from "node:test";
import * as ccc from "@ckb-ccc/core";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { omnilockLock, secp256k1Lock } from "../src/sdk/browser/account-lock.ts";
import { refuseFundingBeyondRequest, tokenChannelReservedCkb } from "../src/sdk/browser/funding-limit.ts";
import { previewFundingTransaction } from "../src/server/funding-transaction.ts";
import type { ReadyWallet } from "../src/server/user-wallet.ts";
import { anchoredRecovery, answerTransactions } from "./recovery-fixture.ts";

const CKB = 100_000_000n;
const FEE = 800n;
const FIBER_FUNDING_LOCK = ccc.Script.from({ codeHash: "0x6c67887fe201ee0c7853f1682c0b77c0e6214044c156c7558269390a8afa6d7c", hashType: "type", args: `0x${"fd".repeat(32)}` });
const publicKey = ccc.hexFrom(secp256k1.getPublicKey(secp256k1.utils.randomSecretKey(), true));
const { recovery, transactions: anchor } = await anchoredRecovery(publicKey);
const wallet = (withRecovery: boolean) => ({
  version: 1, status: "ready", litPkpId: `0x${"11".repeat(20)}`, litPublicKey: publicKey, ckbAddress: "ckt1test",
  encryptedFiberKey: "ciphertext", primaryDeviceIdHash: "a".repeat(64), hasOpenedChannel: false,
  createdAt: "2026-10-23T00:00:00.000Z", updatedAt: "2026-10-23T00:00:00.000Z",
  ...(withRecovery ? { recovery } : {}),
}) as ReadyWallet;

async function offlineClient(cells: ccc.CellLike[] = []): Promise<ccc.Client> {
  const client = new ccc.ClientPublicTestnet({ url: "https://testnet.ckb.dev/" });
  await client.cache.recordCells(cells);
  Object.assign(client, { findSingletonCellByType: async () => undefined, findCells: async function* () {} });
  return answerTransactions(client, anchor);
}

let nextCell = 1;
function cell(lock: ccc.Script, capacity: bigint): ccc.Cell {
  return ccc.Cell.from({ outPoint: { txHash: `0x${(nextCell++).toString(16).padStart(64, "f")}`, index: 0 }, cellOutput: { lock, capacity }, outputData: "0x" });
}

function funding(inputs: ccc.Cell[], outputs: Array<{ lock: ccc.Script; capacity: bigint }>) {
  return ccc.Transaction.from({
    inputs: inputs.map(({ outPoint }) => ({ previousOutput: outPoint })),
    outputs,
    outputsData: outputs.map(() => "0x"),
    witnesses: inputs.map(() => "0x"),
  });
}

const offline = await offlineClient();
const omni = await omnilockLock(offline, recovery);
const legacy = await secp256k1Lock(offline, publicKey);
const peer = await secp256k1Lock(offline, ccc.hexFrom(secp256k1.getPublicKey(secp256k1.utils.randomSecretKey(), true)));

test("a recovered account's funding may not spend its old address, even as the peer's input", async () => {
  const mine = cell(omni, 1_100n * CKB);
  const old = cell(legacy, 600n * CKB);
  const client = await offlineClient([mine, old]);
  // The peer adds the user's old-address cell as "its own" and pays itself from it.
  const attack = funding([mine, old], [
    { lock: FIBER_FUNDING_LOCK, capacity: 1_000n * CKB },
    { lock: omni, capacity: 100n * CKB - FEE },
    { lock: peer, capacity: 600n * CKB },
  ]);
  await assert.rejects(previewFundingTransaction(wallet(true), attack, client), /current address/);

  // Even when it goes into the channel as the peer's share.
  const share = funding([mine, old], [
    { lock: FIBER_FUNDING_LOCK, capacity: 1_600n * CKB },
    { lock: omni, capacity: 100n * CKB - FEE },
  ]);
  await assert.rejects(previewFundingTransaction(wallet(true), share, client), /current address/);
});

test("other parties' outputs must be paid by their own inputs", async () => {
  const mine = cell(omni, 2_000n * CKB);
  const theirs = cell(peer, 100n * CKB);
  const client = await offlineClient([mine, theirs]);
  const uncovered = funding([mine, theirs], [
    { lock: FIBER_FUNDING_LOCK, capacity: 1_000n * CKB },
    { lock: peer, capacity: 500n * CKB },
    { lock: omni, capacity: 600n * CKB - FEE },
  ]);
  await assert.rejects(previewFundingTransaction(wallet(true), uncovered, client), /pays other outputs/);

  // No peer input at all, and an output to someone else.
  const mineOnly = cell(omni, 2_000n * CKB);
  const client2 = await offlineClient([mineOnly]);
  const leak = funding([mineOnly], [
    { lock: FIBER_FUNDING_LOCK, capacity: 1_000n * CKB },
    { lock: peer, capacity: 61n * CKB },
    { lock: omni, capacity: 939n * CKB - FEE },
  ]);
  await assert.rejects(previewFundingTransaction(wallet(true), leak, client2), /pays other outputs/);

  // The account's old address is not its change either: CKB sent there is treated like anyone else's output.
  const toOld = funding([mineOnly], [
    { lock: FIBER_FUNDING_LOCK, capacity: 1_000n * CKB },
    { lock: legacy, capacity: 1_000n * CKB - FEE },
  ]);
  await assert.rejects(previewFundingTransaction(wallet(true), toOld, client2), /pays other outputs/);
});

test("a normal funding with the peer's inputs and change still passes, signing only the current lock", async () => {
  const mine = cell(omni, 1_500n * CKB);
  const theirs = cell(peer, 300n * CKB);
  const client = await offlineClient([mine, theirs]);
  const normal = funding([mine, theirs], [
    { lock: FIBER_FUNDING_LOCK, capacity: 1_000n * CKB },
    { lock: omni, capacity: 500n * CKB - FEE },
    { lock: peer, capacity: 300n * CKB },
  ]);
  const validated = await previewFundingTransaction(wallet(true), normal, client);
  assert.deepEqual(validated.groups.map(({ kind }) => kind), ["omnilock"]);
  assert.equal(validated.preview.amountCkb, "1000");
  assert.equal(validated.outflowShannons, 1_000n * CKB + FEE);

  // An account without recovery funds from its secp256k1 address as before.
  const plain = cell(legacy, 1_500n * CKB);
  const plainClient = await offlineClient([plain, theirs]);
  const secpFunding = funding([plain, theirs], [
    { lock: FIBER_FUNDING_LOCK, capacity: 1_000n * CKB },
    { lock: legacy, capacity: 500n * CKB - FEE },
    { lock: peer, capacity: 300n * CKB },
  ]);
  const secpValidated = await previewFundingTransaction(wallet(false), secpFunding, plainClient);
  assert.deepEqual(secpValidated.groups.map(({ kind }) => kind), ["secp256k1"]);
  assert.equal(secpValidated.preview.amountCkb, "1000");
});

test("a dual-funded channel still passes and counts only the account's share", async () => {
  const mine = cell(omni, 1_500n * CKB);
  const theirs = cell(peer, 1_800n * CKB);
  const client = await offlineClient([mine, theirs]);
  const dual = funding([mine, theirs], [
    { lock: FIBER_FUNDING_LOCK, capacity: 2_000n * CKB },
    { lock: omni, capacity: 500n * CKB - FEE },
    { lock: peer, capacity: 800n * CKB },
  ]);
  const validated = await previewFundingTransaction(wallet(true), dual, client);
  assert.equal(validated.preview.amountCkb, "1000");
  assert.deepEqual(validated.groups.map(({ kind }) => kind), ["omnilock"]);
});

test("the SDK refuses a funding preview that takes more than the app asked Fiber for", () => {
  const ckb = { fundingAmount: 1_000n * CKB };
  refuseFundingBeyondRequest({ amountCkb: "1000" }, ckb);
  refuseFundingBeyondRequest({ amountCkb: "999.5" }, ckb);
  assert.throws(() => refuseFundingBeyondRequest({ amountCkb: "1000.00000001" }, ckb), /more from the account than was requested/);
  assert.throws(() => refuseFundingBeyondRequest({ amountCkb: "1000" }, undefined), /wasn't requested/);
  assert.throws(() => refuseFundingBeyondRequest({ amountCkb: "1", token: { amount: "1" } }, ckb), /more from the account/);

  const rusd = { code_hash: `0x${"aa".repeat(32)}`, hash_type: "type", args: `0x${"cd".repeat(32)}` };
  const shutdown = { code_hash: `0x${"bb".repeat(32)}`, hash_type: "type", args: `0x${"01".repeat(22)}` };
  // 8 capacity + 90 lock (57-byte args at least) + 65 type + 16 data, plus Fiber's 1 CKB minimum shutdown fee.
  assert.equal(tokenChannelReservedCkb(rusd, shutdown), 180n * CKB);
  const token = { fundingAmount: 20n, udtTypeScript: rusd, shutdownScript: shutdown };
  refuseFundingBeyondRequest({ amountCkb: "180", token: { amount: "20" } }, token);
  assert.throws(() => refuseFundingBeyondRequest({ amountCkb: "180", token: { amount: "21" } }, token), /more of the token/);
  assert.throws(() => refuseFundingBeyondRequest({ amountCkb: "180" }, token), /more of the token/);
  assert.throws(() => refuseFundingBeyondRequest({ amountCkb: "180.1", token: { amount: "20" } }, token), /more CKB than a token channel reserves/);
});
