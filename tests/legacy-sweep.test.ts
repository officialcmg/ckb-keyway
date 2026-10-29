import assert from "node:assert/strict";
import test from "node:test";
import * as ccc from "@ckb-ccc/core";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { adminListTypeScript, omnilockArgsFor, secp256k1Lock, type KeyWayRecovery } from "../src/sdk/browser/account-lock.ts";
import { formatCkbSignature, signAccountGroups } from "../src/server/funding-transaction.ts";
import { checkLegacySweepTransaction, lastSweepDecision, planLegacySweep, sweepLegacyAfterSignIn } from "../src/server/legacy-sweep.ts";
import type { ReadyWallet } from "../src/server/user-wallet.ts";

const CKB = 100_000_000n;
const privateKey = secp256k1.utils.randomSecretKey();
const publicKey = ccc.hexFrom(secp256k1.getPublicKey(privateKey, true));
const adminListTypeArgs = `0x${"5a".repeat(32)}`;
const adminListTypeHash = adminListTypeScript({ adminListTypeArgs }).hash();
const recovery: KeyWayRecovery = {
  omnilockArgs: omnilockArgsFor(publicKey, adminListTypeHash), adminListTypeArgs, adminListTypeHash,
  adminListOutPoint: { txHash: `0x${"ad".repeat(32)}`, index: 0 }, legacyAddress: "ckt1legacy", enabledAt: "2026-10-29T00:00:00.000Z",
  backups: [{ kind: "evm", address: `0x${"44".repeat(20)}` }],
};
const wallet = {
  version: 1, status: "ready", litPkpId: `0x${"11".repeat(20)}`, litPublicKey: publicKey, ckbAddress: "ckt1new",
  encryptedFiberKey: "ciphertext", primaryDeviceIdHash: "a".repeat(64), hasOpenedChannel: false,
  createdAt: "2026-10-29T00:00:00.000Z", updatedAt: "2026-10-29T00:00:00.000Z", recovery,
} as ReadyWallet;

/** A testnet client that answers from recorded cells and never reaches the network. */
async function offlineClient(cells: ccc.Cell[]): Promise<ccc.Client> {
  const client = new ccc.ClientPublicTestnet({ url: "https://testnet.ckb.dev/" });
  await client.cache.recordCells(cells);
  Object.assign(client, {
    findSingletonCellByType: async () => undefined,
    findCellsByLock: async function* (lock: ccc.ScriptLike) {
      for (const cell of [...cells].reverse()) if (cell.cellOutput.lock.eq(ccc.Script.from(lock))) yield cell;
    },
  });
  return client;
}

let nextCell = 1;
function cell(lock: ccc.Script, capacity: bigint, type?: ccc.Script, outputData: ccc.Hex = "0x"): ccc.Cell {
  return ccc.Cell.from({ outPoint: { txHash: `0x${(nextCell++).toString(16).padStart(64, "0")}`, index: 0 }, cellOutput: { lock, capacity, type }, outputData });
}
const amount = (value: bigint) => ccc.hexFrom(ccc.numLeToBytes(value, 16));

async function scripts() {
  const base = new ccc.ClientPublicTestnet({ url: "https://testnet.ckb.dev/" });
  const known = async (script: ccc.KnownScript, args: string) => ccc.Script.fromKnownScript(base, script, args as ccc.Hex);
  return {
    secp: await secp256k1Lock(base, publicKey),
    omnilock: await known(ccc.KnownScript.OmniLock, recovery.omnilockArgs),
    xudt: await known(ccc.KnownScript.XUdt, `0x${"77".repeat(32)}`),
    sudt: await known(ccc.KnownScript.SUdt, `0x${"78".repeat(32)}`),
    dao: await known(ccc.KnownScript.NervosDao, "0x"),
    unknown: ccc.Script.from({ codeHash: `0x${"ee".repeat(32)}`, hashType: "type", args: "0x01" }),
  };
}

const sign = async (digest: ccc.Hex) => {
  const raw = secp256k1.sign(ccc.bytesFrom(digest), privateKey, { prehash: false, format: "recovered" });
  return formatCkbSignature({ recoveryParam: raw[0] as 0 | 1, r: ccc.hexFrom(raw.slice(1, 33)), s: ccc.hexFrom(raw.slice(33, 65)) });
};

test("moves plain CKB into one output and standard tokens one-to-one, leaving every other cell", async () => {
  const s = await scripts();
  const cells = {
    small: cell(s.secp, 61n * CKB),
    large: cell(s.secp, 300n * CKB),
    xudt: cell(s.secp, 142n * CKB, s.xudt, amount(1_000n)),
    sudt: cell(s.secp, 142n * CKB, s.sudt, amount(7n)),
    dao: cell(s.secp, 102n * CKB, s.dao, ccc.hexFrom(new Uint8Array(8))),
    nft: cell(s.secp, 200n * CKB, s.unknown, "0x0102"),
    withData: cell(s.secp, 70n * CKB, undefined, "0x1234"),
    shortToken: cell(s.secp, 150n * CKB, s.xudt, "0x01"),
    elsewhere: cell(s.omnilock, 1_000n * CKB),
  };
  const client = await offlineClient(Object.values(cells));
  const plan = await planLegacySweep(client, wallet);
  assert.equal(plan.status, "ready");
  if (plan.status !== "ready") return;
  const { transaction } = plan;
  // The old address's plain and token cells, never the new address's when they cover themselves.
  assert.deepEqual(new Set(transaction.inputs.map(({ previousOutput }) => previousOutput.txHash)),
    new Set([cells.small, cells.large, cells.xudt, cells.sudt].map(({ outPoint }) => outPoint.txHash)));
  assert.equal(plan.topUp, undefined);
  assert.deepEqual(new Set(plan.left.map(({ outPoint }) => outPoint.txHash)),
    new Set([cells.dao, cells.nft, cells.withData, cells.shortToken].map(({ outPoint }) => outPoint.txHash)));
  assert.ok(transaction.outputs.every(({ lock }) => lock.eq(s.omnilock)));
  const [xudtOut, sudtOut, plain] = transaction.outputs;
  assert.ok(xudtOut.type!.eq(s.xudt) && sudtOut.type!.eq(s.sudt) && !plain.type);
  assert.deepEqual(transaction.outputsData, [amount(1_000n), amount(7n), "0x"]);
  // 142 CKB at the old lock, 176 at the 54-byte Omnilock lock.
  assert.equal(xudtOut.capacity, 176n * CKB);
  assert.equal(sudtOut.capacity, 176n * CKB);
  const fee = 645n * CKB - transaction.getOutputsCapacity();
  assert.ok(fee > 0n && fee < CKB / 1000n, "the fee comes out of the moved CKB");
  assert.equal(plain.capacity, 645n * CKB - 352n * CKB - fee);
  assert.deepEqual(plan.groups.map(({ kind }) => kind), ["secp256k1"]);
  await checkLegacySweepTransaction(client, transaction, publicKey, recovery);

  // It signs with the account key's plain secp256k1 witness.
  const signed = await signAccountGroups(transaction.clone(), plan.groups, client, sign);
  assert.equal(ccc.bytesFrom(signed.getWitnessArgsAt(0)!.lock!).length, 65);
  assert.equal(signed.hash(), transaction.hash());

  // Spent cells (a committed sweep the indexer still lists) are skipped.
  const after = await planLegacySweep(client, wallet, transaction.inputs.map(({ previousOutput }) => previousOutput));
  assert.equal(after.status, "empty");
});

test("handles amounts below the Omnilock minimum cell", async () => {
  const s = await scripts();
  // Plain CKB that can't make a 95 CKB cell, and no token: it joins the new address's largest plain cell.
  const small = cell(s.secp, 70n * CKB);
  const adminList = cell(s.omnilock, 5_000n * CKB, adminListTypeScript(recovery), "0x00");
  const topUp = cell(s.omnilock, 200n * CKB);
  const lesser = cell(s.omnilock, 100n * CKB);
  let client = await offlineClient([small, adminList, topUp, lesser]);
  let plan = await planLegacySweep(client, wallet);
  assert.equal(plan.status, "ready");
  if (plan.status !== "ready") return;
  assert.ok(plan.topUp?.outPoint.eq(topUp.outPoint), "the largest plain cell, never the recovery list");
  assert.equal(plan.transaction.inputs.length, 2);
  assert.equal(plan.transaction.outputs.length, 1);
  assert.ok(plan.transaction.outputs[0].capacity > 269n * CKB && plan.transaction.outputs[0].capacity < 270n * CKB);
  assert.deepEqual(plan.groups.map(({ kind }) => kind), ["secp256k1", "omnilock"]);
  await checkLegacySweepTransaction(client, plan.transaction, publicKey, recovery);
  const signed = await signAccountGroups(plan.transaction.clone(), plan.groups, client, sign);
  assert.equal(ccc.bytesFrom(signed.getWitnessArgsAt(1)!.lock!).length, 85, "the Omnilock owner witness");

  // Without a plain cell at the new address it waits for a later sign-in.
  client = await offlineClient([small, adminList]);
  plan = await planLegacySweep(client, wallet);
  assert.equal(plan.status, "short");

  // A token cell that covers its own Omnilock minimum but not a plain cell too keeps the rest in the token cell.
  const roomyToken = cell(s.secp, 200n * CKB, s.xudt, amount(5n));
  client = await offlineClient([roomyToken, topUp]);
  plan = await planLegacySweep(client, wallet);
  assert.equal(plan.status, "ready");
  if (plan.status !== "ready") return;
  assert.equal(plan.topUp, undefined);
  assert.equal(plan.transaction.outputs.length, 1);
  assert.ok(plan.transaction.outputs[0].type!.eq(s.xudt));
  assert.ok(plan.transaction.outputs[0].capacity > 199n * CKB);
  await checkLegacySweepTransaction(client, plan.transaction, publicKey, recovery);

  // A lone 142 CKB token cell can't reach 176 CKB on its own: the new address's plain cell tops it up.
  const loneToken = cell(s.secp, 142n * CKB, s.xudt, amount(9n));
  client = await offlineClient([loneToken, topUp]);
  plan = await planLegacySweep(client, wallet);
  assert.equal(plan.status, "ready");
  if (plan.status !== "ready") return;
  assert.ok(plan.topUp);
  assert.equal(plan.transaction.outputs[0].capacity, 176n * CKB);
  assert.ok(plan.transaction.outputs[1].capacity > 165n * CKB);
  await checkLegacySweepTransaction(client, plan.transaction, publicKey, recovery);

  // Nothing at the old address: nothing to do.
  assert.equal((await planLegacySweep(await offlineClient([topUp]), wallet)).status, "empty");
});

test("the policy allows only this shape: the account's cells to its own recovery address", async () => {
  const s = await scripts();
  const plainCell = cell(s.secp, 500n * CKB);
  const tokenCell = cell(s.secp, 142n * CKB, s.xudt, amount(1_000n));
  const topUp = cell(s.omnilock, 300n * CKB);
  const adminList = cell(s.omnilock, 197n * CKB, adminListTypeScript(recovery), "0x00");
  const stranger = ccc.Script.from({ ...s.secp, args: `0x${"66".repeat(20)}` });
  const foreign = cell(stranger, 500n * CKB);
  const client = await offlineClient([plainCell, tokenCell, topUp, adminList, foreign]);
  const plan = await planLegacySweep(client, wallet);
  assert.equal(plan.status, "ready");
  if (plan.status !== "ready") return;
  await checkLegacySweepTransaction(client, plan.transaction, publicKey, recovery);

  const tamper = async (change: (tx: ccc.Transaction) => void, reason: RegExp) => {
    const tx = plan.transaction.clone();
    change(tx);
    await assert.rejects(checkLegacySweepTransaction(client, tx, publicKey, recovery), reason);
  };
  const last = plan.transaction.outputs.length - 1;
  const input = (target: ccc.Cell) => ccc.CellInput.from({ previousOutput: target.outPoint });
  // Any other destination is refused: a stranger, the old address itself, or another Omnilock of this key.
  const otherOmnilock = await ccc.Script.fromKnownScript(client, ccc.KnownScript.OmniLock, omnilockArgsFor(publicKey, `0x${"99".repeat(32)}`));
  for (const lock of [stranger, s.secp, otherOmnilock]) {
    await tamper((tx) => { tx.outputs[last].lock = lock; }, /somewhere other than the account's recovery address/);
    await tamper((tx) => { tx.outputs[0].lock = lock; }, /somewhere other than the account's recovery address/);
  }
  await tamper((tx) => { tx.outputs[last].capacity -= 100n * CKB; tx.outputs.push(ccc.CellOutput.from({ lock: stranger, capacity: 100n * CKB })); tx.outputsData.push("0x"); }, /somewhere other/);
  // The recovery address from a different AdminList than the stored one is refused too.
  await assert.rejects(checkLegacySweepTransaction(client, plan.transaction, publicKey, { ...recovery, adminListTypeHash: `0x${"99".repeat(32)}` }), /somewhere other/);
  await tamper((tx) => { tx.outputs[last].capacity -= 100n * CKB; tx.outputs.push(ccc.CellOutput.from({ lock: s.omnilock, capacity: 100n * CKB })); tx.outputsData.push("0x"); }, /more than one plain output/);
  await tamper((tx) => { tx.outputsData[last] = "0x00"; }, /isn't plain CKB or a moved token/);
  await tamper((tx) => { tx.outputs[last].type = s.unknown; }, /isn't plain CKB or a moved token/);
  await tamper((tx) => { tx.outputsData[0] = amount(999n); }, /one-to-one/);
  await tamper((tx) => { tx.outputs[0].type = s.sudt; }, /one-to-one/);
  await tamper((tx) => { tx.outputs[last].capacity -= 10n * CKB; }, /fee is outside/);
  await tamper((tx) => { tx.outputs[last].capacity += 10n * CKB; }, /fee is outside/);
  await tamper((tx) => { tx.inputs.push(input(foreign)); tx.outputs[last].capacity += 500n * CKB; }, /an input isn't this account's/);
  await tamper((tx) => { tx.inputs.push(input(adminList)); }, /isn't plain CKB/);
  await tamper((tx) => { tx.inputs = [input(topUp)]; tx.outputs = [ccc.CellOutput.from({ lock: s.omnilock, capacity: 299n * CKB })]; tx.outputsData = ["0x"]; }, /nothing comes from the old address/);
  const second = cell(s.omnilock, 300n * CKB);
  await client.cache.recordCells([second]);
  await tamper((tx) => { tx.inputs.push(input(topUp), input(second)); tx.outputs[last].capacity += 600n * CKB; }, /more than one input from the new address/);
  await tamper((tx) => { tx.headerDeps.push(`0x${"01".repeat(32)}`); }, /header deps/);
});

test("a sweep still in the mempool is never rebuilt", () => {
  const sentAt = new Date("2026-10-29T10:00:00Z");
  const at = (minutes: number) => new Date(sentAt.getTime() + minutes * 60_000);
  for (const status of ["sent", "pending", "proposed"] as const) assert.equal(lastSweepDecision(status, sentAt, at(60)), "wait");
  assert.equal(lastSweepDecision("committed", sentAt, at(1)), "committed");
  assert.equal(lastSweepDecision("rejected", sentAt, at(1)), "gone");
  // Just sent, the node may not know it yet; long gone, it was dropped.
  assert.equal(lastSweepDecision(undefined, sentAt, at(1)), "wait");
  assert.equal(lastSweepDecision("unknown", sentAt, at(9)), "wait");
  assert.equal(lastSweepDecision("unknown", sentAt, at(11)), "gone");
});

test("starting the sweep after sign-in returns at once and only logs a failure", async () => {
  const saved = process.env.DATABASE_URL;
  delete process.env.DATABASE_URL;
  const logged: unknown[] = [];
  const original = console.error;
  console.error = (...args: unknown[]) => { logged.push(args); };
  try {
    assert.equal(sweepLegacyAfterSignIn({ id: crypto.randomUUID() }), undefined);
    await new Promise((resolve) => setTimeout(resolve, 50));
  } finally {
    console.error = original;
    if (saved !== undefined) process.env.DATABASE_URL = saved;
  }
  assert.match(JSON.stringify(logged), /old address sweep failed.*DATABASE_URL is required/);
});
