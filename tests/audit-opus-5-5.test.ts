// Proof-of-concept tests for research/omnilock/audit-opus-5-5.md. Each test asserts the behaviour the audit
// reports as a finding, so it passes while the finding stands and fails once it is fixed.
import assert from "node:assert/strict";
import test from "node:test";
import * as ccc from "@ckb-ccc/core";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { adminListTypeScript, omnilockArgsFor, secp256k1Lock, type KeyWayRecovery } from "../src/sdk/browser/account-lock.ts";
import { backupAuth, recoveryBackupChallenge, verifyBackupOwnership, type RecoveryBackup } from "../src/sdk/browser/recovery-backups.ts";
import { recoveryListRecord, setRecoveryListRecord } from "../src/sdk/browser/recovery-list.ts";
import { adminListData, whitelistTree } from "../src/sdk/browser/recovery-smt.ts";
import { sweepSettlement } from "../src/sdk/browser/settlement-sweep.ts";
import { checkRescueTransaction, openRescueAccount, planRescue, rescueEntryForEvm, RescueError } from "../src/rescue/rescue.ts";
import { planBackupChange } from "../src/server/recovery.ts";
import { planLegacySweep } from "../src/server/legacy-sweep.ts";
import type { ReadyWallet } from "../src/server/user-wallet.ts";

const CKB = 100_000_000n;
const TYPE_ID = "0x00000000000000000000000000000000000000000000000000545950455f4944";
const litKey = secp256k1.utils.randomSecretKey();
const publicKey = ccc.hexFrom(secp256k1.getPublicKey(litKey, true));
const evmKey = secp256k1.utils.randomSecretKey();
const evmAddress = ccc.hexFrom(keccak_256(secp256k1.getPublicKey(evmKey, false).slice(1)).slice(12));

/** A testnet client answering from these cells and transactions, never reaching the network. */
async function offlineClient(cells: ccc.Cell[] = [], transactions: ccc.Transaction[] = [], sent: ccc.Transaction[] = []): Promise<ccc.Client> {
  const client = new ccc.ClientPublicTestnet({ url: "https://testnet.ckb.dev/" });
  await client.cache.recordCells(cells);
  Object.assign(client, {
    findSingletonCellByType: async (type: ccc.ScriptLike) => cells.find((cell) => cell.cellOutput.type?.eq(ccc.Script.from(type))),
    getTransaction: async (hash: ccc.HexLike) => {
      const transaction = transactions.find((candidate) => candidate.hash() === ccc.hexFrom(hash));
      return transaction ? { transaction, status: "committed" } : undefined;
    },
    findCells: async function* () {},
    findCellsByLock: async function* (lock: ccc.ScriptLike) {
      for (const cell of [...cells].reverse()) if (cell.cellOutput.lock.eq(ccc.Script.from(lock))) yield cell;
    },
    getFeeRate: async () => 1000n,
    sendTransaction: async (transaction: ccc.TransactionLike) => {
      const tx = ccc.Transaction.from(transaction);
      sent.push(tx);
      return tx.hash();
    },
  });
  return client;
}

let nextCell = 1;
const cell = (lock: ccc.Script, capacity: bigint, type?: ccc.Script, outputData: ccc.Hex = "0x") =>
  ccc.Cell.from({ outPoint: { txHash: `0x${(nextCell++).toString(16).padStart(64, "0")}`, index: 0 }, cellOutput: { lock, capacity, type }, outputData });
const amount = (value: bigint) => ccc.hexFrom(ccc.numLeToBytes(value, 16));
const occupied = (output: ccc.CellOutput, data: ccc.HexLike) => ccc.fixedPointFrom(output.occupiedSize + ccc.bytesFrom(data).length);

/** A recovery account: its AdminList (under `adminListLock`, the account's Omnilock by default) and its record. */
async function recoveryChain(options: { adminListLock?: (omnilock: ccc.Script) => ccc.Script; extra?: (omnilock: ccc.Script, secp: ccc.Script) => ccc.Cell[] } = {}) {
  const base = await offlineClient();
  const backups: RecoveryBackup[] = [{ kind: "evm", address: evmAddress }];
  const adminListTypeArgs = ccc.hexFrom(new Uint8Array(32).fill(0x42));
  const adminType = adminListTypeScript({ adminListTypeArgs });
  const omnilock = await ccc.Script.fromKnownScript(base, ccc.KnownScript.OmniLock, omnilockArgsFor(publicKey, adminType.hash()));
  const secp = await secp256k1Lock(base, publicKey);
  const { root } = whitelistTree(await Promise.all(backups.map((backup) => backupAuth(base, backup))));
  const listLock = options.adminListLock?.(omnilock) ?? omnilock;
  const created = ccc.Transaction.from({ outputs: [{ lock: listLock, type: adminType, capacity: 197n * CKB }], outputsData: [adminListData(root)] });
  setRecoveryListRecord(created, 0, await recoveryListRecord(base, backups));
  const adminList = ccc.Cell.from({ outPoint: { txHash: created.hash(), index: 0 }, cellOutput: created.outputs[0], outputData: created.outputsData[0] });
  const cells = [adminList, cell(omnilock, 1_000n * CKB), ...(options.extra?.(omnilock, secp) ?? [])];
  const client = await offlineClient(cells, [created]);
  const recovery: KeyWayRecovery = {
    omnilockArgs: omnilock.args, adminListTypeArgs, adminListTypeHash: adminType.hash(),
    adminListOutPoint: { txHash: created.hash(), index: 0 }, legacyAddress: ccc.Address.fromScript(secp, client).toString(),
    enabledAt: "2026-10-29T00:00:00.000Z", backups,
  };
  const wallet = {
    version: 1, status: "ready", litPkpId: `0x${"11".repeat(20)}`, litPublicKey: publicKey, ckbAddress: ccc.Address.fromScript(omnilock, client).toString(),
    encryptedFiberKey: "ciphertext", primaryDeviceIdHash: "a".repeat(64), hasOpenedChannel: false,
    createdAt: "2026-10-29T00:00:00.000Z", updatedAt: "2026-10-29T00:00:00.000Z", recovery,
  } as ReadyWallet;
  return { client, omnilock, secp, adminList, wallet, address: ccc.Address.fromScript(omnilock, client).toString() };
}

test("finding: with recovery on, a settlement key holding a minimum-capacity token cell can never be swept", async () => {
  // A Fiber settlement key holding what a force-closed token channel leaves: an xUDT cell at its exact
  // secp256k1 minimum (142 CKB), and some plain CKB.
  const base = await offlineClient();
  const settlementKey = ccc.hexFrom(secp256k1.utils.randomSecretKey());
  const from = (await new ccc.SignerCkbPrivateKey(base, settlementKey).getRecommendedAddressObj()).script;
  const xudt = await base.getKnownScript(ccc.KnownScript.XUdt);
  const token = ccc.Script.from({ codeHash: xudt.codeHash, hashType: xudt.hashType, args: `0x${"77".repeat(32)}` });
  const tokenCell = cell(from, 142n * CKB, token, amount(1_000n));
  assert.equal(tokenCell.cellOutput.capacity, occupied(tokenCell.cellOutput, tokenCell.outputData));
  const sent: ccc.Transaction[] = [];
  const client = await offlineClient([tokenCell, cell(from, 5_000n * CKB)], [], sent);
  Object.assign(client, { findSingletonCellByType: async () => undefined });
  // With recovery on, the destination is the account's Omnilock (create-keyway.ts sweepNow, managed-node.ts).
  const omnilock = await ccc.Script.fromKnownScript(client, ccc.KnownScript.OmniLock, omnilockArgsFor(publicKey, `0x${"42".repeat(32)}`));

  // CCC raises the token output to its 176 CKB minimum, then looks for 34 more CKB in new inputs instead of taking
  // them from the 5,000 CKB plain output it is building, finds none (every cell is already an input) and throws.
  // The sweep loops (create-keyway.ts sweepNow, managed-node.ts sweepHostedSettlement) swallow the error and
  // retry every 10 minutes, so neither the tokens nor the plain CKB ever leave the settlement key.
  await assert.rejects(sweepSettlement(client, settlementKey, omnilock, 0n), /Insufficient CKB, need 34 extra CKB/);
  assert.equal(sent.length, 0);
  // The same cells sweep fine to a secp256k1 destination (the account's lock before recovery).
  await sweepSettlement(client, settlementKey, await secp256k1Lock(client, publicKey), 0n);
  assert.equal(sent.length, 1);
});

/** A rescue account whose node lies about one cell: `real` is what the chain holds, `reported` what the node says. */
async function lyingNodeRescue(reported: (lock: ccc.Script, token: ccc.Script) => ccc.Cell) {
  const base = await offlineClient();
  const xudt = await base.getKnownScript(ccc.KnownScript.XUdt);
  const token = ccc.Script.from({ codeHash: xudt.codeHash, hashType: xudt.hashType, args: `0x${"77".repeat(32)}` });
  let lie: ccc.Cell | undefined;
  const { client, address } = await recoveryChain({ extra: (omnilock) => [lie = reported(omnilock, token)] });
  const account = await openRescueAccount(client, address);
  const destination = await secp256k1Lock(client, ccc.hexFrom(secp256k1.getPublicKey(secp256k1.utils.randomSecretKey(), true)));
  const plan = await planRescue(client, account, rescueEntryForEvm(account, [evmAddress]), ccc.Address.fromScript(destination, client).toString());
  checkRescueTransaction(plan.transaction, account, destination);
  return { plan, lie: lie!, account, token };
}

test("finding: a lying CKB node can make the rescue page burn the account's CKB as fee", async () => {
  // On chain the cell holds 50,000 CKB; the node reports 61. The out point is all the transaction commits to,
  // so the backup signs a transaction whose real fee is ~50,000 CKB, and the page's own checks pass.
  const { plan, lie } = await lyingNodeRescue((lock) => cell(lock, 61n * CKB));
  const realInputs = 1_000n * CKB + 50_000n * CKB;
  const realFee = realInputs - plan.transaction.getOutputsCapacity();
  assert.ok(plan.transaction.inputs.some(({ previousOutput }) => previousOutput.eq(lie.outPoint)));
  assert.ok(realFee > 49_900n * CKB, `real fee ${ccc.fixedPointToString(realFee)} CKB`);
  assert.ok(plan.fee < CKB / 100n, "the page shows a normal fee");
});

test("finding: a lying CKB node can make the rescue page burn the account's tokens", async () => {
  // On chain the cell is an xUDT cell with 2,500 tokens; the node reports it as plain CKB. The rescue spends it
  // into a plain output and xUDT lets inputs exceed outputs, so the tokens are destroyed.
  const { plan, lie, account } = await lyingNodeRescue((lock) => cell(lock, 176n * CKB));
  assert.ok(plan.transaction.inputs.some(({ previousOutput }) => previousOutput.eq(lie.outPoint)));
  assert.equal(account.tokens.length, 0);
  assert.ok(plan.transaction.outputs.every((output) => !output.type));
});

test("finding: once a backup moves the AdminList to another lock, KeyWay can't remove that backup and keeps sending funds to the address", async () => {
  // A backup spends the AdminList through the administrator path (accepted on testnet, see testnet-adminlist-hijack.ts)
  // and recreates it, same Type ID and list, under its own lock. Omnilock still finds it as a cell dep by type.
  const thief = await secp256k1Lock(await offlineClient(), ccc.hexFrom(secp256k1.getPublicKey(secp256k1.utils.randomSecretKey(), true)));
  const { client, wallet, address, omnilock } = await recoveryChain({
    adminListLock: () => thief,
    extra: (_omnilock, secp) => [cell(secp, 5_000n * CKB)],
  });
  await assert.rejects(planBackupChange(client, wallet, { change: "remove", backup: { kind: "evm", address: evmAddress } }), /isn't this account's/);
  await assert.rejects(planBackupChange(client, wallet, { change: "add", backup: { kind: "evm", address: `0x${"ab".repeat(20)}` } }), /isn't this account's/);
  // The sign-in sweep still moves the old address's funds into the Omnilock the backup now controls for good.
  const sweep = await planLegacySweep(client, wallet);
  assert.equal(sweep.status, "ready");
  if (sweep.status === "ready") assert.ok(sweep.transaction.outputs.every((output) => output.lock.eq(omnilock)));
  // And the rescue page says no backup can move the funds, though Omnilock accepts the list as a cell dep.
  await assert.rejects(openRescueAccount(client, address), (error: unknown) => error instanceof RescueError && error.code === "list-missing");
});

test("info: a backup's ownership proof has no nonce or expiry and verifies again after the backup is removed", async () => {
  const { client, secp } = await recoveryChain();
  const account = ccc.Address.fromScript(secp, client).toString();
  const backup = { kind: "evm" as const, address: evmAddress };
  const text = new TextEncoder().encode(recoveryBackupChallenge(account, backup));
  const digest = keccak_256(ccc.bytesConcat(new TextEncoder().encode(`\x19Ethereum Signed Message:\n${text.length}`), text));
  const raw = secp256k1.sign(digest, evmKey, { prehash: false, format: "recovered" });
  const proof = { ...backup, signature: ccc.hexFrom(ccc.bytesConcat(raw.slice(1), [raw[0] + 27])) };
  // The same signature is accepted for turning recovery on, adding the backup, and re-adding it any time later.
  assert.deepEqual(await verifyBackupOwnership(client, account, proof), backup);
  assert.deepEqual(await verifyBackupOwnership(client, account, JSON.parse(JSON.stringify(proof))), backup);
});
