// Regression tests for research/omnilock/audit-opus-5-5.md. Each began as the audit's proof of concept, asserting
// the weakness; after the fixes (research/omnilock/audit-fixes-results.md) each runs the same scenario and asserts
// the opposite.
import assert from "node:assert/strict";
import test from "node:test";
import * as ccc from "@ckb-ccc/core";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { adminListLock, adminListTypeScript, KEYWAY_OMNILOCK, omnilockArgsFor, omnilockScript, secp256k1Lock, type KeyWayRecovery } from "../src/sdk/browser/account-lock.ts";
import { backupAuth, recoveryBackupChallenge, verifyBackupOwnership, type RecoveryBackup } from "../src/sdk/browser/recovery-backups.ts";
import { recoveryListRecord, setRecoveryListRecord } from "../src/sdk/browser/recovery-list.ts";
import { adminListData, whitelistTree } from "../src/sdk/browser/recovery-smt.ts";
import { sweepSettlement } from "../src/sdk/browser/settlement-sweep.ts";
import { checkRescueTransaction, openRescueAccount, planRescue, rescueEntryForEvm, RescueError } from "../src/rescue/rescue.ts";
import { checkBackupChangeTransaction, planBackupChange } from "../src/server/recovery.ts";
import { planLegacySweep } from "../src/server/legacy-sweep.ts";
import type { ReadyWallet } from "../src/server/user-wallet.ts";

const CKB = 100_000_000n;
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

type Output = { cellOutput: ccc.CellOutputLike; outputData: ccc.Hex };

/**
 * A recovery account made the way KeyWay makes it: a cell of the account's secp256k1 address, spent by the
 * transaction that turned recovery on, whose output 0 is the AdminList (under the key's owner-only lock unless
 * `adminListLock` says otherwise) with its record, then 1,000 CKB at the account and any `extra` outputs.
 * `report` lets the node describe a cell differently from what the chain holds.
 */
async function recoveryChain(options: {
  adminListLock?: (recovery: Pick<KeyWayRecovery, "omnilock" | "omnilockArgs">) => ccc.Script;
  extra?: (omnilock: ccc.Script, secp: ccc.Script) => Output[];
  report?: (cell: ccc.Cell, index: number) => ccc.Cell;
  backups?: RecoveryBackup[];
} = {}) {
  const base = await offlineClient();
  const backups: RecoveryBackup[] = options.backups ?? [{ kind: "evm", address: evmAddress }];
  const secp = await secp256k1Lock(base, publicKey);
  const funding = ccc.Transaction.from({ inputs: [{ previousOutput: { txHash: `0x${(nextCell++).toString(16).padStart(64, "0")}`, index: 0 } }], outputs: [{ lock: secp, capacity: 60_000n * CKB }], outputsData: ["0x"] });
  const input0 = ccc.CellInput.from({ previousOutput: { txHash: funding.hash(), index: 0 } });
  const adminListTypeArgs = ccc.hashTypeId(input0, 0);
  const adminType = adminListTypeScript({ adminListTypeArgs });
  const omnilock = omnilockScript({ omnilock: KEYWAY_OMNILOCK.testnet, omnilockArgs: omnilockArgsFor(publicKey, adminType.hash()) });
  const pinned = { omnilock: KEYWAY_OMNILOCK.testnet, omnilockArgs: omnilock.args };
  const { root } = whitelistTree(await Promise.all(backups.map((backup) => backupAuth(base, backup))));
  const listLock = options.adminListLock?.(pinned) ?? adminListLock(pinned);
  const outputs: Output[] = [
    { cellOutput: { lock: listLock, type: adminType, capacity: 165n * CKB }, outputData: adminListData(root) },
    { cellOutput: { lock: omnilock, capacity: 1_000n * CKB }, outputData: "0x" },
    ...(options.extra?.(omnilock, secp) ?? []),
  ];
  const enable = ccc.Transaction.from({ inputs: [input0], outputs: outputs.map(({ cellOutput }) => cellOutput), outputsData: outputs.map(({ outputData }) => outputData) });
  setRecoveryListRecord(enable, 0, await recoveryListRecord(base, backups));
  const real = enable.outputs.map((cellOutput, index) => ccc.Cell.from({ outPoint: { txHash: enable.hash(), index }, cellOutput, outputData: enable.outputsData[index] }));
  const client = await offlineClient(real.map((cell, index) => options.report?.(cell, index) ?? cell), [funding, enable]);
  const recovery: KeyWayRecovery = {
    omnilockArgs: omnilock.args, omnilock: KEYWAY_OMNILOCK.testnet, adminListTypeArgs, adminListTypeHash: adminType.hash(),
    adminListOutPoint: { txHash: enable.hash(), index: 0 }, enableTransactionHash: enable.hash(), legacyAddress: ccc.Address.fromScript(secp, client).toString(),
    enabledAt: "2026-10-29T00:00:00.000Z", backups,
  };
  const wallet = {
    version: 1, status: "ready", litPkpId: `0x${"11".repeat(20)}`, litPublicKey: publicKey, ckbAddress: ccc.Address.fromScript(omnilock, client).toString(),
    encryptedFiberKey: "ciphertext", primaryDeviceIdHash: "a".repeat(64), hasOpenedChannel: false,
    createdAt: "2026-10-29T00:00:00.000Z", updatedAt: "2026-10-29T00:00:00.000Z", recovery,
  } as ReadyWallet;
  return { client, omnilock, secp, adminList: real[0], real, enable, wallet, recovery, address: ccc.Address.fromScript(omnilock, client).toString() };
}

test("M1 fixed: with recovery on, a settlement key holding a minimum-capacity token cell is swept", async () => {
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
  const omnilock = omnilockScript({ omnilock: KEYWAY_OMNILOCK.testnet, omnilockArgs: omnilockArgsFor(publicKey, `0x${"42".repeat(32)}`) });

  // The token output is sized for the Omnilock (176 CKB) and the 34 CKB difference comes out of the plain CKB.
  await sweepSettlement(client, settlementKey, omnilock, 0n);
  assert.equal(sent.length, 1);
  const [swept] = sent;
  const tokenOutput = swept.outputs.find((output) => output.type?.eq(token))!;
  assert.ok(tokenOutput.lock.eq(omnilock));
  assert.equal(tokenOutput.capacity, 176n * CKB);
  assert.equal(swept.outputsData[swept.outputs.indexOf(tokenOutput)], amount(1_000n));
  const plain = swept.outputs.find((output) => !output.type)!;
  assert.ok(plain.lock.eq(omnilock));
  assert.ok(plain.capacity > 5_000n * CKB - 34n * CKB - CKB && plain.capacity < 5_000n * CKB - 34n * CKB);
  // The same cells still sweep to a secp256k1 destination (the account's lock before recovery).
  await sweepSettlement(client, settlementKey, await secp256k1Lock(client, publicKey), 0n);
  assert.equal(sent.length, 2);

  // 90 CKB tops the token cell up and the 56 CKB left, too little for a plain cell at an Omnilock, rides in it.
  const small: ccc.Transaction[] = [];
  await sweepSettlement(await offlineClient([cell(from, 142n * CKB, token, amount(1_000n)), cell(from, 90n * CKB)], [], small), settlementKey, omnilock, 0n);
  assert.equal(small.length, 1);
  assert.equal(small[0].outputs.length, 1);
  assert.ok(small[0].outputs[0].type?.eq(token) && small[0].outputs[0].capacity > 231n * CKB);
  // 61 CKB tops up one token cell but not two: the second waits on the key for a later sweep.
  const poor: ccc.Transaction[] = [];
  const tokenCells = [cell(from, 142n * CKB, token, amount(1_000n)), cell(from, 142n * CKB, token, amount(7n))];
  await sweepSettlement(await offlineClient([...tokenCells, cell(from, 61n * CKB)], [], poor), settlementKey, omnilock, 0n);
  assert.equal(poor.length, 1);
  assert.equal(poor[0].outputs.filter((output) => output.type).length, 1);
  assert.equal(poor[0].inputs.length, 2);
  assert.equal(tokenCells.filter(({ outPoint }) => poor[0].inputs.some(({ previousOutput }) => previousOutput.eq(outPoint))).length, 1);
});

test("M2 fixed: a lying CKB node can't make the rescue page burn the account's CKB as fee", async () => {
  // On chain the cell holds 50,000 CKB; the node reports 61. The page reads the cell from the transaction that
  // created it (whose hash it checks against the out point), so the rescue moves all 50,000 CKB.
  const { client, address } = await recoveryChain({
    extra: (omnilock) => [{ cellOutput: { lock: omnilock, capacity: 50_000n * CKB }, outputData: "0x" }],
    report: (cell, index) => index === 2 ? ccc.Cell.from({ ...cell, cellOutput: { ...cell.cellOutput, capacity: 61n * CKB } }) : cell,
  });
  const account = await openRescueAccount(client, address);
  assert.equal(account.ckb, 51_000n * CKB);
  const destination = await secp256k1Lock(client, ccc.hexFrom(secp256k1.getPublicKey(secp256k1.utils.randomSecretKey(), true)));
  const plan = await planRescue(client, account, rescueEntryForEvm(account, [evmAddress]), ccc.Address.fromScript(destination, client).toString());
  checkRescueTransaction(plan.transaction, account, destination);
  const realFee = 51_000n * CKB - plan.transaction.getOutputsCapacity();
  assert.equal(realFee, plan.fee);
  assert.ok(realFee < CKB / 100n);
  // And the backup signs a text the chain rebuilds from the real inputs: a node's lie would make it fail.
  assert.match(plan.approvalText, /\nCKB: 50,999\.\d+\n/);

  // A node that returns some other transaction for the out point's hash is refused outright.
  const forged = await recoveryChain();
  const original = forged.client.getTransaction.bind(forged.client);
  Object.assign(forged.client, { getTransaction: async (hash: ccc.HexLike) => {
    const found = await original(hash);
    if (!found || ccc.hexFrom(hash) !== forged.enable.hash()) return found;
    const copy = found.transaction.clone();
    copy.outputs[1].capacity = 61n * CKB;
    return { ...found, transaction: copy };
  } });
  await assert.rejects(openRescueAccount(forged.client, forged.address), (error: unknown) => error instanceof RescueError && error.code === "rpc");
});

test("M2 fixed: a lying CKB node can't make the rescue page burn the account's tokens", async () => {
  // On chain the cell is an xUDT cell with 2,500 tokens; the node reports it as plain CKB. The page reads the
  // cell from its creating transaction, so the tokens move one to one.
  const base = await offlineClient();
  const xudt = await base.getKnownScript(ccc.KnownScript.XUdt);
  const token = ccc.Script.from({ codeHash: xudt.codeHash, hashType: xudt.hashType, args: `0x${"77".repeat(32)}` });
  const { client, address } = await recoveryChain({
    extra: (omnilock) => [{ cellOutput: { lock: omnilock, capacity: 176n * CKB, type: token }, outputData: amount(2_500n) }],
    report: (cell, index) => index === 2 ? ccc.Cell.from({ ...cell, cellOutput: { ...cell.cellOutput, type: undefined }, outputData: "0x" }) : cell,
  });
  const account = await openRescueAccount(client, address);
  assert.deepEqual(account.tokens.map(({ typeHash, amount: value }) => ({ typeHash, value })), [{ typeHash: token.hash(), value: 2_500n }]);
  const destination = await secp256k1Lock(client, ccc.hexFrom(secp256k1.getPublicKey(secp256k1.utils.randomSecretKey(), true)));
  const plan = await planRescue(client, account, rescueEntryForEvm(account, [evmAddress]), ccc.Address.fromScript(destination, client).toString());
  const index = plan.transaction.outputs.findIndex((output) => output.type?.eq(token));
  assert.ok(index >= 0);
  assert.equal(plan.transaction.outputsData[index], amount(2_500n));
  assert.match(plan.approvalText, /\nTokens: 1 token cell\n/);
});

test("M3 fixed: the AdminList is locked to the account's key alone, so a backup can't move it", async () => {
  // The list sits under the Lit key's Omnilock without administrator mode: a backup's identity can't unlock it
  // (proved on testnet: research/omnilock/audit-fixes-results.md), and the account's address doesn't change.
  const second = { kind: "evm" as const, address: `0x${"ab".repeat(20)}` };
  const { client, wallet, address, omnilock, adminList } = await recoveryChain({ backups: [{ kind: "evm", address: evmAddress }, second], extra: (_omnilock, secp) => [{ cellOutput: { lock: secp, capacity: 5_000n * CKB }, outputData: "0x" }] });
  const listArgs = ccc.bytesFrom(adminList.cellOutput.lock.args);
  assert.equal(listArgs.length, 22);
  assert.equal(listArgs[21], 0x00, "no administrator mode on the list's lock");
  assert.equal(adminList.cellOutput.lock.codeHash, omnilock.codeHash);
  // KeyWay removes and adds backups with the Lit key, on the owner path of both locks.
  const removal = await planBackupChange(client, wallet, { change: "remove", backup: second });
  await checkBackupChangeTransaction(client, removal.transaction, wallet.recovery!, removal.backups);
  assert.ok(removal.transaction.outputs[0].lock.eq(adminList.cellOutput.lock));
  // Only KeyWay's own list update, which recreates the list under the same owner-only lock, spends it.
  const moved = removal.transaction.clone();
  moved.outputs[0].lock = omnilock;
  await assert.rejects(checkBackupChangeTransaction(client, moved, wallet.recovery!, removal.backups), /doesn't recreate the recovery list/);
  // The sign-in sweep still targets the account's own Omnilock, and the rescue page finds the list.
  const sweep = await planLegacySweep(client, wallet);
  assert.equal(sweep.status, "ready");
  if (sweep.status === "ready") assert.ok(sweep.transaction.outputs.every((output) => output.lock.eq(omnilock)));
  const account = await openRescueAccount(client, address);
  assert.ok(account.adminList.outPoint.eq(adminList.outPoint));

  // A list somehow found under another lock (only the Lit key could put it there now) is still refused.
  const thief = await secp256k1Lock(await offlineClient(), ccc.hexFrom(secp256k1.getPublicKey(secp256k1.utils.randomSecretKey(), true)));
  const hijacked = await recoveryChain({ adminListLock: () => thief });
  await assert.rejects(planBackupChange(hijacked.client, hijacked.wallet, { change: "add", backup: second }), /doesn't match the chain|isn't this account's/);
});

test("I1 fixed: a backup's ownership proof carries KeyWay's nonce and expires", async () => {
  const { client, secp } = await recoveryChain();
  const account = ccc.Address.fromScript(secp, client).toString();
  const backup = { kind: "evm" as const, address: evmAddress };
  const sign = (nonce: string) => {
    const text = new TextEncoder().encode(recoveryBackupChallenge(account, backup, nonce));
    const digest = keccak_256(ccc.bytesConcat(new TextEncoder().encode(`\x19Ethereum Signed Message:\n${text.length}`), text));
    const raw = secp256k1.sign(digest, evmKey, { prehash: false, format: "recovered" });
    return { ...backup, signature: ccc.hexFrom(ccc.bytesConcat(raw.slice(1), [raw[0] + 27])), challengeNonce: nonce };
  };
  const fresh = `${Date.now() + 600_000}.${"ab".repeat(16)}.${"cd".repeat(32)}`;
  assert.deepEqual(await verifyBackupOwnership(client, account, sign(fresh)), backup);
  // The same signature for another request, without a nonce, or after its expiry is refused.
  await assert.rejects(verifyBackupOwnership(client, account, { ...sign(fresh), challengeNonce: `${Date.now() + 900_000}.${"ab".repeat(16)}.${"cd".repeat(32)}` }), /didn't sign/);
  const { challengeNonce: _dropped, ...bare } = sign(fresh);
  await assert.rejects(verifyBackupOwnership(client, account, bare), /approval request is invalid/);
  const stale = `${Date.now() - 1}.${"ab".repeat(16)}.${"cd".repeat(32)}`;
  await assert.rejects(verifyBackupOwnership(client, account, sign(stale)), /approval expired/);
  // The server also checks the nonce is one it issued to this user: tests/recovery-flow.test.ts.
});
