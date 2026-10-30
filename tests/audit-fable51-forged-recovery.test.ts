// Regression tests for the audit's M2 (audit/omnilock-fable-5-1): nothing tied a stored recovery record to the user
// except the database row, so anyone who could write the wallet row could point an account at an AdminList *they*
// minted, whose whitelist holds *their* backup. These began as the audit's proof of concept; now the same forged
// record is refused because the chain shows the list wasn't made from the account's own cell
// (`verifyRecoveryAnchor`), by the server before the sweep, bootstrap and signing, and by the SDK on what
// /bootstrap returns.
import assert from "node:assert/strict";
import test from "node:test";
import * as ccc from "@ckb-ccc/core";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import {
  adminListLock,
  adminListTypeScript,
  KEYWAY_OMNILOCK,
  omnilockArgsFor,
  omnilockScript,
  parseRecovery,
  secp256k1Lock,
  verifyRecoveryAnchor,
  type KeyWayRecovery,
} from "../src/sdk/browser/account-lock.ts";
import { checkWalletRecovery } from "../src/sdk/browser/bootstrap.ts";
import { backupAuth, type RecoveryBackup } from "../src/sdk/browser/recovery-backups.ts";
import { readRecoveryList, recoveryListRecord, setRecoveryListRecord } from "../src/sdk/browser/recovery-list.ts";
import { adminListData, whitelistTree } from "../src/sdk/browser/recovery-smt.ts";
import { signRecoverySpendWithEvm } from "../src/sdk/browser/recovery-spend.ts";
import { formatCkbSignature, signAccountGroups } from "../src/server/funding-transaction.ts";
import { checkLegacySweepTransaction, planLegacySweep } from "../src/server/legacy-sweep.ts";
import { previewGeneralTransaction } from "../src/server/transaction-policy.ts";
import type { ReadyWallet } from "../src/server/user-wallet.ts";

const CKB = 100_000_000n;
// The victim's Lit key (the attacker never has it) and the attacker's own keys.
const victimKey = secp256k1.utils.randomSecretKey();
const victimPublicKey = ccc.hexFrom(secp256k1.getPublicKey(victimKey, true));
const attackerKey = secp256k1.utils.randomSecretKey();
const attackerPublicKey = ccc.hexFrom(secp256k1.getPublicKey(attackerKey, true));
const attackerEvmKey = secp256k1.utils.randomSecretKey();
const attackerEvm = ccc.hexFrom(keccak_256(secp256k1.getPublicKey(attackerEvmKey, false).slice(1)).slice(12));

async function offlineClient(cells: ccc.Cell[], transactions: ccc.Transaction[] = []): Promise<ccc.Client> {
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
      for (const cell of cells) if (cell.cellOutput.lock.eq(ccc.Script.from(lock))) yield cell;
    },
  });
  return client;
}

let nextCell = 1;
const cell = (lock: ccc.Script, capacity: bigint, type?: ccc.Script, outputData: ccc.Hex = "0x") =>
  ccc.Cell.from({ outPoint: { txHash: `0x${(nextCell++).toString(16).padStart(64, "0")}`, index: 0 }, cellOutput: { lock, capacity, type }, outputData });

const sign = (key: Uint8Array) => async (digest: ccc.Hex) => {
  const raw = secp256k1.sign(ccc.bytesFrom(digest), key, { prehash: false, format: "recovered" });
  return formatCkbSignature({ recoveryParam: raw[0] as 0 | 1, r: ccc.hexFrom(raw.slice(1, 33)), s: ccc.hexFrom(raw.slice(33, 65)) });
};

/**
 * The attacker mints an AdminList from their own cell: Type ID args from their input, lock = the victim's
 * owner-only Omnilock (as KeyWay's would be), whitelist = the attacker's EVM wallet, and the record KeyWay's
 * readers expect. Every field of the recovery record checks out against the victim's public key; only the chain
 * shows the list was made from the attacker's cell.
 */
async function attackerMintsList(base: ccc.Client) {
  const attackerSecp = await secp256k1Lock(base, attackerPublicKey);
  const paid = ccc.Transaction.from({ inputs: [{ previousOutput: { txHash: `0x${(nextCell++).toString(16).padStart(64, "0")}`, index: 0 } }], outputs: [{ lock: attackerSecp, capacity: 500n * CKB }], outputsData: ["0x"] });
  const funding = ccc.Cell.from({ outPoint: { txHash: paid.hash(), index: 0 }, cellOutput: paid.outputs[0], outputData: "0x" });
  const input0 = ccc.CellInput.from({ previousOutput: funding.outPoint });
  const adminType = adminListTypeScript({ adminListTypeArgs: ccc.hashTypeId(input0, 0) });
  const omnilock = omnilockScript({ omnilock: KEYWAY_OMNILOCK.testnet, omnilockArgs: omnilockArgsFor(victimPublicKey, adminType.hash()) });
  const listLock = adminListLock({ omnilock: KEYWAY_OMNILOCK.testnet, omnilockArgs: omnilock.args });
  const backups: RecoveryBackup[] = [{ kind: "evm", address: attackerEvm }];
  const { root } = whitelistTree(await Promise.all(backups.map((backup) => backupAuth(base, backup))));
  const mint = ccc.Transaction.from({
    inputs: [input0],
    outputs: [{ lock: listLock, type: adminType, capacity: 165n * CKB }, { lock: attackerSecp, capacity: 334n * CKB }],
    outputsData: [adminListData(root), "0x"],
  });
  await mint.addCellDepsOfKnownScripts(base, ccc.KnownScript.Secp256k1Blake160);
  mint.witnesses = [ccc.hexFrom(ccc.WitnessArgs.from({ lock: ccc.hexFrom(new Uint8Array(65)) }).toBytes())];
  setRecoveryListRecord(mint, 0, await recoveryListRecord(base, backups));
  await offlineClient([funding]).then((client) => signAccountGroups(mint, [{ script: attackerSecp, kind: "secp256k1" }], client, sign(attackerKey)));
  const adminList = ccc.Cell.from({ outPoint: { txHash: mint.hash(), index: 0 }, cellOutput: mint.outputs[0], outputData: mint.outputsData[0] });
  const forged: KeyWayRecovery = {
    omnilockArgs: omnilock.args,
    omnilock: KEYWAY_OMNILOCK.testnet,
    adminListTypeArgs: adminType.args,
    adminListTypeHash: adminType.hash(),
    adminListOutPoint: { txHash: mint.hash(), index: 0 },
    enableTransactionHash: mint.hash(),
    legacyAddress: ccc.Address.fromScript(await secp256k1Lock(base, victimPublicKey), base).toString(),
    enabledAt: new Date().toISOString(),
    backups,
  };
  return { mint, paid, adminList, omnilock, forged, backups };
}

const walletWith = (recovery: KeyWayRecovery) => ({
  version: 1, status: "ready", litPkpId: `0x${"11".repeat(20)}`, litPublicKey: victimPublicKey, ckbAddress: "ckt1forged",
  encryptedFiberKey: "ciphertext", primaryDeviceIdHash: "a".repeat(64), hasOpenedChannel: false,
  createdAt: "2026-10-29T00:00:00.000Z", updatedAt: "2026-10-29T00:00:00.000Z", recovery,
}) as ReadyWallet;

const notAnchored = /recovery record doesn't match the chain: the recovery list wasn't made from this account's own cell/;

test("a recovery record pointing at an attacker-minted AdminList is refused by the chain check", async () => {
  const base = await offlineClient([]);
  const { adminList, forged, mint, paid } = await attackerMintsList(base);
  // The record is internally consistent with the victim's key, as before.
  assert.deepEqual(parseRecovery(forged, victimPublicKey), forged);
  const client = await offlineClient([adminList], [mint, paid]);
  // The chain shows input 0 of the list's transaction was the attacker's cell, not the victim's.
  await assert.rejects(verifyRecoveryAnchor(client, victimPublicKey, forged), notAnchored);
  // The SDK runs the same check on what /bootstrap returns, so the server alone can't change the user's address.
  await assert.rejects(checkWalletRecovery({ litPublicKey: victimPublicKey, recovery: forged }, client), notAnchored);
  // A record naming a transaction that isn't committed, or one the node swapped, is refused too.
  const pending = await offlineClient([adminList], [paid]);
  Object.assign(pending, { getTransaction: async (hash: ccc.HexLike) => ccc.hexFrom(hash) === mint.hash() ? { transaction: mint, status: "pending" } : { transaction: paid, status: "committed" } });
  await assert.rejects(verifyRecoveryAnchor(pending, victimPublicKey, { ...forged, adminListTypeArgs: forged.adminListTypeArgs }), /isn't committed/);
});

test("the sweep and ordinary signing refuse a forged record before signing anything with the victim's key", async () => {
  const base = await offlineClient([]);
  const { adminList, forged, omnilock, mint, paid } = await attackerMintsList(base);
  const victimSecp = await secp256k1Lock(base, victimPublicKey);
  const legacyFunds = cell(victimSecp, 1_000n * CKB);
  const client = await offlineClient([adminList, legacyFunds], [mint, paid]);
  const payee = await secp256k1Lock(base, attackerPublicKey);
  const transaction = ccc.Transaction.from({
    inputs: [{ previousOutput: legacyFunds.outPoint }],
    outputs: [{ lock: payee, capacity: 100n * CKB }, { lock: omnilock, capacity: 900n * CKB - 100_000n }],
    outputsData: ["0x", "0x"],
  });
  await transaction.addCellDepsOfKnownScripts(client, ccc.KnownScript.Secp256k1Blake160);
  transaction.witnesses = [ccc.hexFrom(ccc.WitnessArgs.from({ lock: ccc.hexFrom(new Uint8Array(65)) }).toBytes())];
  await assert.rejects(previewGeneralTransaction(walletWith(forged), transaction, client), notAnchored);
  // The sign-in sweep (sweepLegacyAddress) runs the same check first; with the forged record it signs nothing:
  // tests/legacy-sweep-postgres.test.ts. Its plan alone would still target the forged address, which is why
  // the check sits in front of it.
  const plan = await planLegacySweep(client, walletWith(forged));
  assert.equal(plan.status, "ready");
  if (plan.status === "ready") await checkLegacySweepTransaction(client, plan.transaction, victimPublicKey, forged);
});

test("even with funds at a forged address, the attacker's backup must sign a text naming where they go", async () => {
  const base = await offlineClient([]);
  const { adminList, forged, omnilock, mint, paid } = await attackerMintsList(base);
  const client = await offlineClient([adminList], [mint, paid]);
  const list = await readRecoveryList(client, forged);
  const swept = cell(omnilock, 5_000n * CKB);
  const after = await offlineClient([adminList, swept], [mint, paid]);
  const attackerSecp = await secp256k1Lock(base, attackerPublicKey);
  const drain = ccc.Transaction.from({ inputs: [{ previousOutput: swept.outPoint }], outputs: [{ lock: attackerSecp, capacity: 4_999n * CKB }], outputsData: ["0x"] });
  let shown = "";
  const wallet = {
    request: async ({ method, params }: { method: string; params?: unknown[] }) => {
      if (method !== "personal_sign") throw new Error(method);
      shown = new TextDecoder().decode(ccc.bytesFrom(params![0] as string));
      const bytes = ccc.bytesFrom(params![0] as string);
      const digest = keccak_256(ccc.bytesConcat(new TextEncoder().encode(`\x19Ethereum Signed Message:\n${bytes.length}`), bytes));
      const raw = secp256k1.sign(digest, attackerEvmKey, { prehash: false, format: "recovered" });
      return ccc.hexFrom(ccc.bytesConcat(raw.slice(1), [raw[0] + 27]));
    },
  };
  await signRecoverySpendWithEvm(drain, { client: after, lock: omnilock, omnilock: forged.omnilock, list: list.entries, entry: list.entries[0], adminList: adminList.outPoint, inputCapacity: 5_000n * CKB }, wallet);
  assert.match(shown, new RegExp(`^KeyWay recovery\nMove everything to ${ccc.Address.fromScript(attackerSecp, after).toString()}\nCKB: 4,999\nTokens: none\nFee: 1 CKB\nTransaction: 0x[0-9a-f]{64}$`));
});
