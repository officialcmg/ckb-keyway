// Parity between the policy Action's recovery-list checks and KeyWay's own encoders (src/sdk/browser/recovery-*.ts,
// src/server/recovery.ts): version 3 records of salted auths, built by the real server code and taken from the
// testnet proof, are accepted; tampered ones are refused.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import * as ccc from "@ckb-ccc/core";
import { p256 } from "@noble/curves/nist.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { secp256k1Lock } from "../src/sdk/browser/account-lock.ts";
import { execAuth, execPreimage, normalizeEvmAddress, saltedBackupId, type RecoveryBackup } from "../src/sdk/browser/recovery-backups.ts";
import { backupAuths, decodeRecoveryList, recoveryListRecord, recoveryListRecordOf, setRecoveryListRecord } from "../src/sdk/browser/recovery-list.ts";
import { adminListData, whitelistTree } from "../src/sdk/browser/recovery-smt.ts";
import { litBackupIds } from "../src/server/lit-policy.ts";
import { planRecovery } from "../src/server/recovery.ts";
import type { ReadyWallet } from "../src/server/user-wallet.ts";
import { fakeLit, type ActionModule } from "./lit-action-fixture.ts";

process.env.LIT_EMAIL_API_KEY ??= "re_test_sending_key";

const CKB = 100_000_000n;
/** The verifiers before backup unlinking (unsalted identities), which a list may no longer name. */
const OLD_EVM_VERIFIER = "0x33bd1c699b633d685a6f60f6b0ca16fe8bb896f81323926ca6e0671bf8ab3c88";
const OLD_JOYID_VERIFIER = "0xf1185da23bf04b638010038b40ec64b587654db5cb98eb39f0373ad8919bcd89";

const privateKey = secp256k1.utils.randomSecretKey();
const publicKey = ccc.hexFrom(secp256k1.getPublicKey(privateKey, true));
const pkpId = ccc.hexFrom(keccak_256(secp256k1.getPublicKey(privateKey, false).slice(1)).slice(12));
const evm = (seed: number): RecoveryBackup => ({ kind: "evm", address: ccc.hexFrom(keccak_256(Uint8Array.of(seed)).slice(12)) });

async function joyId(client: ccc.Client): Promise<RecoveryBackup> {
  const key = ccc.hexFrom(p256.getPublicKey(p256.utils.randomSecretKey(), false).slice(1));
  const script = await client.getKnownScript(ccc.KnownScript.JoyId);
  const lock = ccc.Script.from({ codeHash: script.codeHash, hashType: script.hashType, args: ccc.bytesConcat("0x0001", ccc.hashCkbShort(key)) });
  return { kind: "joyid", address: ccc.Address.fromScript(lock, client).toString() };
}

const walletFor = (key: string) => ({
  version: 1, status: "ready", litPkpId: pkpId, litPublicKey: key, ckbAddress: "ckt1test",
  encryptedFiberKey: "ciphertext", primaryDeviceIdHash: "a".repeat(64), hasOpenedChannel: false,
  createdAt: "2026-11-06T00:00:00.000Z", updatedAt: "2026-11-06T00:00:00.000Z",
}) as ReadyWallet;

async function offlineClient(cells: ccc.CellLike[]): Promise<ccc.Client> {
  const client = new ccc.ClientPublicTestnet({ url: "https://testnet.ckb.dev/" });
  const known = cells.map((cell) => ccc.Cell.from(cell));
  await client.cache.recordCells(known);
  Object.assign(client, {
    findCells: async function* () {},
    findCellsByLock: async function* (lock: ccc.ScriptLike) { for (const cell of known) if (cell.cellOutput.lock.eq(ccc.Script.from(lock))) yield cell; },
  });
  return client;
}

/** A funded key, an Action that knows its funding, and the server's plan to turn recovery on with `backups`. */
async function planned(backups: RecoveryBackup[] | ((client: ccc.Client) => Promise<RecoveryBackup[]>)) {
  const base = await offlineClient([]);
  const secp = await secp256k1Lock(base, publicKey);
  const funding = ccc.Transaction.from({ inputs: [{ previousOutput: { txHash: `0x${"0f".repeat(32)}`, index: 0 } }], outputs: [{ lock: secp, capacity: 1_000n * CKB }], outputsData: ["0x"] });
  const client = await offlineClient([{ outPoint: { txHash: funding.hash(), index: 0 }, cellOutput: funding.outputs[0], outputData: "0x" }]);
  const list = typeof backups === "function" ? await backups(client) : backups;
  const plan = await planRecovery(client, walletFor(publicKey), list, { emailBinding: true });
  const env = fakeLit({ privateKey, pkpId, lookup: (hash) => hash === funding.hash() ? { tx: funding, status: "committed" } : undefined, transactions: () => [funding] });
  const action = await env.load();
  return { client, plan, list, env, action, salt: plan.adminListType.hash() };
}

/** Asks the Action to email a code for this enable, which runs every list check first. */
function sendCode(action: ActionModule, transaction: ccc.Transaction, backups: unknown) {
  return action.main({ mode: "send-code", pkpId, transaction: JSON.parse(ccc.stringify(transaction)), email: "user@example.com", emailApiKey: "re_test_sending_key", appName: "Demo", backups });
}

/** The enable with its AdminList data and record replaced by these auths. */
function withAuths(transaction: ccc.Transaction, auths: ccc.HexLike[], record: ccc.HexLike = recoveryListRecord(auths)) {
  const tx = transaction.clone();
  tx.outputsData[0] = adminListData(whitelistTree(auths.map((auth) => ccc.hexFrom(auth))).root);
  setRecoveryListRecord(tx, 0, record);
  return tx;
}

test("the Action decodes the testnet proof's version 3 records and salts each backup exactly as the SDK does", async () => {
  const fixture = JSON.parse(await readFile(new URL("./fixtures/recovery-backup-unlinking.json", import.meta.url), "utf8"));
  const action = await fakeLit({ privateKey, pkpId, lookup: () => undefined, transactions: () => [] }).load();
  const client = await offlineClient([]);
  const backups: RecoveryBackup[] = [{ kind: "evm", address: fixture.evmBackup }, { kind: "joyid", address: fixture.joyIdBackup }];
  const ids = await litBackupIds(client, backups);
  assert.deepEqual(ids, [{ kind: "evm", id: normalizeEvmAddress(fixture.evmBackup) }, { kind: "joyid", id: ccc.hexFrom(ccc.hashCkbShort(fixture.joyIdPublicKey)) }]);
  const salts: ccc.Hex[] = [];
  for (const name of ["A", "B"]) {
    const enable = ccc.Transaction.from(fixture[`enable${name}`].transaction);
    const record = recoveryListRecordOf(enable, 0)!;
    const salt = enable.outputs[0].type!.hash();
    salts.push(salt);
    const auths = action.listMembers(ccc.bytesFrom(record), ccc.bytesFrom(enable.outputsData[0])).map((auth) => ccc.hexFrom(auth));
    assert.deepEqual(auths, decodeRecoveryList(record));
    assert.deepEqual(auths, await backupAuths(client, backups, salt));
    assert.deepEqual(ids.map((id) => ccc.hexFrom(action.backupAuth({ kind: id.kind, id: ccc.bytesFrom(id.id) }, ccc.bytesFrom(salt)))), auths);
  }
  // Under the other account's salt the same backups give other auths, so they aren't on this list.
  const other = await backupAuths(client, backups, salts[1]);
  const enableA = ccc.Transaction.from(fixture.enableA.transaction);
  assert.ok(decodeRecoveryList(recoveryListRecordOf(enableA, 0)!).every((auth) => !other.includes(auth)));
});

test("an enable built by the server, with an EVM wallet and a JoyID passkey, is accepted and names both backups", async () => {
  const { client, plan, list, env, action } = await planned(async (client) => [evm(1), await joyId(client)]);
  const ids = await litBackupIds(client, list);
  const sent = await sendCode(action, plan.transaction, ids) as { ticket: string; binding: string };
  assert.ok(sent.ticket && sent.binding);
  const text = env.emails[0].text;
  assert.match(text, new RegExp(`Backup: EVM wallet ${list[0].address}`));
  assert.match(text, new RegExp(`Backup: JoyID passkey \\(key id ${ids[1].id}\\)`));
  // The same ids in another order name the same list.
  assert.ok(await sendCode(action, plan.transaction, [...ids].reverse()));
});

test("the Action refuses a list under the wrong salt, with an extra or missing auth, an old verifier, or a version 2 record", async () => {
  const { client, plan, list, action, salt } = await planned([evm(2), evm(3)]);
  const ids = await litBackupIds(client, list);
  const auths = await backupAuths(client, list, salt);
  assert.equal(recoveryListRecordOf(plan.transaction, 0), recoveryListRecord(auths));

  // The backups salted with another account's type hash: a consistent list, but not this account's backups.
  const otherSalt = `0x${"33".repeat(32)}`;
  await assert.rejects(sendCode(action, withAuths(plan.transaction, await backupAuths(client, list, otherSalt)), ids), /names a backup KeyWay doesn't support/);
  // The ids unsalted (as before backup unlinking).
  const unsalted = list.map((backup) => execAuth(execPreimage("0x14715402af1d6cdb6036ac02d10c822e84349c289c938320c2f7e8bb6d54b86f", normalizeEvmAddress(backup.address))));
  await assert.rejects(sendCode(action, withAuths(plan.transaction, unsalted), ids), /names a backup KeyWay doesn't support/);

  // An extra auth: in the record only (the root no longer matches), or in both with nobody to name it.
  const extra = await backupAuths(client, [evm(4)], salt);
  const tx = plan.transaction.clone();
  setRecoveryListRecord(tx, 0, recoveryListRecord([...auths, ...extra]));
  await assert.rejects(sendCode(action, tx, ids), /don't match the recovery list's root/);
  await assert.rejects(sendCode(action, withAuths(plan.transaction, [...auths, ...extra]), ids), /names a backup KeyWay doesn't support/);
  // A missing auth: from the record only, or from both while the caller still names it.
  const short = plan.transaction.clone();
  setRecoveryListRecord(short, 0, recoveryListRecord(auths.slice(0, 1)));
  await assert.rejects(sendCode(action, short, ids), /don't match the recovery list's root/);
  await assert.rejects(sendCode(action, withAuths(plan.transaction, auths.slice(0, 1)), ids), /isn't on the recovery list/);
  // The caller leaving a listed backup out, or naming one twice or of another kind.
  await assert.rejects(sendCode(action, plan.transaction, ids.slice(0, 1)), /names a backup KeyWay doesn't support/);
  await assert.rejects(sendCode(action, plan.transaction, [...ids, ids[0]]), /listed twice/);
  await assert.rejects(sendCode(action, plan.transaction, [{ kind: "secp256k1", id: ids[0].id }]), /EVM wallet or a JoyID passkey/);
  await assert.rejects(sendCode(action, plan.transaction, undefined), /backups is required/);
  // A JoyID id where the list holds an EVM wallet with the same 20 bytes: another verifier, another auth.
  await assert.rejects(sendCode(action, plan.transaction, [{ kind: "joyid", id: ids[0].id }, ids[1]]), /KeyWay doesn't support|isn't on the recovery list/);

  // The old verifiers, salted or not, are no longer KeyWay's.
  for (const verifier of [OLD_EVM_VERIFIER, OLD_JOYID_VERIFIER]) {
    for (const id of [saltedBackupId(ids[0].id, salt), ids[0].id]) {
      const old = execAuth(execPreimage(verifier, id));
      await assert.rejects(sendCode(action, withAuths(plan.transaction, [old, auths[1]]), ids), /names a backup KeyWay doesn't support/);
    }
  }

  // A version 2 record (0xFD ‖ 62-byte preimage per backup) is refused even when its auths hash to the root.
  const preimages = list.map((backup) => execPreimage("0x14715402af1d6cdb6036ac02d10c822e84349c289c938320c2f7e8bb6d54b86f", saltedBackupId(normalizeEvmAddress(backup.address), salt)));
  assert.deepEqual(preimages.map(execAuth), auths);
  const v2 = ccc.hexFrom(ccc.bytesConcat("0x4b57524c", [2, preimages.length], ...preimages.map((preimage) => ccc.bytesConcat([0xfd], preimage))));
  await assert.rejects(sendCode(action, withAuths(plan.transaction, auths, v2), ids), /record is malformed/);
  // So is a version 3 record with a non-exec auth, a duplicate, or trailing bytes.
  await assert.rejects(sendCode(action, withAuths(plan.transaction, auths, ccc.hexFrom(ccc.bytesConcat(ccc.bytesFrom(recoveryListRecord(auths)), [0]))), ids), /wrong number of backups/);
  const flagged = ccc.bytesFrom(recoveryListRecord(auths));
  flagged[6] = 0x00;
  await assert.rejects(sendCode(action, withAuths(plan.transaction, auths, flagged), ids), /record is malformed/);
  const twice = ccc.hexFrom(ccc.bytesConcat("0x4b57524c", [3, 2], auths[0], auths[0]));
  await assert.rejects(sendCode(action, withAuths(plan.transaction, auths, twice), ids), /listed twice/);

  // The untouched plan is still accepted.
  assert.ok(await sendCode(action, plan.transaction, ids));
});
