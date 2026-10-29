import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import * as ccc from "@ckb-ccc/core";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { adminListTypeScript, omnilockArgsFor, secp256k1Lock, type KeyWayRecovery } from "../src/sdk/browser/account-lock.ts";
import { backupAuth, evmBackupAuth, joyIdOmnilockMessage, omnilockAdminWitnessLock, recoveryBackupChallenge, type RecoveryBackup } from "../src/sdk/browser/recovery-backups.ts";
import { decodeRecoveryList, readRecoveryList, recoveryListRecord, recoveryListRecordOf, setRecoveryListRecord } from "../src/sdk/browser/recovery-list.ts";
import { adminListData, whitelistTree } from "../src/sdk/browser/recovery-smt.ts";
import { verifyWebAuthn } from "../src/sdk/browser/webauthn.ts";
import { formatCkbSignature, previewFundingTransaction, signAccountGroups } from "../src/server/funding-transaction.ts";
import {
  backupChangeLines,
  checkBackupChangeTransaction,
  checkRecoveryTransaction,
  planBackupChange,
  planRecovery,
  recoveryBackupChange,
  recoveryLines,
  recoverySetup,
  type RecoveryContext,
} from "../src/server/recovery.ts";
import { previewGeneralTransaction } from "../src/server/transaction-policy.ts";
import type { ReadyWallet } from "../src/server/user-wallet.ts";

const CKB = 100_000_000n;
const privateKey = secp256k1.utils.randomSecretKey();
const publicKey = ccc.hexFrom(secp256k1.getPublicKey(privateKey, true));
const evmKey = secp256k1.utils.randomSecretKey();
const evmAddress = ccc.hexFrom(keccak_256(secp256k1.getPublicKey(evmKey, false).slice(1)).slice(12));
const backups: RecoveryBackup[] = [{ kind: "evm", address: evmAddress }];

const walletFor = (key: ccc.Hex, recovery?: KeyWayRecovery) => ({
  version: 1, status: "ready", litPkpId: `0x${"11".repeat(20)}`, litPublicKey: key, ckbAddress: "ckt1test",
  encryptedFiberKey: "ciphertext", primaryDeviceIdHash: "a".repeat(64), hasOpenedChannel: false,
  createdAt: "2026-10-28T00:00:00.000Z", updatedAt: "2026-10-28T00:00:00.000Z", ...(recovery ? { recovery } : {}),
}) as ReadyWallet;

/** A testnet client that answers from recorded cells and never reaches the network. */
async function offlineClient(cells: ccc.CellLike[] = [], transactions: ccc.TransactionLike[] = []): Promise<ccc.Client> {
  const client = new ccc.ClientPublicTestnet({ url: "https://testnet.ckb.dev/" });
  await client.cache.recordCells(cells);
  const live = cells.map((cell) => ccc.Cell.from(cell));
  const known = transactions.map((transaction) => ccc.Transaction.from(transaction));
  Object.assign(client, {
    findSingletonCellByType: async (type: ccc.ScriptLike) => live.find((cell) => cell.cellOutput.type?.eq(ccc.Script.from(type))),
    getTransaction: async (hash: ccc.HexLike) => {
      const transaction = known.find((candidate) => candidate.hash() === ccc.hexFrom(hash));
      return transaction ? { transaction, status: "committed" } : undefined;
    },
    findCells: async function* () {},
    // Newest first, so tests show the plan doesn't depend on the indexer's order.
    findCellsByLock: async function* (lock: ccc.ScriptLike) {
      for (const cell of [...live].reverse()) if (cell.cellOutput.lock.eq(ccc.Script.from(lock))) yield cell;
    },
  });
  return client;
}

let nextCell = 1;
function cell(lock: ccc.Script, capacity: bigint, type?: ccc.Script, outputData: ccc.Hex = "0x"): ccc.Cell {
  return ccc.Cell.from({ outPoint: { txHash: `0x${(nextCell++).toString(16).padStart(64, "0")}`, index: 0 }, cellOutput: { lock, capacity, type }, outputData });
}

const amount = (value: bigint) => ccc.hexFrom(ccc.numLeToBytes(value, 16));

async function accountCells() {
  const base = await offlineClient();
  const secp = await secp256k1Lock(base, publicKey);
  const xudt = await base.getKnownScript(ccc.KnownScript.XUdt);
  const token = ccc.Script.from({ codeHash: xudt.codeHash, hashType: xudt.hashType, args: `0x${"77".repeat(32)}` });
  const dao = await base.getKnownScript(ccc.KnownScript.NervosDao);
  const cells = {
    small: cell(secp, 300n * CKB),
    large: cell(secp, 2_000n * CKB),
    token: cell(secp, 143n * CKB, token, amount(2_500n)),
    dao: cell(secp, 102n * CKB, ccc.Script.from({ codeHash: dao.codeHash, hashType: dao.hashType, args: "0x" }), ccc.hexFrom(new Uint8Array(8))),
    withData: cell(secp, 70n * CKB, undefined, "0x1234"),
  };
  return { cells, secp, token, client: await offlineClient(Object.values(cells)) };
}

test("builds the one recovery transaction from the account's own cells", async () => {
  const { cells, secp, token, client } = await accountCells();
  const plan = await planRecovery(client, walletFor(publicKey), backups);
  const { transaction, preview } = plan;

  // Input 0 is the largest plain cell, and it fixes the AdminList's Type ID and the new address.
  assert.ok(transaction.inputs[0].previousOutput.eq(cells.large.outPoint));
  assert.equal(transaction.inputs.length, 3, "plain and token cells move; the DAO cell and the cell with data stay");
  assert.equal(preview.cellsLeft, 2);
  const typeId = adminListTypeScript({ adminListTypeArgs: ccc.hashTypeId(transaction.inputs[0], 0) });
  assert.equal(plan.omnilock.args, omnilockArgsFor(publicKey, typeId.hash()));
  assert.equal(preview.newAddress, ccc.Address.fromScript(plan.omnilock, client).toString());
  assert.equal(preview.legacyAddress, ccc.Address.fromScript(secp, client).toString());

  const [adminList, tokenOutput, change] = transaction.outputs;
  assert.ok(adminList.type!.eq(typeId) && adminList.lock.eq(plan.omnilock));
  assert.equal(transaction.outputsData[0], adminListData(whitelistTree([evmBackupAuth(evmAddress)]).root));
  assert.equal(adminList.capacity, 197n * CKB);
  // A token cell needs 34 more bytes for the 54-byte Omnilock args: 176 CKB, up from this cell's 143.
  assert.ok(tokenOutput.type!.eq(token) && tokenOutput.lock.eq(plan.omnilock));
  assert.equal(transaction.outputsData[1], amount(2_500n));
  assert.equal(tokenOutput.capacity, 176n * CKB);
  assert.equal(preview.tokenCellsExtraCkb, "33");
  assert.equal(preview.lockedCkb, "230");
  assert.equal(preview.minimumCellCkb, "95");
  assert.ok(change.lock.eq(plan.omnilock) && !change.type);
  const fee = 2_443n * CKB - transaction.getOutputsCapacity();
  assert.equal(preview.feeCkb, (Number(fee) / 1e8).toString());
  assert.ok(fee > 0n && fee < CKB / 1000n);
  assert.deepEqual(preview.tokens, [{ asset: token.hash(), amount: "2500", amountText: `2500 of token ${token.hash().slice(0, 10)}…${token.hash().slice(-6)}` }]);
  assert.equal(preview.transactionHash, transaction.hash());

  // Deterministic: the same cells give the same transaction, so enable can rebuild and compare it.
  assert.equal((await planRecovery(client, walletFor(publicKey), backups)).transaction.hash(), transaction.hash());
  await checkRecoveryTransaction(client, transaction, publicKey, backups);

  const lines = recoveryLines(preview);
  assert.ok(lines.includes(`Backup: EVM wallet ${evmAddress.slice(0, 10)}…${evmAddress.slice(-6)}`));
  assert.ok(lines.includes("Your address will change because you're turning on recovery."));
  assert.ok(lines.some((line) => line.startsWith("Locks 230 CKB")));
});

test("refuses when the balance can't cover it or there is no plain CKB", async () => {
  const base = await offlineClient();
  const secp = await secp256k1Lock(base, publicKey);
  await assert.rejects(planRecovery(await offlineClient([cell(secp, 250n * CKB)]), walletFor(publicKey), backups), /can't cover turning on recovery: it needs 42\.0+\d+ CKB more/);
  await assert.rejects(planRecovery(await offlineClient([]), walletFor(publicKey), backups), /needs plain CKB/);
  assert.ok(await planRecovery(await offlineClient([cell(secp, 293n * CKB)]), walletFor(publicKey), backups));
});

test("reproduces the testnet JoyID-backup enable, its spend through the WebAuthn verifier, and adding an EVM backup", async () => {
  // research/omnilock/joyid-verifier-results.md and phase4-results.md: 0x749adad0…61cc turned recovery on with a
  // JoyID-style backup, 0x7e0bc481…b445 spent through the verifier, 0x310a9ceb…6829 added an EVM backup.
  const fixture = JSON.parse(await readFile(new URL("./fixtures/recovery-enable.json", import.meta.url), "utf8"));
  const joyId: RecoveryBackup = { kind: "joyid", address: fixture.joyIdBackup };
  const client = await offlineClient(fixture.enable.inputCells);
  const plan = await planRecovery(client, walletFor(fixture.publicKey), [joyId]);
  const enable = ccc.Transaction.from(fixture.enable.transaction);
  assert.equal(plan.transaction.hash(), "0x749adad0d67555b18816d419c79c662f5d6bc68655abf6cafcd713329e3861cc");
  assert.equal(plan.transaction.hash(), enable.hash());
  // Witness 0 records the list beside the AdminList, and it reads back to the backup.
  assert.equal(recoveryListRecordOf(enable, 0), await recoveryListRecord(client, [joyId]));
  assert.deepEqual((await decodeRecoveryList(client, recoveryListRecordOf(enable, 0)!)).map(({ backup }) => backup), [joyId]);
  // Its secp256k1 signature is over the digest KeyWay signs, which covers the record.
  const digest = (await plan.transaction.getSignHashInfo(plan.secp, client))!.message;
  const signature = ccc.bytesFrom(enable.getWitnessArgsAt(0)!.lock!);
  const recovered = secp256k1.recoverPublicKey(Uint8Array.from([signature[64], ...signature.slice(0, 64)]), ccc.bytesFrom(digest), { prehash: false });
  assert.equal(ccc.hexFrom(recovered), fixture.publicKey);

  // The JoyID spend: the witness carries the 768-byte verifier blob, whose assertion is the passkey's signature
  // over "CKB transaction: 0x<sighash>".
  const spend = ccc.Transaction.from(fixture.joyIdSpend.transaction);
  const spendClient = await offlineClient(fixture.joyIdSpend.inputCells);
  const [entry] = await decodeRecoveryList(client, recoveryListRecordOf(enable, 0)!);
  const lock = ccc.bytesFrom(spend.getWitnessArgsAt(0)!.lock!);
  const blob = lock.slice(20, 20 + 768);
  assert.equal(ccc.hexFrom(lock), omnilockAdminWitnessLock({ signature: blob, auth: entry.auth, proof: whitelistTree([entry.auth]).proofs[entry.auth], preimage: entry.preimage }));
  assert.deepEqual(blob.slice(1, 65), ccc.bytesFrom(fixture.joyIdPublicKey));
  const authLength = blob[129] | (blob[130] << 8);
  const clientAt = 131 + authLength;
  const assertion = {
    publicKey: blob.slice(1, 65), rs: blob.slice(65, 129), authData: blob.slice(131, clientAt),
    clientDataJson: blob.slice(clientAt + 2, clientAt + 2 + (blob[clientAt] | (blob[clientAt + 1] << 8))),
  };
  const unsigned = spend.clone();
  unsigned.setWitnessArgsAt(0, ccc.WitnessArgs.from({ lock: ccc.hexFrom(new Uint8Array(lock.length)) }));
  const sighash = (await unsigned.getSignHashInfo(plan.omnilock, spendClient))!.message;
  assert.ok(verifyWebAuthn(assertion, joyIdOmnilockMessage(sighash)));
  assert.ok(!verifyWebAuthn(assertion, joyIdOmnilockMessage(ccc.hashCkb(sighash))));

  // Adding the EVM backup: rebuilt from the chain's own list, it hashes the same and passes the checks.
  const recovery: KeyWayRecovery = {
    omnilockArgs: plan.omnilock.args, adminListTypeArgs: plan.adminListType.args, adminListTypeHash: plan.adminListType.hash(),
    adminListOutPoint: { txHash: enable.hash(), index: 0 }, legacyAddress: plan.preview.legacyAddress, enabledAt: "2026-10-29T00:00:00.000Z", backups: [joyId],
  };
  const add = ccc.Transaction.from(fixture.addEvm.transaction);
  const addClient = await offlineClient(fixture.addEvm.inputCells, [enable]);
  const evm: RecoveryBackup = { kind: "evm", address: fixture.evmBackup };
  const change = await planBackupChange(addClient, walletFor(fixture.publicKey, recovery), { change: "add", backup: evm });
  assert.equal(change.transaction.hash(), "0x310a9cebc1c06316c458cf5f96982c0e11a2b2a1b10c054166600637d5e56829");
  assert.equal(change.transaction.hash(), add.hash());
  assert.equal(recoveryListRecordOf(add, 0), await recoveryListRecord(addClient, [joyId, evm]));
  await checkBackupChangeTransaction(addClient, add, recovery, [joyId, evm]);
  // One owner signature by the account key covers the AdminList and the fee cell.
  const ownerDigest = (await change.transaction.getSignHashInfo(change.omnilock, addClient))!.message;
  const owner = ccc.bytesFrom(add.getWitnessArgsAt(0)!.lock!).slice(20);
  assert.equal(ccc.hexFrom(secp256k1.recoverPublicKey(Uint8Array.from([owner[64], ...owner.slice(0, 64)]), ccc.bytesFrom(ownerDigest), { prehash: false })), fixture.publicKey);
});

test("refuses a recovery transaction that doesn't match what KeyWay computed", async () => {
  const { client, secp } = await accountCells();
  const plan = await planRecovery(client, walletFor(publicKey), backups);
  const tamper = async (change: (tx: ccc.Transaction) => void, reason: RegExp, tamperedBackups = backups) => {
    const tx = plan.transaction.clone();
    change(tx);
    await assert.rejects(checkRecoveryTransaction(client, tx, publicKey, tamperedBackups), reason);
  };
  const stranger = ccc.Script.from({ ...secp, args: `0x${"66".repeat(20)}` });
  const last = plan.transaction.outputs.length - 1;
  await tamper((tx) => { tx.outputs[last].lock = stranger; }, /somewhere other than your new address/);
  await tamper((tx) => { tx.outputs.push(ccc.CellOutput.from({ lock: stranger, capacity: 100n * CKB })); tx.outputsData.push("0x"); tx.outputs[last].capacity -= 100n * CKB; }, /somewhere other than your new address/);
  await tamper(() => undefined, /exactly these backups/, [{ kind: "evm", address: `0x${"44".repeat(20)}` }]);
  await tamper((tx) => { tx.outputsData[0] = adminListData(whitelistTree([evmBackupAuth(evmAddress), evmBackupAuth(`0x${"44".repeat(20)}`)]).root); }, /exactly these backups/);
  await tamper((tx) => { tx.outputs[0].capacity += CKB; tx.outputs[last].capacity -= CKB; }, /capacity is wrong/);
  await tamper((tx) => { tx.outputsData[1] = amount(2_000n); }, /tokens don't all move/);
  await tamper((tx) => { tx.outputs[last].capacity -= 10n * CKB; }, /fee is outside/);
  await tamper((tx) => { tx.outputsData[last] = "0x00"; }, /carries data/);
  await tamper((tx) => { [tx.inputs[0], tx.inputs[1]] = [tx.inputs[1], tx.inputs[0]]; }, /recovery list/);
  const foreign = cell(stranger, 500n * CKB);
  await client.cache.recordCells([foreign]);
  await tamper((tx) => { tx.inputs.push(ccc.CellInput.from({ previousOutput: foreign.outPoint })); }, /an input isn't this account's/);
});

test("general signing and channel funding can't create a recovery list or pay into another Omnilock of this key", async () => {
  const { client } = await accountCells();
  const plan = await planRecovery(client, walletFor(publicKey), backups);
  // The enable transaction itself is refused outside the recovery flow.
  await assert.rejects(previewGeneralTransaction(walletFor(publicKey), plan.transaction, client), /Omnilock address of this account that isn't its own/);
  await assert.rejects(previewFundingTransaction(walletFor(publicKey), {
    ...plan.transaction,
    outputs: [...plan.transaction.outputs, { lock: { codeHash: "0x6c67887fe201ee0c7853f1682c0b77c0e6214044c156c7558269390a8afa6d7c", hashType: "type", args: `0x${"fd".repeat(32)}` }, capacity: 100n * CKB }],
    outputsData: [...plan.transaction.outputsData, "0x"],
  }, client), /Omnilock address of this account that isn't its own/);

  // Once recovery is on, the account's own Omnilock is fine, but one pointing at another AdminList isn't.
  const recovery: KeyWayRecovery = {
    omnilockArgs: plan.omnilock.args, adminListTypeArgs: plan.adminListType.args, adminListTypeHash: plan.adminListType.hash(),
    adminListOutPoint: { txHash: `0x${"ad".repeat(32)}`, index: 0 }, legacyAddress: plan.preview.legacyAddress, enabledAt: "2026-10-28T00:00:00.000Z", backups,
  };
  const secpInput = plan.inputCells[0];
  const toOwn = ccc.Transaction.from({
    inputs: [{ previousOutput: secpInput.outPoint }],
    outputs: [{ lock: plan.omnilock, capacity: secpInput.cellOutput.capacity - 10_000n }],
    outputsData: ["0x"],
    witnesses: [ccc.hexFrom(ccc.WitnessArgs.from({ lock: ccc.hexFrom(new Uint8Array(65)) }).toBytes())],
  });
  assert.equal((await previewGeneralTransaction(walletFor(publicKey, recovery), toOwn, client)).preview.receivingCkb, "0");
  const other = await ccc.Script.fromKnownScript(client, ccc.KnownScript.OmniLock, omnilockArgsFor(publicKey, `0x${"99".repeat(32)}`));
  const toOther = toOwn.clone();
  toOther.outputs[0].lock = other;
  await assert.rejects(previewGeneralTransaction(walletFor(publicKey, recovery), toOther, client), /isn't its own/);
});

test("the recovery service refuses before touching anything when recovery is on or no backup is given", async () => {
  const { client } = await accountCells();
  const plan = await planRecovery(client, walletFor(publicKey), backups);
  const recovery: KeyWayRecovery = {
    omnilockArgs: plan.omnilock.args, adminListTypeArgs: plan.adminListType.args, adminListTypeHash: plan.adminListType.hash(),
    adminListOutPoint: { txHash: `0x${"ad".repeat(32)}`, index: 0 }, legacyAddress: plan.preview.legacyAddress, enabledAt: "2026-10-28T00:00:00.000Z",
  };
  const context = (wallet: ReadyWallet): RecoveryContext => ({
    user: { id: crypto.randomUUID() }, wallet, appName: "Acme", client,
    email: async () => "ana@acme.example", sendEmail: async () => undefined,
    rateLimit: async () => ({ allowed: true, retryAfter: null }), recordSigning: async () => undefined,
  });
  await assert.rejects(recoverySetup(context(walletFor(publicKey, recovery)), { operation: "preview", backups }), /already on/);
  await assert.rejects(recoverySetup(context(walletFor(publicKey)), { operation: "preview", backups: [] }), /at least one backup/);
  // Without a signature from the backup, nothing is previewed.
  await assert.rejects(recoverySetup(context(walletFor(publicKey)), { operation: "preview", backups }), /didn't sign/);
  const wrongAccount = { ...backups[0], signature: personalSign(recoveryBackupChallenge("ckt1qother", backups[0])) };
  await assert.rejects(recoverySetup(context(walletFor(publicKey)), { operation: "preview", backups: [wrongAccount] }), /didn't sign/);
});

function personalSign(message: string): ccc.Hex {
  const bytes = new TextEncoder().encode(message);
  const raw = secp256k1.sign(keccak_256(ccc.bytesConcat(new TextEncoder().encode(`\x19Ethereum Signed Message:\n${bytes.length}`), bytes)), evmKey, { prehash: false, format: "recovered" });
  return ccc.hexFrom(ccc.bytesConcat(raw.slice(1), [raw[0] + 27]));
}

test("signs the recovery transaction with the account key's plain secp256k1 witness", async () => {
  const { client } = await accountCells();
  const plan = await planRecovery(client, walletFor(publicKey), backups);
  const signed = await signAccountGroups(plan.transaction.clone(), [{ script: plan.secp, kind: "secp256k1" }], client, async (digest) => {
    const raw = secp256k1.sign(ccc.bytesFrom(digest), privateKey, { prehash: false, format: "recovered" });
    return formatCkbSignature({ recoveryParam: raw[0] as 0 | 1, r: ccc.hexFrom(raw.slice(1, 33)), s: ccc.hexFrom(raw.slice(33, 65)) });
  });
  assert.equal(ccc.bytesFrom(signed.getWitnessArgsAt(0)!.lock!).length, 65);
  assert.equal(signed.hash(), plan.transaction.hash());
});

/** An account right after turning recovery on: its AdminList and change cell, and the enable transaction. */
async function enabledAccount(list: RecoveryBackup[] = backups) {
  const { cells, client: setupClient } = await accountCells();
  const plan = await planRecovery(setupClient, walletFor(publicKey), list);
  const hash = plan.transaction.hash();
  const outputs = plan.transaction.outputs.map((cellOutput, index) => ccc.Cell.from({ outPoint: { txHash: hash, index }, cellOutput, outputData: plan.transaction.outputsData[index] }));
  const recovery: KeyWayRecovery = {
    omnilockArgs: plan.omnilock.args, adminListTypeArgs: plan.adminListType.args, adminListTypeHash: plan.adminListType.hash(),
    adminListOutPoint: { txHash: hash, index: 0 }, legacyAddress: plan.preview.legacyAddress, enabledAt: "2026-10-29T00:00:00.000Z", backups: list,
  };
  const live = [outputs[0], outputs[outputs.length - 1], cells.dao];
  return { plan, recovery, outputs, client: await offlineClient(live, [plan.transaction]), wallet: walletFor(publicKey, recovery) };
}

test("reads the backup list back from the chain and checks it against the root", async () => {
  const second: RecoveryBackup = { kind: "evm", address: `0x${"44".repeat(20)}` };
  const { client, recovery, plan } = await enabledAccount([...backups, second]);
  const list = await readRecoveryList(client, recovery);
  assert.deepEqual(list.entries.map(({ backup }) => backup), [...backups, second]);
  assert.equal(list.root, whitelistTree([evmBackupAuth(evmAddress), evmBackupAuth(second.address)]).root);
  assert.equal(list.proofs[evmBackupAuth(second.address)], whitelistTree([evmBackupAuth(evmAddress), evmBackupAuth(second.address)]).proofs[evmBackupAuth(second.address)]);
  // A record that doesn't hash to the cell's root, a malformed one, and none at all are all refused.
  const forged = plan.transaction.clone();
  setRecoveryListRecord(forged, 0, await recoveryListRecord(client, backups));
  await assert.rejects(readRecoveryList(await offlineClient([plan.transaction.outputs[0]].map((cellOutput) => ({ outPoint: { txHash: forged.hash(), index: 0 }, cellOutput, outputData: plan.transaction.outputsData[0] })), [forged]), recovery), /don't match/);
  await assert.rejects(decodeRecoveryList(client, "0x4b57524c0101"), /malformed/);
  await assert.rejects(decodeRecoveryList(client, `0x4b57524c0201`), /version 2/);
  const bare = plan.transaction.clone();
  bare.setWitnessArgsAt(0, ccc.WitnessArgs.from({ lock: ccc.hexFrom(new Uint8Array(65)) }));
  await assert.rejects(readRecoveryList(await offlineClient([{ outPoint: { txHash: bare.hash(), index: 0 }, cellOutput: plan.transaction.outputs[0], outputData: plan.transaction.outputsData[0] }], [bare]), recovery), /doesn't record its backups/);
});

test("builds the list update: same AdminList cell with the new root and record, the rest back to the account", async () => {
  const { client, wallet, recovery, outputs } = await enabledAccount();
  const added: RecoveryBackup = { kind: "evm", address: `0x${"55".repeat(20)}` };
  const plan = await planBackupChange(client, wallet, { change: "add", backup: added });
  const { transaction } = plan;
  assert.ok(transaction.inputs[0].previousOutput.eq(outputs[0].outPoint), "input 0 is the AdminList");
  assert.ok(transaction.inputs[1].previousOutput.eq(outputs[outputs.length - 1].outPoint), "then the account's plain CKB");
  assert.equal(transaction.inputs.length, 2, "the DAO cell isn't touched");
  assert.ok(transaction.outputs[0].lock.eq(outputs[0].cellOutput.lock) && transaction.outputs[0].type!.eq(outputs[0].cellOutput.type!));
  assert.equal(transaction.outputs[0].capacity, outputs[0].cellOutput.capacity);
  assert.equal(transaction.outputsData[0], adminListData(whitelistTree([evmBackupAuth(evmAddress), evmBackupAuth(added.address)]).root));
  assert.equal(recoveryListRecordOf(transaction, 0), await recoveryListRecord(client, [...backups, added]));
  assert.ok(transaction.outputs[1].lock.eq(plan.omnilock) && !transaction.outputs[1].type);
  assert.equal(transaction.witnesses.length, 1);
  assert.equal(ccc.bytesFrom(transaction.getWitnessArgsAt(0)!.lock!).length, 85, "one owner placeholder for the whole group");
  assert.deepEqual(plan.backups, [...backups, added]);
  assert.equal(plan.preview.backup.label, `EVM wallet 0x55555555…555555`);
  await checkBackupChangeTransaction(client, transaction, recovery, plan.backups);
  const lines = backupChangeLines(plan.preview);
  assert.equal(lines[0], "Add a recovery backup");
  assert.ok(lines.includes("Adding: EVM wallet 0x55555555…555555"));
  assert.ok(lines.includes("Backups after this change: 2"));

  const removal = await planBackupChange(client, walletFor(publicKey, recovery), { change: "remove", backup: backups[0] }).catch((error: Error) => error);
  assert.match(String(removal), /Keep at least one backup\. Add another backup before removing this one/);
  await assert.rejects(planBackupChange(client, wallet, { change: "add", backup: backups[0] }), /is already a backup/);
  await assert.rejects(planBackupChange(client, wallet, { change: "remove", backup: added }), /isn't a backup/);
});

test("removes a backup and refuses an add past the limit", async () => {
  const extra = Array.from({ length: 7 }, (_, index): RecoveryBackup => ({ kind: "evm", address: `0x${(index + 1).toString(16).padStart(2, "0").repeat(20)}` }));
  const { client, wallet, recovery } = await enabledAccount([...backups, ...extra]);
  const plan = await planBackupChange(client, wallet, { change: "remove", backup: extra[3] });
  assert.deepEqual(plan.backups, [...backups, ...extra.filter((_, index) => index !== 3)]);
  assert.equal(plan.preview.change, "remove");
  assert.ok(backupChangeLines(plan.preview).includes("Removing: EVM wallet 0x04040404…040404"));
  assert.ok(!backupChangeLines(plan.preview).some((line) => /move everything/.test(line)));
  await checkBackupChangeTransaction(client, plan.transaction, recovery, plan.backups);
  await assert.rejects(planBackupChange(client, wallet, { change: "add", backup: { kind: "evm", address: `0x${"99".repeat(20)}` } }), /At most 8 backups/);
});

test("refuses a list update that doesn't match what KeyWay computed", async () => {
  const { client, wallet, recovery, plan: enabled } = await enabledAccount();
  const added: RecoveryBackup = { kind: "evm", address: `0x${"55".repeat(20)}` };
  const plan = await planBackupChange(client, wallet, { change: "add", backup: added });
  const list = [...backups, added];
  const tamper = async (change: (tx: ccc.Transaction) => void, reason: RegExp, expected = list) => {
    const tx = plan.transaction.clone();
    change(tx);
    await assert.rejects(checkBackupChangeTransaction(client, tx, recovery, expected), reason);
  };
  const stranger = ccc.Script.from({ ...plan.omnilock, args: `0x${"66".repeat(54)}` });
  await tamper((tx) => { tx.outputs[1].lock = stranger; }, /output 1 isn't plain CKB at your address/);
  await tamper((tx) => { tx.outputs[0].lock = stranger; }, /doesn't recreate the recovery list/);
  await tamper((tx) => { tx.outputs[0].capacity -= CKB; tx.outputs[1].capacity += CKB; }, /doesn't recreate the recovery list/);
  await tamper(() => undefined, /exactly these backups/, backups);
  await tamper((tx) => { setRecoveryListRecord(tx, 0, ccc.hexFrom(ccc.bytesConcat("0x4b57524c", [1, 1, 0x12], new Uint8Array(20).fill(0x55)))); }, /recorded backup list/);
  await tamper((tx) => { [tx.inputs[0], tx.inputs[1]] = [tx.inputs[1], tx.inputs[0]]; }, /input 0 isn't the recovery list/);
  await tamper((tx) => { tx.outputs[1].capacity -= 10n * CKB; }, /fee is outside/);
  await tamper((tx) => { tx.outputs.splice(1, 1); tx.outputsData.splice(1, 1); }, /nothing returns|fee is outside/);
  const foreign = cell(stranger, 500n * CKB);
  await client.cache.recordCells([foreign]);
  await tamper((tx) => { tx.inputs.push(ccc.CellInput.from({ previousOutput: foreign.outPoint })); }, /an input isn't this account's/);
  // General signing still never spends the AdminList.
  await assert.rejects(previewGeneralTransaction(walletFor(publicKey, recovery), plan.transaction, client), /recovery list/);
  assert.ok(enabled);
});

test("the backup service refuses when recovery is off and needs the new backup's signature to add it", async () => {
  const { client, wallet } = await enabledAccount();
  const context = (current: ReadyWallet): RecoveryContext => ({
    user: { id: crypto.randomUUID() }, wallet: current, appName: "Acme", client,
    email: async () => "ana@acme.example", sendEmail: async () => undefined,
    rateLimit: async () => ({ allowed: true, retryAfter: null }), recordSigning: async () => undefined,
  });
  const added = { kind: "evm" as const, address: `0x${"55".repeat(20)}` };
  await assert.rejects(recoveryBackupChange(context(walletFor(publicKey)), { operation: "preview", change: "add", backup: added }), /recovery is off/);
  await assert.rejects(recoveryBackupChange(context(wallet), { operation: "preview", change: "swap", backup: added }), /add or remove/);
  await assert.rejects(recoveryBackupChange(context(wallet), { operation: "preview", change: "add", backup: added }), /didn't sign/);
  await assert.rejects(recoveryBackupChange(context(wallet), { operation: "preview", change: "add", backup: { kind: "joyid", address: "ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqv82scyl0ywuurakhc80ha0agm5x8ye8kca6zq0u" } }), /isn't a JoyID address/);
  assert.equal(await backupAuth(client, backups[0]), evmBackupAuth(evmAddress));
});
