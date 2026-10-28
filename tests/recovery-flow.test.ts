import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import * as ccc from "@ckb-ccc/core";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { adminListTypeScript, omnilockArgsFor, secp256k1Lock, type KeyWayRecovery } from "../src/sdk/browser/account-lock.ts";
import { evmBackupAuth, evmPersonalSignAddress, omnilockAdminWitnessLock, recoveryBackupChallenge, type RecoveryBackup } from "../src/sdk/browser/recovery-backups.ts";
import { adminListData, whitelistTree } from "../src/sdk/browser/recovery-smt.ts";
import { formatCkbSignature, previewFundingTransaction, signAccountGroups } from "../src/server/funding-transaction.ts";
import { checkRecoveryTransaction, planRecovery, recoveryLines, recoverySetup, type RecoveryContext } from "../src/server/recovery.ts";
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
async function offlineClient(cells: ccc.CellLike[] = []): Promise<ccc.Client> {
  const client = new ccc.ClientPublicTestnet({ url: "https://testnet.ckb.dev/" });
  await client.cache.recordCells(cells);
  const live = cells.map((cell) => ccc.Cell.from(cell));
  Object.assign(client, {
    findSingletonCellByType: async () => undefined,
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

test("reproduces the testnet enable transaction and its EVM backup spend from the recorded cells", async () => {
  // research/omnilock/phase2-results.md: 0x250e0b50…1af4 turned recovery on; 0x7597ed3d…ac66 is the EVM spend.
  const fixture = JSON.parse(await readFile(new URL("./fixtures/recovery-enable.json", import.meta.url), "utf8"));
  const client = await offlineClient(fixture.inputCells);
  const plan = await planRecovery(client, walletFor(fixture.publicKey), [{ kind: "evm", address: fixture.evmBackup }]);
  const onChain = ccc.Transaction.from(fixture.transaction);
  assert.equal(plan.transaction.hash(), "0x250e0b50785082de4819b618251aa4c1d6148c36fb5bb1379488edfaa0911af4");
  assert.equal(plan.transaction.hash(), onChain.hash());
  // Its secp256k1 signature is over the digest KeyWay signs.
  const digest = (await plan.transaction.getSignHashInfo(plan.secp, client))!.message;
  const signature = ccc.bytesFrom(onChain.getWitnessArgsAt(0)!.lock!);
  const recovered = secp256k1.recoverPublicKey(Uint8Array.from([signature[64], ...signature.slice(0, 64)]), ccc.bytesFrom(digest), { prehash: false });
  assert.equal(ccc.hexFrom(recovered), fixture.publicKey);

  // The backup spend: an admin witness whose signature is the EVM backup's personal_sign of the raw sighash.
  const spend = ccc.Transaction.from(fixture.evmSpend.transaction);
  const spendClient = await offlineClient([fixture.evmSpend.inputCell]);
  const auth = evmBackupAuth(fixture.evmBackup);
  const lock = spend.getWitnessArgsAt(0)!.lock!;
  const spendSignature = ccc.hexFrom(ccc.bytesFrom(lock).slice(20, 85));
  assert.equal(lock, omnilockAdminWitnessLock({ signature: spendSignature, auth, proof: whitelistTree([auth]).proofs[auth] }));
  const unsigned = spend.clone();
  unsigned.setWitnessArgsAt(0, ccc.WitnessArgs.from({ lock: ccc.hexFrom(new Uint8Array(ccc.bytesFrom(lock).length)) }));
  const sighash = (await unsigned.getSignHashInfo(plan.omnilock, spendClient))!.message;
  assert.equal(evmPersonalSignAddress(ccc.bytesFrom(sighash), spendSignature), fixture.evmBackup);
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
