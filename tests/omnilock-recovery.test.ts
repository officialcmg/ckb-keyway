import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import * as ccc from "@ckb-ccc/core";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { createCccExternalFundingResolver } from "@fiber-pay/sdk/browser";
import {
  adminListTypeScript,
  FUNDING_LOCK_KNOWN_SCRIPTS,
  omnilockArgsFor,
  omnilockLock,
  omnilockOwnerWitnessLock,
  parseRecovery,
  secp256k1Lock,
  type KeyWayRecovery,
} from "../src/sdk/browser/account-lock.ts";
import { getLockBalance } from "../src/sdk/browser/ckb-balance.ts";
import { KeyWaySigner } from "../src/sdk/browser/keyway-signer.ts";
import { RemoteCkbSigner } from "../src/sdk/browser/remote-ckb-signer.ts";
import { formatCkbSignature, previewFundingTransaction, signAccountGroups } from "../src/server/funding-transaction.ts";
import { previewGeneralTransaction, previewSummaryLines } from "../src/server/transaction-policy.ts";
import type { ReadyWallet } from "../src/server/user-wallet.ts";

const CKB = 100_000_000n;
const FIBER_FUNDING_LOCK = ccc.Script.from({ codeHash: "0x6c67887fe201ee0c7853f1682c0b77c0e6214044c156c7558269390a8afa6d7c", hashType: "type", args: `0x${"fd".repeat(32)}` });
const privateKey = secp256k1.utils.randomSecretKey();
const publicKey = ccc.hexFrom(secp256k1.getPublicKey(privateKey, true));
const adminListTypeArgs = `0x${"3e".repeat(32)}`;
const adminListTypeHash = adminListTypeScript({ adminListTypeArgs }).hash();
const recovery: KeyWayRecovery = {
  omnilockArgs: omnilockArgsFor(publicKey, adminListTypeHash),
  adminListTypeArgs,
  adminListTypeHash,
  adminListOutPoint: { txHash: `0x${"ad".repeat(32)}`, index: 0 },
  legacyAddress: "ckt1legacy",
  enabledAt: "2026-10-23T00:00:00.000Z",
};
const wallet = (withRecovery: boolean) => ({
  version: 1, status: "ready", litPkpId: `0x${"11".repeat(20)}`, litPublicKey: publicKey, ckbAddress: "ckt1test",
  encryptedFiberKey: "ciphertext", primaryDeviceIdHash: "a".repeat(64), hasOpenedChannel: false,
  createdAt: "2026-10-23T00:00:00.000Z", updatedAt: "2026-10-23T00:00:00.000Z",
  ...(withRecovery ? { recovery } : {}),
}) as ReadyWallet;

/** A testnet client that answers from recorded cells and never reaches the network. */
async function offlineClient(cells: ccc.CellLike[] = []): Promise<ccc.Client> {
  const client = new ccc.ClientPublicTestnet({ url: "https://testnet.ckb.dev/" });
  await client.cache.recordCells(cells);
  Object.assign(client, {
    findSingletonCellByType: async () => undefined,
    findCells: async function* () {},
  });
  return client;
}

function signWithKey(digest: ccc.Hex): ccc.Hex {
  const raw = secp256k1.sign(ccc.bytesFrom(digest), privateKey, { prehash: false, format: "recovered" });
  return formatCkbSignature({ recoveryParam: raw[0] as 0 | 1, r: ccc.hexFrom(raw.slice(1, 33)), s: ccc.hexFrom(raw.slice(33, 65)) });
}

function recoverSigner(digest: ccc.Hex, signature: ccc.BytesLike): ccc.Hex {
  const bytes = ccc.bytesFrom(signature);
  return ccc.hexFrom(secp256k1.recoverPublicKey(Uint8Array.from([bytes[64], ...bytes.slice(0, 64)]), ccc.bytesFrom(digest), { prehash: false }));
}

let nextCell = 1;
function cell(lock: ccc.Script, capacity: bigint, type?: ccc.Script, outputData: ccc.Hex = "0x"): ccc.Cell {
  return ccc.Cell.from({ outPoint: { txHash: `0x${(nextCell++).toString(16).padStart(64, "0")}`, index: 0 }, cellOutput: { lock, capacity, type }, outputData });
}

function spend(inputs: ccc.Cell[], outputs: Array<{ lock: ccc.Script; capacity: bigint; type?: ccc.Script }>, placeholder = 65) {
  return ccc.Transaction.from({
    inputs: inputs.map(({ outPoint }) => ({ previousOutput: outPoint })),
    outputs,
    outputsData: outputs.map(() => "0x"),
    witnesses: inputs.map((_, index) => index === 0 ? ccc.hexFrom(ccc.WitnessArgs.from({ lock: ccc.hexFrom(new Uint8Array(placeholder)) }).toBytes()) : "0x"),
  });
}

/** The digest of one lock group, with its first witness lock zeroed at `length` bytes. */
async function digestOf(transaction: ccc.Transaction, lock: ccc.Script, length: number, client: ccc.Client): Promise<ccc.Hex> {
  const copy = transaction.clone();
  await copy.prepareSighashAllWitness(lock, length, client);
  return (await copy.getSignHashInfo(lock, client))!.message;
}

test("the owner digest and 85-byte witness reproduce the spike's on-chain Omnilock spend", async () => {
  // Testnet transaction 0x6aeb4ddb…b326 (research/omnilock step 2), signed by throwaway key K.
  const fixture = JSON.parse(await readFile(new URL("./fixtures/omnilock-owner-spend.json", import.meta.url), "utf8"));
  const client = await offlineClient(fixture.inputCells);
  const onChain = ccc.Transaction.from(fixture.transaction);
  assert.equal(onChain.hash(), "0x6aeb4ddb970b5a35016e56296fc615ab230134c41b0935a0f5515f108783b326");
  const lock = ccc.Script.from(fixture.inputCells[0].cellOutput.lock);
  const witness = ccc.bytesFrom(onChain.witnesses[0]);
  assert.equal(witness.length, 105);
  assert.equal(ccc.hexFrom(witness.slice(0, 20)), "0x6900000010000000690000006900000055000000");
  const signature = ccc.bytesFrom(onChain.getWitnessArgsAt(0)!.lock!).slice(20);
  assert.equal(omnilockOwnerWitnessLock(signature), onChain.getWitnessArgsAt(0)!.lock);

  // The key behind the signature owns the lock: its args are 0x00 ‖ blake160(key) ‖ 0x01 ‖ AdminList type hash.
  const digest = await digestOf(onChain, lock, 85, client);
  const owner = recoverSigner(digest, signature);
  const spikeTypeHash = adminListTypeScript({ adminListTypeArgs: "0x3e4768432d91e76c3774ce0d9f23986f78e12d692aa92a4ed1712f593395ac95" }).hash();
  assert.equal(spikeTypeHash, "0x065073c8ae6940d42006cda37b1f31ed32288855f92930961fe788b196bb36d3");
  assert.equal(lock.args, omnilockArgsFor(owner, spikeTypeHash));
  assert.equal((await omnilockLock(client, { omnilockArgs: lock.args })).eq(lock), true);
  assert.equal(
    ccc.Address.fromScript(lock, client).toString(),
    "ckt1qrejnmlar3r452tcg57gvq8patctcgy8acync0hxfnyka35ywafvkqgqsa2rqnau3mns0k6lqa7l4l4rwscuny7mqyr9qu7g4e55p4pqqmx6x7clx8kny2yg2hujjvykrlnc3vvkhvmdx0k2zdy",
  );
  // A digest over a 65-byte placeholder doesn't verify, as the spike's negative check found on-chain.
  assert.notEqual(recoverSigner(await digestOf(onChain, lock, 65, client), signature), owner);

  // Signing the unsigned transaction writes exactly the on-chain witness.
  const unsigned = onChain.clone();
  unsigned.witnesses[0] = ccc.hexFrom(ccc.WitnessArgs.from({ lock: ccc.hexFrom(new Uint8Array(65)) }).toBytes());
  const signed = await signAccountGroups(unsigned, [{ script: lock, kind: "omnilock" }], client, async (message) => {
    assert.equal(message, digest);
    return ccc.hexFrom(signature);
  });
  assert.deepEqual(signed.witnesses, onChain.witnesses);
});

test("secp256k1 signing is byte-for-byte what it was", async () => {
  const secp = await secp256k1Lock(await offlineClient(), publicKey);
  const input = cell(secp, 500n * CKB);
  const client = await offlineClient([input]);
  const transaction = spend([input], [{ lock: secp, capacity: 500n * CKB - 1_000n }]);
  // The previous signer: sign CCC's digest of the client's 65-byte placeholder, then write the bare signature.
  const before = transaction.clone();
  const info = (await before.getSignHashInfo(secp, client))!;
  const witness = before.getWitnessArgsAt(info.position)!;
  witness.lock = signWithKey(info.message);
  before.setWitnessArgsAt(info.position, witness);

  const after = await signAccountGroups(transaction, [{ script: secp, kind: "secp256k1" }], client, async (digest) => signWithKey(digest));
  assert.deepEqual(after.witnesses, before.witnesses);
});

test("signs the account's secp256k1 and Omnilock groups in one transaction, each with its own witness", async () => {
  const offline = await offlineClient();
  const secp = await secp256k1Lock(offline, publicKey);
  const omni = await omnilockLock(offline, recovery);
  const legacy = cell(secp, 300n * CKB);
  const current = cell(omni, 500n * CKB);
  const client = await offlineClient([legacy, current]);
  const transaction = spend([legacy, current], [{ lock: omni, capacity: 800n * CKB - 2_000n }]);
  const signed = await signAccountGroups(transaction.clone(), [{ script: omni, kind: "omnilock" }, { script: secp, kind: "secp256k1" }], client, async (digest) => signWithKey(digest));

  const secpLock = signed.getWitnessArgsAt(0)!.lock!;
  const omniLock = signed.getWitnessArgsAt(1)!.lock!;
  assert.equal(ccc.bytesFrom(secpLock).length, 65);
  assert.equal(ccc.bytesFrom(omniLock).length, 85);
  assert.equal(omniLock.slice(0, 42), "0x5500000010000000550000005500000041000000");
  assert.equal(recoverSigner(await digestOf(signed, secp, 65, client), secpLock), publicKey);
  assert.equal(recoverSigner(await digestOf(signed, omni, 85, client), ccc.bytesFrom(omniLock).slice(20)), publicKey);
});

test("general signing treats both locks as the user's own and refuses to spend the AdminList", async () => {
  const offline = await offlineClient();
  const secp = await secp256k1Lock(offline, publicKey);
  const omni = await omnilockLock(offline, recovery);
  const alice = ccc.Script.from({ codeHash: secp.codeHash, hashType: secp.hashType, args: `0x${"22".repeat(20)}` });
  const legacy = cell(secp, 300n * CKB);
  const current = cell(omni, 500n * CKB);
  const adminList = cell(omni, 197n * CKB, adminListTypeScript(recovery), `0x00000000${"0c".repeat(32)}02`);
  const client = await offlineClient([legacy, current, adminList]);

  const sweep = await previewGeneralTransaction(wallet(true), spend([current, legacy], [{ lock: omni, capacity: 800n * CKB - 2_000n }]), client);
  assert.deepEqual(sweep.groups.map(({ kind }) => kind), ["omnilock", "secp256k1"]);
  assert.equal(sweep.script.eq(omni), true);
  assert.equal(sweep.preview.sendingCkb, "0");
  assert.equal(sweep.preview.otherSigners, 0);
  assert.deepEqual(sweep.preview.details.inputs.map(({ lock }) => lock), ["you", "you"]);
  assert.deepEqual(sweep.preview.details.outputs.map(({ lock }) => lock), ["you"]);

  const send = await previewGeneralTransaction(wallet(true), spend([current], [{ lock: alice, capacity: 100n * CKB }, { lock: omni, capacity: 400n * CKB - 1_000n }]), client);
  assert.equal(send.preview.sendingCkb, "100");
  assert.equal(send.preview.recipients.length, 1);

  // Creating the AdminList (as turning recovery on will) is shown; spending it is never signed here.
  const writes = await previewGeneralTransaction(wallet(true), spend([current], [{ lock: omni, capacity: 197n * CKB, type: adminListTypeScript(recovery) }, { lock: omni, capacity: 303n * CKB - 1_000n }]), client);
  assert.equal(writes.preview.details.outputs[0].type, "recovery list");
  assert.ok(previewSummaryLines(writes.preview).includes("Writes the account's recovery list"));
  await assert.rejects(
    previewGeneralTransaction(wallet(true), spend([current, adminList], [{ lock: omni, capacity: 697n * CKB - 1_000n }]), client),
    /recovery list/,
  );
  // Without recovery the Omnilock isn't the account's, and the secp256k1 account works as before.
  await assert.rejects(previewGeneralTransaction(wallet(false), spend([current], [{ lock: alice, capacity: 500n * CKB - 1_000n }]), client), /no input owned/);
  const plain = await previewGeneralTransaction(wallet(false), spend([legacy], [{ lock: alice, capacity: 300n * CKB - 1_000n }]), client);
  assert.deepEqual(plain.groups.map(({ kind }) => kind), ["secp256k1"]);
});

test("channel funding from an Omnilock account is signed as the user's and never spends the AdminList", async () => {
  const offline = await offlineClient();
  const omni = await omnilockLock(offline, recovery);
  const funds = cell(omni, 2_000n * CKB);
  const adminList = cell(omni, 197n * CKB, adminListTypeScript(recovery), `0x00000000${"0c".repeat(32)}02`);
  const client = await offlineClient([funds, adminList]);
  const funding = (inputs: ccc.Cell[]) => spend(inputs, [
    { lock: FIBER_FUNDING_LOCK, capacity: 1_000n * CKB },
    { lock: omni, capacity: inputs.reduce((sum, { cellOutput }) => sum + cellOutput.capacity, 0n) - 1_000n * CKB - 800n },
  ]);

  const validated = await previewFundingTransaction(wallet(true), funding([funds]), client);
  assert.deepEqual(validated.groups.map(({ kind }) => kind), ["omnilock"]);
  assert.equal(validated.preview.amountCkb, "1000");
  assert.equal(validated.preview.feeCkb, "0.000008");
  const signed = await signAccountGroups(validated.transaction, validated.groups, client, async (digest) => signWithKey(digest));
  assert.equal(ccc.bytesFrom(signed.getWitnessArgsAt(0)!.lock!).length, 85);
  assert.deepEqual(signed.cellDeps, funding([funds]).cellDeps);

  await assert.rejects(previewFundingTransaction(wallet(true), funding([funds, adminList]), client), /recovery list/);
  await assert.rejects(previewFundingTransaction(wallet(false), funding([funds]), client), /no input controlled/);
});

test("SDK signers use the account's current lock and the right placeholders", async () => {
  const offline = await offlineClient();
  const secp = await secp256k1Lock(offline, publicKey);
  const omni = await omnilockLock(offline, recovery);
  const current = cell(omni, 500n * CKB);
  const legacy = cell(secp, 300n * CKB);
  const client = await offlineClient([current, legacy]);
  const handlers = { approveCkbTransaction: () => false, approveCkbMessage: () => false, requestEmailCode: async () => undefined };
  const signer = new KeyWaySigner("token", publicKey, handlers, client, undefined, recovery);

  assert.equal((await signer.getRecommendedAddressObj()).script.eq(omni), true);
  assert.deepEqual((await signer.getAddressObjs()).map(({ script }) => script.hash()), [omni.hash(), secp.hash()]);
  assert.deepEqual((await signer.getRelatedScripts(spend([legacy, current], []))).map(({ script }) => script.hash()), [omni.hash(), secp.hash()]);
  const prepared = await signer.prepareTransaction(spend([current, legacy], [{ lock: omni, capacity: 800n * CKB - 2_000n }]));
  assert.equal(prepared.getWitnessArgsAt(0)!.lock, ccc.hexFrom(new Uint8Array(85)));
  assert.equal(prepared.getWitnessArgsAt(1)!.lock, ccc.hexFrom(new Uint8Array(65)));
  const deps = (await client.getKnownScript(ccc.KnownScript.OmniLock)).cellDeps.map(({ cellDep }) => cellDep);
  for (const dep of deps) assert.ok(prepared.cellDeps.some((included) => included.eq(dep)));

  // Without recovery the signer prepares exactly what CCC's public-key signer does.
  const plain = new KeyWaySigner("token", publicKey, handlers, client);
  assert.equal((await plain.getRecommendedAddressObj()).script.eq(secp), true);
  const unprepared = spend([legacy], [{ lock: secp, capacity: 300n * CKB - 1_000n }]);
  assert.deepEqual(
    (await plain.prepareTransaction(unprepared)).toBytes(),
    (await new ccc.SignerCkbPublicKey(client, publicKey).prepareTransaction(unprepared)).toBytes(),
  );
});

test("the funding signer only writes placeholders on Fiber's frozen transaction", async () => {
  const offline = await offlineClient();
  const secp = await secp256k1Lock(offline, publicKey);
  const omni = await omnilockLock(offline, recovery);
  const current = cell(omni, 2_000n * CKB);
  const legacy = cell(secp, 2_000n * CKB);
  const client = await offlineClient([current, legacy]);
  const fiberDep = ccc.CellDep.from({ outPoint: { txHash: `0x${"de".repeat(32)}`, index: 0 }, depType: "depGroup" });
  for (const [walletRecovery, input, length] of [[recovery, current, 85], [undefined, legacy, 65]] as const) {
    const signer = new RemoteCkbSigner("token", publicKey, () => false, client, undefined, walletRecovery);
    const frozen = spend([input], [{ lock: FIBER_FUNDING_LOCK, capacity: 1_000n * CKB }, { lock: input.cellOutput.lock, capacity: 1_000n * CKB - 800n }]);
    frozen.cellDeps.push(fiberDep);
    const prepared = await signer.prepareTransaction(frozen);
    assert.equal(prepared.hash(), frozen.hash());
    assert.deepEqual(prepared.cellDeps, [fiberDep]);
    assert.equal(prepared.getWitnessArgsAt(0)!.lock, ccc.hexFrom(new Uint8Array(length)));
  }

  // Fiber's resolver funds from the Omnilock address and gets both of its cell deps.
  const resolve = createCccExternalFundingResolver({
    signer: new RemoteCkbSigner("token", publicKey, () => false, client, undefined, recovery),
    knownScripts: FUNDING_LOCK_KNOWN_SCRIPTS,
  });
  const funding = await resolve(undefined);
  assert.equal(funding.fundingLockScript.args, omni.args);
  assert.equal(funding.shutdownScript.args, omni.args);
  assert.deepEqual(funding.fundingLockScriptCellDeps?.map(({ dep_type }) => dep_type), ["dep_group", "code"]);
});

test("the balance is the current lock's, without the AdminList", async () => {
  const offline = await offlineClient();
  const secp = await secp256k1Lock(offline, publicKey);
  const omni = await omnilockLock(offline, recovery);
  const adminList = cell(omni, 197n * CKB, adminListTypeScript(recovery));
  const client = await offlineClient();
  Object.assign(client, { findSingletonCellByType: async (type: ccc.Script) => type.eq(adminListTypeScript(recovery)) ? adminList : undefined });
  const read: string[] = [];
  const readBalance = async (script: ccc.Script) => { read.push(script.hash()); return 1_000n * CKB; };

  assert.equal(await getLockBalance(client, omni, recovery, readBalance), 803n * CKB);
  assert.equal(await getLockBalance(client, secp, undefined, readBalance), 1_000n * CKB);
  // An AdminList-looking cell under someone else's lock isn't the user's to subtract.
  assert.equal(await getLockBalance(client, secp, recovery, readBalance), 1_000n * CKB);
  assert.deepEqual(read, [omni.hash(), secp.hash(), secp.hash()]);
});

test("recovery settings must belong to the account's key", () => {
  assert.deepEqual(parseRecovery(recovery, publicKey), recovery);
  assert.equal(parseRecovery(undefined, publicKey), undefined);
  const other = ccc.hexFrom(secp256k1.getPublicKey(secp256k1.utils.randomSecretKey(), true));
  assert.throws(() => parseRecovery(recovery, other), /recovery settings are invalid/);
  assert.throws(() => parseRecovery({ ...recovery, adminListTypeHash: `0x${"00".repeat(32)}` }, publicKey), /invalid/);
  assert.throws(() => parseRecovery({ ...recovery, adminListOutPoint: undefined }, publicKey), /invalid/);
  assert.throws(() => new KeyWaySigner("token", other, { approveCkbTransaction: () => false, approveCkbMessage: () => false, requestEmailCode: async () => undefined }, undefined, undefined, recovery), /invalid/);
});
