// The policy Action (lit-actions/sign-ckb-transaction.js) run under Node with a fake Lit global, a fake
// ethers v5 SigningKey and a fake CKB RPC and email API, so its rules are checked without Lit or the network.
import assert from "node:assert/strict";
import test from "node:test";
import * as ccc from "@ckb-ccc/core";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { adminListLock, adminListTypeScript, KEYWAY_OMNILOCK, omnilockArgsFor, secp256k1Lock, type KeyWayRecovery } from "../src/sdk/browser/account-lock.ts";
import { execAuth, execPreimage, saltedBackupId, type RecoveryBackup } from "../src/sdk/browser/recovery-backups.ts";
import { backupAuths, recoveryListRecord, setRecoveryListRecord } from "../src/sdk/browser/recovery-list.ts";
import { adminListData, whitelistTree } from "../src/sdk/browser/recovery-smt.ts";
import { fakeLit, litCodeIn, type ActionModule } from "./lit-action-fixture.ts";
import { litBackupIds, policyIdentitySignature, policySendCode, policySignMessage, policySignTransaction, setEmailBinding } from "../src/server/lit-policy.ts";
import { planBackupChange, planRecovery } from "../src/server/recovery.ts";
import type { ReadyWallet } from "../src/server/user-wallet.ts";
import { recoverPkpPublicKey } from "../src/server/pkp-identity.ts";

process.env.LIT_USAGE_API_KEY ??= "test-usage-key";
process.env.LIT_EMAIL_API_KEY ??= "re_test_sending_key";

const CKB = 100_000_000n;
const privateKey = secp256k1.utils.randomSecretKey();
const publicKey = ccc.hexFrom(secp256k1.getPublicKey(privateKey, true));
const pkpId = ccc.hexFrom(keccak_256(secp256k1.getPublicKey(privateKey, false).slice(1)).slice(12));
const actionKey = secp256k1.utils.randomSecretKey();
const evm = (seed: number): RecoveryBackup => ({ kind: "evm", address: ccc.hexFrom(keccak_256(Uint8Array.of(seed)).slice(12)) });

const hex = (bytes: Uint8Array) => ccc.hexFrom(bytes);

/** A fake chain for this test's key, with the transactions given known as committed. */
function world(transactions: ccc.Transaction[] = []) {
  const known = new Map<string, { tx: ccc.Transaction; status: string }>();
  const add = (tx: ccc.Transaction, status = "committed") => known.set(tx.hash(), { tx, status });
  transactions.forEach((tx) => add(tx));
  const lit = fakeLit({ privateKey, pkpId, actionKey, lookup: (hash) => known.get(hash), transactions: () => [...known.values()].map(({ tx }) => tx) });
  return { ...lit, add };
}

const loadAction = (env: ReturnType<typeof world>) => env.load();
const runner = (action: ActionModule) => async (_config: unknown, params: Record<string, unknown>) => action.main(params);
const codeIn = litCodeIn;
const wallet = { litPkpId: pkpId, litPublicKey: publicKey };

const walletFor = (recovery?: KeyWayRecovery) => ({
  version: 1, status: "ready", litPkpId: pkpId, litPublicKey: publicKey, ckbAddress: "ckt1test",
  encryptedFiberKey: "ciphertext", primaryDeviceIdHash: "a".repeat(64), hasOpenedChannel: false,
  createdAt: "2026-10-28T00:00:00.000Z", updatedAt: "2026-10-28T00:00:00.000Z", ...(recovery ? { recovery } : {}),
}) as ReadyWallet;

/** A testnet client that answers from recorded transactions' outputs and never reaches the network. */
async function offlineClient(transactions: ccc.Transaction[], spent: string[] = []): Promise<ccc.Client> {
  const client = new ccc.ClientPublicTestnet({ url: "https://testnet.ckb.dev/" });
  const cells = transactions.flatMap((tx) => tx.outputs.map((cellOutput, index) => ccc.Cell.from({ outPoint: { txHash: tx.hash(), index }, cellOutput, outputData: tx.outputsData[index] })));
  await client.cache.recordCells(cells);
  const live = cells.filter((cell) => !spent.includes(`${cell.outPoint.txHash}:${cell.outPoint.index}`));
  Object.assign(client, {
    findSingletonCellByType: async (type: ccc.ScriptLike) => live.find((cell) => cell.cellOutput.type?.eq(ccc.Script.from(type))),
    getTransaction: async (hash: ccc.HexLike) => {
      const transaction = transactions.find((candidate) => candidate.hash() === ccc.hexFrom(hash));
      return transaction ? { transaction, status: "committed" } : undefined;
    },
    findCells: async function* () {},
    findCellsByLock: async function* (lock: ccc.ScriptLike) {
      for (const cell of live) if (cell.cellOutput.lock.eq(ccc.Script.from(lock))) yield cell;
    },
  });
  return client;
}

let seed = 1;
async function funded() {
  const client = await offlineClient([]);
  const secp = await secp256k1Lock(client, publicKey);
  const funding = ccc.Transaction.from({
    inputs: [{ previousOutput: { txHash: `0x${(seed++).toString(16).padStart(64, "0")}`, index: 0 } }],
    outputs: [{ lock: secp, capacity: 1_000n * CKB }, { lock: secp, capacity: 300n * CKB }],
    outputsData: ["0x", "0x"],
  });
  return { funding, secp, client: await offlineClient([funding]) };
}

/** Turns recovery on through the Action and returns the signed enabling transaction and its settings. */
async function enableWithPolicy(backups: RecoveryBackup[], email = "user@example.com") {
  const { funding, client } = await funded();
  const env = world([funding]);
  const action = await loadAction(env);
  const plan = await planRecovery(client, walletFor(), backups, { emailBinding: true });
  const sent = await policySendCode(plan.transaction, wallet, { email, appName: "Demo", backups, client }, runner(action));
  setEmailBinding(plan.transaction, sent.binding!);
  const signed = await policySignTransaction(plan.transaction, [{ script: plan.secp, kind: "secp256k1" }], client, wallet, { email, emailCode: { code: codeIn(env.emails[0]), ticket: sent.ticket }, backups }, runner(action));
  const recovery: KeyWayRecovery = {
    omnilockArgs: plan.omnilock.args, omnilock: KEYWAY_OMNILOCK.testnet, adminListTypeArgs: plan.adminListType.args, adminListTypeHash: plan.adminListType.hash(),
    adminListOutPoint: { txHash: signed.hash(), index: 0 }, enableTransactionHash: signed.hash(), legacyAddress: plan.preview.legacyAddress,
    enabledAt: "2026-11-06T00:00:00.000Z", backups, litEmailBound: true,
  };
  return { funding, signed, recovery, plan, env };
}

test("the Action's blake2b, transaction hash and SMT root match CCC and the SDK", async () => {
  const action = await loadAction(world());
  for (const length of [0, 1, 55, 127, 128, 129, 256, 1000]) {
    const data = Uint8Array.from({ length }, (_, i) => (i * 31 + length) & 0xff);
    assert.equal(hex(action.ckbHash(data)), ccc.hashCkb(data), `length ${length}`);
  }
  const { funding } = await funded();
  const tx = ccc.Transaction.from({
    cellDeps: [{ outPoint: { txHash: `0x${"ab".repeat(32)}`, index: 3 }, depType: "depGroup" }, { outPoint: { txHash: `0x${"cd".repeat(32)}`, index: 0 }, depType: "code" }],
    headerDeps: [`0x${"ef".repeat(32)}`],
    inputs: [{ previousOutput: { txHash: funding.hash(), index: 1 }, since: 0x1234n }],
    outputs: [funding.outputs[0], { lock: funding.outputs[0].lock, type: adminListTypeScript({ adminListTypeArgs: "0x01" }), capacity: 200n * CKB }],
    outputsData: ["0x", "0x0102"],
  });
  assert.equal(hex(action.rawTransactionHash(action.parseTransaction(JSON.parse(ccc.stringify(tx))))), tx.hash());
  const backups = [evm(1), evm(2), evm(3)];
  const client = await offlineClient([]);
  const salt = `0x${"5a".repeat(32)}`;
  const auths = await backupAuths(client, backups, salt);
  const { root } = whitelistTree(auths);
  assert.equal(hex(action.whitelistRoot(action.parseListRecord(ccc.bytesFrom(recoveryListRecord(auths))))), root);
});

test("identity and message modes sign only what the Action hashes itself; there is no raw digest mode", async () => {
  const action = await loadAction(world());
  const identity = await policyIdentitySignature(pkpId, runner(action));
  const digest = sha256(new TextEncoder().encode("CKB KeyWay identity v1"));
  assert.equal(hex(recoverPkpPublicKey(digest, identity)), publicKey);
  const signature = await policySignMessage(wallet, "hello", runner(action));
  assert.ok(ccc.verifyMessageCkbSecp256k1("hello", signature, publicKey));
  await assert.rejects(action.main({ mode: "digest", pkpId, digest: `0x${"11".repeat(32)}` }), /mode must be/);
  await assert.rejects(action.main({ pkpId, digest: `0x${"11".repeat(32)}` }), /mode must be/);
});

test("signs a plain transaction from the chain's own input cells and refuses unprepared witnesses or foreign inputs", async () => {
  const { funding, secp, client } = await funded();
  const env = world([funding]);
  const action = await loadAction(env);
  const tx = ccc.Transaction.from({
    inputs: [{ previousOutput: { txHash: funding.hash(), index: 0 } }],
    outputs: [{ lock: ccc.Script.from({ codeHash: `0x${"99".repeat(32)}`, hashType: "type", args: "0x" }), capacity: 900n * CKB }],
    outputsData: ["0x"],
  });
  await tx.addCellDepsOfKnownScripts(client, ccc.KnownScript.Secp256k1Blake160);
  const signed = await policySignTransaction(tx.clone(), [{ script: secp, kind: "secp256k1" }], client, wallet, {}, runner(action));
  assert.equal(ccc.bytesFrom(signed.getWitnessArgsAt(0)!.lock!).length, 65);
  // Witness not zeroed at its final length: the digest wouldn't be the one the chain checks.
  const unprepared = tx.clone();
  unprepared.witnesses = [ccc.hexFrom(ccc.WitnessArgs.from({ lock: "0x01" }).toBytes())];
  await assert.rejects(action.main({ mode: "transaction", pkpId, transaction: JSON.parse(ccc.stringify(unprepared)) }), /witness isn't prepared/);
  // An input the chain doesn't know can't be signed for; neither can a transaction with nothing of the account's.
  const unknown = tx.clone();
  unknown.inputs[0].previousOutput.txHash = `0x${"42".repeat(32)}`;
  await assert.rejects(action.main({ mode: "transaction", pkpId, transaction: JSON.parse(ccc.stringify(unknown)) }), /isn't on chain/);
  const foreign = ccc.Transaction.from({ inputs: [], outputs: [{ lock: ccc.Script.from({ codeHash: `0x${"98".repeat(32)}`, hashType: "type", args: "0x" }), capacity: 100n * CKB }], outputsData: ["0x"] });
  env.add(foreign);
  const other = ccc.Transaction.from({ inputs: [{ previousOutput: { txHash: foreign.hash(), index: 0 } }], outputs: [], outputsData: [] });
  other.witnesses = [ccc.hexFrom(ccc.WitnessArgs.from({ lock: ccc.hexFrom(new Uint8Array(65)) }).toBytes())];
  await assert.rejects(action.main({ mode: "transaction", pkpId, transaction: JSON.parse(ccc.stringify(other)) }), /spends nothing of this account's/);
});

test("turning recovery on needs the code the Action emailed, to the address bound in the transaction", async () => {
  const { funding, client } = await funded();
  const env = world([funding]);
  const action = await loadAction(env);
  const backups = [evm(4)];
  const plan = await planRecovery(client, walletFor(), backups, { emailBinding: true });
  const groups = [{ script: plan.secp, kind: "secp256k1" as const }];
  const sign = (transaction: ccc.Transaction, emailCode?: { code: string; ticket: string }) =>
    policySignTransaction(transaction.clone(), groups, client, wallet, { email: "user@example.com", backups, ...(emailCode ? { emailCode } : {}) }, runner(action));

  // Without a binding (only its zero placeholder) or a code it refuses.
  await assert.rejects(sign(plan.transaction), /email binding is malformed/);
  const unbound = plan.transaction.clone();
  const w0 = unbound.getWitnessArgsAt(0)!;
  w0.inputType = undefined;
  unbound.setWitnessArgsAt(0, w0);
  await assert.rejects(sign(unbound), /must bind the account's email/);
  const sent = await policySendCode(plan.transaction, wallet, { email: "user@example.com", appName: "Demo", backups, client }, runner(action));
  assert.equal(env.emails.length, 1);
  assert.deepEqual(env.emails[0].to, ["user@example.com"]);
  assert.equal(env.emails[0].from, "CKB KeyWay <security@auth.ckbkeyway.dev>");
  assert.match(env.emails[0].text, /Turn on account recovery[\s\S]*Backup: EVM wallet 0x/);
  const code = codeIn(env.emails[0]);
  const bound = plan.transaction.clone();
  setEmailBinding(bound, sent.binding!);
  await assert.rejects(sign(bound), /eight-digit code/);
  await assert.rejects(sign(bound, { code: code === "00000000" ? "00000001" : "00000000", ticket: sent.ticket }), /isn't right/);
  // A binding for another address isn't this account's address, and the code is for this transaction only.
  const other = await policySendCode(plan.transaction, wallet, { email: "attacker@example.com", appName: "Demo", backups, client }, runner(action));
  const swapped = plan.transaction.clone();
  setEmailBinding(swapped, other.binding!);
  await assert.rejects(sign(swapped, { code, ticket: sent.ticket }), /isn't the email address bound/);
  const changed = bound.clone();
  changed.outputs[changed.outputs.length - 1].capacity -= 1n;
  await assert.rejects(sign(changed, { code, ticket: sent.ticket }), /isn't right/);
  // An expired or far-future ticket is refused.
  await assert.rejects(sign(bound, { code, ticket: `v1.${Date.now() - 1}.${"0".repeat(32)}` }), /expired/);
  await assert.rejects(sign(bound, { code, ticket: `v1.${Date.now() + 3_600_000}.${"0".repeat(32)}` }), /ticket is invalid/);
  const signed = await sign(bound, { code, ticket: sent.ticket });
  assert.equal(signed.hash(), plan.transaction.hash());
});

test("the enabling transaction carries only a 37-byte fingerprint of the email, never the address", async () => {
  const email = "Private.Person@example.com";
  const { signed } = await enableWithPolicy([evm(60)], email);
  const binding = ccc.bytesFrom(signed.getWitnessArgsAt(0)!.inputType!);
  assert.equal(binding.length, 37);
  assert.equal(ccc.hexFrom(binding.slice(0, 5)), "0x4b57454202");
  const bytes = signed.toBytes();
  const contains = (needle: Uint8Array) => {
    outer: for (let i = 0; i + needle.length <= bytes.length; i++) {
      for (let j = 0; j < needle.length; j++) if (bytes[i + j] !== needle[j]) continue outer;
      return true;
    }
    return false;
  };
  for (const form of [email, email.toLowerCase(), "example.com", "private.person"]) {
    assert.equal(contains(new TextEncoder().encode(form)), false, `the transaction holds "${form}"`);
  }
});

test("an email's fingerprint differs per account and survives a new version of the Action", async () => {
  const email = "user@example.com";
  const action = await loadAction(world());
  const mine = await action.emailFingerprint(pkpId, email);
  assert.equal(mine.length, 32);
  assert.equal(hex(await action.emailFingerprint(pkpId, "USER@example.com")), hex(mine));
  assert.notEqual(hex(await action.emailFingerprint(pkpId, "other@example.com")), hex(mine));
  // Another account with the same email gets an unrelated fingerprint, so the chain can't link the two.
  const otherKey = secp256k1.utils.randomSecretKey();
  const otherPkp = ccc.hexFrom(keccak_256(secp256k1.getPublicKey(otherKey, false).slice(1)).slice(12));
  const other = await fakeLit({ privateKey: otherKey, pkpId: otherPkp, actionKey, lookup: () => undefined, transactions: () => [] }).load();
  assert.notEqual(hex(await other.emailFingerprint(otherPkp, email)), hex(mine));
  // A later Action (a new CID, so a new action key) still computes the same fingerprint for this account.
  const upgraded = await fakeLit({ privateKey, pkpId, actionKey: secp256k1.utils.randomSecretKey(), lookup: () => undefined, transactions: () => [] }).load();
  assert.equal(hex(await upgraded.emailFingerprint(pkpId, email)), hex(mine));
});

test("a bound account's backup change needs the Action's code, sent to the bound address, never one the server picks", async () => {
  const backups = [evm(5)];
  const { funding, signed: enable, recovery, env } = await enableWithPolicy(backups);
  env.add(enable);
  const action = await loadAction(env);
  const client = await offlineClient([funding, enable], [`${funding.hash()}:0`, `${funding.hash()}:1`]);
  const plan = await planBackupChange(client, walletFor(recovery), { change: "add", backup: evm(6) });
  const groups = [{ script: plan.listLock, kind: "omnilock" as const }, { script: plan.omnilock, kind: "omnilock" as const }];
  const all = [...backups, evm(6)];
  const sign = (transaction: ccc.Transaction, emailCode?: { code: string; ticket: string }, enableTransactionHash = recovery.enableTransactionHash) =>
    policySignTransaction(transaction.clone(), groups, client, wallet, { enableTransactionHash, email: "user@example.com", backups: all, ...(emailCode ? { emailCode } : {}) }, runner(action));

  await assert.rejects(sign(plan.transaction), /eight-digit code/);
  await assert.rejects(sign(plan.transaction, undefined, funding.hash()), /isn't the transaction that made this recovery list/);
  // A code for a wrong address isn't accepted either: signing needs the bound address too.
  await assert.rejects(policySignTransaction(plan.transaction.clone(), groups, client, wallet, { enableTransactionHash: recovery.enableTransactionHash, email: "attacker@example.com", backups: all, emailCode: { code: "00000000", ticket: `v1.${Date.now() + 60_000}.${"0".repeat(32)}` } }, runner(action)), /isn't the email address bound/);
  const before = env.emails.length;
  // The server can't redirect the code: an address whose fingerprint isn't the one bound on chain gets nothing.
  await assert.rejects(policySendCode(plan.transaction, wallet, { enableTransactionHash: recovery.enableTransactionHash, email: "attacker@example.com", appName: "Demo", backups: all, client }, runner(action)), /isn't the email address bound/);
  assert.equal(env.emails.length, before);
  // Case doesn't matter: the fingerprint is of the lowercased address.
  const sent = await policySendCode(plan.transaction, wallet, { enableTransactionHash: recovery.enableTransactionHash, email: "User@Example.com", appName: "Demo", backups: all, client }, runner(action));
  assert.equal(sent.sentTo.toLowerCase(), "user@example.com");
  const email = env.emails[before];
  assert.equal(email.to.length, 1);
  assert.equal(email.to[0].toLowerCase(), "user@example.com");
  assert.match(email.text, /Add a recovery backup in Demo\n\nAdding: EVM wallet 0x/);
  const signed = await sign(plan.transaction, { code: codeIn(email), ticket: sent.ticket });
  assert.equal(signed.hash(), plan.transaction.hash());
});

test("the Action refuses moving, retyping, destroying or rewriting the recovery list, whatever code is given", async () => {
  const { funding, signed: enable, recovery, env, plan: enablePlan } = await enableWithPolicy([evm(7), evm(8)]);
  env.add(enable);
  const action = await loadAction(env);
  const client = await offlineClient([funding, enable], [`${funding.hash()}:0`, `${funding.hash()}:1`]);
  const plan = await planBackupChange(client, walletFor(recovery), { change: "add", backup: evm(9) });
  const ids = await litBackupIds(client, [evm(7), evm(8), evm(9), evm(10)]);
  const attempt = (mutate: (tx: ccc.Transaction) => void | Promise<void>) => async () => {
    const tx = plan.transaction.clone();
    await mutate(tx);
    return action.main({ mode: "transaction", pkpId, transaction: JSON.parse(ccc.stringify(tx)), enableTransactionHash: recovery.enableTransactionHash, email: "user@example.com", backups: ids });
  };
  await assert.rejects(attempt((tx) => { tx.outputs[0].lock = enablePlan.secp; }), /lock can't change/);
  await assert.rejects(attempt((tx) => { tx.outputs[0].type = adminListTypeScript({ adminListTypeArgs: `0x${"12".repeat(32)}` }); }), /Type ID can't change|can't be destroyed/);
  await assert.rejects(attempt((tx) => { tx.outputs[0].type = undefined; tx.outputs[0].lock = enablePlan.omnilock; }), /can't be destroyed/);
  await assert.rejects(attempt((tx) => { tx.outputs[0].capacity -= CKB; tx.outputs[1].capacity += CKB; }), /capacity can't change/);
  await assert.rejects(attempt(async (tx) => {
    // Two new backups at once.
    const auths = await backupAuths(client, [evm(7), evm(8), evm(9), evm(10)], recovery.adminListTypeHash);
    tx.outputsData[0] = adminListData(whitelistTree(auths).root);
    setRecoveryListRecord(tx, 0, recoveryListRecord(auths));
  }), /exactly one backup/);
  await assert.rejects(attempt((tx) => {
    // A second list output under the owner-only lock.
    tx.outputs.push(ccc.CellOutput.from({ lock: adminListLock(recovery), type: adminListTypeScript(recovery), capacity: 200n * CKB }));
    tx.outputsData.push(tx.outputsData[0]);
  }), /only one recovery list/);
  await assert.rejects(attempt((tx) => { tx.outputsData[0] = adminListData(`0x${"34".repeat(32)}`); }), /don't match the recovery list's root/);
  // Adding one auth that isn't a KeyWay backup of this account: the new backup under another salt, or under the
  // verifier from before backup unlinking.
  const current = await backupAuths(client, [evm(7), evm(8)], recovery.adminListTypeHash);
  const added = (auth: ccc.Hex) => (tx: ccc.Transaction) => {
    tx.outputsData[0] = adminListData(whitelistTree([...current, auth]).root);
    setRecoveryListRecord(tx, 0, recoveryListRecord([...current, auth]));
  };
  const [otherSalt] = await backupAuths(client, [evm(9)], `0x${"66".repeat(32)}`);
  await assert.rejects(attempt(added(otherSalt)), /names a backup KeyWay doesn't support/);
  const oldVerifier = execAuth(execPreimage("0x33bd1c699b633d685a6f60f6b0ca16fe8bb896f81323926ca6e0671bf8ab3c88", saltedBackupId(evm(9).address, recovery.adminListTypeHash)));
  await assert.rejects(attempt(added(oldVerifier)), /names a backup KeyWay doesn't support/);
  // The true change, but the caller leaves out the backup being added.
  await assert.rejects(action.main({ mode: "transaction", pkpId, transaction: JSON.parse(ccc.stringify(plan.transaction)), enableTransactionHash: recovery.enableTransactionHash, email: "user@example.com", backups: ids.slice(0, 2) }), /names a backup KeyWay doesn't support/);
});

test("an account that turned recovery on before the policy Action keeps its server checks and the list rules, no code", async () => {
  const backups = [evm(11)];
  const { funding, client } = await funded();
  const plan = await planRecovery(client, walletFor(), backups, { emailBinding: false });
  // Signed the old way: a raw digest signature, with no email binding in witness 0.
  const signed = plan.transaction.clone();
  await signed.prepareSighashAllWitness(plan.secp, 65, client);
  const digest = (await signed.getSignHashInfo(plan.secp, client))!.message;
  const raw = secp256k1.sign(ccc.bytesFrom(digest), privateKey, { prehash: false, format: "recovered" } as never) as Uint8Array;
  const witness = signed.getWitnessArgsAt(0)!;
  witness.lock = ccc.hexFrom(Uint8Array.from([...raw.slice(1), raw[0]]));
  signed.setWitnessArgsAt(0, witness);
  const env = world([funding, signed]);
  const action = await loadAction(env);
  const recovery: KeyWayRecovery = {
    omnilockArgs: plan.omnilock.args, omnilock: KEYWAY_OMNILOCK.testnet, adminListTypeArgs: plan.adminListType.args, adminListTypeHash: plan.adminListType.hash(),
    adminListOutPoint: { txHash: signed.hash(), index: 0 }, enableTransactionHash: signed.hash(), legacyAddress: plan.preview.legacyAddress, enabledAt: "2026-10-01T00:00:00.000Z", backups,
  };
  const listClient = await offlineClient([funding, signed], [`${funding.hash()}:0`, `${funding.hash()}:1`]);
  const change = await planBackupChange(listClient, walletFor(recovery), { change: "add", backup: evm(12) });
  const groups = [{ script: change.listLock, kind: "omnilock" as const }, { script: change.omnilock, kind: "omnilock" as const }];
  const all = [...backups, evm(12)];
  const result = await policySignTransaction(change.transaction.clone(), groups, listClient, wallet, { enableTransactionHash: recovery.enableTransactionHash, backups: all }, runner(action));
  assert.equal(result.hash(), change.transaction.hash());
  await assert.rejects(action.main({ mode: "send-code", pkpId, transaction: JSON.parse(ccc.stringify(change.transaction)), enableTransactionHash: recovery.enableTransactionHash, backups: await litBackupIds(listClient, all), emailApiKey: "re_test_sending_key" }), /doesn't need an email code/);
});

test("a key with a recovery list can't make a second one, or move funds to an address naming another list", async () => {
  const { funding, signed: enable, recovery, env, plan: enablePlan } = await enableWithPolicy([evm(13)]);
  env.add(enable);
  const action = await loadAction(env);
  // Someone pays the old secp256k1 address again; the server tries to turn recovery on a second time, with its
  // own backup and its own address for the code.
  const refund = ccc.Transaction.from({
    inputs: [{ previousOutput: { txHash: `0x${(seed++).toString(16).padStart(64, "0")}`, index: 0 } }],
    outputs: [{ lock: enablePlan.secp, capacity: 1_000n * CKB }],
    outputsData: ["0x"],
  });
  env.add(refund);
  const client = await offlineClient([funding, enable, refund], [`${funding.hash()}:0`, `${funding.hash()}:1`]);
  const second = await planRecovery(client, walletFor(), [evm(14)], { emailBinding: true });
  await assert.rejects(policySendCode(second.transaction, wallet, { email: "attacker@example.com", appName: "Demo", backups: [evm(14)], client }, runner(action)), /already on for this key/);

  // Moving the account's funds to an Omnilock of the same key that names another list is refused; to its own
  // address it is fine.
  const omnilockCell = enable.outputs.findIndex((output) => output.lock.eq(enablePlan.omnilock));
  const spend = (lock: ccc.Script) => {
    const tx = ccc.Transaction.from({
      inputs: [{ previousOutput: { txHash: enable.hash(), index: omnilockCell } }],
      outputs: [{ lock, capacity: enable.outputs[omnilockCell].capacity - 100_000n }],
      outputsData: ["0x"],
      witnesses: [ccc.hexFrom(ccc.WitnessArgs.from({ lock: ccc.hexFrom(new Uint8Array(85)) }).toBytes())],
    });
    return action.main({ mode: "transaction", pkpId, transaction: JSON.parse(ccc.stringify(tx)) });
  };
  const foreign = ccc.Script.from({ ...enablePlan.omnilock, args: ccc.hexFrom(ccc.bytesConcat(ccc.bytesFrom(enablePlan.omnilock.args).slice(0, 22), second.adminListType.hash())) });
  await assert.rejects(spend(foreign), /another recovery list/);
  const ok = await spend(enablePlan.omnilock) as { operation: string };
  assert.equal(ok.operation, "plain");
  assert.ok(recovery.litEmailBound);
});

test("cells under longer lock args (which the indexer's prefix search would return) block neither an enable nor a send", async () => {
  const { funding, client } = await funded();
  const env = world([funding]);
  const action = await loadAction(env);
  const backups = [evm(31)];
  const plan = await planRecovery(client, walletFor(), backups, { emailBinding: true });
  const longer = (lock: ccc.Script) => ccc.Script.from({ ...lock, args: ccc.hexFrom(ccc.bytesConcat(ccc.bytesFrom(lock.args), [0])) });
  const listLock = plan.transaction.outputs[0].lock;
  // Unspendable cells an outsider plants: a "plain cell" at the secp256k1 code hash with 21-byte args, and a Type ID
  // cell under the list lock's args plus one byte.
  env.add(ccc.Transaction.from({
    inputs: [],
    outputs: [{ lock: longer(plan.secp), capacity: 62n * CKB }, { lock: longer(listLock), type: adminListTypeScript({ adminListTypeArgs: `0x${"ab".repeat(32)}` }), capacity: 170n * CKB }],
    outputsData: ["0x", adminListData(`0x${"cd".repeat(32)}`)],
  }));
  const sent = await policySendCode(plan.transaction, wallet, { email: "user@example.com", appName: "Demo", backups, client }, runner(action));
  setEmailBinding(plan.transaction, sent.binding!);
  const enable = await policySignTransaction(plan.transaction, [{ script: plan.secp, kind: "secp256k1" }], client, wallet, { email: "user@example.com", emailCode: { code: codeIn(env.emails[0]), ticket: sent.ticket }, backups }, runner(action));
  env.add(enable);
  // An ordinary send from the new address, with change to it, still signs.
  const index = enable.outputs.findIndex((output) => output.lock.eq(plan.omnilock));
  const spend = ccc.Transaction.from({
    inputs: [{ previousOutput: { txHash: enable.hash(), index } }],
    outputs: [{ lock: plan.omnilock, capacity: enable.outputs[index].capacity - 100_000n }],
    outputsData: ["0x"],
    witnesses: [ccc.hexFrom(ccc.WitnessArgs.from({ lock: ccc.hexFrom(new Uint8Array(85)) }).toBytes())],
  });
  const result = await action.main({ mode: "transaction", pkpId, transaction: JSON.parse(ccc.stringify(spend)) }) as { operation: string };
  assert.equal(result.operation, "plain");
});

test("a backup change must spend the recovery list as input 0", async () => {
  const backups = [evm(32)];
  const { funding, signed: enable, recovery, env } = await enableWithPolicy(backups);
  env.add(enable);
  const action = await loadAction(env);
  const client = await offlineClient([funding, enable], [`${funding.hash()}:0`, `${funding.hash()}:1`]);
  const plan = await planBackupChange(client, walletFor(recovery), { change: "add", backup: evm(33) });
  const swapped = plan.transaction.clone();
  swapped.inputs.reverse();
  await assert.rejects(action.main({ mode: "transaction", pkpId, transaction: JSON.parse(ccc.stringify(swapped)), enableTransactionHash: recovery.enableTransactionHash, email: "user@example.com", backups: await litBackupIds(client, [...backups, evm(33)]) }), /must be input 0/);
});

test("a cell anyone sends to the list lock doesn't count as a list, and an enable must spend every plain cell", async () => {
  const { funding, client } = await funded();
  const env = world([funding]);
  const action = await loadAction(env);
  const plan = await planRecovery(client, walletFor(), [evm(15)], { emailBinding: true });
  // An outsider creates a Type ID cell under the key's list lock from their own cell.
  const outsider = ccc.Transaction.from({ inputs: [], outputs: [{ lock: ccc.Script.from({ codeHash: `0x${"97".repeat(32)}`, hashType: "type", args: "0x" }), capacity: 500n * CKB }], outputsData: ["0x"] });
  env.add(outsider);
  const forged = ccc.Transaction.from({
    inputs: [{ previousOutput: { txHash: outsider.hash(), index: 0 } }],
    outputs: [{ lock: plan.transaction.outputs[0].lock, type: adminListTypeScript({ adminListTypeArgs: `0x${"56".repeat(32)}` }), capacity: 200n * CKB }],
    outputsData: [adminListData(`0x${"78".repeat(32)}`)],
  });
  env.add(forged);
  // Another made by spending an Omnilock with this key's auth but the attacker's own list, which their own backup
  // can unlock: still not a list of this key's.
  const attackerOmnilock = ccc.Script.from({ ...plan.omnilock, args: ccc.hexFrom(ccc.bytesConcat(ccc.bytesFrom(plan.omnilock.args).slice(0, 22), `0x${"9a".repeat(32)}`)) });
  const paid = ccc.Transaction.from({ inputs: [], outputs: [{ lock: attackerOmnilock, capacity: 500n * CKB }], outputsData: ["0x"] });
  env.add(paid);
  env.add(ccc.Transaction.from({
    inputs: [{ previousOutput: { txHash: paid.hash(), index: 0 } }],
    outputs: [{ lock: plan.transaction.outputs[0].lock, type: adminListTypeScript({ adminListTypeArgs: `0x${"bc".repeat(32)}` }), capacity: 200n * CKB }],
    outputsData: [adminListData(`0x${"de".repeat(32)}`)],
  }));
  // Plain cells sent to the list lock aren't even looked at, however many there are.
  env.add(ccc.Transaction.from({ inputs: [], outputs: Array.from({ length: 300 }, () => ({ lock: plan.transaction.outputs[0].lock, capacity: 70n * CKB })), outputsData: Array.from({ length: 300 }, () => "0x") }));
  const sent = await policySendCode(plan.transaction, wallet, { email: "user@example.com", appName: "Demo", backups: [evm(15)], client }, runner(action));
  assert.ok(sent.ticket);
  // A new plain cell at the secp256k1 address that the enable leaves out: refused.
  const extra = ccc.Transaction.from({ inputs: [], outputs: [{ lock: plan.secp, capacity: 100n * CKB }], outputsData: ["0x"] });
  env.add(extra);
  await assert.rejects(policySendCode(plan.transaction, wallet, { email: "user@example.com", appName: "Demo", backups: [evm(15)], client }, runner(action)), /spend every plain cell/);
});

test("an enable that commits between the Action's two chain reads can't let a second enable through", async () => {
  // Enable A is signed and broadcast; a new plain cell arrives at the key's address; then enable B, spending only
  // that new cell, is checked, and A commits while the Action is between its reads of the chain.
  const { funding, signed: enableA, plan: planA } = await enableWithPolicy([evm(40)]);
  const fresh = ccc.Transaction.from({
    inputs: [{ previousOutput: { txHash: `0x${(seed++).toString(16).padStart(64, "0")}`, index: 0 } }],
    outputs: [{ lock: planA.secp, capacity: 1_000n * CKB }],
    outputsData: ["0x"],
  });
  const known = new Map<string, { tx: ccc.Transaction; status: string }>([funding, fresh].map((tx) => [tx.hash(), { tx, status: "committed" }]));
  let reads = 0;
  const env = fakeLit({
    privateKey, pkpId, actionKey,
    lookup: (hash) => known.get(hash),
    transactions: () => {
      const snapshot = [...known.values()].map(({ tx }) => tx);
      if (++reads === 1) known.set(enableA.hash(), { tx: enableA, status: "committed" });
      return snapshot;
    },
  });
  const action = await env.load();
  const client = await offlineClient([funding, enableA, fresh], [`${funding.hash()}:0`, `${funding.hash()}:1`]);
  const planB = await planRecovery(client, walletFor(), [evm(41)], { emailBinding: true });
  assert.deepEqual(planB.transaction.inputs.map((input) => input.previousOutput.txHash), [fresh.hash()]);
  await assert.rejects(
    policySendCode(planB.transaction, wallet, { email: "attacker@example.com", appName: "Demo", backups: [evm(41)], client }, runner(action)),
    /spend every plain cell|already on for this key/,
  );
  assert.equal(env.emails.length, 0);
});

test("two enables from typed cells at an address with no plain cells are refused, so they can't both commit", async () => {
  // Anyone can send typed cells to the key's address. Without the plain input 0 rule, two enables each spending one
  // of them conflict on nothing, and with no plain cell to spend, both would pass and both commit.
  const client0 = await offlineClient([]);
  const secp = await secp256k1Lock(client0, publicKey);
  const gift = ccc.Transaction.from({
    inputs: [{ previousOutput: { txHash: `0x${(seed++).toString(16).padStart(64, "0")}`, index: 0 } }],
    outputs: [0, 1].map(() => ({ lock: secp, type: ccc.Script.from({ codeHash: `0x${"77".repeat(32)}`, hashType: "type", args: "0x" }), capacity: 1_000n * CKB })),
    outputsData: ["0x", "0x"],
  });
  const env = world([gift]);
  const action = await loadAction(env);
  const { client: planClient } = await funded();
  const base = await planRecovery(planClient, walletFor(), [evm(42)], { emailBinding: true });
  const fromTyped = async (index: number) => {
    const tx = base.transaction.clone();
    tx.inputs = [ccc.CellInput.from({ previousOutput: { txHash: gift.hash(), index } })];
    tx.witnesses = [tx.witnesses[0]];
    const type = adminListTypeScript({ adminListTypeArgs: ccc.hashTypeId(tx.inputs[0], 0) });
    const auths = await backupAuths(planClient, [evm(42)], type.hash());
    tx.outputs[0].type = type;
    tx.outputsData[0] = adminListData(whitelistTree(auths).root);
    setRecoveryListRecord(tx, 0, recoveryListRecord(auths));
    const omnilockArgs = omnilockArgsFor(publicKey, type.hash());
    tx.outputs[0].lock = adminListLock({ omnilock: KEYWAY_OMNILOCK.testnet, omnilockArgs });
    tx.outputs[tx.outputs.length - 1].lock = ccc.Script.from({ ...base.omnilock, args: omnilockArgs });
    return action.main({ mode: "send-code", pkpId, transaction: JSON.parse(ccc.stringify(tx)), email: "user@example.com", backups: await litBackupIds(planClient, [evm(42)]), emailApiKey: "re_test_sending_key" });
  };
  await assert.rejects(fromTyped(0), /plain CKB cell/);
  await assert.rejects(fromTyped(1), /plain CKB cell/);
  assert.equal(env.emails.length, 0);
});

test("a key's live list blocks a second enable without fetching its transactions, and a failed history read refuses", async () => {
  const { funding, signed: enable, plan } = await enableWithPolicy([evm(43)]);
  const refund = ccc.Transaction.from({
    inputs: [{ previousOutput: { txHash: `0x${(seed++).toString(16).padStart(64, "0")}`, index: 0 } }],
    outputs: [{ lock: plan.secp, capacity: 1_000n * CKB }],
    outputsData: ["0x"],
  });
  const client = await offlineClient([funding, enable, refund], [`${funding.hash()}:0`, `${funding.hash()}:1`]);
  const second = await planRecovery(client, walletFor(), [evm(44)], { emailBinding: true });
  // Even with the transaction the enable spent unknown to get_transaction, the key's own history proves the list.
  const known = new Map<string, { tx: ccc.Transaction; status: string }>([enable, refund].map((tx) => [tx.hash(), { tx, status: "committed" }]));
  const env = fakeLit({ privateKey, pkpId, actionKey, lookup: (hash) => known.get(hash), transactions: () => [funding, enable, refund] });
  await assert.rejects(policySendCode(second.transaction, wallet, { email: "attacker@example.com", appName: "Demo", backups: [evm(44)], client }, runner(await env.load())), /already on for this key/);
  assert.ok(!env.fetched.includes(enable.hash()), "the list's creating transaction isn't downloaded");
  // If the history can't be read, the check fails closed rather than leaving the list out.
  const down = fakeLit({ privateKey, pkpId, actionKey, lookup: (hash) => known.get(hash), transactions: () => [funding, enable, refund], failing: (method) => method === "get_transactions" });
  await assert.rejects(policySendCode(second.transaction, wallet, { email: "attacker@example.com", appName: "Demo", backups: [evm(44)], client }, runner(await down.load())), /HTTP 500/);
  assert.equal(env.emails.length + down.emails.length, 0);
});

test("fake lists made by huge transactions are ruled out from the key's history, without downloading them", async () => {
  const { funding, signed: enable, plan } = await enableWithPolicy([evm(45)]);
  const env = world([funding, enable]);
  // An outsider plants Type ID cells under the list lock, each from its own transaction padded with a big witness,
  // so that fetching them all would exhaust the Action's memory or the node's response limit.
  const listLock = enable.outputs[0].lock;
  const planted: string[] = [];
  for (let i = 0; i < 8; i++) {
    const own = ccc.Transaction.from({ inputs: [], outputs: [{ lock: ccc.Script.from({ codeHash: `0x${"97".repeat(32)}`, hashType: "type", args: ccc.numToHex(i) }), capacity: 500n * CKB }], outputsData: ["0x"] });
    env.add(own);
    const fake = ccc.Transaction.from({
      inputs: [{ previousOutput: { txHash: own.hash(), index: 0 } }],
      outputs: [{ lock: listLock, type: adminListTypeScript({ adminListTypeArgs: ccc.hexFrom(ccc.hashCkb(ccc.numLeToBytes(i, 4))) }), capacity: 200n * CKB }],
      outputsData: [adminListData(`0x${"78".repeat(32)}`)],
      witnesses: [ccc.hexFrom(new Uint8Array(500_000))],
    });
    env.add(fake);
    planted.push(fake.hash(), own.hash());
  }
  const action = await loadAction(env);
  const index = enable.outputs.findIndex((output) => output.lock.eq(plan.omnilock));
  const spend = ccc.Transaction.from({
    inputs: [{ previousOutput: { txHash: enable.hash(), index } }],
    outputs: [{ lock: plan.omnilock, capacity: enable.outputs[index].capacity - 100_000n }],
    outputsData: ["0x"],
    witnesses: [ccc.hexFrom(ccc.WitnessArgs.from({ lock: ccc.hexFrom(new Uint8Array(85)) }).toBytes())],
  });
  const result = await action.main({ mode: "transaction", pkpId, transaction: JSON.parse(ccc.stringify(spend)) }) as { operation: string };
  assert.equal(result.operation, "plain");
  assert.deepEqual(env.fetched.filter((hash) => planted.includes(hash)), [], "no planted transaction is fetched");
});

test("a key with a long history still signs: only the blocks holding candidate lists are read", async () => {
  const { funding, signed: enable, plan } = await enableWithPolicy([evm(47)]);
  const env = world([funding, enable]);
  // More than 9,000 entries in the key's secp256k1 history, from cells sent to it (spending them wouldn't remove
  // the entries either).
  env.add(ccc.Transaction.from({
    inputs: [{ previousOutput: { txHash: `0x${(seed++).toString(16).padStart(64, "0")}`, index: 0 } }],
    outputs: Array.from({ length: 9_000 }, () => ({ lock: plan.secp, capacity: 61n * CKB })),
    outputsData: Array.from({ length: 9_000 }, () => "0x"),
  }));
  const action = await loadAction(env);
  const index = enable.outputs.findIndex((output) => output.lock.eq(plan.omnilock));
  const spend = ccc.Transaction.from({
    inputs: [{ previousOutput: { txHash: enable.hash(), index } }],
    outputs: [{ lock: plan.omnilock, capacity: enable.outputs[index].capacity - 100_000n }],
    outputsData: ["0x"],
    witnesses: [ccc.hexFrom(ccc.WitnessArgs.from({ lock: ccc.hexFrom(new Uint8Array(85)) }).toBytes())],
  });
  const result = await action.main({ mode: "transaction", pkpId, transaction: JSON.parse(ccc.stringify(spend)) }) as { operation: string };
  assert.equal(result.operation, "plain");
  assert.ok(env.historyReads.length > 0, "the history is read");
  assert.ok(Math.max(...env.historyReads) < 10, "only the enable's block is read");
});

test("typed cells sent to the key's address don't count toward the plain-cell limit an enable checks", async () => {
  const { funding, client } = await funded();
  const env = world([funding]);
  const plan = await planRecovery(client, walletFor(), [evm(48)], { emailBinding: true });
  env.add(ccc.Transaction.from({
    inputs: [{ previousOutput: { txHash: `0x${(seed++).toString(16).padStart(64, "0")}`, index: 0 } }],
    outputs: Array.from({ length: 300 }, (_, i) => ({ lock: plan.secp, type: ccc.Script.from({ codeHash: `0x${"77".repeat(32)}`, hashType: "type", args: ccc.numToHex(i) }), capacity: 100n * CKB })),
    outputsData: Array.from({ length: 300 }, () => "0x"),
  }));
  const action = await loadAction(env);
  const sent = await policySendCode(plan.transaction, wallet, { email: "user@example.com", appName: "Demo", backups: [evm(48)], client }, runner(action));
  assert.ok(sent.ticket);
});

test("the list check reads candidates and history from the same node, retrying both on the next", async () => {
  const { funding, signed: enable, plan } = await enableWithPolicy([evm(49)]);
  // The first node lists cells but fails history queries; the check must not pair its candidates with the second
  // node's history, which could be behind.
  const env = fakeLit({
    privateKey, pkpId, actionKey,
    lookup: (hash) => [funding, enable].find((tx) => tx.hash() === hash) && { tx: [funding, enable].find((tx) => tx.hash() === hash)!, status: "committed" },
    transactions: () => [funding, enable],
    failingAt: (url, methods) => url === "https://testnet.ckb.dev/" && methods.includes("get_transactions"),
  });
  const action = await env.load();
  const index = enable.outputs.findIndex((output) => output.lock.eq(plan.omnilock));
  const spend = ccc.Transaction.from({
    inputs: [{ previousOutput: { txHash: enable.hash(), index } }],
    outputs: [{ lock: plan.omnilock, capacity: enable.outputs[index].capacity - 100_000n }],
    outputsData: ["0x"],
    witnesses: [ccc.hexFrom(ccc.WitnessArgs.from({ lock: ccc.hexFrom(new Uint8Array(85)) }).toBytes())],
  });
  assert.equal((await action.main({ mode: "transaction", pkpId, transaction: JSON.parse(ccc.stringify(spend)) }) as { operation: string }).operation, "plain");
  const second = env.requests.filter(({ url }) => url === "https://testnet.ckbapp.dev/");
  assert.ok(second.some(({ methods }) => methods.includes("get_cells")), "the second node lists the candidates too");
  assert.ok(second.some(({ methods }) => methods.includes("get_transactions")));
});

test("an enable stays within Lit's request limit, code email included, however many fake lists there are", async () => {
  const { funding, client } = await funded();
  const env = world([funding]);
  const plan = await planRecovery(client, walletFor(), [evm(50)], { emailBinding: true });
  const listLock = plan.transaction.outputs[0].lock;
  // 1,000 fake lists, each in its own block, so each needs its own history query.
  for (let i = 0; i < 1_000; i++) {
    env.add(ccc.Transaction.from({
      inputs: [{ previousOutput: { txHash: `0x${(seed++).toString(16).padStart(64, "0")}`, index: 0 } }],
      outputs: [{ lock: listLock, type: adminListTypeScript({ adminListTypeArgs: ccc.hexFrom(ccc.hashCkb(ccc.numLeToBytes(i + 10_000, 4))) }), capacity: 200n * CKB }],
      outputsData: [adminListData(`0x${"78".repeat(32)}`)],
    }));
  }
  const action = await loadAction(env);
  const sent = await policySendCode(plan.transaction, wallet, { email: "user@example.com", appName: "Demo", backups: [evm(50)], client }, runner(action));
  assert.ok(sent.ticket);
  // Lit allows 50 outbound requests a run by default; the email is one more.
  assert.ok(env.requests.length + env.emails.length <= 25, `${env.requests.length} RPC requests`);
});

test("no output may go to an administrator-mode Omnilock of the key in another shape: other flags or the official deployment", async () => {
  const { funding, signed: enable, plan } = await enableWithPolicy([evm(46)]);
  const env = world([funding, enable]);
  const action = await loadAction(env);
  const index = enable.outputs.findIndex((output) => output.lock.eq(plan.omnilock));
  const spendTo = (lock: ccc.Script) => {
    const tx = ccc.Transaction.from({
      inputs: [{ previousOutput: { txHash: enable.hash(), index } }],
      outputs: [{ lock, capacity: enable.outputs[index].capacity - 100_000n }],
      outputsData: ["0x"],
      witnesses: [ccc.hexFrom(ccc.WitnessArgs.from({ lock: ccc.hexFrom(new Uint8Array(85)) }).toBytes())],
    });
    return action.main({ mode: "transaction", pkpId, transaction: JSON.parse(ccc.stringify(tx)) });
  };
  const auth = ccc.bytesFrom(plan.omnilock.args).slice(0, 21);
  const attackerList = new Uint8Array(32).fill(0x9a);
  const official = { codeHash: "0xf329effd1c475a2978453c8600e1eaf0bc2087ee093c3ee64cc96ec6847752cb" as const, hashType: "type" as const };
  const variants = [
    ccc.Script.from({ ...plan.omnilock, args: ccc.hexFrom(ccc.bytesConcat(auth, [0x03], attackerList, [0x00])) }), // admin + anyone-can-pay
    ccc.Script.from({ ...plan.omnilock, args: ccc.hexFrom(ccc.bytesConcat(auth, [0x05], attackerList, new Uint8Array(8))) }), // admin + time lock
    ccc.Script.from({ ...official, args: ccc.hexFrom(ccc.bytesConcat(auth, [0x01], attackerList)) }),
    // The official deployment naming the account's own list is still not the account's address.
    ccc.Script.from({ ...official, args: plan.omnilock.args }),
  ];
  for (const lock of variants) await assert.rejects(spendTo(lock), /Omnilock of this key that KeyWay doesn't use/);
  assert.equal((await spendTo(plan.omnilock) as { operation: string }).operation, "plain");
});

test("a list made before on-chain records changes by one backup only, checked against the record the server supplies", async () => {
  const backups = [evm(16), evm(17)];
  const { funding, client } = await funded();
  const plan = await planRecovery(client, walletFor(), backups, { emailBinding: false });
  const signed = plan.transaction.clone();
  const w0 = signed.getWitnessArgsAt(0)!;
  w0.outputType = undefined; // no record, as before records existed
  signed.setWitnessArgsAt(0, w0);
  await signed.prepareSighashAllWitness(plan.secp, 65, client);
  const digest = (await signed.getSignHashInfo(plan.secp, client))!.message;
  const raw = secp256k1.sign(ccc.bytesFrom(digest), privateKey, { prehash: false, format: "recovered" } as never) as Uint8Array;
  const witness = signed.getWitnessArgsAt(0)!;
  witness.lock = ccc.hexFrom(Uint8Array.from([...raw.slice(1), raw[0]]));
  signed.setWitnessArgsAt(0, witness);
  const env = world([funding, signed]);
  const action = await loadAction(env);
  const recovery: KeyWayRecovery = {
    omnilockArgs: plan.omnilock.args, omnilock: KEYWAY_OMNILOCK.testnet, adminListTypeArgs: plan.adminListType.args, adminListTypeHash: plan.adminListType.hash(),
    adminListOutPoint: { txHash: signed.hash(), index: 0 }, enableTransactionHash: signed.hash(), legacyAddress: plan.preview.legacyAddress, enabledAt: "2026-09-01T00:00:00.000Z", backups,
  };
  const listClient = await offlineClient([funding, signed], [`${funding.hash()}:0`, `${funding.hash()}:1`]);
  const change = await planBackupChange(listClient, walletFor(recovery), { change: "add", backup: evm(18) });
  const groups = [{ script: change.listLock, kind: "omnilock" as const }, { script: change.omnilock, kind: "omnilock" as const }];
  const all = [...backups, evm(18)];
  const sign = (previousListRecord?: ccc.Hex) => policySignTransaction(change.transaction.clone(), groups, listClient, wallet, { enableTransactionHash: recovery.enableTransactionHash, backups: all, ...(previousListRecord ? { previousListRecord } : {}) }, runner(action));
  await assert.rejects(sign(), /previousListRecord is required/);
  const salt = recovery.adminListTypeHash;
  await assert.rejects(sign(recoveryListRecord(await backupAuths(listClient, [evm(19), evm(20)], salt))), /don't match the recovery list's root/);
  // The true list, unsalted or under another account's salt, doesn't hash to the root either.
  await assert.rejects(sign(recoveryListRecord(await backupAuths(listClient, backups, `0x${"77".repeat(32)}`))), /don't match the recovery list's root/);
  // Replacing every backup at once, with the true previous record: refused.
  const replaced = change.transaction.clone();
  const list = [evm(21), evm(22), evm(23)];
  const auths = await backupAuths(listClient, list, salt);
  replaced.outputsData[0] = adminListData(whitelistTree(auths).root);
  setRecoveryListRecord(replaced, 0, recoveryListRecord(auths));
  await assert.rejects(action.main({ mode: "transaction", pkpId, transaction: JSON.parse(ccc.stringify(replaced)), enableTransactionHash: recovery.enableTransactionHash, backups: await litBackupIds(listClient, [...backups, ...list]), previousListRecord: change.previousRecord }), /exactly one backup/);
  const result = await sign(change.previousRecord);
  assert.equal(result.hash(), change.transaction.hash());
});
