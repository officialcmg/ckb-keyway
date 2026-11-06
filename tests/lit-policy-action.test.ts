// The policy Action (lit-actions/sign-ckb-transaction.js) run under Node with a fake Lit global, a fake
// ethers v5 SigningKey and a fake CKB RPC and email API, so its rules are checked without Lit or the network.
import assert from "node:assert/strict";
import test from "node:test";
import * as ccc from "@ckb-ccc/core";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { adminListLock, adminListTypeScript, KEYWAY_OMNILOCK, secp256k1Lock, type KeyWayRecovery } from "../src/sdk/browser/account-lock.ts";
import type { RecoveryBackup } from "../src/sdk/browser/recovery-backups.ts";
import { recoveryListRecord, setRecoveryListRecord } from "../src/sdk/browser/recovery-list.ts";
import { adminListData, whitelistTree } from "../src/sdk/browser/recovery-smt.ts";
import { backupAuth } from "../src/sdk/browser/recovery-backups.ts";
import { fakeLit, litCodeIn, type ActionModule } from "./lit-action-fixture.ts";
import { policyIdentitySignature, policySendCode, policySignMessage, policySignTransaction, setEmailBinding } from "../src/server/lit-policy.ts";
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
  const sent = await policySendCode(plan.transaction, wallet, { email, appName: "Demo" }, runner(action));
  setEmailBinding(plan.transaction, sent.binding!);
  const signed = await policySignTransaction(plan.transaction, [{ script: plan.secp, kind: "secp256k1" }], client, wallet, { emailCode: { code: codeIn(env.emails[0]), ticket: sent.ticket } }, runner(action));
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
  const record = ccc.bytesFrom(await recoveryListRecord(client, backups));
  const preimages = backups.map((_, i) => record.slice(6 + i * 63 + 1, 6 + (i + 1) * 63));
  const { root } = whitelistTree(await Promise.all(backups.map((backup) => backupAuth(client, backup))));
  assert.equal(hex(action.whitelistRoot(preimages)), root);
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
    policySignTransaction(transaction.clone(), groups, client, wallet, emailCode ? { emailCode } : {}, runner(action));

  // Without a binding (only its zero placeholder) or a code it refuses.
  await assert.rejects(sign(plan.transaction), /email binding is malformed/);
  const unbound = plan.transaction.clone();
  const w0 = unbound.getWitnessArgsAt(0)!;
  w0.inputType = undefined;
  unbound.setWitnessArgsAt(0, w0);
  await assert.rejects(sign(unbound), /must bind the account's email/);
  const sent = await policySendCode(plan.transaction, wallet, { email: "user@example.com", appName: "Demo" }, runner(action));
  assert.equal(env.emails.length, 1);
  assert.deepEqual(env.emails[0].to, ["user@example.com"]);
  assert.equal(env.emails[0].from, "CKB KeyWay <security@auth.ckbkeyway.dev>");
  assert.match(env.emails[0].text, /Turn on account recovery[\s\S]*Backup: EVM wallet 0x/);
  const code = codeIn(env.emails[0]);
  const bound = plan.transaction.clone();
  setEmailBinding(bound, sent.binding!);
  await assert.rejects(sign(bound), /eight-digit code/);
  await assert.rejects(sign(bound, { code: code === "00000000" ? "00000001" : "00000000", ticket: sent.ticket }), /isn't right/);
  // A binding for another address doesn't take this address's code, and the code is for this transaction only.
  const other = await policySendCode(plan.transaction, wallet, { email: "attacker@example.com", appName: "Demo" }, runner(action));
  const swapped = plan.transaction.clone();
  setEmailBinding(swapped, other.binding!);
  await assert.rejects(sign(swapped, { code, ticket: sent.ticket }), /isn't right/);
  const changed = bound.clone();
  changed.outputs[changed.outputs.length - 1].capacity -= 1n;
  await assert.rejects(sign(changed, { code, ticket: sent.ticket }), /isn't right/);
  // An expired or far-future ticket is refused.
  await assert.rejects(sign(bound, { code, ticket: `v1.${Date.now() - 1}.${"0".repeat(32)}` }), /expired/);
  await assert.rejects(sign(bound, { code, ticket: `v1.${Date.now() + 3_600_000}.${"0".repeat(32)}` }), /ticket is invalid/);
  const signed = await sign(bound, { code, ticket: sent.ticket });
  assert.equal(signed.hash(), plan.transaction.hash());
});

test("a bound account's backup change needs the Action's code, sent to the bound address, never one the server picks", async () => {
  const backups = [evm(5)];
  const { funding, signed: enable, recovery, env } = await enableWithPolicy(backups);
  env.add(enable);
  const action = await loadAction(env);
  const client = await offlineClient([funding, enable], [`${funding.hash()}:0`, `${funding.hash()}:1`]);
  const plan = await planBackupChange(client, walletFor(recovery), { change: "add", backup: evm(6) });
  const groups = [{ script: plan.listLock, kind: "omnilock" as const }, { script: plan.omnilock, kind: "omnilock" as const }];
  const sign = (transaction: ccc.Transaction, emailCode?: { code: string; ticket: string }, enableTransactionHash = recovery.enableTransactionHash) =>
    policySignTransaction(transaction.clone(), groups, client, wallet, { enableTransactionHash, ...(emailCode ? { emailCode } : {}) }, runner(action));

  await assert.rejects(sign(plan.transaction), /eight-digit code/);
  await assert.rejects(sign(plan.transaction, undefined, funding.hash()), /isn't the transaction that made this recovery list/);
  const before = env.emails.length;
  // The server can't redirect the code: the address comes from the chain, whatever email it passes.
  const sent = await policySendCode(plan.transaction, wallet, { enableTransactionHash: recovery.enableTransactionHash, email: "attacker@example.com", appName: "Demo" }, runner(action));
  assert.equal(sent.sentTo, "user@example.com");
  const email = env.emails[before];
  assert.deepEqual(email.to, ["user@example.com"]);
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
  const attempt = (mutate: (tx: ccc.Transaction) => void | Promise<void>) => async () => {
    const tx = plan.transaction.clone();
    await mutate(tx);
    return action.main({ mode: "transaction", pkpId, transaction: JSON.parse(ccc.stringify(tx)), enableTransactionHash: recovery.enableTransactionHash });
  };
  await assert.rejects(attempt((tx) => { tx.outputs[0].lock = enablePlan.secp; }), /lock can't change/);
  await assert.rejects(attempt((tx) => { tx.outputs[0].type = adminListTypeScript({ adminListTypeArgs: `0x${"12".repeat(32)}` }); }), /Type ID can't change|can't be destroyed/);
  await assert.rejects(attempt((tx) => { tx.outputs[0].type = undefined; tx.outputs[0].lock = enablePlan.omnilock; }), /can't be destroyed/);
  await assert.rejects(attempt((tx) => { tx.outputs[0].capacity -= CKB; tx.outputs[1].capacity += CKB; }), /capacity can't change/);
  await assert.rejects(attempt(async (tx) => {
    // Two new backups at once.
    const list = [evm(7), evm(8), evm(9), evm(10)];
    const { root } = whitelistTree(await Promise.all(list.map((backup) => backupAuth(client, backup))));
    tx.outputsData[0] = adminListData(root);
    setRecoveryListRecord(tx, 0, await recoveryListRecord(client, list));
  }), /exactly one backup/);
  await assert.rejects(attempt((tx) => {
    // A second list output under the owner-only lock.
    tx.outputs.push(ccc.CellOutput.from({ lock: adminListLock(recovery), type: adminListTypeScript(recovery), capacity: 200n * CKB }));
    tx.outputsData.push(tx.outputsData[0]);
  }), /only one recovery list/);
  await assert.rejects(attempt((tx) => { tx.outputsData[0] = adminListData(`0x${"34".repeat(32)}`); }), /don't match the recovery list's root/);
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
  const result = await policySignTransaction(change.transaction.clone(), groups, listClient, wallet, { enableTransactionHash: recovery.enableTransactionHash }, runner(action));
  assert.equal(result.hash(), change.transaction.hash());
  await assert.rejects(action.main({ mode: "send-code", pkpId, transaction: JSON.parse(ccc.stringify(change.transaction)), enableTransactionHash: recovery.enableTransactionHash, emailApiKey: "re_test_sending_key" }), /doesn't need an email code/);
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
  await assert.rejects(policySendCode(second.transaction, wallet, { email: "attacker@example.com", appName: "Demo" }, runner(action)), /already on for this key/);

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
