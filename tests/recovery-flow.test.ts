import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import * as ccc from "@ckb-ccc/core";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { adminListLock, adminListTypeScript, KEYWAY_OMNILOCK, omnilockArgsFor, omnilockScript, secp256k1Lock, type KeyWayRecovery } from "../src/sdk/browser/account-lock.ts";
import { recoveryApprovalText, rescueApproval } from "../src/sdk/browser/recovery-approval.ts";
import { accountSalt, backupAuth, EVM_PERSONAL_SIGN_VERIFIER, evmBackupAuth, evmPersonalSignAddress, evmPreimage, joyIdPreimage, recoveryBackupChallenge, type RecoveryBackup } from "../src/sdk/browser/recovery-backups.ts";
import { backupAuths, decodeRecoveryList, readRecoveryList, recoveryListEntry, recoveryListRecord, recoveryListRecordOf, setRecoveryListRecord } from "../src/sdk/browser/recovery-list.ts";
import { adminListData, whitelistTree } from "../src/sdk/browser/recovery-smt.ts";
import { verifyWebAuthn } from "../src/sdk/browser/webauthn.ts";
import { formatCkbSignature, previewFundingTransaction, signAccountGroups } from "../src/server/funding-transaction.ts";
import {
  backupChangeLines,
  checkBackupChallenge,
  checkBackupChangeTransaction,
  issueBackupChallenge,
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

process.env.KEYWAY_RATE_LIMIT_SECRET ??= "test-rate-limit-secret-that-is-long-enough";

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

/**
 * The account's cells as the outputs of one transaction that paid them, so the chain shows they were the
 * account's (the recovery record's anchor reads the cell input 0 spent from that transaction).
 */
async function accountCells() {
  const base = await offlineClient();
  const secp = await secp256k1Lock(base, publicKey);
  const xudt = await base.getKnownScript(ccc.KnownScript.XUdt);
  const token = ccc.Script.from({ codeHash: xudt.codeHash, hashType: xudt.hashType, args: `0x${"77".repeat(32)}` });
  const dao = await base.getKnownScript(ccc.KnownScript.NervosDao);
  const outputs: Record<"small" | "large" | "token" | "dao" | "withData", { lock: ccc.Script; capacity: bigint; type?: ccc.Script; data: ccc.Hex }> = {
    small: { lock: secp, capacity: 300n * CKB, data: "0x" },
    large: { lock: secp, capacity: 2_000n * CKB, data: "0x" },
    token: { lock: secp, capacity: 143n * CKB, type: token, data: amount(2_500n) },
    dao: { lock: secp, capacity: 102n * CKB, type: ccc.Script.from({ codeHash: dao.codeHash, hashType: dao.hashType, args: "0x" }), data: ccc.hexFrom(new Uint8Array(8)) },
    withData: { lock: secp, capacity: 70n * CKB, data: "0x1234" },
  };
  const values = Object.values(outputs);
  const funding = ccc.Transaction.from({
    inputs: [{ previousOutput: { txHash: `0x${(nextCell++).toString(16).padStart(64, "0")}`, index: 0 } }],
    outputs: values.map(({ lock, capacity, type }) => ({ lock, capacity, type })),
    outputsData: values.map(({ data }) => data),
  });
  const cells = Object.fromEntries(Object.entries(outputs).map(([name], index) => [name, ccc.Cell.from({
    outPoint: { txHash: funding.hash(), index }, cellOutput: funding.outputs[index], outputData: funding.outputsData[index],
  })])) as Record<keyof typeof outputs, ccc.Cell>;
  return { cells, secp, token, funding, client: await offlineClient(Object.values(cells), [funding]) };
}

/** The settings turning recovery on with this plan gives, anchored by its transaction. */
function recoveryFrom(plan: Awaited<ReturnType<typeof planRecovery>>, list?: RecoveryBackup[]): KeyWayRecovery {
  const hash = plan.transaction.hash();
  return {
    omnilockArgs: plan.omnilock.args, omnilock: KEYWAY_OMNILOCK.testnet, adminListTypeArgs: plan.adminListType.args, adminListTypeHash: plan.adminListType.hash(),
    adminListOutPoint: { txHash: hash, index: 0 }, enableTransactionHash: hash, legacyAddress: plan.preview.legacyAddress, enabledAt: "2026-10-29T00:00:00.000Z",
    ...(list ? { backups: list } : {}),
  };
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
  // The account runs KeyWay's pinned Omnilock; the list sits under the key's owner-only lock, which no backup can use.
  assert.equal(plan.omnilock.codeHash, KEYWAY_OMNILOCK.testnet.codeHash);
  assert.equal(plan.omnilock.hashType, "data1");
  assert.ok(adminList.type!.eq(typeId) && adminList.lock.eq(adminListLock({ omnilock: KEYWAY_OMNILOCK.testnet, omnilockArgs: plan.omnilock.args })));
  assert.equal(adminList.lock.args, `0x00${ccc.hashCkbShort(publicKey).slice(2)}00`);
  // The backup's auth is salted with this account's AdminList type hash, and the record holds only that auth.
  assert.equal(transaction.outputsData[0], adminListData(whitelistTree([evmBackupAuth(evmAddress, typeId.hash())]).root));
  assert.deepEqual(decodeRecoveryList(recoveryListRecordOf(transaction, 0)!), [evmBackupAuth(evmAddress, typeId.hash())]);
  assert.ok(!recoveryListRecordOf(transaction, 0)!.includes(evmAddress.slice(2)), "the backup's address isn't on chain");
  // 165 CKB: the owner-only lock's args are 22 bytes, 32 fewer than the account's.
  assert.equal(adminList.capacity, 165n * CKB);
  // A token cell needs 34 more bytes for the 54-byte Omnilock args: 176 CKB, up from this cell's 143.
  assert.ok(tokenOutput.type!.eq(token) && tokenOutput.lock.eq(plan.omnilock));
  assert.equal(transaction.outputsData[1], amount(2_500n));
  assert.equal(tokenOutput.capacity, 176n * CKB);
  assert.equal(preview.tokenCellsExtraCkb, "33");
  assert.equal(preview.lockedCkb, "198");
  assert.equal(preview.minimumCellCkb, "95");
  assert.ok(change.lock.eq(plan.omnilock) && !change.type);
  const fee = 2_443n * CKB - transaction.getOutputsCapacity();
  assert.equal(preview.feeCkb, (Number(fee) / 1e8).toString());
  assert.ok(fee > 0n && fee < CKB / 1000n);
  assert.deepEqual(preview.tokens, [{ asset: token.hash(), amount: "2500", amountText: `2500 of token ${token.hash()}` }]);
  assert.equal(preview.transactionHash, transaction.hash());

  // Deterministic: the same cells give the same transaction, so enable can rebuild and compare it.
  assert.equal((await planRecovery(client, walletFor(publicKey), backups)).transaction.hash(), transaction.hash());
  await checkRecoveryTransaction(client, transaction, publicKey, backups);

  const lines = recoveryLines(preview);
  assert.ok(lines.includes(`Backup: EVM wallet ${evmAddress}`));
  assert.ok(lines.includes(`New address: ${preview.newAddress}`));
  assert.ok(lines.every((line) => !line.includes("…")), "nothing the user approves is shortened");
  assert.ok(lines.includes("Your address will change because you're turning on recovery."));
  assert.ok(lines.some((line) => line.startsWith("Locks 198 CKB")));
});

test("refuses when the balance can't cover it or there is no plain CKB", async () => {
  const base = await offlineClient();
  const secp = await secp256k1Lock(base, publicKey);
  await assert.rejects(planRecovery(await offlineClient([cell(secp, 250n * CKB)]), walletFor(publicKey), backups), /can't cover turning on recovery: it needs 10\.0+\d+ CKB more/);
  await assert.rejects(planRecovery(await offlineClient([]), walletFor(publicKey), backups), /needs plain CKB/);
  assert.ok(await planRecovery(await offlineClient([cell(secp, 261n * CKB)]), walletFor(publicKey), backups));
});

test("reproduces the testnet proof: two accounts, one EVM and one JoyID-style backup each, unrelated on chain, each rescued through the salted verifiers", async () => {
  // research/backup-unlinking/README.md: 0xf709012a…b295 and 0x6807abfa…206f turned recovery on for A and B with
  // the same two backups; 0xfd7674dd…6d12 (E1 rescues A) and 0xe4634e3f…b757 (J1 rescues B).
  const fixture = JSON.parse(await readFile(new URL("./fixtures/recovery-backup-unlinking.json", import.meta.url), "utf8"));
  const evm: RecoveryBackup = { kind: "evm", address: fixture.evmBackup };
  const joy: RecoveryBackup = { kind: "joyid", address: fixture.joyIdBackup };
  const lists: ccc.Hex[][] = [];
  for (const [name, hash] of [["A", "0xf709012a4e22b078bf6217aa73b8890d3c31b6dafab35805b352137ca38cb295"], ["B", "0x6807abfa7a21fa5f7ce58f852ff6a6885544605119dd4fd158f7495ac89d206f"]] as const) {
    const recorded = fixture[`enable${name}`];
    const enable = ccc.Transaction.from(recorded.transaction);
    const client = await offlineClient(recorded.inputCells, [ccc.Transaction.from(recorded.funding)]);
    // These enables predate the policy signer, so they carry no email binding.
    const plan = await planRecovery(client, walletFor(fixture[`publicKey${name}`]), [evm, joy], { emailBinding: false });
    assert.equal(plan.transaction.hash(), hash);
    assert.equal(enable.hash(), hash);
    // The emailed code names the JoyID backup by its whole address, as JoyID shows it, not a start and a checksum.
    const lines = recoveryLines(plan.preview);
    assert.ok(lines.includes(`Backup: JoyID ${fixture.joyIdBackup}`), lines.join("\n"));
    assert.ok(lines.includes(`Backup: EVM wallet ${fixture.evmBackup.toLowerCase()}`), lines.join("\n"));
    assert.equal(plan.preview.backups[1].label, `JoyID ${fixture.joyIdBackup}`);
    await checkRecoveryTransaction(client, enable, fixture[`publicKey${name}`], [evm, joy]);
    // The record is the two auths salted with this account's AdminList type hash; it names neither backup.
    const salt = plan.adminListType.hash();
    const record = recoveryListRecordOf(enable, 0)!;
    const auths = decodeRecoveryList(record);
    assert.deepEqual(auths, await backupAuths(client, [evm, joy], salt));
    assert.ok(!record.includes(fixture.evmBackup.slice(2)) && !record.includes(ccc.hexFrom(ccc.hashCkbShort(fixture.joyIdPublicKey)).slice(2)));
    lists.push(auths);
  }
  // The same backups have unrelated auths in the two accounts.
  assert.ok(lists[0].every((auth) => !lists[1].includes(auth)));

  // Each rescue's backup signed the readable text the verifier rebuilds, and the witness carries the salted preimage.
  const approvalOf = async (recorded: { transaction: ccc.TransactionLike; inputCells: ccc.CellLike[] }) => {
    const transaction = ccc.Transaction.from(recorded.transaction);
    const spendClient = await offlineClient(recorded.inputCells);
    const lock = ccc.Script.from(recorded.inputCells[0].cellOutput.lock);
    const witness = ccc.bytesFrom(transaction.getWitnessArgsAt(0)!.lock!);
    const zeroed = transaction.clone();
    zeroed.setWitnessArgsAt(0, ccc.WitnessArgs.from({ lock: ccc.hexFrom(new Uint8Array(witness.length)) }));
    const sighash = (await zeroed.getSignHashInfo(lock, spendClient))!.message;
    const inputs = recorded.inputCells.map((cell) => ({ cellOutput: cell.cellOutput, outputData: cell.outputData ?? "0x" }));
    return { text: recoveryApprovalText(spendClient, rescueApproval(transaction, lock, inputs), sighash), witness, salt: accountSalt(lock.args) };
  };
  const evmRescue = await approvalOf(fixture.rescueEvmA);
  assert.match(evmRescue.text, /\nCKB: 9,834\.99997964\nTokens: none\nFee: 0\.00001025 CKB\n/);
  assert.deepEqual([evmRescue.witness[20], evmRescue.witness[21]], [1, 0]);
  assert.equal(evmPersonalSignAddress(evmRescue.text, evmRescue.witness.slice(22, 87)), fixture.evmBackup);
  assert.equal(ccc.hexFrom(evmRescue.witness.slice(-62)), evmPreimage(fixture.evmBackup, evmRescue.salt));
  const joyRescue = await approvalOf(fixture.rescueJoyIdB);
  assert.match(joyRescue.text, /\nCKB: 9,834\.99996529\nTokens: none\nFee: 0\.0000246 CKB\n/);
  const blob = joyRescue.witness.slice(20, 20 + 1024);
  assert.deepEqual([blob[0], blob[1]], [2, 0]);
  assert.deepEqual(blob.slice(2, 66), ccc.bytesFrom(fixture.joyIdPublicKey));
  const clientAt = 132 + (blob[130] | (blob[131] << 8));
  const assertion = {
    publicKey: blob.slice(2, 66), rs: blob.slice(66, 130), authData: blob.slice(132, clientAt),
    clientDataJson: blob.slice(clientAt + 2, clientAt + 2 + (blob[clientAt] | (blob[clientAt + 1] << 8))),
  };
  assert.ok(verifyWebAuthn(assertion, joyRescue.text));
  assert.equal(ccc.hexFrom(joyRescue.witness.slice(-62)), joyIdPreimage(ccc.hashCkbShort(fixture.joyIdPublicKey), joyRescue.salt));
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
  const salt = plan.adminListType.hash();
  await tamper((tx) => { tx.outputsData[0] = adminListData(whitelistTree([evmBackupAuth(evmAddress, salt), evmBackupAuth(`0x${"44".repeat(20)}`, salt)]).root); }, /exactly these backups/);
  // The right backup under another account's salt, or unsalted as the previous record format had it.
  await tamper((tx) => { const auths = [evmBackupAuth(evmAddress, `0x${"24".repeat(32)}`)]; tx.outputsData[0] = adminListData(whitelistTree(auths).root); setRecoveryListRecord(tx, 0, recoveryListRecord(auths)); }, /exactly these backups/);
  await tamper((tx) => { setRecoveryListRecord(tx, 0, ccc.hexFrom(ccc.bytesConcat("0x4b57524c", [2, 1, 0xfd], EVM_PERSONAL_SIGN_VERIFIER.codeHash, [2, 0], new Uint8Array(8), evmAddress))); }, /recorded backup list/);
  await tamper((tx) => { tx.outputs[0].capacity += CKB; tx.outputs[last].capacity -= CKB; }, /capacity is wrong/);
  // The list under the account's own admin-mode Omnilock, where a backup could spend or rewrite it, is refused.
  await tamper((tx) => { tx.outputs[0].lock = plan.omnilock; }, /locked to your key alone/);
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
  const recovery = recoveryFrom(plan, backups);
  answer(client, plan.transaction);
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
  // The same through KeyWay's pinned Omnilock, by data hash.
  toOther.outputs[0].lock = omnilockScript({ omnilock: KEYWAY_OMNILOCK.testnet, omnilockArgs: omnilockArgsFor(publicKey, `0x${"99".repeat(32)}`) });
  await assert.rejects(previewGeneralTransaction(walletFor(publicKey, recovery), toOther, client), /isn't its own/);
});

/** Lets the client also answer `transaction` as committed. */
function answer(client: ccc.Client, transaction: ccc.Transaction): void {
  const previous = client.getTransaction.bind(client);
  Object.assign(client, { getTransaction: async (hash: ccc.HexLike) => ccc.hexFrom(hash) === transaction.hash() ? { transaction, status: "committed" } : previous(hash) });
}

test("the recovery service refuses before touching anything when recovery is on or no backup is given", async () => {
  const { client } = await accountCells();
  const plan = await planRecovery(client, walletFor(publicKey), backups);
  const recovery = recoveryFrom(plan);
  const user = { id: crypto.randomUUID() };
  const context = (wallet: ReadyWallet): RecoveryContext => ({
    user, wallet, appName: "Acme", client,
    email: async () => "ana@acme.example", sendEmail: async () => undefined,
    rateLimit: async () => ({ allowed: true, retryAfter: null }), recordSigning: async () => undefined,
  });
  await assert.rejects(recoverySetup(context(walletFor(publicKey, recovery)), { operation: "preview", backups }), /already on/);
  await assert.rejects(recoverySetup(context(walletFor(publicKey)), { operation: "preview", backups: [] }), /at least one backup/);
  // Without a challenge KeyWay issued to this user, or a signature from the backup, nothing is previewed.
  await assert.rejects(recoverySetup(context(walletFor(publicKey)), { operation: "preview", backups }), /approval request is invalid/);
  const { challengeNonce } = issueBackupChallenge(user);
  await assert.rejects(recoverySetup(context(walletFor(publicKey)), { operation: "preview", backups: [{ ...backups[0], challengeNonce }] }), /didn't sign/);
  const wrongAccount = { ...backups[0], challengeNonce, signature: personalSign(recoveryBackupChallenge("ckt1qother", backups[0], challengeNonce)) };
  await assert.rejects(recoverySetup(context(walletFor(publicKey)), { operation: "preview", backups: [wrongAccount] }), /didn't sign/);
  // Another user's nonce, an expired one, or one with a forged tag is refused before the signature is read.
  const foreign = issueBackupChallenge({ id: crypto.randomUUID() }).challengeNonce;
  const expired = issueBackupChallenge(user, Date.now() - 16 * 60_000).challengeNonce;
  const forged = `${challengeNonce.slice(0, -64)}${"00".repeat(32)}`;
  for (const nonce of [foreign, expired, forged]) {
    const proof = { ...backups[0], challengeNonce: nonce, signature: personalSign(recoveryBackupChallenge(plan.preview.legacyAddress, backups[0], nonce)) };
    await assert.rejects(recoverySetup(context(walletFor(publicKey)), { operation: "preview", backups: [proof] }), /approval request is invalid or expired/);
  }
  // A fresh challenge is issued on request.
  const issued = await recoverySetup(context(walletFor(publicKey)), { operation: "challenge" }) as { challengeNonce: string; expiresAt: string };
  assert.ok(Date.parse(issued.expiresAt) - Date.now() > 14 * 60_000);
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
  const { cells, funding, client: setupClient } = await accountCells();
  const plan = await planRecovery(setupClient, walletFor(publicKey), list);
  const hash = plan.transaction.hash();
  const outputs = plan.transaction.outputs.map((cellOutput, index) => ccc.Cell.from({ outPoint: { txHash: hash, index }, cellOutput, outputData: plan.transaction.outputsData[index] }));
  const recovery = recoveryFrom(plan, list);
  const live = [outputs[0], outputs[outputs.length - 1], cells.dao];
  return { plan, recovery, outputs, client: await offlineClient(live, [funding, plan.transaction]), wallet: walletFor(publicKey, recovery) };
}

test("reads the backup list back from the chain and checks it against the root", async () => {
  const second: RecoveryBackup = { kind: "evm", address: `0x${"44".repeat(20)}` };
  const { client, recovery, plan } = await enabledAccount([...backups, second]);
  const list = await readRecoveryList(client, recovery);
  const salt = recovery.adminListTypeHash;
  const auths = [evmBackupAuth(evmAddress, salt), evmBackupAuth(second.address, salt)];
  assert.equal(list.salt, salt);
  assert.deepEqual(list.auths, auths);
  assert.equal(list.root, whitelistTree(auths).root);
  assert.equal(list.proofs[auths[1]], whitelistTree(auths).proofs[auths[1]]);
  // Whoever holds a backup finds it on the list by computing its auth with the account's salt.
  assert.deepEqual(await recoveryListEntry(client, list, second), { backup: second, auth: auths[1], preimage: evmPreimage(second.address, salt) });
  assert.equal(await recoveryListEntry(client, list, { kind: "evm", address: `0x${"45".repeat(20)}` }), undefined);
  assert.equal(await recoveryListEntry(client, { ...list, salt: `0x${"24".repeat(32)}` }, second), undefined);
  // A record that doesn't hash to the cell's root, a malformed one, and none at all are all refused.
  const forged = plan.transaction.clone();
  setRecoveryListRecord(forged, 0, recoveryListRecord(await backupAuths(client, backups, salt)));
  await assert.rejects(readRecoveryList(await offlineClient([plan.transaction.outputs[0]].map((cellOutput) => ({ outPoint: { txHash: forged.hash(), index: 0 }, cellOutput, outputData: plan.transaction.outputsData[0] })), [forged]), recovery), /don't match/);
  assert.throws(() => decodeRecoveryList("0x4b57524c0301"), /malformed/);
  assert.throws(() => decodeRecoveryList("0x4b57524c0300"), /malformed/);
  assert.throws(() => decodeRecoveryList(ccc.hexFrom(ccc.bytesConcat("0x4b57524c", [3, 1], auths[0], [0]))), /malformed/);
  assert.throws(() => decodeRecoveryList(ccc.hexFrom(ccc.bytesConcat("0x4b57524c", [3, 2], auths[0], auths[0]))), /malformed/);
  assert.throws(() => decodeRecoveryList(ccc.hexFrom(ccc.bytesConcat("0x4b57524c", [3, 1, 0x00], new Uint8Array(20).fill(0x55)))), /malformed/);
  assert.throws(() => recoveryListRecord([ccc.hexFrom(ccc.bytesConcat([0x00], new Uint8Array(20)))]), /only exec auths/);
  // Version 1 (flag 0x12 EVM entries) and version 2 (preimages naming the backup) records are gone.
  assert.throws(() => decodeRecoveryList(ccc.hexFrom(ccc.bytesConcat("0x4b57524c", [1, 1, 0x12], new Uint8Array(20).fill(0x55)))), /version 1/);
  assert.throws(() => decodeRecoveryList(ccc.hexFrom(ccc.bytesConcat("0x4b57524c", [2, 1, 0xfd], new Uint8Array(32).fill(9), [2, 0], new Uint8Array(8), new Uint8Array(20).fill(0x55)))), /version 2/);
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
  assert.ok(plan.listLock.eq(adminListLock(recovery)) && outputs[0].cellOutput.lock.eq(plan.listLock));
  assert.ok(transaction.inputs[1].previousOutput.eq(outputs[outputs.length - 1].outPoint), "then the account's plain CKB");
  assert.equal(transaction.inputs.length, 2, "the DAO cell isn't touched");
  assert.ok(transaction.outputs[0].lock.eq(outputs[0].cellOutput.lock) && transaction.outputs[0].type!.eq(outputs[0].cellOutput.type!));
  assert.equal(transaction.outputs[0].capacity, outputs[0].cellOutput.capacity);
  const auths = [evmBackupAuth(evmAddress, recovery.adminListTypeHash), evmBackupAuth(added.address, recovery.adminListTypeHash)];
  assert.equal(transaction.outputsData[0], adminListData(whitelistTree(auths).root));
  assert.equal(recoveryListRecordOf(transaction, 0), recoveryListRecord(auths));
  assert.ok(transaction.outputs[1].lock.eq(plan.omnilock) && !transaction.outputs[1].type);
  // Two lock groups, the list's owner-only lock and the account's Omnilock, each with an owner placeholder.
  assert.equal(transaction.witnesses.length, 2);
  assert.equal(ccc.bytesFrom(transaction.getWitnessArgsAt(0)!.lock!).length, 85);
  assert.equal(ccc.bytesFrom(transaction.getWitnessArgsAt(1)!.lock!).length, 85);
  assert.deepEqual(plan.backups, [...backups, added]);
  assert.equal(plan.preview.backup.label, `EVM wallet 0x${"55".repeat(20)}`);
  await checkBackupChangeTransaction(client, transaction, recovery, plan.backups);
  const lines = backupChangeLines(plan.preview);
  assert.equal(lines[0], "Add a recovery backup");
  assert.ok(lines.includes(`Adding: EVM wallet 0x${"55".repeat(20)}`));
  assert.ok(lines.includes("Backups after this change: 2"));

  // A JoyID passkey is named in the email by its whole address, as JoyID shows it: every JoyID address starts the
  // same, so a start and a 6-character checksum would leave only the checksum to tell two apart.
  const joy: RecoveryBackup = { kind: "joyid", address: "ckt1qrfrwcdnvssswdwpn3s9v8fp87emat306ctjwsm3nmlkjg8qyza2cqgqqxhnyynqdn0w3ukfvnlz44tgcusk2p6ecurrdqmx" };
  const joyPlan = await planBackupChange(client, wallet, { change: "add", backup: joy });
  assert.equal(joyPlan.preview.backup.label, `JoyID ${joy.address}`);
  assert.ok(backupChangeLines(joyPlan.preview).includes(`Adding: JoyID ${joy.address}`));
  assert.ok(backupChangeLines(joyPlan.preview).every((line) => !line.includes("…")));
  // Given in CKB's old full-address format, the same passkey is still named as JoyID shows it.
  const { bech32 } = await import("bech32");
  const joyIdScript = await client.getKnownScript(ccc.KnownScript.JoyId);
  const oldFormat = bech32.encode("ckt", bech32.toWords([0x04, ...ccc.bytesFrom(joyIdScript.codeHash), ...ccc.bytesFrom((await ccc.Address.fromString(joy.address, client)).script.args)]), 1023);
  assert.notEqual(oldFormat, joy.address);
  const oldPlan = await planBackupChange(client, wallet, { change: "add", backup: { kind: "joyid", address: oldFormat } });
  assert.ok(backupChangeLines(oldPlan.preview).includes(`Adding: JoyID ${joy.address}`));

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
  assert.ok(backupChangeLines(plan.preview).includes(`Removing: EVM wallet 0x${"04".repeat(20)}`));
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
  // Moving the list to the account's admin-mode Omnilock, where backups could rewrite it, is refused.
  await tamper((tx) => { tx.outputs[0].lock = plan.omnilock; }, /doesn't recreate the recovery list/);
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
  const user = { id: crypto.randomUUID() };
  const context = (current: ReadyWallet): RecoveryContext => ({
    user, wallet: current, appName: "Acme", client,
    email: async () => "ana@acme.example", sendEmail: async () => undefined,
    rateLimit: async () => ({ allowed: true, retryAfter: null }), recordSigning: async () => undefined,
  });
  const added = { kind: "evm" as const, address: `0x${"55".repeat(20)}` };
  await assert.rejects(recoveryBackupChange(context(walletFor(publicKey)), { operation: "preview", change: "add", backup: added }), /recovery is off/);
  await assert.rejects(recoveryBackupChange(context(wallet), { operation: "preview", change: "swap", backup: added }), /add or remove/);
  await assert.rejects(recoveryBackupChange(context(wallet), { operation: "preview", change: "add", backup: added }), /approval request is invalid/);
  const { challengeNonce } = issueBackupChallenge(user);
  await assert.rejects(recoveryBackupChange(context(wallet), { operation: "preview", change: "add", backup: { ...added, challengeNonce } }), /didn't sign/);
  await assert.rejects(recoveryBackupChange(context(wallet), { operation: "preview", change: "add", backup: { kind: "joyid", address: "ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqv82scyl0ywuurakhc80ha0agm5x8ye8kca6zq0u", challengeNonce } }), /isn't a JoyID address/);
  assert.equal(await backupAuth(client, backups[0], wallet.recovery!.adminListTypeHash), evmBackupAuth(evmAddress, wallet.recovery!.adminListTypeHash));
});

test("a malformed backup challenge nonce is refused as invalid, never a crash", () => {
  const user = { id: "user-1" };
  const { challengeNonce } = issueBackupChallenge(user);
  checkBackupChallenge(user, challengeNonce);
  const [time, random, tag] = challengeNonce.split(".");
  const invalid = /invalid or expired/;
  for (const nonce of [
    undefined, 42, "", "...", `${time}.${random}`, `${time}.${random}.${tag}.00`,
    `${time}.${random}.${tag.slice(2)}`, `${time}.${random}.${tag}00`, `${time}.${random}.ab`,
    `${time}.${random}.${"zz".repeat(32)}`, `${time}.${random}.${tag.toUpperCase()}`, `${time}.${random.slice(2)}.${tag}`,
    `${time.slice(1)}.${random}.${tag}`, `${time}.${random}.${"00".repeat(32)}`,
  ]) assert.throws(() => checkBackupChallenge(user, nonce), invalid, String(nonce));
  assert.throws(() => checkBackupChallenge({ id: "user-2" }, challengeNonce), invalid);
  assert.throws(() => checkBackupChallenge(user, challengeNonce, new Date(Number(time))), invalid);
});
