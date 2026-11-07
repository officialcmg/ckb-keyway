import assert from "node:assert/strict";
import test from "node:test";
import * as ccc from "@ckb-ccc/core";
import { p256 } from "@noble/curves/nist.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { secp256k1Lock } from "../src/sdk/browser/account-lock.ts";
import { backupAuth, recoveryBackupChallenge } from "../src/sdk/browser/recovery-backups.ts";
import { decodeRecoveryList, recoveryListRecordOf } from "../src/sdk/browser/recovery-list.ts";
import { database } from "../src/server/database.ts";
import { formatCkbSignature } from "../src/server/funding-transaction.ts";
import { signingSettings } from "../src/server/general-signing.ts";
import { issueBackupChallenge, recoveryBackupChange, recoverySetup, settleRecoveryChange, type RecoveryContext } from "../src/server/recovery.ts";
import { readWallet, saveWallet, type ReadyWallet } from "../src/server/user-wallet.ts";
import { litSignerOverride } from "../src/server/lit-config.ts";
import { litPolicyRunner } from "../src/server/lit-policy.ts";
import { fakeLit, litCodeIn } from "./lit-action-fixture.ts";

const enabled = Boolean(process.env.KEYWAY_AUTH_TEST_DATABASE_URL);
const CKB = 100_000_000n;
process.env.KEYWAY_RATE_LIMIT_SECRET ??= "test-rate-limit-secret-that-is-long-enough";

function evmWallet() {
  const key = secp256k1.utils.randomSecretKey();
  const address = ccc.hexFrom(keccak_256(secp256k1.getPublicKey(key, false).slice(1)).slice(12));
  const personalSign = (message: string) => {
    const bytes = new TextEncoder().encode(message);
    const raw = secp256k1.sign(keccak_256(ccc.bytesConcat(new TextEncoder().encode(`\x19Ethereum Signed Message:\n${bytes.length}`), bytes)), key, { prehash: false, format: "recovered" });
    return ccc.hexFrom(ccc.bytesConcat(raw.slice(1), [raw[0] + 27]));
  };
  return { address, personalSign };
}

/** A JoyID passkey stand-in: a P-256 key whose WebAuthn assertion has the shape JoyID's signMessage returns. */
async function joyIdWallet(client: ccc.Client) {
  const privateKey = p256.utils.randomSecretKey();
  const publicKey = ccc.hexFrom(p256.getPublicKey(privateKey, false).slice(1));
  const joyId = await client.getKnownScript(ccc.KnownScript.JoyId);
  const lock = ccc.Script.from({ codeHash: joyId.codeHash, hashType: joyId.hashType, args: ccc.bytesConcat("0x0001", ccc.hashCkbShort(publicKey)) });
  const address = ccc.Address.fromScript(lock, client).toString();
  const base64url = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");
  const sign = (challenge: string) => {
    const authData = new Uint8Array(37).fill(7);
    const clientData = new TextEncoder().encode(JSON.stringify({ type: "webauthn.get", challenge: base64url(new TextEncoder().encode(challenge)), origin: "https://testnet.joyid.dev" }));
    const der = p256.sign(ccc.bytesConcat(authData, sha256(clientData)), privateKey, { format: "der" });
    return {
      signature: JSON.stringify({ alg: -7, signature: base64url(der), message: base64url(ccc.bytesConcat(authData, clientData)) }),
      identity: JSON.stringify({ keyType: "main_key", publicKey: publicKey.slice(2) }),
    };
  };
  return { address, publicKey, sign };
}

let nextCell = 1;
async function harness() {
  const privateKey = secp256k1.utils.randomSecretKey();
  const publicKey = ccc.hexFrom(secp256k1.getPublicKey(privateKey, true));
  const client = new ccc.ClientPublicTestnet({ url: "https://testnet.ckb.dev/" });
  const secp = await secp256k1Lock(client, publicKey);
  const cells: ccc.Cell[] = [];
  /** What the node knows: each transaction and its status. Cells are paid by transactions here too. */
  const chain = new Map<string, { transaction: ccc.Transaction; status: ccc.TransactionStatus }>();
  const addCell = async (capacity: bigint) => {
    const paid = ccc.Transaction.from({ inputs: [{ previousOutput: { txHash: `0x${(nextCell++).toString(16).padStart(64, "f")}`, index: 0 } }], outputs: [{ lock: secp, capacity }], outputsData: ["0x"] });
    chain.set(paid.hash(), { transaction: paid, status: "committed" });
    const cell = ccc.Cell.from({ outPoint: { txHash: paid.hash(), index: 0 }, cellOutput: paid.outputs[0], outputData: "0x" });
    await client.cache.recordCells([cell]);
    cells.push(cell);
  };
  Object.assign(client, {
    findSingletonCellByType: async () => undefined,
    findCells: async function* () {},
    findCellsByLock: async function* () { yield* cells; },
    getTransaction: async (hash: ccc.HexLike) => chain.get(ccc.hexFrom(hash)),
  });
  await addCell(1_000n * CKB);

  const user = { id: crypto.randomUUID() };
  const legacyAddress = ccc.Address.fromScript(secp, client).toString();
  const wallet: ReadyWallet = {
    version: 1, status: "ready", litPkpId: `0x${"11".repeat(20)}`, litPublicKey: publicKey, ckbAddress: legacyAddress,
    encryptedFiberKey: "ciphertext", primaryDeviceIdHash: "a".repeat(64), hasOpenedChannel: false,
    createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
  };
  await saveWallet(user, wallet);
  const emails: Array<{ subject: string; plaintext: string }> = [];
  const broadcasts: ccc.Transaction[] = [];
  const context = (current: ReadyWallet): RecoveryContext => ({
    user, wallet: current, appName: "Acme Pay", client,
    email: async () => "ana@acmepay.example",
    sendEmail: async (_to, message) => { emails.push(message); },
    rateLimit: async () => ({ allowed: true, retryAfter: null }),
    recordSigning: async () => undefined,
    signDigest: async (digest) => {
      const raw = secp256k1.sign(ccc.bytesFrom(digest), privateKey, { prehash: false, format: "recovered" });
      return formatCkbSignature({ recoveryParam: raw[0] as 0 | 1, r: ccc.hexFrom(raw.slice(1, 33)), s: ccc.hexFrom(raw.slice(33, 65)) });
    },
    broadcast: async (transaction) => {
      broadcasts.push(transaction);
      chain.set(transaction.hash(), { transaction, status: "pending" });
      return transaction.hash();
    },
  });
  /** A backup's ownership proof over a nonce KeyWay issued to this user. */
  const sign = (wallet: ReturnType<typeof evmWallet>) => {
    const backup = { kind: "evm" as const, address: wallet.address };
    const { challengeNonce } = issueBackupChallenge(user);
    return { ...backup, challengeNonce, signature: wallet.personalSign(recoveryBackupChallenge(legacyAddress, backup, challengeNonce)) };
  };
  const evm = evmWallet();
  const proof = sign(evm);
  /** The node commits (or rejects) everything sent, and the account settles at its next request. */
  const settle = async (status: ccc.TransactionStatus = "committed") => {
    for (const entry of chain.values()) if (entry.status === "pending") entry.status = status;
    return settleRecoveryChange(context(await readWallet(user) as ReadyWallet));
  };
  return { privateKey, user, wallet, legacyAddress, publicKey, client, context, emails, broadcasts, proof, sign, settle, chain, addCell, codeFrom: () => /code is (\d{6})/.exec(emails.findLast(({ plaintext }) => /code is \d{6}/.test(plaintext))!.plaintext)![1] };
}

/** Moves a pending request, and its code, this many minutes into the past, as if that time had gone by. */
async function age(nonce: string, minutes: number) {
  const sql = await database();
  const shift = `${minutes} minutes`;
  await sql`
    update keyway_v2_signature_requests
    set expires_at = expires_at - ${shift}::interval, email_code_expires_at = email_code_expires_at - ${shift}::interval
    where nonce = ${nonce}
  `;
}

const EXPIRED = /^Error: This request expired\. Start again\.$/;

type Preview = { preview: { newAddress: string; adminListCkb: string; transactionHash: string }; confirmationNonce: string; requiresEmailCode: boolean };

test("turning recovery on: preview, emailed code, enable", { skip: !enabled }, async (t) => {
  process.env.DATABASE_URL = process.env.KEYWAY_AUTH_TEST_DATABASE_URL;

  await t.test("always needs the emailed code, names the backups, and stores the new lock once committed", async () => {
    const h = await harness();
    const preview = await recoverySetup(h.context(h.wallet), { operation: "preview", backups: [h.proof] }) as Preview;
    assert.equal(preview.requiresEmailCode, true, "even with email confirmation off");
    assert.equal(preview.preview.adminListCkb, "165");
    const nonce = preview.confirmationNonce;
    await assert.rejects(recoverySetup(h.context(h.wallet), { operation: "enable", backups: [h.proof], confirmationNonce: nonce, emailCode: "123456" }), /expired/);
    await recoverySetup(h.context(h.wallet), { operation: "request-email-code", backups: [h.proof], confirmationNonce: nonce });
    assert.equal(h.emails.length, 1);
    assert.match(h.emails[0].subject, /Turn on account recovery/);
    assert.match(h.emails[0].plaintext, new RegExp(`Backup: EVM wallet ${h.proof.address.slice(0, 10)}`));
    assert.match(h.emails[0].plaintext, /Your address will change because you're turning on recovery\./);
    const wrong = h.codeFrom() === "000000" ? "111111" : "000000";
    await assert.rejects(recoverySetup(h.context(h.wallet), { operation: "enable", backups: [h.proof], confirmationNonce: nonce, emailCode: wrong }), /isn't right/);
    assert.equal(h.broadcasts.length, 0);

    const result = await recoverySetup(h.context(h.wallet), { operation: "enable", backups: [h.proof], confirmationNonce: nonce, emailCode: h.codeFrom() }) as { transactionHash: string; ckbAddress: string; pending: boolean };
    assert.equal(h.broadcasts.length, 1);
    assert.equal(result.transactionHash, preview.preview.transactionHash);
    assert.equal(result.ckbAddress, preview.preview.newAddress);
    assert.equal(result.pending, true);
    // Until the transaction is committed nothing changes but the pending record, and no notice goes out.
    const sent = await readWallet(h.user) as ReadyWallet;
    assert.equal(sent.recovery, undefined);
    assert.equal(sent.ckbAddress, h.legacyAddress);
    assert.equal(sent.recoveryPending?.transactionHash, result.transactionHash);
    assert.equal(h.emails.length, 1);
    assert.deepEqual(await recoverySetup(h.context(sent), { operation: "status" }), { pending: true, transactionHash: result.transactionHash, recovery: undefined, ckbAddress: h.legacyAddress });
    await assert.rejects(recoverySetup(h.context(sent), { operation: "preview", backups: [h.sign(evmWallet())] }), /still confirming on chain/);
    await h.settle();
    // Then a notice with the full new address and the rescue page, for when KeyWay is gone.
    assert.equal(h.emails.length, 2);
    assert.match(h.emails[1].subject, /Account recovery is on/);
    assert.ok(h.emails[1].plaintext.includes(result.ckbAddress));
    assert.ok(h.emails[1].plaintext.includes(`EVM wallet ${h.proof.address}`));
    assert.match(h.emails[1].plaintext, /https:\/\/ckbkeyway\.dev\/rescue/);
    const stored = await readWallet(h.user) as ReadyWallet;
    assert.equal(stored.ckbAddress, preview.preview.newAddress);
    assert.equal(stored.recovery?.legacyAddress, h.legacyAddress);
    assert.deepEqual(stored.recovery?.backups, [{ kind: "evm", address: h.proof.address }]);
    assert.deepEqual(stored.recovery?.adminListOutPoint, { txHash: result.transactionHash, index: 0 });
    assert.equal(stored.recovery?.enableTransactionHash, result.transactionHash);
    assert.equal(stored.recoveryPending, undefined);
    // The signed witness is the account key's own secp256k1 signature.
    assert.equal(ccc.bytesFrom(h.broadcasts[0].getWitnessArgsAt(0)!.lock!).length, 65);

    // It doesn't count toward the daily amount.
    const sql = await database();
    const [{ count }] = await sql<Array<{ count: number }>>`select count(*)::int as count from keyway_v2_signed_outflows where user_id = ${h.user.id}`;
    assert.equal(count, 0);

    // Once on, it can't be turned on again, with the stale wallet or the stored one.
    await assert.rejects(recoverySetup(h.context(h.wallet), { operation: "enable", backups: [h.proof], confirmationNonce: nonce, emailCode: h.codeFrom() }), /already on/);
    await assert.rejects(recoverySetup(h.context(stored), { operation: "preview", backups: [h.proof] }), /already on/);
  });

  await t.test("a change the network rejects is dropped, and recovery can be turned on again", async () => {
    const h = await harness();
    const preview = await recoverySetup(h.context(h.wallet), { operation: "preview", backups: [h.proof] }) as Preview;
    await recoverySetup(h.context(h.wallet), { operation: "request-email-code", backups: [h.proof], confirmationNonce: preview.confirmationNonce });
    await recoverySetup(h.context(h.wallet), { operation: "enable", backups: [h.proof], confirmationNonce: preview.confirmationNonce, emailCode: h.codeFrom() });
    const dropped = await h.settle("rejected");
    assert.equal(dropped.recovery, undefined);
    assert.equal(dropped.recoveryPending, undefined);
    assert.equal(dropped.ckbAddress, h.legacyAddress);
    assert.equal(h.emails.filter(({ subject }) => /Account recovery is on/.test(subject)).length, 0, "no notice for a change that didn't happen");
    const again = await recoverySetup(h.context(dropped), { operation: "preview", backups: [h.sign(evmWallet())] }) as Preview;
    assert.equal(again.requiresEmailCode, true);
  });

  await t.test("needs the code even when a daily amount would allow the transfer", async () => {
    const h = await harness();
    await signingSettings(h.context(h.wallet), { operation: "set-daily-amount", asset: "ckb", amount: (1_000_000n * CKB).toString() });
    const preview = await recoverySetup(h.context(h.wallet), { operation: "preview", backups: [h.proof] }) as Preview;
    assert.equal(preview.requiresEmailCode, true);
    await assert.rejects(recoverySetup(h.context(h.wallet), { operation: "enable", backups: [h.proof], confirmationNonce: preview.confirmationNonce }), /expired|six-digit/);
  });

  await t.test("the approval lives as long as its code, and each resend extends both", async () => {
    const h = await harness();
    const body = { backups: [h.proof] };
    const preview = await recoverySetup(h.context(h.wallet), { ...body, operation: "preview" }) as Preview;
    const nonce = preview.confirmationNonce;
    const sent = await recoverySetup(h.context(h.wallet), { ...body, operation: "request-email-code", confirmationNonce: nonce }) as { sentTo: string };
    assert.equal(sent.sentTo, "ana@acmepay.example");
    await age(nonce, 6);
    await recoverySetup(h.context(h.wallet), { ...body, operation: "request-email-code", confirmationNonce: nonce });
    await age(nonce, 9);
    await recoverySetup(h.context(h.wallet), { ...body, operation: "enable", confirmationNonce: nonce, emailCode: h.codeFrom() });
    assert.equal(h.broadcasts.length, 1);
  });

  await t.test("confirms six minutes after the code, and says plainly once the request expired", async () => {
    const h = await harness();
    const body = { backups: [h.proof] };
    const ask = async () => {
      const preview = await recoverySetup(h.context(h.wallet), { ...body, operation: "preview" }) as Preview;
      await recoverySetup(h.context(h.wallet), { ...body, operation: "request-email-code", confirmationNonce: preview.confirmationNonce });
      return preview.confirmationNonce;
    };
    const expired = await ask();
    await age(expired, 11);
    await assert.rejects(recoverySetup(h.context(h.wallet), { ...body, operation: "request-email-code", confirmationNonce: expired }), EXPIRED);
    await assert.rejects(recoverySetup(h.context(h.wallet), { ...body, operation: "enable", confirmationNonce: expired, emailCode: h.codeFrom() }), EXPIRED);
    const late = await ask();
    await age(late, 6);
    await recoverySetup(h.context(h.wallet), { ...body, operation: "enable", confirmationNonce: late, emailCode: h.codeFrom() });
    assert.equal(h.broadcasts.length, 1);
  });

  await t.test("refuses when the account's cells changed since the preview", async () => {
    const h = await harness();
    const preview = await recoverySetup(h.context(h.wallet), { operation: "preview", backups: [h.proof] }) as Preview;
    await recoverySetup(h.context(h.wallet), { operation: "request-email-code", backups: [h.proof], confirmationNonce: preview.confirmationNonce });
    await h.addCell(500n * CKB);
    await assert.rejects(
      recoverySetup(h.context(h.wallet), { operation: "enable", backups: [h.proof], confirmationNonce: preview.confirmationNonce, emailCode: h.codeFrom() }),
      /changed since the preview/,
    );
    assert.equal(h.broadcasts.length, 0);
    assert.equal((await readWallet(h.user) as ReadyWallet).recovery, undefined);
  });

  await t.test("refuses other backups than the previewed ones, and backups without their own signature", async () => {
    const h = await harness();
    const preview = await recoverySetup(h.context(h.wallet), { operation: "preview", backups: [h.proof] }) as Preview;
    await recoverySetup(h.context(h.wallet), { operation: "request-email-code", backups: [h.proof], confirmationNonce: preview.confirmationNonce });
    const otherProof = h.sign(evmWallet());
    const enable = (backups: unknown[]) => recoverySetup(h.context(h.wallet), { operation: "enable", backups, confirmationNonce: preview.confirmationNonce, emailCode: h.codeFrom() });
    await assert.rejects(enable([otherProof]), /changed since the preview/);
    await assert.rejects(enable([{ ...h.proof, signature: otherProof.signature }]), /didn't sign/);
    await assert.rejects(enable([h.proof, otherProof]), /changed since the preview/);
    assert.equal(h.broadcasts.length, 0);
  });
});

test("adding and removing backups: preview, emailed code, apply", { skip: !enabled }, async (t) => {
  process.env.DATABASE_URL = process.env.KEYWAY_AUTH_TEST_DATABASE_URL;

  /** Recovery turned on through the real flow, with the client then answering from the enable transaction's outputs. */
  async function enabledHarness() {
    const h = await harness();
    const preview = await recoverySetup(h.context(h.wallet), { operation: "preview", backups: [h.proof] }) as Preview;
    await recoverySetup(h.context(h.wallet), { operation: "request-email-code", backups: [h.proof], confirmationNonce: preview.confirmationNonce });
    await recoverySetup(h.context(h.wallet), { operation: "enable", backups: [h.proof], confirmationNonce: preview.confirmationNonce, emailCode: h.codeFrom() });
    await h.settle();
    const transactions = [...h.broadcasts];
    const live = () => {
      const spent = new Set(transactions.flatMap((tx) => tx.inputs.map((input) => input.previousOutput.toBytes().toString())));
      return transactions.flatMap((tx) => tx.outputs.map((cellOutput, index) => ccc.Cell.from({ outPoint: { txHash: tx.hash(), index }, cellOutput, outputData: tx.outputsData[index] })))
        .filter((cell) => !spent.has(cell.outPoint.toBytes().toString()));
    };
    Object.assign(h.client, {
      findSingletonCellByType: async (type: ccc.ScriptLike) => live().find((cell) => cell.cellOutput.type?.eq(ccc.Script.from(type))),
      findCellsByLock: async function* (lock: ccc.ScriptLike) { for (const cell of live()) if (cell.cellOutput.lock.eq(ccc.Script.from(lock))) yield cell; },
    });
    await h.client.cache.recordCells(transactions.flatMap((tx) => tx.outputs.map((cellOutput, index) => ({ outPoint: { txHash: tx.hash(), index }, cellOutput, outputData: tx.outputsData[index] }))));
    h.emails.length = 0;
    const apply = async (body: Record<string, unknown>) => {
      const wallet = await readWallet(h.user) as ReadyWallet;
      const shown = await recoveryBackupChange(h.context(wallet), { ...body, operation: "preview" }) as { preview: { feeCkb: string; backups: unknown[] }; confirmationNonce: string; requiresEmailCode: boolean };
      await recoveryBackupChange(h.context(wallet), { ...body, operation: "request-email-code", confirmationNonce: shown.confirmationNonce });
      const result = await recoveryBackupChange(h.context(wallet), { ...body, operation: "apply", confirmationNonce: shown.confirmationNonce, emailCode: h.codeFrom() }) as { transactionHash: string };
      transactions.push(h.broadcasts.at(-1)!);
      await h.settle();
      return { shown, result };
    };
    return { ...h, apply, transactions };
  }

  await t.test("adds a backup with its signature and the emailed code, keeping the address", async () => {
    const h = await enabledHarness();
    const enabledWallet = await readWallet(h.user) as ReadyWallet;
    const second = evmWallet();
    const proof = h.sign(second);
    const backup = { kind: "evm" as const, address: second.address };
    const preview = await recoveryBackupChange(h.context(enabledWallet), { operation: "preview", change: "add", backup: proof }) as { preview: { backups: unknown[] }; confirmationNonce: string; requiresEmailCode: boolean };
    assert.equal(preview.requiresEmailCode, true);
    assert.equal(preview.preview.backups.length, 2);
    await assert.rejects(recoveryBackupChange(h.context(enabledWallet), { operation: "apply", change: "add", backup: proof, confirmationNonce: preview.confirmationNonce, emailCode: "123456" }), /expired/);
    await recoveryBackupChange(h.context(enabledWallet), { operation: "request-email-code", change: "add", backup: proof, confirmationNonce: preview.confirmationNonce });
    assert.match(h.emails.at(-1)!.subject, /Add a recovery backup/);
    assert.match(h.emails.at(-1)!.plaintext, new RegExp(`Adding: EVM wallet ${second.address.slice(0, 10)}`));
    assert.match(h.emails.at(-1)!.plaintext, /move everything in your account without KeyWay/);
    // Without the backup's own signature, or with another one, nothing is applied.
    await assert.rejects(recoveryBackupChange(h.context(enabledWallet), { operation: "apply", change: "add", backup, confirmationNonce: preview.confirmationNonce, emailCode: h.codeFrom() }), /approval request is invalid/);
    await assert.rejects(recoveryBackupChange(h.context(enabledWallet), { operation: "apply", change: "add", backup: { ...proof, signature: h.proof.signature }, confirmationNonce: preview.confirmationNonce, emailCode: h.codeFrom() }), /didn't sign/);
    const before = h.broadcasts.length;
    const result = await recoveryBackupChange(h.context(enabledWallet), { operation: "apply", change: "add", backup: proof, confirmationNonce: preview.confirmationNonce, emailCode: h.codeFrom() }) as { transactionHash: string };
    assert.equal(h.broadcasts.length, before + 1);
    // The list only changes, and the notice only goes out, once the transaction is committed.
    assert.deepEqual((await readWallet(h.user) as ReadyWallet).recovery?.backups, [{ kind: "evm", address: h.proof.address }]);
    assert.doesNotMatch(h.emails.at(-1)!.subject, /A recovery backup was added/);
    await h.settle();
    const stored = await readWallet(h.user) as ReadyWallet;
    assert.equal(stored.ckbAddress, enabledWallet.ckbAddress, "the address doesn't change");
    assert.match(h.emails.at(-1)!.subject, /A recovery backup was added/);
    assert.ok(h.emails.at(-1)!.plaintext.includes(stored.ckbAddress));
    assert.deepEqual(stored.recovery?.backups, [{ kind: "evm", address: h.proof.address }, backup]);
    assert.deepEqual(stored.recovery?.adminListOutPoint, { txHash: result.transactionHash, index: 0 });
    assert.equal(stored.recovery?.omnilockArgs, enabledWallet.recovery?.omnilockArgs);
    // The owner path on both groups, the list's owner-only lock and the account's Omnilock: 85-byte witnesses
    // signed by the account key.
    assert.equal(ccc.bytesFrom(h.broadcasts.at(-1)!.getWitnessArgsAt(0)!.lock!).length, 85);
    assert.equal(ccc.bytesFrom(h.broadcasts.at(-1)!.getWitnessArgsAt(1)!.lock!).length, 85);
  });

  await t.test("removes a backup with the emailed code and refuses removing the last one", async () => {
    const h = await enabledHarness();
    await assert.rejects(recoveryBackupChange(h.context(await readWallet(h.user) as ReadyWallet), { operation: "preview", change: "remove", backup: { kind: "evm", address: h.proof.address } }), /Keep at least one backup/);
    const second = evmWallet();
    const backup = { kind: "evm" as const, address: second.address };
    await h.apply({ change: "add", backup: h.sign(second) });
    const { shown } = await h.apply({ change: "remove", backup: { kind: "evm", address: h.proof.address } });
    assert.equal(shown.requiresEmailCode, true);
    assert.match(h.emails.at(-2)!.subject, /Remove a recovery backup/);
    assert.match(h.emails.at(-2)!.plaintext, new RegExp(`Removing: EVM wallet ${h.proof.address.slice(0, 10)}`));
    assert.match(h.emails.at(-1)!.subject, /A recovery backup was removed/);
    assert.ok(h.emails.at(-1)!.plaintext.includes((await readWallet(h.user) as ReadyWallet).ckbAddress));
    assert.ok(h.emails.at(-1)!.plaintext.includes(`EVM wallet ${second.address}`) && !h.emails.at(-1)!.plaintext.includes(h.proof.address));
    assert.deepEqual((await readWallet(h.user) as ReadyWallet).recovery?.backups, [backup]);
  });

  await t.test("a backup change lives as long as its code, and says plainly once it expired", async () => {
    const h = await enabledHarness();
    const wallet = await readWallet(h.user) as ReadyWallet;
    const proof = h.sign(evmWallet());
    const body = { change: "add", backup: proof };
    const ask = async () => {
      const preview = await recoveryBackupChange(h.context(wallet), { ...body, operation: "preview" }) as { confirmationNonce: string };
      const sent = await recoveryBackupChange(h.context(wallet), { ...body, operation: "request-email-code", confirmationNonce: preview.confirmationNonce }) as { sentTo: string };
      assert.equal(sent.sentTo, "ana@acmepay.example");
      return preview.confirmationNonce;
    };
    const expired = await ask();
    await age(expired, 11);
    await assert.rejects(recoveryBackupChange(h.context(wallet), { ...body, operation: "request-email-code", confirmationNonce: expired }), EXPIRED);
    await assert.rejects(recoveryBackupChange(h.context(wallet), { ...body, operation: "apply", confirmationNonce: expired, emailCode: h.codeFrom() }), EXPIRED);
    const late = await ask();
    await age(late, 6);
    await recoveryBackupChange(h.context(wallet), { ...body, operation: "request-email-code", confirmationNonce: late });
    await age(late, 9);
    const before = h.broadcasts.length;
    await recoveryBackupChange(h.context(wallet), { ...body, operation: "apply", confirmationNonce: late, emailCode: h.codeFrom() });
    assert.equal(h.broadcasts.length, before + 1);
  });

  await t.test("needs the code even when a daily amount is set", async () => {
    const h = await enabledHarness();
    const wallet = await readWallet(h.user) as ReadyWallet;
    await signingSettings(h.context(wallet), { operation: "set-daily-amount", asset: "ckb", amount: (1_000_000n * CKB).toString() });
    const proof = h.sign(evmWallet());
    const preview = await recoveryBackupChange(h.context(wallet), { operation: "preview", change: "add", backup: proof }) as { confirmationNonce: string; requiresEmailCode: boolean };
    assert.equal(preview.requiresEmailCode, true);
    await assert.rejects(recoveryBackupChange(h.context(wallet), { operation: "apply", change: "add", backup: proof, confirmationNonce: preview.confirmationNonce }), /expired|six-digit/);
  });
});

test("with the policy Action: Lit emails the code, binds the email on chain, and checks the code itself", { skip: !enabled }, async (t) => {
  process.env.DATABASE_URL = process.env.KEYWAY_AUTH_TEST_DATABASE_URL;
  process.env.LIT_USAGE_API_KEY ??= "test-usage-key";
  process.env.RESEND_API_KEY ??= "re_test_sending_key";
  const previous = { signer: litSignerOverride.mode, run: litPolicyRunner.run };
  litSignerOverride.mode = "policy";
  t.after(() => {
    litSignerOverride.mode = previous.signer;
    litPolicyRunner.run = previous.run;
  });

  const h = await harness();
  const pkpId = ccc.hexFrom(keccak_256(secp256k1.getPublicKey(h.privateKey, false).slice(1)).slice(12));
  const wallet = { ...h.wallet, litPkpId: pkpId };
  await saveWallet(h.user, wallet);
  const lit = fakeLit({ privateKey: h.privateKey, pkpId, lookup: (hash) => {
    const found = h.chain.get(hash);
    return found ? { tx: found.transaction, status: found.status } : undefined;
  }, transactions: () => [...h.chain.values()].map(({ transaction }) => transaction) });
  litPolicyRunner.run = await lit.runner();
  // No digest signer: everything goes through the Action.
  const context = (current: ReadyWallet): RecoveryContext => {
    const { signDigest: _none, ...rest } = h.context(current);
    return rest;
  };

  const preview = await recoverySetup(context(wallet), { operation: "preview", backups: [h.proof] }) as Preview;
  const nonce = preview.confirmationNonce;
  const sent = await recoverySetup(context(wallet), { operation: "request-email-code", backups: [h.proof], confirmationNonce: nonce }) as { sentTo: string; codeLength: number };
  assert.equal(sent.codeLength, 8);
  assert.equal(sent.sentTo, "ana@acmepay.example");
  assert.equal(h.emails.length, 0, "the server sends nothing itself");
  assert.equal(lit.emails.length, 1);
  assert.deepEqual(lit.emails[0].to, ["ana@acmepay.example"]);
  const code = litCodeIn(lit.emails[0]);
  // The code never reaches the server: nothing it stored contains it.
  const sql = await database();
  const [stored] = await sql<Array<{ summary: unknown; email_code_hash: string | null }>>`select summary, email_code_hash from keyway_v2_signature_requests where nonce = ${nonce}`;
  assert.equal(stored.email_code_hash, null);
  assert.ok(!JSON.stringify(stored.summary).includes(code));

  await assert.rejects(recoverySetup(context(wallet), { operation: "enable", backups: [h.proof], confirmationNonce: nonce, emailCode: "123456" }), /eight-digit code/);
  const wrong = code === "00000000" ? "11111111" : "00000000";
  await assert.rejects(recoverySetup(context(wallet), { operation: "enable", backups: [h.proof], confirmationNonce: nonce, emailCode: wrong }), /isn't right/);
  assert.equal(h.broadcasts.length, 0);
  // A wrong code doesn't use up the request.
  const result = await recoverySetup(context(wallet), { operation: "enable", backups: [h.proof], confirmationNonce: nonce, emailCode: code }) as { transactionHash: string };
  assert.equal(result.transactionHash, preview.preview.transactionHash, "the binding doesn't change the transaction hash");
  assert.equal(h.broadcasts.length, 1);
  const enable = h.broadcasts[0];
  // Witness 0 holds only the 37-byte fingerprint of the address, never the address.
  assert.equal(ccc.bytesFrom(enable.getWitnessArgsAt(0)!.inputType!).length, 37);
  await h.settle();
  const enabled = await readWallet(h.user) as ReadyWallet;
  assert.equal(enabled.recovery?.litEmailBound, true);

  // Adding a backup: the code goes to the bound address, through Lit.
  const live = () => {
    const transactions = h.broadcasts;
    const spent = new Set(transactions.flatMap((tx) => tx.inputs.map((input) => input.previousOutput.toBytes().toString())));
    return transactions.flatMap((tx) => tx.outputs.map((cellOutput, index) => ccc.Cell.from({ outPoint: { txHash: tx.hash(), index }, cellOutput, outputData: tx.outputsData[index] })))
      .filter((cell) => !spent.has(cell.outPoint.toBytes().toString()));
  };
  Object.assign(h.client, {
    findSingletonCellByType: async (type: ccc.ScriptLike) => live().find((cell) => cell.cellOutput.type?.eq(ccc.Script.from(type))),
    findCellsByLock: async function* (lock: ccc.ScriptLike) { for (const cell of live()) if (cell.cellOutput.lock.eq(ccc.Script.from(lock))) yield cell; },
  });
  await h.client.cache.recordCells(enable.outputs.map((cellOutput, index) => ({ outPoint: { txHash: enable.hash(), index }, cellOutput, outputData: enable.outputsData[index] })));
  const second = evmWallet();
  const proof = h.sign(second);
  const change = await recoveryBackupChange(context(enabled), { operation: "preview", change: "add", backup: proof }) as { confirmationNonce: string };
  const asked = await recoveryBackupChange(context(enabled), { operation: "request-email-code", change: "add", backup: proof, confirmationNonce: change.confirmationNonce }) as { codeLength: number };
  assert.equal(asked.codeLength, 8);
  assert.equal(lit.emails.length, 2);
  assert.deepEqual(lit.emails[1].to, ["ana@acmepay.example"]);
  assert.match(lit.emails[1].text, /Add a recovery backup/);
  const applied = await recoveryBackupChange(context(enabled), { operation: "apply", change: "add", backup: proof, confirmationNonce: change.confirmationNonce, emailCode: litCodeIn(lit.emails[1]) }) as { transactionHash: string };
  assert.equal(h.broadcasts.at(-1)!.hash(), applied.transactionHash);
  assert.equal(ccc.bytesFrom(h.broadcasts.at(-1)!.getWitnessArgsAt(0)!.lock!).length, 85);
  const recordLatest = async () => h.client.cache.recordCells(h.broadcasts.at(-1)!.outputs.map((cellOutput, index) => ({ outPoint: { txHash: h.broadcasts.at(-1)!.hash(), index }, cellOutput, outputData: h.broadcasts.at(-1)!.outputsData[index] })));
  /** Runs a backup change through preview, the Action's code and apply, and returns the code email. */
  const changeThroughLit = async (current: ReadyWallet, body: Record<string, unknown>) => {
    const opened = await recoveryBackupChange(context(current), { operation: "preview", ...body }) as { confirmationNonce: string };
    await recoveryBackupChange(context(current), { operation: "request-email-code", ...body, confirmationNonce: opened.confirmationNonce });
    const email = lit.emails.at(-1)!;
    await recoveryBackupChange(context(current), { operation: "apply", ...body, confirmationNonce: opened.confirmationNonce, emailCode: litCodeIn(email) });
    await h.settle();
    await recordLatest();
    return { email, wallet: await readWallet(h.user) as ReadyWallet };
  };
  // The record on chain holds only the salted auths of exactly the stored backups.
  const onChainAuths = () => decodeRecoveryList(recoveryListRecordOf(h.broadcasts.at(-1)!, 0)!);
  const saltedAuths = async (current: ReadyWallet) => Promise.all(current.recovery!.backups!.map((backup) => backupAuth(h.client, backup, current.recovery!.adminListTypeHash)));
  await h.settle();
  await recordLatest();
  let current = await readWallet(h.user) as ReadyWallet;
  assert.deepEqual(onChainAuths(), await saltedAuths(current));

  // A JoyID passkey (the proof the cross-origin-isolated popup or redirect returns) is added through the Action too,
  // which names it by its key id; the record names neither backup.
  const joy = await joyIdWallet(h.client);
  const joyBackup = { kind: "joyid" as const, address: joy.address };
  const { challengeNonce } = issueBackupChallenge(h.user);
  const joyProof = { ...joyBackup, challengeNonce, ...joy.sign(recoveryBackupChallenge(h.legacyAddress, joyBackup, challengeNonce)) };
  const added = await changeThroughLit(current, { change: "add", backup: joyProof });
  assert.match(added.email.text, new RegExp(`Adding: JoyID passkey \\(key id ${ccc.hexFrom(ccc.hashCkbShort(joy.publicKey))}\\)`));
  assert.match(added.email.text, /Backups after this change: 3/);
  current = added.wallet;
  assert.equal(current.recovery!.backups!.length, 3);
  assert.deepEqual(onChainAuths(), await saltedAuths(current));
  assert.ok(!ccc.hexFrom(recoveryListRecordOf(h.broadcasts.at(-1)!, 0)!).includes(ccc.hexFrom(ccc.hashCkbShort(joy.publicKey)).slice(2)));

  // Removing a backup also needs the Action's code, sent to the bound address.
  const removed = await changeThroughLit(current, { change: "remove", backup: { kind: "evm", address: second.address } });
  assert.deepEqual(removed.email.to, ["ana@acmepay.example"]);
  assert.match(removed.email.text, new RegExp(`Removing: EVM wallet ${second.address}`));
  assert.match(removed.email.text, /Backups after this change: 2/);
  current = removed.wallet;
  assert.deepEqual(current.recovery!.backups!.map((backup) => backup.kind), ["evm", "joyid"]);
  assert.deepEqual(onChainAuths(), await saltedAuths(current));

  // A request opened under one signer can't be finished under the other: the user is asked to start again.
  const updated = current;
  const third = h.sign(evmWallet());
  litSignerOverride.mode = "digest";
  const opened = await recoveryBackupChange(context(updated), { operation: "preview", change: "add", backup: third }) as { confirmationNonce: string };
  litSignerOverride.mode = "policy";
  await assert.rejects(recoveryBackupChange(context(updated), { operation: "request-email-code", change: "add", backup: third, confirmationNonce: opened.confirmationNonce }), /switched signers/);
  await assert.rejects(recoveryBackupChange(context(updated), { operation: "apply", change: "add", backup: third, confirmationNonce: opened.confirmationNonce, emailCode: "12345678" }), /switched signers/);
});
