import assert from "node:assert/strict";
import test from "node:test";
import * as ccc from "@ckb-ccc/core";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { secp256k1Lock } from "../src/sdk/browser/account-lock.ts";
import { recoveryBackupChallenge } from "../src/sdk/browser/recovery-backups.ts";
import { database } from "../src/server/database.ts";
import { formatCkbSignature } from "../src/server/funding-transaction.ts";
import { signingSettings } from "../src/server/general-signing.ts";
import { recoveryBackupChange, recoverySetup, type RecoveryContext } from "../src/server/recovery.ts";
import { readWallet, saveWallet, type ReadyWallet } from "../src/server/user-wallet.ts";

const enabled = Boolean(process.env.KEYWAY_AUTH_TEST_DATABASE_URL);
const CKB = 100_000_000n;

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

let nextCell = 1;
async function harness() {
  const privateKey = secp256k1.utils.randomSecretKey();
  const publicKey = ccc.hexFrom(secp256k1.getPublicKey(privateKey, true));
  const client = new ccc.ClientPublicTestnet({ url: "https://testnet.ckb.dev/" });
  const secp = await secp256k1Lock(client, publicKey);
  const cells: ccc.Cell[] = [];
  const addCell = async (capacity: bigint) => {
    const cell = ccc.Cell.from({ outPoint: { txHash: `0x${(nextCell++).toString(16).padStart(64, "f")}`, index: 0 }, cellOutput: { lock: secp, capacity }, outputData: "0x" });
    await client.cache.recordCells([cell]);
    cells.push(cell);
  };
  Object.assign(client, {
    findSingletonCellByType: async () => undefined,
    findCells: async function* () {},
    findCellsByLock: async function* () { yield* cells; },
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
    broadcast: async (transaction) => { broadcasts.push(transaction); return transaction.hash(); },
  });
  const evm = evmWallet();
  const backup = { kind: "evm" as const, address: evm.address };
  const proof = { ...backup, signature: evm.personalSign(recoveryBackupChallenge(legacyAddress, backup)) };
  return { user, wallet, legacyAddress, publicKey, client, context, emails, broadcasts, proof, addCell, codeFrom: () => /code is (\d{6})/.exec(emails.at(-1)!.plaintext)![1] };
}

type Preview = { preview: { newAddress: string; adminListCkb: string; transactionHash: string }; confirmationNonce: string; requiresEmailCode: boolean };

test("turning recovery on: preview, emailed code, enable", { skip: !enabled }, async (t) => {
  process.env.DATABASE_URL = process.env.KEYWAY_AUTH_TEST_DATABASE_URL;

  await t.test("always needs the emailed code, names the backups, and stores the new lock", async () => {
    const h = await harness();
    const preview = await recoverySetup(h.context(h.wallet), { operation: "preview", backups: [h.proof] }) as Preview;
    assert.equal(preview.requiresEmailCode, true, "even with email confirmation off");
    assert.equal(preview.preview.adminListCkb, "197");
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

    const result = await recoverySetup(h.context(h.wallet), { operation: "enable", backups: [h.proof], confirmationNonce: nonce, emailCode: h.codeFrom() }) as { transactionHash: string; ckbAddress: string };
    assert.equal(h.broadcasts.length, 1);
    assert.equal(result.transactionHash, preview.preview.transactionHash);
    assert.equal(result.ckbAddress, preview.preview.newAddress);
    const stored = await readWallet(h.user) as ReadyWallet;
    assert.equal(stored.ckbAddress, preview.preview.newAddress);
    assert.equal(stored.recovery?.legacyAddress, h.legacyAddress);
    assert.deepEqual(stored.recovery?.backups, [{ kind: "evm", address: h.proof.address }]);
    assert.deepEqual(stored.recovery?.adminListOutPoint, { txHash: result.transactionHash, index: 0 });
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

  await t.test("needs the code even when a daily amount would allow the transfer", async () => {
    const h = await harness();
    await signingSettings(h.context(h.wallet), { operation: "set-daily-amount", asset: "ckb", amount: (1_000_000n * CKB).toString() });
    const preview = await recoverySetup(h.context(h.wallet), { operation: "preview", backups: [h.proof] }) as Preview;
    assert.equal(preview.requiresEmailCode, true);
    await assert.rejects(recoverySetup(h.context(h.wallet), { operation: "enable", backups: [h.proof], confirmationNonce: preview.confirmationNonce }), /expired|six-digit/);
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
    const other = evmWallet();
    const otherBackup = { kind: "evm" as const, address: other.address };
    const otherProof = { ...otherBackup, signature: other.personalSign(recoveryBackupChallenge(h.legacyAddress, otherBackup)) };
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
    const transactions = [...h.broadcasts];
    const live = () => {
      const spent = new Set(transactions.flatMap((tx) => tx.inputs.map((input) => input.previousOutput.toBytes().toString())));
      return transactions.flatMap((tx) => tx.outputs.map((cellOutput, index) => ccc.Cell.from({ outPoint: { txHash: tx.hash(), index }, cellOutput, outputData: tx.outputsData[index] })))
        .filter((cell) => !spent.has(cell.outPoint.toBytes().toString()));
    };
    Object.assign(h.client, {
      findSingletonCellByType: async (type: ccc.ScriptLike) => live().find((cell) => cell.cellOutput.type?.eq(ccc.Script.from(type))),
      findCellsByLock: async function* (lock: ccc.ScriptLike) { for (const cell of live()) if (cell.cellOutput.lock.eq(ccc.Script.from(lock))) yield cell; },
      getTransaction: async (hash: ccc.HexLike) => {
        const transaction = transactions.find((tx) => tx.hash() === ccc.hexFrom(hash));
        return transaction ? { transaction, status: "committed" } : undefined;
      },
    });
    await h.client.cache.recordCells(transactions.flatMap((tx) => tx.outputs.map((cellOutput, index) => ({ outPoint: { txHash: tx.hash(), index }, cellOutput, outputData: tx.outputsData[index] }))));
    h.emails.length = 0;
    const apply = async (body: Record<string, unknown>) => {
      const wallet = await readWallet(h.user) as ReadyWallet;
      const shown = await recoveryBackupChange(h.context(wallet), { ...body, operation: "preview" }) as { preview: { feeCkb: string; backups: unknown[] }; confirmationNonce: string; requiresEmailCode: boolean };
      await recoveryBackupChange(h.context(wallet), { ...body, operation: "request-email-code", confirmationNonce: shown.confirmationNonce });
      const result = await recoveryBackupChange(h.context(wallet), { ...body, operation: "apply", confirmationNonce: shown.confirmationNonce, emailCode: h.codeFrom() }) as { transactionHash: string };
      transactions.push(h.broadcasts.at(-1)!);
      return { shown, result };
    };
    return { ...h, apply, transactions };
  }

  await t.test("adds a backup with its signature and the emailed code, keeping the address", async () => {
    const h = await enabledHarness();
    const enabledWallet = await readWallet(h.user) as ReadyWallet;
    const second = evmWallet();
    const backup = { kind: "evm" as const, address: second.address };
    const proof = { ...backup, signature: second.personalSign(recoveryBackupChallenge(h.legacyAddress, backup)) };
    const preview = await recoveryBackupChange(h.context(enabledWallet), { operation: "preview", change: "add", backup: proof }) as { preview: { backups: unknown[] }; confirmationNonce: string; requiresEmailCode: boolean };
    assert.equal(preview.requiresEmailCode, true);
    assert.equal(preview.preview.backups.length, 2);
    await assert.rejects(recoveryBackupChange(h.context(enabledWallet), { operation: "apply", change: "add", backup: proof, confirmationNonce: preview.confirmationNonce, emailCode: "123456" }), /expired/);
    await recoveryBackupChange(h.context(enabledWallet), { operation: "request-email-code", change: "add", backup: proof, confirmationNonce: preview.confirmationNonce });
    assert.match(h.emails.at(-1)!.subject, /Add a recovery backup/);
    assert.match(h.emails.at(-1)!.plaintext, new RegExp(`Adding: EVM wallet ${second.address.slice(0, 10)}`));
    assert.match(h.emails.at(-1)!.plaintext, /move everything in your account without KeyWay/);
    // Without the backup's own signature, or with another one, nothing is applied.
    await assert.rejects(recoveryBackupChange(h.context(enabledWallet), { operation: "apply", change: "add", backup, confirmationNonce: preview.confirmationNonce, emailCode: h.codeFrom() }), /didn't sign/);
    const before = h.broadcasts.length;
    const result = await recoveryBackupChange(h.context(enabledWallet), { operation: "apply", change: "add", backup: proof, confirmationNonce: preview.confirmationNonce, emailCode: h.codeFrom() }) as { transactionHash: string };
    assert.equal(h.broadcasts.length, before + 1);
    const stored = await readWallet(h.user) as ReadyWallet;
    assert.equal(stored.ckbAddress, enabledWallet.ckbAddress, "the address doesn't change");
    assert.deepEqual(stored.recovery?.backups, [{ kind: "evm", address: h.proof.address }, backup]);
    assert.deepEqual(stored.recovery?.adminListOutPoint, { txHash: result.transactionHash, index: 0 });
    assert.equal(stored.recovery?.omnilockArgs, enabledWallet.recovery?.omnilockArgs);
    // The owner path: one 85-byte Omnilock witness signed by the account key.
    assert.equal(ccc.bytesFrom(h.broadcasts.at(-1)!.getWitnessArgsAt(0)!.lock!).length, 85);
  });

  await t.test("removes a backup with the emailed code and refuses removing the last one", async () => {
    const h = await enabledHarness();
    await assert.rejects(recoveryBackupChange(h.context(await readWallet(h.user) as ReadyWallet), { operation: "preview", change: "remove", backup: { kind: "evm", address: h.proof.address } }), /Keep at least one backup/);
    const second = evmWallet();
    const backup = { kind: "evm" as const, address: second.address };
    await h.apply({ change: "add", backup: { ...backup, signature: second.personalSign(recoveryBackupChallenge(h.legacyAddress, backup)) } });
    const { shown } = await h.apply({ change: "remove", backup: { kind: "evm", address: h.proof.address } });
    assert.equal(shown.requiresEmailCode, true);
    assert.match(h.emails.at(-1)!.subject, /Remove a recovery backup/);
    assert.match(h.emails.at(-1)!.plaintext, new RegExp(`Removing: EVM wallet ${h.proof.address.slice(0, 10)}`));
    assert.deepEqual((await readWallet(h.user) as ReadyWallet).recovery?.backups, [backup]);
  });

  await t.test("needs the code even when a daily amount is set", async () => {
    const h = await enabledHarness();
    const wallet = await readWallet(h.user) as ReadyWallet;
    await signingSettings(h.context(wallet), { operation: "set-daily-amount", asset: "ckb", amount: (1_000_000n * CKB).toString() });
    const second = evmWallet();
    const backup = { kind: "evm" as const, address: second.address };
    const proof = { ...backup, signature: second.personalSign(recoveryBackupChallenge(h.legacyAddress, backup)) };
    const preview = await recoveryBackupChange(h.context(wallet), { operation: "preview", change: "add", backup: proof }) as { confirmationNonce: string; requiresEmailCode: boolean };
    assert.equal(preview.requiresEmailCode, true);
    await assert.rejects(recoveryBackupChange(h.context(wallet), { operation: "apply", change: "add", backup: proof, confirmationNonce: preview.confirmationNonce }), /expired|six-digit/);
  });
});
