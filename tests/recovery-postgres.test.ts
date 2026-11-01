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
import { issueBackupChallenge, recoveryBackupChange, recoverySetup, settleRecoveryChange, type RecoveryContext } from "../src/server/recovery.ts";
import { readWallet, saveWallet, type ReadyWallet } from "../src/server/user-wallet.ts";

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
  return { user, wallet, legacyAddress, publicKey, client, context, emails, broadcasts, proof, sign, settle, chain, addCell, codeFrom: () => /code is (\d{6})/.exec(emails.findLast(({ plaintext }) => /code is \d{6}/.test(plaintext))!.plaintext)![1] };
}

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
