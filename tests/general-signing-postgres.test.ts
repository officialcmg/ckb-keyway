import assert from "node:assert/strict";
import test from "node:test";
import * as ccc from "@ckb-ccc/core";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { formatCkbSignature, type ValidatedFunding } from "../src/server/funding-transaction.ts";
import { fundingSigning, type FundingContext } from "../src/server/funding-signing.ts";
import { database } from "../src/server/database.ts";
import { countLitCodeAttempt, issueRequest, loadRequest, messageSigning, outflowNeedsEmailCode, recordLitCode, reserveOutflow, signingSettings, transactionSigning, type SigningContext } from "../src/server/general-signing.ts";
import type { ValidatedTransaction } from "../src/server/transaction-policy.ts";
import type { ReadyWallet } from "../src/server/user-wallet.ts";

const enabled = Boolean(process.env.KEYWAY_AUTH_TEST_DATABASE_URL);
const CKB = 100_000_000n;
const RUSD = `0x${"ee".repeat(32)}`;
const privateKey = secp256k1.utils.randomSecretKey();
const publicKey = ccc.hexFrom(secp256k1.getPublicKey(privateKey, true));

function signWithKey(digest: ccc.Hex): ccc.Hex {
  const raw = secp256k1.sign(ccc.bytesFrom(digest), privateKey, { prehash: false, format: "recovered" });
  return formatCkbSignature({ recoveryParam: raw[0] as 0 | 1, r: ccc.hexFrom(raw.slice(1, 33)), s: ccc.hexFrom(raw.slice(33, 65)) });
}

function harness(outflow: bigint, tokenOutflows: Array<{ asset: string; amount: bigint }> = []) {
  const emails: Array<{ to: string; subject: string; plaintext: string }> = [];
  const user = { id: crypto.randomUUID() };
  const wallet = { litPkpId: `0x${"11".repeat(20)}`, litPublicKey: publicKey, status: "ready" } as unknown as ReadyWallet;
  const preview = async (_wallet: ReadyWallet, input: unknown): Promise<ValidatedTransaction> => {
    const transaction = ccc.Transaction.from(input as ccc.TransactionLike);
    Object.assign(transaction, { getSignHashInfo: async () => ({ message: ccc.hexFrom(`0x${"ab".repeat(32)}`), position: 0 }) });
    const script = ccc.Script.from({ codeHash: `0x${"9b".repeat(32)}`, hashType: "type", args: "0x" });
    return {
      transaction,
      signer: { client: new ccc.ClientPublicTestnet() } as unknown as ccc.SignerCkbPublicKey,
      script,
      groups: [{ script, kind: "secp256k1" }],
      preview: {
        network: "CKB testnet", sendingCkb: "100", receivingCkb: "0", feeCkb: "0.00001", tokens: [], nfts: [], dao: [],
        recipients: [{ address: "ckt1qtest", kind: "wallet", walletType: "standard", ckb: "100", tokens: [], nfts: [] }],
        unrecognized: [], otherSigners: 0, details: { inputs: [], outputs: [] }, transactionHash: transaction.hash(),
      },
      outflowShannons: outflow,
      tokensLeaving: tokenOutflows.length > 0,
      tokenOutflows,
    };
  };
  const context: SigningContext = {
    user,
    wallet,
    appName: "Acme Pay",
    email: async () => "ana@acmepay.example",
    sendEmail: async (to, message) => { emails.push({ to, subject: message.subject, plaintext: message.plaintext }); },
    rateLimit: async () => ({ allowed: true, retryAfter: null }),
    recordSigning: async () => undefined,
    preview,
    signDigest: async (digest) => signWithKey(digest),
  };
  return { context, emails, codeFrom: () => /code is (\d{6})/.exec(emails.at(-1)!.plaintext)![1] };
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

/** Channel funding with the preview and signer replaced: `debit` is the CKB leaving the account, fee included. */
function fundingHarness(user: { id: string }, emails: Array<{ subject: string; plaintext: string }>) {
  const wallet = { litPkpId: `0x${"11".repeat(20)}`, litPublicKey: publicKey, status: "ready" } as unknown as ReadyWallet;
  let debit = 0n;
  const context: FundingContext = {
    user,
    wallet,
    appName: "Acme Pay",
    email: async () => "ana@acmepay.example",
    sendEmail: async (_to, message) => { emails.push({ subject: message.subject, plaintext: message.plaintext }); },
    rateLimit: async () => ({ allowed: true, retryAfter: null }),
    recordSigning: async () => undefined,
    preview: async (_wallet, input) => {
      const transaction = ccc.Transaction.from(input as ccc.TransactionLike);
      const script = ccc.Script.from({ codeHash: `0x${"9b".repeat(32)}`, hashType: "type", args: "0x" });
      return {
        transaction,
        signer: { client: new ccc.ClientPublicTestnet() } as unknown as ccc.SignerCkbPublicKey,
        script,
        groups: [{ script, kind: "secp256k1" }],
        preview: { amountCkb: ccc.fixedPointToString(debit - 10_000n, 8), feeCkb: "0.0001", destination: `0x6c67887fe201ee0c7853f1682c0b77c0e6214044c156c7558269390a8afa6d7c:0x${"cc".repeat(20)}`, transactionHash: transaction.hash() },
        outflowShannons: debit,
      } as ValidatedFunding;
    },
    sign: async (validated) => validated.transaction,
  };
  return { context, funding: (shannons: bigint, body: Record<string, unknown>) => { debit = shannons; return fundingSigning(context, body) as Promise<Record<string, unknown>>; } };
}

const tx = (marker: number) => ({ outputs: [{ lock: { codeHash: `0x${"9b".repeat(32)}`, hashType: "type", args: "0x" }, capacity: 100n * CKB + BigInt(marker) }], witnesses: ["0x"] });

test("general signing binds approvals, email codes and threshold changes", { skip: !enabled }, async (t) => {
  process.env.DATABASE_URL = process.env.KEYWAY_AUTH_TEST_DATABASE_URL;

  await t.test("signs only the exact previewed transaction, once", async () => {
    const { context } = harness(100n * CKB);
    const preview = await transactionSigning(context, { operation: "preview", transaction: tx(1) }) as { confirmationNonce: string; requiresEmailCode: boolean };
    assert.equal(preview.requiresEmailCode, false);
    await assert.rejects(() => transactionSigning(context, { operation: "sign", transaction: tx(2), confirmationNonce: preview.confirmationNonce }), /invalid or expired/);
    const signed = await transactionSigning(context, { operation: "sign", transaction: tx(1), confirmationNonce: preview.confirmationNonce }) as { transaction: unknown };
    assert.ok(signed.transaction);
    await assert.rejects(() => transactionSigning(context, { operation: "sign", transaction: tx(1), confirmationNonce: preview.confirmationNonce }), /^Error: This request expired\. Start again\.$/);
  });

  await t.test("asks for an emailed code at or above the user's threshold", async () => {
    const { context, emails, codeFrom } = harness(100n * CKB);
    await signingSettings(context, { operation: "set-daily-amount", asset: "ckb", amount: (100n * CKB).toString() });
    const preview = await transactionSigning(context, { operation: "preview", transaction: tx(3) }) as { confirmationNonce: string; requiresEmailCode: boolean };
    assert.equal(preview.requiresEmailCode, true);
    await assert.rejects(() => transactionSigning(context, { operation: "sign", transaction: tx(3), confirmationNonce: preview.confirmationNonce }), /six-digit code/);
    await transactionSigning(context, { operation: "request-email-code", transaction: tx(3), confirmationNonce: preview.confirmationNonce });
    assert.equal(emails.length, 1);
    assert.match(emails[0].subject, /Confirm a transaction in Acme Pay/);
    const wrong = codeFrom() === "000000" ? "111111" : "000000";
    await assert.rejects(() => transactionSigning(context, { operation: "sign", transaction: tx(3), confirmationNonce: preview.confirmationNonce, emailCode: wrong }), /isn't right/);
    const signed = await transactionSigning(context, { operation: "sign", transaction: tx(3), confirmationNonce: preview.confirmationNonce, emailCode: codeFrom() });
    assert.ok(signed);
  });

  await t.test("a token with no daily amount of its own has no limit, even with a CKB amount set", async () => {
    const { context } = harness(1n * CKB, [{ asset: RUSD, amount: 5n }]);
    await signingSettings(context, { operation: "set-daily-amount", asset: "ckb", amount: (1_000n * CKB).toString() });
    for (const marker of [5, 7, 8]) {
      const preview = await transactionSigning(context, { operation: "preview", transaction: tx(marker) }) as { requiresEmailCode: boolean; confirmationNonce: string };
      assert.equal(preview.requiresEmailCode, false, `transfer ${marker}`);
      await transactionSigning(context, { operation: "sign", transaction: tx(marker), confirmationNonce: preview.confirmationNonce });
    }
    const off = harness(1n * CKB, [{ asset: RUSD, amount: 5n }]);
    const free = await transactionSigning(off.context, { operation: "preview", transaction: tx(6) }) as { requiresEmailCode: boolean };
    assert.equal(free.requiresEmailCode, false);
  });

  await t.test("tokens with their own daily amount count toward it, separately from CKB", async () => {
    const { context, emails, codeFrom } = harness(1n * CKB, [{ asset: RUSD, amount: 40n }]);
    await signingSettings(context, { operation: "set-daily-amount", asset: "ckb", amount: (1_000n * CKB).toString() });
    // Giving a token its own amount limits a token that had none, so it applies at once.
    assert.deepEqual(await signingSettings(context, { operation: "set-daily-amount", asset: RUSD, amount: "100" }), {
      dailyAmounts: { ckb: (1_000n * CKB).toString(), [RUSD]: "100" },
    });
    assert.equal(emails.length, 0);
    for (const [marker, needsCode] of [[20, false], [21, false], [22, true]] as const) {
      const preview = await transactionSigning(context, { operation: "preview", transaction: tx(marker) }) as { confirmationNonce: string; requiresEmailCode: boolean };
      assert.equal(preview.requiresEmailCode, needsCode, `transfer ${marker}`);
      if (!needsCode) await transactionSigning(context, { operation: "sign", transaction: tx(marker), confirmationNonce: preview.confirmationNonce });
    }
    // Removing the token's amount leaves it with no limit: that loosens, so it needs the emailed code.
    const pending = await signingSettings(context, { operation: "set-daily-amount", asset: RUSD, amount: null }) as { requiresEmailCode: boolean; confirmationNonce: string };
    assert.equal(pending.requiresEmailCode, true);
    assert.match(emails.at(-1)!.plaintext, /token 0x/);
    assert.deepEqual(await signingSettings(context, { operation: "set-daily-amount", asset: RUSD, amount: null, confirmationNonce: pending.confirmationNonce, emailCode: codeFrom() }), {
      dailyAmounts: { ckb: (1_000n * CKB).toString() },
    });
  });

  await t.test("counts everything signed in the last 24 hours toward the threshold", async () => {
    const { context } = harness(40n * CKB);
    await signingSettings(context, { operation: "set-daily-amount", asset: "ckb", amount: (100n * CKB).toString() });
    const signFree = async (marker: number) => {
      const preview = await transactionSigning(context, { operation: "preview", transaction: tx(marker) }) as { confirmationNonce: string; requiresEmailCode: boolean };
      assert.equal(preview.requiresEmailCode, false);
      await transactionSigning(context, { operation: "sign", transaction: tx(marker), confirmationNonce: preview.confirmationNonce });
    };
    await signFree(10);
    await signFree(11);
    // Signing the same transaction again doesn't count it twice.
    await signFree(11);
    const third = await transactionSigning(context, { operation: "preview", transaction: tx(12) }) as { requiresEmailCode: boolean };
    assert.equal(third.requiresEmailCode, true);
  });

  await t.test("refuses to sign without a code if the threshold tightened after the preview", async () => {
    const { context } = harness(40n * CKB);
    const preview = await transactionSigning(context, { operation: "preview", transaction: tx(13) }) as { confirmationNonce: string; requiresEmailCode: boolean };
    assert.equal(preview.requiresEmailCode, false);
    await signingSettings(context, { operation: "set-daily-amount", asset: "ckb", amount: (10n * CKB).toString() });
    await assert.rejects(() => transactionSigning(context, { operation: "sign", transaction: tx(13), confirmationNonce: preview.confirmationNonce }), /now needs an email code/);
  });

  await t.test("a transaction waiting on its signature already counts, so an overlapping one can't slip under the amount", async () => {
    const { context } = harness(60n * CKB);
    await signingSettings(context, { operation: "set-daily-amount", asset: "ckb", amount: (100n * CKB).toString() });
    const signDigest = context.signDigest!;
    let resume!: () => void;
    let entered!: () => void;
    const signing = new Promise<void>((resolve) => { entered = resolve; });
    const held = new Promise<void>((resolve) => { resume = resolve; });
    context.signDigest = async (digest, wallet) => { entered(); await held; return signDigest(digest, wallet); };
    const first = await transactionSigning(context, { operation: "preview", transaction: tx(50) }) as { confirmationNonce: string; requiresEmailCode: boolean };
    assert.equal(first.requiresEmailCode, false);
    const firstSigned = transactionSigning(context, { operation: "sign", transaction: tx(50), confirmationNonce: first.confirmationNonce });
    await signing;
    context.signDigest = signDigest;
    // The first 60 CKB is still being signed; another 60 CKB reaches the 100 CKB amount.
    const second = await transactionSigning(context, { operation: "preview", transaction: tx(51) }) as { confirmationNonce: string; requiresEmailCode: boolean };
    assert.equal(second.requiresEmailCode, true);
    resume();
    await firstSigned;
  });

  await t.test("a failed signature doesn't count, and doesn't remove the count of an earlier signature of the same transaction", async () => {
    const { context } = harness(60n * CKB);
    await signingSettings(context, { operation: "set-daily-amount", asset: "ckb", amount: (100n * CKB).toString() });
    const signDigest = context.signDigest!;
    const failing = async () => { throw new Error("Lit is unavailable"); };
    const attempt = async (marker: number) => {
      const preview = await transactionSigning(context, { operation: "preview", transaction: tx(marker) }) as { confirmationNonce: string; requiresEmailCode: boolean };
      assert.equal(preview.requiresEmailCode, false, `transaction ${marker}`);
      return transactionSigning(context, { operation: "sign", transaction: tx(marker), confirmationNonce: preview.confirmationNonce });
    };
    context.signDigest = failing;
    await assert.rejects(() => attempt(52), /Lit is unavailable/);
    context.signDigest = signDigest;
    await attempt(53);
    context.signDigest = failing;
    await assert.rejects(() => attempt(53), /Lit is unavailable/);
    context.signDigest = signDigest;
    const after = await transactionSigning(context, { operation: "preview", transaction: tx(54) }) as { requiresEmailCode: boolean };
    assert.equal(after.requiresEmailCode, true);
  });

  await t.test("of two overlapping attempts at one outflow, the one that fails leaves the other's count in place", async () => {
    const { context } = harness(60n * CKB);
    await signingSettings(context, { operation: "set-daily-amount", asset: "ckb", amount: (100n * CKB).toString() });
    const outflow = { id: `0x${"5a".repeat(32)}`, shannons: 60n * CKB, tokens: [] };
    const failed = await reserveOutflow(context.user, outflow, false, "transaction");
    await reserveOutflow(context.user, outflow, false, "transaction");
    // The first attempt fails after the second counted the same outflow again; the second goes on to sign.
    await failed();
    assert.equal(await outflowNeedsEmailCode(context.user, { id: "next", shannons: 60n * CKB, tokens: [] }), true);
  });

  await t.test("channel funding counts toward the daily amount, and past it needs the emailed code", async () => {
    const emails: Array<{ subject: string; plaintext: string }> = [];
    const { context: send } = harness(500n * CKB);
    const { funding } = fundingHarness(send.user, emails);
    await signingSettings(send, { operation: "set-daily-amount", asset: "ckb", amount: (1_000n * CKB).toString() });

    // 2,000 CKB is over the amount: the preview asks for the code, and signing without it is refused.
    const big = await funding(2_000n * CKB, { operation: "preview", transaction: tx(60) });
    assert.equal(big.requiresEmailCode, true);
    await assert.rejects(() => funding(2_000n * CKB, { operation: "sign", transaction: tx(60), confirmationNonce: big.confirmationNonce }));
    const sent = await funding(2_000n * CKB, { operation: "request-email-code", transaction: tx(60), confirmationNonce: big.confirmationNonce });
    assert.equal(sent.sentTo, "ana@acmepay.example");
    assert.match(emails.at(-1)!.subject, /Confirm a channel opening in Acme Pay/);
    assert.match(emails.at(-1)!.plaintext, /1999\.9999 CKB/);
    const code = /code is (\d{6})/.exec(emails.at(-1)!.plaintext)![1];
    assert.ok((await funding(2_000n * CKB, { operation: "sign", transaction: tx(60), confirmationNonce: big.confirmationNonce, emailCode: code })).transaction);

    // Under the amount it signs without a code, and counts: a send that then reaches the amount needs the code.
    const other = harness(500n * CKB);
    const small = fundingHarness(other.context.user, emails);
    await signingSettings(other.context, { operation: "set-daily-amount", asset: "ckb", amount: (1_000n * CKB).toString() });
    const preview = await small.funding(600n * CKB, { operation: "preview", transaction: tx(61) });
    assert.ok(!preview.requiresEmailCode);
    await small.funding(600n * CKB, { operation: "sign", transaction: tx(61), confirmationNonce: preview.confirmationNonce });
    const after = await transactionSigning(other.context, { operation: "preview", transaction: tx(62) }) as { requiresEmailCode: boolean };
    assert.equal(after.requiresEmailCode, true);
  });

  await t.test("stops after five wrong codes", async () => {
    const { context, codeFrom } = harness(100n * CKB);
    await signingSettings(context, { operation: "set-daily-amount", asset: "ckb", amount: "1" });
    const preview = await transactionSigning(context, { operation: "preview", transaction: tx(4) }) as { confirmationNonce: string };
    await transactionSigning(context, { operation: "request-email-code", transaction: tx(4), confirmationNonce: preview.confirmationNonce });
    const wrong = codeFrom() === "000000" ? "111111" : "000000";
    for (let attempt = 0; attempt < 5; attempt++) {
      await assert.rejects(() => transactionSigning(context, { operation: "sign", transaction: tx(4), confirmationNonce: preview.confirmationNonce, emailCode: wrong }));
    }
    await assert.rejects(() => transactionSigning(context, { operation: "sign", transaction: tx(4), confirmationNonce: preview.confirmationNonce, emailCode: codeFrom() }), /Too many wrong codes/);
  });

  await t.test("strengthening applies at once; weakening needs the emailed code", async () => {
    const { context, emails, codeFrom } = harness(0n);
    assert.deepEqual(await signingSettings(context, { operation: "set-daily-amount", asset: "ckb", amount: (500n * CKB).toString() }), { dailyAmounts: { ckb: (500n * CKB).toString() } });
    assert.deepEqual(await signingSettings(context, { operation: "set-daily-amount", asset: "ckb", amount: (100n * CKB).toString() }), { dailyAmounts: { ckb: (100n * CKB).toString() } });
    assert.equal(emails.length, 0);
    const pending = await signingSettings(context, { operation: "set-daily-amount", asset: "ckb", amount: null }) as { requiresEmailCode: boolean; confirmationNonce: string };
    assert.equal(pending.requiresEmailCode, true);
    assert.match(emails[0].plaintext, /turn email confirmation off/);
    assert.deepEqual(await signingSettings(context, { operation: "get" }), { dailyAmounts: { ckb: (100n * CKB).toString() } });
    await assert.rejects(() => signingSettings(context, { operation: "set-daily-amount", asset: "ckb", amount: (900n * CKB).toString(), confirmationNonce: pending.confirmationNonce, emailCode: codeFrom() }), /invalid or expired/);
    await signingSettings(context, { operation: "set-daily-amount", asset: "ckb", amount: null, confirmationNonce: pending.confirmationNonce, emailCode: codeFrom() });
    assert.deepEqual(await signingSettings(context, { operation: "get" }), { dailyAmounts: {} });
    await assert.rejects(() => signingSettings(context, { operation: "set", emailThresholdShannons: "1" }), /valid settings operation/);
  });

  await t.test("a transaction approval lives as long as its code, and each resend extends both", async () => {
    const { context, emails, codeFrom } = harness(100n * CKB);
    await signingSettings(context, { operation: "set-daily-amount", asset: "ckb", amount: "1" });
    const sent = async (marker: number) => {
      const preview = await transactionSigning(context, { operation: "preview", transaction: tx(marker) }) as { confirmationNonce: string };
      const request = await transactionSigning(context, { operation: "request-email-code", transaction: tx(marker), confirmationNonce: preview.confirmationNonce }) as { sentTo: string };
      assert.equal(request.sentTo, "ana@acmepay.example");
      return preview.confirmationNonce;
    };
    const sign = (marker: number, confirmationNonce: string) => transactionSigning(context, { operation: "sign", transaction: tx(marker), confirmationNonce, emailCode: codeFrom() });
    const resend = (marker: number, confirmationNonce: string) => transactionSigning(context, { operation: "request-email-code", transaction: tx(marker), confirmationNonce });

    // Six minutes after the code was sent: past the old five-minute approval, within the code's ten.
    const confirmLate = await sent(30);
    await age(confirmLate, 6);
    assert.ok(await sign(30, confirmLate));

    // A resend after six minutes works, and gives the new code (and the request) ten minutes again.
    const resendLate = await sent(31);
    await age(resendLate, 6);
    await resend(31, resendLate);
    assert.equal(emails.length, 3);
    await age(resendLate, 9);
    assert.ok(await sign(31, resendLate));

    // Past the real expiry, resending and confirming both say so plainly.
    const expired = await sent(32);
    await age(expired, 11);
    await assert.rejects(() => resend(32, expired), /^Error: This request expired\. Start again\.$/);
    await assert.rejects(() => sign(32, expired), /^Error: This request expired\. Start again\.$/);
  });

  await t.test("a security change lives as long as its code", async () => {
    const { context, codeFrom } = harness(0n);
    await signingSettings(context, { operation: "set-daily-amount", asset: "ckb", amount: (100n * CKB).toString() });
    const change = (extra: Record<string, unknown> = {}) => signingSettings(context, { operation: "set-daily-amount", asset: "ckb", amount: null, ...extra });
    const pending = await change() as { confirmationNonce: string; sentTo: string };
    assert.equal(pending.sentTo, "ana@acmepay.example");
    await age(pending.confirmationNonce, 6);
    await change({ confirmationNonce: pending.confirmationNonce, emailCode: codeFrom() });
    assert.deepEqual(await signingSettings(context, { operation: "get" }), { dailyAmounts: {} });

    await signingSettings(context, { operation: "set-daily-amount", asset: "ckb", amount: (100n * CKB).toString() });
    const late = await change() as { confirmationNonce: string };
    await age(late.confirmationNonce, 11);
    await assert.rejects(() => change({ confirmationNonce: late.confirmationNonce, emailCode: codeFrom() }), /^Error: This request expired\. Start again\.$/);
  });

  await t.test("the code limit applies to resends, and a refused settings resend keeps the last code usable", async () => {
    const { context, codeFrom } = harness(0n);
    let sent = 0;
    context.rateLimit = async (key) => key.startsWith("step-up-email:") && ++sent > 5 ? { allowed: false, retryAfter: 412 } : { allowed: true, retryAfter: null };
    await signingSettings(context, { operation: "set-daily-amount", asset: "ckb", amount: (100n * CKB).toString() });
    const change = (extra: Record<string, unknown> = {}) => signingSettings(context, { operation: "set-daily-amount", asset: "ckb", amount: null, ...extra });
    let pending = await change() as { confirmationNonce: string };
    for (let resend = 0; resend < 4; resend++) pending = await change() as { confirmationNonce: string };
    await assert.rejects(change, /^Error: Too many codes sent\. Try again in 7 minutes$/);
    await change({ confirmationNonce: pending.confirmationNonce, emailCode: codeFrom() });
    assert.deepEqual(await signingSettings(context, { operation: "get" }), { dailyAmounts: {} });

    // The same limit stops transaction resends, and the request stays valid.
    const signing = harness(100n * CKB);
    await signingSettings(signing.context, { operation: "set-daily-amount", asset: "ckb", amount: "1" });
    signing.context.rateLimit = context.rateLimit;
    const preview = await transactionSigning(signing.context, { operation: "preview", transaction: tx(40) }) as { confirmationNonce: string };
    await assert.rejects(() => transactionSigning(signing.context, { operation: "request-email-code", transaction: tx(40), confirmationNonce: preview.confirmationNonce }), /Too many codes sent/);
  });

  await t.test("signs approved messages in CKB's message format", async () => {
    const { context } = harness(0n);
    const preview = await messageSigning(context, { operation: "preview", message: "Log in to Acme Pay" }) as { confirmationNonce: string; preview: { message: string } };
    assert.equal(preview.preview.message, "Log in to Acme Pay");
    await assert.rejects(() => messageSigning(context, { operation: "sign", message: "Something else", confirmationNonce: preview.confirmationNonce }), /invalid or expired/);
    const signed = await messageSigning(context, { operation: "sign", message: "Log in to Acme Pay", confirmationNonce: preview.confirmationNonce }) as { signature: string; identity: string };
    assert.equal(ccc.verifyMessageCkbSecp256k1("Log in to Acme Pay", signed.signature, signed.identity), true);
  });

  await t.test("a Lit-sent code: the ticket is kept with the request, which lives as long as the code and allows five tries", async () => {
    const user = { id: crypto.randomUUID() };
    const nonce = await issueRequest(user, "recovery", "digest", { lines: ["Turn on account recovery"] }, true);
    await assert.rejects(() => countLitCodeAttempt(user, "recovery", nonce), /expired/);
    await recordLitCode(user, "recovery", nonce, { litTicket: "v1.1.ticket", litBinding: "0x00" });
    const request = await loadRequest(user, "recovery", nonce, "digest");
    assert.deepEqual(request.summary, { lines: ["Turn on account recovery"], litTicket: "v1.1.ticket", litBinding: "0x00" });
    for (let i = 0; i < 5; i++) await countLitCodeAttempt(user, "recovery", nonce);
    await assert.rejects(() => countLitCodeAttempt(user, "recovery", nonce), /Too many wrong codes/);
    // A new code starts the count again.
    await recordLitCode(user, "recovery", nonce, { litTicket: "v1.2.ticket" });
    await countLitCodeAttempt(user, "recovery", nonce);
    assert.equal((await loadRequest(user, "recovery", nonce, "digest")).summary.litTicket, "v1.2.ticket");
    await assert.rejects(() => recordLitCode(user, "recovery", crypto.randomUUID(), {}), /expired/);
  });
});
