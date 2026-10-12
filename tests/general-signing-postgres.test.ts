import assert from "node:assert/strict";
import test from "node:test";
import * as ccc from "@ckb-ccc/core";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { formatCkbSignature } from "../src/server/funding-transaction.ts";
import { messageSigning, signingSettings, transactionSigning, type SigningContext } from "../src/server/general-signing.ts";
import type { ValidatedTransaction } from "../src/server/transaction-policy.ts";
import type { ReadyWallet } from "../src/server/user-wallet.ts";

const enabled = Boolean(process.env.KEYWAY_AUTH_TEST_DATABASE_URL);
const CKB = 100_000_000n;
const privateKey = secp256k1.utils.randomSecretKey();
const publicKey = ccc.hexFrom(secp256k1.getPublicKey(privateKey, true));

function signWithKey(digest: ccc.Hex): ccc.Hex {
  const raw = secp256k1.sign(ccc.bytesFrom(digest), privateKey, { prehash: false, format: "recovered" });
  return formatCkbSignature({ recoveryParam: raw[0] as 0 | 1, r: ccc.hexFrom(raw.slice(1, 33)), s: ccc.hexFrom(raw.slice(33, 65)) });
}

function harness(outflow: bigint) {
  const emails: Array<{ to: string; subject: string; plaintext: string }> = [];
  const user = { id: crypto.randomUUID() };
  const wallet = { litPkpId: `0x${"11".repeat(20)}`, litPublicKey: publicKey, status: "ready" } as unknown as ReadyWallet;
  const preview = async (_wallet: ReadyWallet, input: unknown): Promise<ValidatedTransaction> => {
    const transaction = ccc.Transaction.from(input as ccc.TransactionLike);
    Object.assign(transaction, { getSignHashInfo: async () => ({ message: ccc.hexFrom(`0x${"ab".repeat(32)}`), position: 0 }) });
    return {
      transaction,
      signer: { client: new ccc.ClientPublicTestnet() } as unknown as ccc.SignerCkbPublicKey,
      script: ccc.Script.from({ codeHash: `0x${"9b".repeat(32)}`, hashType: "type", args: "0x" }),
      preview: {
        network: "CKB testnet", sendingCkb: "100", receivingCkb: "0", feeCkb: "0.00001", tokens: [], nfts: [], dao: [],
        recipients: [{ address: "ckt1qtest", kind: "wallet", walletType: "standard", ckb: "100", tokens: [], nfts: [] }],
        unrecognized: [], otherSigners: 0, details: { inputs: [], outputs: [] }, transactionHash: transaction.hash(),
      },
      outflowShannons: outflow,
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
    await assert.rejects(() => transactionSigning(context, { operation: "sign", transaction: tx(1), confirmationNonce: preview.confirmationNonce }), /invalid or expired/);
  });

  await t.test("asks for an emailed code at or above the user's threshold", async () => {
    const { context, emails, codeFrom } = harness(100n * CKB);
    await signingSettings(context, { operation: "set", emailThresholdShannons: (100n * CKB).toString() });
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

  await t.test("stops after five wrong codes", async () => {
    const { context, codeFrom } = harness(100n * CKB);
    await signingSettings(context, { operation: "set", emailThresholdShannons: "1" });
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
    assert.deepEqual(await signingSettings(context, { operation: "set", emailThresholdShannons: (500n * CKB).toString() }), { emailThresholdShannons: (500n * CKB).toString() });
    assert.deepEqual(await signingSettings(context, { operation: "set", emailThresholdShannons: (100n * CKB).toString() }), { emailThresholdShannons: (100n * CKB).toString() });
    assert.equal(emails.length, 0);
    const pending = await signingSettings(context, { operation: "set", emailThresholdShannons: null }) as { requiresEmailCode: boolean; confirmationNonce: string };
    assert.equal(pending.requiresEmailCode, true);
    assert.match(emails[0].plaintext, /turn it off/);
    assert.deepEqual(await signingSettings(context, { operation: "get" }), { emailThresholdShannons: (100n * CKB).toString() });
    await assert.rejects(() => signingSettings(context, { operation: "set", emailThresholdShannons: (900n * CKB).toString(), confirmationNonce: pending.confirmationNonce, emailCode: codeFrom() }), /invalid or expired/);
    await signingSettings(context, { operation: "set", emailThresholdShannons: null, confirmationNonce: pending.confirmationNonce, emailCode: codeFrom() });
    assert.deepEqual(await signingSettings(context, { operation: "get" }), { emailThresholdShannons: null });
  });

  await t.test("signs approved messages in CKB's message format", async () => {
    const { context } = harness(0n);
    const preview = await messageSigning(context, { operation: "preview", message: "Log in to Acme Pay" }) as { confirmationNonce: string; preview: { message: string } };
    assert.equal(preview.preview.message, "Log in to Acme Pay");
    await assert.rejects(() => messageSigning(context, { operation: "sign", message: "Something else", confirmationNonce: preview.confirmationNonce }), /invalid or expired/);
    const signed = await messageSigning(context, { operation: "sign", message: "Log in to Acme Pay", confirmationNonce: preview.confirmationNonce }) as { signature: string; identity: string };
    assert.equal(ccc.verifyMessageCkbSecp256k1("Log in to Acme Pay", signed.signature, signed.identity), true);
  });
});
