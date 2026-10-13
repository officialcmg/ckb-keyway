import assert from "node:assert/strict";
import test from "node:test";
import { fiberPayment, type PaymentContext } from "../src/server/fiber-payments.ts";
import { signingSettings, type SigningContext } from "../src/server/general-signing.ts";

const enabled = Boolean(process.env.KEYWAY_AUTH_TEST_DATABASE_URL);
const CKB = 100_000_000n;

function harness(amount: bigint, options: { failSend?: boolean } = {}) {
  const emails: Array<{ subject: string; plaintext: string }> = [];
  const sent: unknown[] = [];
  const context: PaymentContext = {
    user: { id: crypto.randomUUID() },
    appName: "Acme Pay",
    email: async () => "ana@acmepay.example",
    sendEmail: async (_to, message) => { emails.push({ subject: message.subject, plaintext: message.plaintext }); },
    rateLimit: async () => ({ allowed: true, retryAfter: null }),
  };
  const node = {
    call: async <T>(method: string, params: Array<Record<string, unknown>> = []): Promise<T> => {
      if (method === "parse_invoice") {
        return { invoice: { amount: `0x${amount.toString(16)}`, data: { payment_hash: `0x${"ab".repeat(32)}`, attrs: [{ description: "tea" }] } } } as T;
      }
      if (method === "send_payment" && params[0]?.dry_run) return { fee: "0x0" } as T;
      if (method === "send_payment") {
        if (options.failSend) throw new Error("no route");
        sent.push(params[0]);
        return { payment_hash: `0x${"cd".repeat(32)}`, status: "Created", fee: "0x0" } as T;
      }
      throw new Error(`unexpected ${method}`);
    },
  };
  const settings = (threshold: bigint | null) => signingSettings({ ...context, wallet: {} } as unknown as SigningContext, { operation: "set", emailThresholdShannons: threshold?.toString() ?? null });
  return { context, node, emails, sent, settings, codeFrom: () => /code is (\d{6})/.exec(emails.at(-1)!.plaintext)![1] };
}

const pay = (h: ReturnType<typeof harness>, extra: Record<string, unknown>, invoice = "fibt1test") =>
  fiberPayment(h.context, h.node, { method: "sendPayment", params: { invoice }, ...extra }) as Promise<Record<string, unknown>>;

test("hosted Fiber payments: daily amount, email codes and overlapping approvals", { skip: !enabled }, async (t) => {
  process.env.DATABASE_URL = process.env.KEYWAY_AUTH_TEST_DATABASE_URL;

  await t.test("pays without a code until the 24-hour total reaches the amount, then asks for one", async () => {
    const h = harness(40n * CKB);
    await h.settings(100n * CKB);
    for (let i = 0; i < 2; i++) {
      const preview = await pay(h, { stage: "preview" });
      assert.equal(preview.requiresEmailCode, false);
      await pay(h, { stage: "send", confirmationNonce: preview.confirmationNonce });
    }
    const third = await pay(h, { stage: "preview" });
    assert.equal(third.requiresEmailCode, true);
    await assert.rejects(() => pay(h, { stage: "send", confirmationNonce: third.confirmationNonce }), /six-digit code/);
    await pay(h, { stage: "request-email-code", confirmationNonce: third.confirmationNonce });
    assert.match(h.emails[0].subject, /Confirm a payment in Acme Pay/);
    assert.match(h.emails[0].plaintext, /Pay 40 CKB for "tea"/);
    await pay(h, { stage: "send", confirmationNonce: third.confirmationNonce, emailCode: h.codeFrom() });
    assert.equal(h.sent.length, 3);
  });

  await t.test("binds each approval to the exact payment, once", async () => {
    const h = harness(1n * CKB);
    const preview = await pay(h, { stage: "preview" });
    await assert.rejects(() => pay(h, { stage: "send", confirmationNonce: preview.confirmationNonce }, "fibt1other"), /invalid or expired/);
    await pay(h, { stage: "send", confirmationNonce: preview.confirmationNonce });
    await assert.rejects(() => pay(h, { stage: "send", confirmationNonce: preview.confirmationNonce }), /invalid or expired/);
  });

  await t.test("overlapping approvals can't both slip under the amount", async () => {
    const h = harness(60n * CKB);
    await h.settings(100n * CKB);
    const first = await pay(h, { stage: "preview" });
    const second = await pay(h, { stage: "preview" });
    assert.equal(first.requiresEmailCode, false);
    assert.equal(second.requiresEmailCode, false);
    await pay(h, { stage: "send", confirmationNonce: first.confirmationNonce });
    await assert.rejects(() => pay(h, { stage: "send", confirmationNonce: second.confirmationNonce }), /now needs an email code/);
    assert.equal(h.sent.length, 1);
  });

  await t.test("a failed payment doesn't count toward the total", async () => {
    const failing = harness(60n * CKB, { failSend: true });
    await failing.settings(100n * CKB);
    const preview = await pay(failing, { stage: "preview" });
    await assert.rejects(() => pay(failing, { stage: "send", confirmationNonce: preview.confirmationNonce }), /no route/);
    const again = await pay(failing, { stage: "preview" });
    assert.equal(again.requiresEmailCode, false);
  });

  await t.test("token payments count toward the token's own amount; with none, they need the code", async () => {
    const h = harness(5n);
    const rusd = { code_hash: `0x${"11".repeat(32)}`, hash_type: "type", args: "0x" };
    const token = { method: "sendPayment", params: { invoice: "fibt1test", udt_type_script: rusd } };
    const off = await fiberPayment(h.context, h.node, { ...token, stage: "preview" }) as { requiresEmailCode: boolean; preview: { asset: string } };
    assert.equal(off.requiresEmailCode, false);
    assert.match(off.preview.asset, /^0x[0-9a-f]{64}$/);
    await h.settings(100n * CKB);
    const on = await fiberPayment(h.context, h.node, { ...token, stage: "preview" }) as { requiresEmailCode: boolean };
    assert.equal(on.requiresEmailCode, true);
  });

  await t.test("refuses payments with neither an invoice nor a keysend target", async () => {
    const h = harness(1n * CKB);
    await assert.rejects(() => fiberPayment(h.context, h.node, { method: "sendPayment", stage: "preview", params: { amount: "0x1" } }), /keysend/);
    await assert.rejects(() => fiberPayment(h.context, h.node, { method: "openChannel", stage: "preview", params: {} }), /payment method/);
  });
});
