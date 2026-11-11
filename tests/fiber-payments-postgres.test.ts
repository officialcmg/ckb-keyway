import assert from "node:assert/strict";
import test from "node:test";
import { fiberPayment, PAYMENT_STALE_MS, type PaymentContext } from "../src/server/fiber-payments.ts";
import { DEFAULT_STALE_MS, MAX_WAITING_REPEATS, runIdempotentMutation, waitingRepeatCount } from "../src/server/idempotency.ts";
import { database } from "../src/server/database.ts";
import { signingSettings, type SigningContext } from "../src/server/general-signing.ts";

const enabled = Boolean(process.env.KEYWAY_AUTH_TEST_DATABASE_URL);
const CKB = 100_000_000n;

function harness(amount: bigint, options: { failSend?: boolean; fee?: bigint } = {}) {
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
      if (method === "send_payment" && params[0]?.dry_run) return { fee: `0x${(options.fee ?? 0n).toString(16)}` } as T;
      if (method === "send_payment") {
        // As Fiber refuses: its own error, with the request's params attached as data.
        if (options.failSend) throw Object.assign(new Error("no route"), { code: -32000, data: params[0] });
        sent.push(params[0]);
        return { payment_hash: `0x${"cd".repeat(32)}`, status: "Created", fee: "0x0" } as T;
      }
      // As Fiber answers for a payment it never made (a rejected send leaves none).
      if (method === "get_payment") throw new Error(`Invalid parameter: Payment session not found: ${String(params[0]?.payment_hash)}`);
      throw new Error(`unexpected ${method}`);
    },
  };
  // The amounts as the server keeps them (a test signer, so no send-limit cell is built on chain).
  const settings = (threshold: bigint | null, asset = "ckb") => signingSettings({ ...context, wallet: {}, signDigest: async () => "0x" } as unknown as SigningContext, { operation: "set-daily-amount", asset, amount: threshold?.toString() ?? null });
  return { context, node, emails, sent, settings, codeFrom: () => /code is (\d{6})/.exec(emails.at(-1)!.plaintext)![1] };
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
    await assert.rejects(() => pay(h, { stage: "send", confirmationNonce: preview.confirmationNonce }), /This request expired\. Start again\./);
  });

  await t.test("a payment approval lives as long as its code, and each resend extends both", async () => {
    const h = harness(40n * CKB);
    await h.settings(1n);
    const sent = async () => {
      const preview = await pay(h, { stage: "preview" });
      const request = await pay(h, { stage: "request-email-code", confirmationNonce: preview.confirmationNonce });
      assert.equal(request.sentTo, "ana@acmepay.example");
      return String(preview.confirmationNonce);
    };
    const confirmLate = await sent();
    await age(confirmLate, 6);
    await pay(h, { stage: "send", confirmationNonce: confirmLate, emailCode: h.codeFrom() });

    const resendLate = await sent();
    await age(resendLate, 6);
    await pay(h, { stage: "request-email-code", confirmationNonce: resendLate });
    await age(resendLate, 9);
    await pay(h, { stage: "send", confirmationNonce: resendLate, emailCode: h.codeFrom() });
    assert.equal(h.sent.length, 2);

    const expired = await sent();
    await age(expired, 11);
    await assert.rejects(() => pay(h, { stage: "request-email-code", confirmationNonce: expired }), /^Error: This request expired\. Start again\.$/);
    await assert.rejects(() => pay(h, { stage: "send", confirmationNonce: expired, emailCode: h.codeFrom() }), /^Error: This request expired\. Start again\.$/);
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

  await t.test("a send without an idempotency key that times out stays counted, since the node may still have paid", async () => {
    const h = harness(60n * CKB);
    await h.settings(100n * CKB);
    // The node takes the payment, but the answer never arrives: the SDK reports a timeout, with no data.
    const node = { call: async <T>(method: string, params: Array<Record<string, unknown>> = []): Promise<T> => {
      if (method === "send_payment" && !params[0]?.dry_run) {
        h.sent.push(params[0]);
        throw Object.assign(new Error("Request timeout"), { code: -32000 });
      }
      return h.node.call<T>(method, params);
    } };
    const body = { method: "sendPayment", params: { invoice: "fibt1test" } };
    const first = await fiberPayment(h.context, node, { ...body, stage: "preview" }) as { requiresEmailCode: boolean; confirmationNonce: string };
    assert.equal(first.requiresEmailCode, false);
    await assert.rejects(() => fiberPayment(h.context, node, { ...body, stage: "send", confirmationNonce: first.confirmationNonce }), /outcome isn't known yet/);
    assert.equal(h.sent.length, 1);
    const second = await pay(h, { stage: "preview" });
    assert.equal(second.requiresEmailCode, true);
  });

  await t.test("token payments count toward the token's own amount; with none, they have no limit", async () => {
    const h = harness(5n);
    const rusd = { code_hash: `0x${"11".repeat(32)}`, hash_type: "type", args: "0x" };
    const token = { method: "sendPayment", params: { invoice: "fibt1test", udt_type_script: rusd } };
    const off = await fiberPayment(h.context, h.node, { ...token, stage: "preview" }) as { requiresEmailCode: boolean; preview: { asset: string } };
    assert.equal(off.requiresEmailCode, false);
    assert.match(off.preview.asset, /^0x[0-9a-f]{64}$/);
    await h.settings(100n * CKB);
    const on = await fiberPayment(h.context, h.node, { ...token, stage: "preview" }) as { requiresEmailCode: boolean };
    assert.equal(on.requiresEmailCode, false, "a CKB amount doesn't limit a token without its own");
    await h.settings(5n, off.preview.asset);
    const limited = await fiberPayment(h.context, h.node, { ...token, stage: "preview" }) as { requiresEmailCode: boolean };
    assert.equal(limited.requiresEmailCode, true, "the payment reaches the token's own amount");
  });

  await t.test("a repeated send with the same idempotency key returns the first result and pays once", async () => {
    const h = harness(10n * CKB);
    const preview = await pay(h, { stage: "preview" });
    const body = { method: "sendPayment", params: { invoice: "fibt1test" }, stage: "send", confirmationNonce: preview.confirmationNonce };
    const key = `retry-${crypto.randomUUID()}`;
    const first = await fiberPayment(h.context, h.node, body, key);
    const again = await fiberPayment(h.context, h.node, body, key);
    assert.deepEqual(again, first);
    assert.equal(h.sent.length, 1);
    // Without the key, or with another one, the used approval is refused rather than paid again.
    await assert.rejects(() => fiberPayment(h.context, h.node, body), /request expired/i);
    await assert.rejects(() => fiberPayment(h.context, h.node, body, `other-${crypto.randomUUID()}`), /request expired/i);
    assert.equal(h.sent.length, 1);
    // The same key can't be reused for another payment.
    const next = await pay(h, { stage: "preview" });
    await assert.rejects(() => fiberPayment(h.context, h.node, { ...body, confirmationNonce: next.confirmationNonce }, key), /already used for another request/);
  });

  await t.test("a repeated send after a failed payment returns the same failure and doesn't try again", async () => {
    const failing = harness(10n * CKB, { failSend: true });
    const preview = await pay(failing, { stage: "preview" });
    const body = { method: "sendPayment", params: { invoice: "fibt1test" }, stage: "send", confirmationNonce: preview.confirmationNonce };
    const key = `retry-${crypto.randomUUID()}`;
    let calls = 0;
    const node = { call: async <T>(method: string, params?: unknown[]): Promise<T> => { if (method === "send_payment") calls++; return failing.node.call<T>(method, params as never); } };
    await assert.rejects(() => fiberPayment(failing.context, node, body, key), /no route/);
    await assert.rejects(() => fiberPayment(failing.context, node, body, key), /no route/);
    assert.equal(calls, 1);
  });

  await t.test("a repeat that arrives while the first send runs waits for it and returns the same result", async () => {
    const h = harness(10n * CKB);
    const preview = await pay(h, { stage: "preview" });
    const body = { method: "sendPayment", params: { invoice: "fibt1test" }, stage: "send", confirmationNonce: preview.confirmationNonce };
    let calls = 0;
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    let entered!: () => void;
    const started = new Promise<void>((resolve) => { entered = resolve; });
    const slow = { call: async <T>(method: string, params?: unknown[]): Promise<T> => {
      if (method === "send_payment") { calls++; entered(); await gate; }
      return h.node.call<T>(method, params as never);
    } };
    const key = `retry-${crypto.randomUUID()}`;
    const first = fiberPayment(h.context, slow, body, key);
    // The repeat starts only once the first send is in flight, and is still waiting when that send is released.
    await started;
    let repeatDone = false;
    const again = fiberPayment(h.context, slow, body, key).finally(() => { repeatDone = true; });
    await new Promise((resolve) => setTimeout(resolve, 400));
    assert.equal(repeatDone, false, "the repeat waits for the running send");
    release();
    assert.deepEqual(await again, await first);
    assert.equal(calls, 1);
  });

  await t.test("a repeat that arrives while a failing send runs waits for it and returns the same failure", async () => {
    const failing = harness(10n * CKB, { failSend: true });
    const preview = await pay(failing, { stage: "preview" });
    const body = { method: "sendPayment", params: { invoice: "fibt1test" }, stage: "send", confirmationNonce: preview.confirmationNonce };
    let calls = 0;
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    let entered!: () => void;
    const started = new Promise<void>((resolve) => { entered = resolve; });
    const slow = { call: async <T>(method: string, params?: unknown[]): Promise<T> => {
      if (method === "send_payment") { calls++; entered(); await gate; }
      return failing.node.call<T>(method, params as never);
    } };
    const key = `retry-${crypto.randomUUID()}`;
    const first = fiberPayment(failing.context, slow, body, key);
    await started;
    const again = fiberPayment(failing.context, slow, body, key);
    await new Promise((resolve) => setTimeout(resolve, 300));
    release();
    await assert.rejects(first, /no route/);
    await assert.rejects(again, /no route/);
    assert.equal(calls, 1);
  });

  await t.test("only a bounded number of repeats wait for a running send; the rest answer at once and none pays", async () => {
    const h = harness(10n * CKB);
    const preview = await pay(h, { stage: "preview" });
    const body = { method: "sendPayment", params: { invoice: "fibt1test" }, stage: "send", confirmationNonce: preview.confirmationNonce };
    let calls = 0;
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    let entered!: () => void;
    const started = new Promise<void>((resolve) => { entered = resolve; });
    const slow = { call: async <T>(method: string, params?: unknown[]): Promise<T> => {
      if (method === "send_payment") { calls++; entered(); await gate; }
      return h.node.call<T>(method, params as never);
    } };
    const key = `burst-${crypto.randomUUID()}`;
    const first = fiberPayment(h.context, slow, body, key);
    await started;
    const waiting = Array.from({ length: MAX_WAITING_REPEATS }, () => fiberPayment(h.context, slow, body, key));
    // Every waiting slot is taken before the extra repeat starts.
    for (let i = 0; waitingRepeatCount() < MAX_WAITING_REPEATS; i++) {
      assert.ok(i < 200, "the repeats all start waiting");
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
    // One more repeat than may wait: it doesn't poll for 30 seconds, it says the send is still running.
    const startedAt = Date.now();
    await assert.rejects(() => fiberPayment(h.context, slow, body, key), /still in progress/);
    assert.ok(Date.now() - startedAt < 2_000, "the extra repeat answers at once");
    release();
    const result = await first;
    for (const repeat of waiting) assert.deepEqual(await repeat, result);
    assert.equal(calls, 1);
  });

  await t.test("a send whose result can't be stored still answers, and a later repeat recovers it from the node without paying again", async () => {
    const sql = await database();
    const h = harness(10n * CKB);
    const preview = await pay(h, { stage: "preview" });
    const body = { method: "sendPayment", params: { invoice: "fibt1test" }, stage: "send", confirmationNonce: preview.confirmationNonce };
    const hash = `0x${"ab".repeat(32)}`;
    let sends = 0;
    let createdAt = 0;
    const node = { call: async <T>(method: string, params: Array<Record<string, unknown>> = []): Promise<T> => {
      if (method === "send_payment" && !params[0]?.dry_run) { sends++; createdAt = Date.now(); return { payment_hash: hash, status: "Created", fee: "0x0", created_at: `0x${createdAt.toString(16)}` } as T; }
      if (method === "get_payment") {
        assert.equal(params[0]?.payment_hash, hash);
        if (!createdAt) throw new Error("Payment session not found");
        return { payment_hash: hash, status: "Success", fee: "0x0", created_at: `0x${createdAt.toString(16)}` } as T;
      }
      return h.node.call<T>(method, params);
    } };
    const key = `nostore-${crypto.randomUUID()}`;
    // The database refuses to store this key's result, as if it failed right after the payment went through.
    await sql.unsafe(`
      create or replace function keyway_test_refuse_completion() returns trigger language plpgsql as $$
      begin
        if new.status = 'completed' and new.idempotency_key like 'nostore-%' then raise exception 'storage is down'; end if;
        return new;
      end $$;
      drop trigger if exists keyway_test_refuse_completion on keyway_v2_idempotency_keys;
      create trigger keyway_test_refuse_completion before update on keyway_v2_idempotency_keys
        for each row execute function keyway_test_refuse_completion();
    `);
    let first: Record<string, unknown>;
    try {
      first = await fiberPayment(h.context, node, body, key) as Record<string, unknown>;
    } finally {
      await sql.unsafe(`drop trigger if exists keyway_test_refuse_completion on keyway_v2_idempotency_keys; drop function if exists keyway_test_refuse_completion();`);
    }
    assert.equal(first.payment_hash, hash);
    const [row] = await sql<Array<{ status: string }>>`select status from keyway_v2_idempotency_keys where user_id = ${h.context.user.id} and idempotency_key = ${key}`;
    assert.equal(row.status, "running", "an unstored success is never recorded as a failure");
    // A minute on (the process could equally have exited after paying), a repeat asks the node and stores what it says.
    await sql`update keyway_v2_idempotency_keys set updated_at = now() - ${`${PAYMENT_STALE_MS + 1_000} milliseconds`}::interval where user_id = ${h.context.user.id} and idempotency_key = ${key}`;
    const again = await fiberPayment(h.context, node, body, key) as Record<string, unknown>;
    assert.equal(again.payment_hash, hash);
    assert.equal(again.status, "Success");
    assert.deepEqual(await fiberPayment(h.context, node, body, key), again);
    assert.equal(sends, 1);
  });

  await t.test("a stale send is only matched to a payment the node made after it began, and a keysend is never guessed", async () => {
    const sql = await database();
    const stale = async (h: ReturnType<typeof harness>, key: string) => {
      await sql`
        update keyway_v2_idempotency_keys set updated_at = now() - ${`${PAYMENT_STALE_MS + 1_000} milliseconds`}::interval
        where user_id = ${h.context.user.id} and idempotency_key = ${key}
      `;
    };
    // An invoice paid long ago: the node's old payment of the same hash isn't this send's outcome.
    const h = harness(10n * CKB);
    const preview = await pay(h, { stage: "preview" });
    const body = { method: "sendPayment", params: { invoice: "fibt1test" }, stage: "send", confirmationNonce: preview.confirmationNonce };
    let sends = 0;
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    let entered!: () => void;
    const started = new Promise<void>((resolve) => { entered = resolve; });
    const old = `0x${(Date.now() - 60 * 60_000).toString(16)}`;
    const node = { call: async <T>(method: string, params: Array<Record<string, unknown>> = []): Promise<T> => {
      if (method === "send_payment" && !params[0]?.dry_run) { sends++; entered(); await gate; }
      if (method === "get_payment") return { payment_hash: params[0]?.payment_hash, status: "Success", fee: "0x0", created_at: old } as T;
      return h.node.call<T>(method, params);
    } };
    const key = `old-${crypto.randomUUID()}`;
    const first = fiberPayment(h.context, node, body, key);
    await started;
    await stale(h, key);
    await assert.rejects(() => fiberPayment(h.context, node, body, key), /outcome isn't known yet/);
    release();
    await first;
    assert.equal(sends, 1);

    // A keysend has no payment hash until the node makes one, so a stale keysend stays unknown rather than repaid.
    const k = harness(10n * CKB);
    const keysend = { method: "sendPayment", params: { target_pubkey: `0x02${"11".repeat(32)}`, amount: "0x3b9aca00", keysend: true } };
    const kPreview = await fiberPayment(k.context, k.node, { ...keysend, stage: "preview" }) as Record<string, unknown>;
    const kBody = { ...keysend, stage: "send", confirmationNonce: kPreview.confirmationNonce };
    let kRelease!: () => void;
    const kGate = new Promise<void>((resolve) => { kRelease = resolve; });
    let kEntered!: () => void;
    const kStarted = new Promise<void>((resolve) => { kEntered = resolve; });
    let kSends = 0;
    const kNode = { call: async <T>(method: string, params: Array<Record<string, unknown>> = []): Promise<T> => {
      if (method === "send_payment" && !params[0]?.dry_run) { kSends++; kEntered(); await kGate; }
      if (method === "get_payment") throw new Error("a keysend can't be looked up before it has a hash");
      return k.node.call<T>(method, params);
    } };
    const kKey = `keysend-${crypto.randomUUID()}`;
    const kFirst = fiberPayment(k.context, kNode, kBody, kKey);
    await kStarted;
    await stale(k, kKey);
    await assert.rejects(() => fiberPayment(k.context, kNode, kBody, kKey), /outcome isn't known yet/);
    kRelease();
    await kFirst;
    assert.equal(kSends, 1);
  });

  await t.test("a send that errors after the node took the payment returns the payment, and keeps it counted", async () => {
    const sql = await database();
    const hash = `0x${"ab".repeat(32)}`;
    // Three nodes whose send_payment call fails (a timeout, say). What get_payment then says decides the outcome.
    const run = async (afterError: "made" | "absent" | "refused" | "unreachable") => {
      const h = harness(10n * CKB);
      const preview = await pay(h, { stage: "preview" });
      const body = { method: "sendPayment", params: { invoice: "fibt1test" }, stage: "send", confirmationNonce: preview.confirmationNonce };
      let sends = 0;
      let createdAt = 0;
      let reachable = afterError !== "unreachable";
      const node = { call: async <T>(method: string, params: Array<Record<string, unknown>> = []): Promise<T> => {
        if (method === "send_payment" && !params[0]?.dry_run) {
          sends++;
          if (afterError === "refused") throw Object.assign(new Error("Failed to send payment: no path found"), { code: -32000, data: params[0] });
          if (afterError !== "absent") createdAt = Date.now();
          throw Object.assign(new Error("Request timeout"), { code: -32000 });
        }
        if (method === "get_payment") {
          if (!reachable) throw new Error("HTTP error: 502 Bad Gateway");
          if (!createdAt) throw new Error("Invalid parameter: Payment session not found: Hash256(0xab)");
          return { payment_hash: hash, status: "Inflight", fee: "0x0", created_at: `0x${createdAt.toString(16)}` } as T;
        }
        return h.node.call<T>(method, params);
      } };
      const key = `timeout-${crypto.randomUUID()}`;
      const counted = async () => (await sql<Array<{ n: number }>>`select count(*)::int as n from keyway_v2_signed_outflows where user_id = ${h.context.user.id} and transaction_hash = ${`payment:${preview.confirmationNonce}`}`)[0].n;
      const status = async () => (await sql<Array<{ status: string }>>`select status from keyway_v2_idempotency_keys where user_id = ${h.context.user.id} and idempotency_key = ${key}`)[0].status;
      return { h, node, body, key, counted, status, sends: () => sends, reconnect: () => { reachable = true; } };
    };

    // The node has it: that's the send's result, and it counts toward the 24-hour total.
    const made = await run("made");
    const result = await fiberPayment(made.h.context, made.node, made.body, made.key) as Record<string, unknown>;
    assert.equal(result.payment_hash, hash);
    assert.deepEqual(await fiberPayment(made.h.context, made.node, made.body, made.key), result);
    assert.equal(await made.counted(), 1);
    assert.equal(made.sends(), 1);

    // The node refused it, and has no such payment: a rejection, recorded and released as before.
    const refused = await run("refused");
    await assert.rejects(() => fiberPayment(refused.h.context, refused.node, refused.body, refused.key), /no path found/);
    assert.equal(await refused.status(), "failed");
    assert.equal(await refused.counted(), 0);
    await assert.rejects(() => fiberPayment(refused.h.context, refused.node, refused.body, refused.key), /no path found/);
    assert.equal(refused.sends(), 1);

    // A timeout, then "not found": the node may not have made the session yet, so it isn't a rejection.
    const early = await run("absent");
    await assert.rejects(() => fiberPayment(early.h.context, early.node, early.body, early.key), /outcome isn't known yet/);
    assert.equal(await early.status(), "running");
    assert.equal(await early.counted(), 1);
    assert.equal(early.sends(), 1);

    // The node can't be asked: unknown, not failed. The amount stays counted, and once the node answers a repeat
    // gets the payment, without paying again.
    const unknown = await run("unreachable");
    await assert.rejects(() => fiberPayment(unknown.h.context, unknown.node, unknown.body, unknown.key), /outcome isn't known yet/);
    assert.equal(await unknown.status(), "running");
    assert.equal(await unknown.counted(), 1);
    unknown.reconnect();
    await sql`update keyway_v2_idempotency_keys set updated_at = now() - ${`${PAYMENT_STALE_MS + 1_000} milliseconds`}::interval where user_id = ${unknown.h.context.user.id} and idempotency_key = ${unknown.key}`;
    const recovered = await fiberPayment(unknown.h.context, unknown.node, unknown.body, unknown.key) as Record<string, unknown>;
    assert.equal(recovered.payment_hash, hash);
    assert.equal(unknown.sends(), 1);
  });

  await t.test("a slow send that a repeat already reconciled can't replace that answer with its own late error", async () => {
    const sql = await database();
    const h = harness(10n * CKB);
    const preview = await pay(h, { stage: "preview" });
    const body = { method: "sendPayment", params: { invoice: "fibt1test" }, stage: "send", confirmationNonce: preview.confirmationNonce };
    const hash = `0x${"ab".repeat(32)}`;
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    let entered!: () => void;
    const started = new Promise<void>((resolve) => { entered = resolve; });
    const createdAt = Date.now();
    const node = { call: async <T>(method: string, params: Array<Record<string, unknown>> = []): Promise<T> => {
      if (method === "send_payment" && !params[0]?.dry_run) {
        entered();
        await gate;
        throw Object.assign(new Error("Failed to send payment: late"), { code: -32000, data: params[0] });
      }
      if (method === "get_payment") {
        // The owner's own late lookup gets nothing, so it ends in its refusal and tries to record a failure.
        if (lookupsFail) throw new Error("Invalid parameter: Payment session not found");
        return { payment_hash: hash, status: "Success", fee: "0x0", created_at: `0x${createdAt.toString(16)}` } as T;
      }
      return h.node.call<T>(method, params);
    } };
    let lookupsFail = false;
    const key = `late-${crypto.randomUUID()}`;
    const first = fiberPayment(h.context, node, body, key);
    await started;
    await sql`update keyway_v2_idempotency_keys set updated_at = now() - ${`${PAYMENT_STALE_MS + 1_000} milliseconds`}::interval where user_id = ${h.context.user.id} and idempotency_key = ${key}`;
    const reconciled = await fiberPayment(h.context, node, body, key) as Record<string, unknown>;
    assert.equal(reconciled.status, "Success");
    lookupsFail = true;
    release();
    await assert.rejects(first, /late/);
    assert.deepEqual(await fiberPayment(h.context, node, body, key), reconciled);
    const [row] = await sql<Array<{ status: string }>>`select status from keyway_v2_idempotency_keys where user_id = ${h.context.user.id} and idempotency_key = ${key}`;
    assert.equal(row.status, "completed");
  });

  await t.test("an operation without reconciliation whose result was never stored says its outcome is unknown, not that it still runs", async () => {
    const sql = await database();
    const userId = crypto.randomUUID();
    const key = `channel-${crypto.randomUUID()}`;
    // As if the process had exited after opening the channel, before storing the result.
    await sql`
      insert into keyway_v2_idempotency_keys (user_id, operation, idempotency_key, request_digest, status, expires_at)
      values (${userId}, 'managed:open-channel', ${key}, ${"0".repeat(64)}, 'running', now() + interval '24 hours')
    `;
    let runs = 0;
    const repeat = () => runIdempotentMutation(userId, "managed:open-channel", key, { peer: "a" }, async () => { runs++; return {}; });
    await sql`update keyway_v2_idempotency_keys set request_digest = encode(sha256(convert_to(${JSON.stringify({ peer: "a" })}, 'UTF8')), 'hex') where user_id = ${userId} and idempotency_key = ${key}`;
    await assert.rejects(repeat, /still in progress/);
    await sql`update keyway_v2_idempotency_keys set updated_at = now() - ${`${DEFAULT_STALE_MS + 1_000} milliseconds`}::interval where user_id = ${userId} and idempotency_key = ${key}`;
    await assert.rejects(repeat, /outcome isn't known yet/);
    assert.equal(runs, 0);
  });

  await t.test("refuses payments with neither an invoice nor a keysend target", async () => {
    const h = harness(1n * CKB);
    await assert.rejects(() => fiberPayment(h.context, h.node, { method: "sendPayment", stage: "preview", params: { amount: "0x1" } }), /keysend/);
    await assert.rejects(() => fiberPayment(h.context, h.node, { method: "openChannel", stage: "preview", params: {} }), /payment method/);
  });
});

test("a hosted payment can't pay a higher fee than the one counted toward the daily amount (audit M14)", { skip: !enabled }, async () => {
  process.env.DATABASE_URL = process.env.KEYWAY_AUTH_TEST_DATABASE_URL;
  const fee = 5_000n;
  const h = harness(40n * CKB, { fee });
  // The caller's own fee limits are far above the dry run's estimate.
  const params = { invoice: "fibt1test", max_fee_amount: `0x${(10n * CKB).toString(16)}`, max_fee_rate: "0x3e8" };
  const preview = await fiberPayment(h.context, h.node, { method: "sendPayment", params, stage: "preview" }) as Record<string, unknown>;
  assert.equal((preview.preview as { fee: string }).fee, fee.toString());
  await fiberPayment(h.context, h.node, { method: "sendPayment", params, stage: "send", confirmationNonce: preview.confirmationNonce });
  const sent = h.sent.at(-1) as Record<string, unknown>;
  assert.equal(sent.max_fee_amount, `0x${fee.toString(16)}`, "capped at the counted fee");
  assert.equal(sent.max_fee_rate, undefined, "no second, looser cap from the caller");

  // A caller's own lower cap still holds.
  const lower = { invoice: "fibt1test", max_fee_amount: "0x3e8" };
  const second = await fiberPayment(h.context, h.node, { method: "sendPayment", params: lower, stage: "preview" }) as Record<string, unknown>;
  await fiberPayment(h.context, h.node, { method: "sendPayment", params: lower, stage: "send", confirmationNonce: second.confirmationNonce });
  assert.equal((h.sent.at(-1) as Record<string, unknown>).max_fee_amount, "0x3e8");

  // No cap given: the counted fee is the cap.
  const bare = await fiberPayment(h.context, h.node, { method: "sendPayment", params: { invoice: "fibt1test" }, stage: "preview" }) as Record<string, unknown>;
  await fiberPayment(h.context, h.node, { method: "sendPayment", params: { invoice: "fibt1test" }, stage: "send", confirmationNonce: bare.confirmationNonce });
  assert.equal((h.sent.at(-1) as Record<string, unknown>).max_fee_amount, `0x${fee.toString(16)}`);
});

test("a payment request without a counted fee is refused before anything is counted", { skip: !enabled }, async () => {
  process.env.DATABASE_URL = process.env.KEYWAY_AUTH_TEST_DATABASE_URL;
  const h = harness(40n * CKB, { fee: 5_000n });
  const preview = await pay(h, { stage: "preview" });
  const sql = await database();
  await sql`update keyway_v2_signature_requests set summary = summary - 'fee' where nonce = ${String(preview.confirmationNonce)}`;
  await assert.rejects(pay(h, { stage: "send", confirmationNonce: preview.confirmationNonce }), /expired/);
  const counted = await sql`select 1 from keyway_v2_signed_outflows where user_id = ${h.context.user.id}`;
  assert.equal(counted.length, 0, "nothing stays counted for a payment that was never sent");
  assert.equal(h.sent.length, 0);
});
