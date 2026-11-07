import type { ParseInvoiceResult } from "@fiber-pay/sdk/node";
import { FIBER_METHODS, paymentFiberParams } from "../sdk/browser/fiber-methods.ts";
import { describePayment } from "../sdk/browser/fiber-payment.ts";
import {
  consumeRequest,
  hashText,
  issueRequest,
  limit,
  loadRequest,
  outflowNeedsEmailCode,
  requiredNonce,
  reserveOutflow,
  sendCode,
  verifyCode,
  type SigningContext,
} from "./general-signing.ts";
import { OutcomeUnknownError, runIdempotentMutation, type RecordHandle } from "./idempotency.ts";

export type FiberCaller = { call<T>(method: string, params?: unknown[]): Promise<T> };
export type PaymentContext = Pick<SigningContext, "user" | "appName" | "email" | "sendEmail" | "rateLimit">;

/**
 * Hosted-node payments: preview, request-email-code, send. There is no built-in dialog (apps may add
 * their own), but every payment counts toward the user's 24-hour email-confirmation amount, and past it
 * the emailed code is required. Each approval is bound to the exact payment by a single-use nonce.
 *
 * A send with an idempotency key is recorded under it: repeating the same request with the same key (a
 * retry after a lost response) returns the first result, or the first error, and never pays twice. A repeat that
 * arrives while the first send still runs waits for it (up to 30 seconds). Before paying, the send records the
 * payment hash; if its result was never stored (the process exited, or the database failed), a repeat a minute
 * later asks the node for that payment and returns it, and never pays again.
 */
export async function fiberPayment(context: PaymentContext, node: FiberCaller, body: Record<string, unknown>, idempotencyKey?: string): Promise<unknown> {
  if (body.stage === "send" && idempotencyKey) {
    const { method, params, confirmationNonce, emailCode } = body;
    return runIdempotentMutation(context.user.id, "fiber-pay", idempotencyKey, { method, params, confirmationNonce, emailCode }, (record) => payOnce(context, node, body, record), {
      waitMs: 30_000,
      staleAfterMs: PAYMENT_STALE_MS,
      reconcile: (handle) => reconcilePayment(node, handle),
    });
  }
  return payOnce(context, node, body);
}

/** How long a send may stay unrecorded before a repeat asks the node for its outcome. */
export const PAYMENT_STALE_MS = 60_000;
/** Allowed clock difference between this server and the Fiber node when matching a payment to its send. */
const CLOCK_SKEW_MS = 5 * 60_000;

type PaymentHandle = { paymentHash: string; sentAfter: number };

/**
 * The node's record of a payment a send recorded but never stored: the payment with that hash, if the node made it
 * after the send began (an older payment of the same invoice isn't this one). Undefined while the node doesn't
 * know it, or can't be asked.
 */
async function reconcilePayment(node: FiberCaller, handle: unknown): Promise<{ completed: unknown } | undefined> {
  const { paymentHash, sentAfter } = (handle ?? {}) as Partial<PaymentHandle>;
  if (typeof paymentHash !== "string" || typeof sentAfter !== "number") return undefined;
  const found = await lookupPayment(node, { paymentHash, sentAfter });
  return found.kind === "made" ? { completed: found.payment } : undefined;
}

/**
 * What the node says about a send's payment: "made" (a payment with its hash, made after the send began),
 * "absent" (the node answered that it has no payment with that hash) or "unknown" (it couldn't be asked, or
 * answered something else, such as an older payment of the same invoice).
 */
async function lookupPayment(node: FiberCaller, { paymentHash, sentAfter }: PaymentHandle): Promise<{ kind: "made"; payment: unknown } | { kind: "absent" | "unknown" }> {
  let payment: { payment_hash?: unknown; created_at?: unknown } | undefined;
  try {
    payment = await node.call<{ payment_hash?: unknown; created_at?: unknown }>("get_payment", [{ payment_hash: paymentHash }]);
  } catch (error) {
    // Fiber answers an unknown hash with "Payment session not found". Transport failures share its error type
    // and code, so only that answer counts as the node saying it never made the payment.
    return { kind: error instanceof Error && /payment session not found/i.test(error.message) ? "absent" : "unknown" };
  }
  if (!payment || payment.payment_hash !== paymentHash || typeof payment.created_at !== "string" || !/^0x[0-9a-f]{1,16}$/i.test(payment.created_at)) return { kind: "unknown" };
  if (Number(BigInt(payment.created_at)) < sentAfter - CLOCK_SKEW_MS) return { kind: "unknown" };
  return { kind: "made", payment };
}

/** The payment hash a send will use, when it is known before sending: given, or the invoice's. A keysend has none. */
async function paymentHashOf(node: FiberCaller, params: Record<string, unknown>): Promise<string | undefined> {
  if (typeof params.payment_hash === "string") return params.payment_hash;
  if (typeof params.invoice !== "string") return undefined;
  const parsed = await node.call<ParseInvoiceResult>("parse_invoice", [{ invoice: params.invoice }]);
  const hash = parsed?.invoice?.data?.payment_hash;
  return typeof hash === "string" ? hash : undefined;
}

async function payOnce(context: PaymentContext, node: FiberCaller, body: Record<string, unknown>, record?: RecordHandle): Promise<unknown> {
  const method = body.method === "sendPaymentWithRouter" ? "sendPaymentWithRouter" : body.method === "sendPayment" ? "sendPayment" : undefined;
  if (!method) throw new Error("A Fiber payment method is required");
  const params = paymentFiberParams(method, body.params, "testnet");
  if (params.dry_run === true) throw new Error("Use the node call for dry runs");
  const digest = hashText(JSON.stringify({ method, params }));

  if (body.stage === "preview") {
    await limit(context, "fiber-pay", { max: 120, window: 60 });
    const { preview, outflow, asset } = await describePayment(method, params, {
      parseInvoice: (invoice) => node.call<ParseInvoiceResult>("parse_invoice", [{ invoice }]),
      dryRun: (dryRun) => node.call<{ fee: string }>(FIBER_METHODS[method].rpc, [dryRun]),
    });
    // The approval's own nonce identifies this payment in the 24-hour total.
    const pending = crypto.randomUUID();
    const requiresEmailCode = await outflowNeedsEmailCode(context.user, { id: `payment:${pending}`, ...paymentOutflow(asset, outflow) });
    const lines = [
      `Pay ${preview.amountText}${preview.description ? ` for "${preview.description}"` : ""}`,
      `Estimated network fee: ${preview.feeText}`,
      ...(preview.payee ? [`To Fiber node ${preview.payee.slice(0, 10)}…${preview.payee.slice(-6)}`] : []),
    ];
    const confirmationNonce = await issueRequest(context.user, "payment", digest, { lines, outflow: outflow.toString(), asset }, requiresEmailCode);
    return { preview: { ...preview, requiresEmailCode }, confirmationNonce, requiresEmailCode };
  }

  const nonce = requiredNonce(body.confirmationNonce);
  const request = await loadRequest(context.user, "payment", nonce, digest);
  if (body.stage === "request-email-code") {
    if (!request.requires_email_code) throw new Error("This payment doesn't need an email code");
    const sentTo = await sendCode(context, "payment", nonce, "Confirm a payment", request.summary.lines ?? []);
    return { sent: true, sentTo };
  }
  if (body.stage !== "send") throw new Error("A valid payment stage is required");
  if (request.requires_email_code) await verifyCode(context.user, "payment", nonce, body.emailCode);
  await consumeRequest(context.user, "payment", nonce);
  const outflow = { id: `payment:${nonce}`, ...paymentOutflow(String(request.summary.asset ?? "ckb"), BigInt(String(request.summary.outflow ?? "0"))) };
  const release = await reserveOutflow(context.user, outflow, request.requires_email_code);
  let handle: PaymentHandle | undefined;
  try {
    if (record) {
      const paymentHash = await paymentHashOf(node, params);
      if (paymentHash) {
        handle = { paymentHash, sentAfter: Date.now() };
        await record(handle);
      }
    }
  } catch (error) {
    await release();
    throw error;
  }
  try {
    return await node.call(FIBER_METHODS[method].rpc, [params]);
  } catch (error) {
    // A timeout or dropped connection looks like a rejection, but the node may have taken the payment. With its
    // hash recorded, ask the node: a payment it made is this send's result; one it says it never made is a
    // rejection; anything else keeps the reservation and leaves the outcome for a repeat to reconcile.
    if (handle) {
      const found = await lookupPayment(node, handle);
      if (found.kind === "made") return found.payment;
      if (found.kind === "unknown") {
        throw new OutcomeUnknownError(`The payment's outcome isn't known yet (${error instanceof Error ? error.message : "the node didn't answer"}). Repeat the request with the same idempotency key to check it`);
      }
    }
    await release();
    throw error;
  }
}

/** A CKB payment counts toward the CKB amount; a token payment, fee included, toward that token's. */
function paymentOutflow(asset: string, amount: bigint) {
  return asset === "ckb" ? { shannons: amount, tokens: [] } : { shannons: 0n, tokens: [{ asset, amount }] };
}
