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

export type FiberCaller = { call<T>(method: string, params?: unknown[]): Promise<T> };
export type PaymentContext = Pick<SigningContext, "user" | "appName" | "email" | "sendEmail" | "rateLimit">;

/**
 * Hosted-node payments: preview, request-email-code, send. There is no built-in dialog (apps may add
 * their own), but every payment counts toward the user's 24-hour email-confirmation amount, and past it
 * the emailed code is required. Each approval is bound to the exact payment by a single-use nonce.
 */
export async function fiberPayment(context: PaymentContext, node: FiberCaller, body: Record<string, unknown>): Promise<unknown> {
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
    await sendCode(context, "payment", nonce, "Confirm a payment", request.summary.lines ?? []);
    return { sent: true };
  }
  if (body.stage !== "send") throw new Error("A valid payment stage is required");
  if (request.requires_email_code) await verifyCode(context.user, "payment", nonce, body.emailCode);
  await consumeRequest(context.user, "payment", nonce);
  const outflow = { id: `payment:${nonce}`, ...paymentOutflow(String(request.summary.asset ?? "ckb"), BigInt(String(request.summary.outflow ?? "0"))) };
  const release = await reserveOutflow(context.user, outflow, request.requires_email_code);
  try {
    return await node.call(FIBER_METHODS[method].rpc, [params]);
  } catch (error) {
    await release();
    throw error;
  }
}

/** A CKB payment counts toward the CKB amount; a token payment, fee included, toward that token's. */
function paymentOutflow(asset: string, amount: bigint) {
  return asset === "ckb" ? { shannons: amount, tokens: [] } : { shannons: 0n, tokens: [{ asset, amount }] };
}
