import type { ParseInvoiceResult } from "@fiber-pay/sdk/browser";
import { formatAsset, tokenAsset } from "./tokens";

/** What an app's own payment confirmation (`approveFiberPayment`) is shown. KeyWay draws no payment dialog. */
export type FiberPaymentPreview = {
  method: "sendPayment" | "sendPaymentWithRouter";
  /** "ckb", or the paid token's type script hash. Fees are paid in the same asset. */
  asset: string;
  /** The amount the payee receives, in the asset's smallest unit (shannons for CKB). */
  amount: string;
  /** The amount for people, such as "1.5 CKB" or "20 RUSD". */
  amountText: string;
  /** The estimated routing fee from Fiber's dry run, in the asset's smallest unit. */
  fee: string;
  feeText: string;
  /** The payee's Fiber node ID, when known. */
  payee?: string;
  description?: string;
  keysend: boolean;
  network: "CKB testnet";
  /** True when this payment, with everything sent in the last 24 hours, reaches the user's email-confirmation amount. */
  requiresEmailCode: boolean;
};

export type ApproveFiberPayment = (preview: FiberPaymentPreview) => boolean | Promise<boolean>;

type PaymentIo = {
  parseInvoice: (invoice: string) => Promise<ParseInvoiceResult>;
  dryRun: (params: Record<string, unknown>) => Promise<{ fee: string }>;
};

/**
 * Works out what a payment sends, from its invoice or explicit amount and a dry run. `outflow` is the most
 * that leaves the user's channels, in `asset`: the amount plus the estimated fee (a route's first hop
 * already includes fees).
 */
export async function describePayment(
  method: "sendPayment" | "sendPaymentWithRouter",
  params: Record<string, unknown>,
  io: PaymentIo,
): Promise<{ preview: Omit<FiberPaymentPreview, "requiresEmailCode">; outflow: bigint; asset: string }> {
  const invoice = typeof params.invoice === "string" ? (await io.parseInvoice(params.invoice)).invoice : undefined;
  const attrs = (invoice?.data.attrs ?? []) as Array<Record<string, unknown>>;
  const description = attrs.map((attr) => attr.description).find((value): value is string => typeof value === "string");
  const invoicePayee = attrs.map((attr) => attr.payee_public_key).find((value): value is string => typeof value === "string");
  const invoiceToken = attrs.map((attr) => attr.udt_script).find((value): value is string => typeof value === "string");
  const typeScript = params.udt_type_script as { code_hash: string; hash_type: string; args: string } | undefined;
  const asset = typeScript ? tokenAsset(typeScript) : invoiceToken ? tokenAsset(invoiceToken) : "ckb";
  const router = method === "sendPaymentWithRouter" ? params.router as Array<{ target: string; amount_received: string }> : undefined;
  const feeShannons = BigInt((await io.dryRun({ ...params, dry_run: true })).fee);

  let amount: bigint;
  let outflow: bigint;
  if (router) {
    outflow = BigInt(router[0].amount_received);
    amount = BigInt(router.at(-1)!.amount_received);
  } else {
    const explicit = typeof params.amount === "string" ? params.amount : invoice?.amount;
    if (!explicit) throw new Error("This payment has no amount. Pass amount for an invoice without one");
    amount = BigInt(explicit);
    outflow = amount + feeShannons;
  }
  const routeFee = router ? outflow - amount : feeShannons;
  return {
    asset,
    preview: {
      method,
      asset,
      amount: amount.toString(),
      amountText: formatAsset(amount, asset),
      fee: routeFee.toString(),
      feeText: formatAsset(routeFee, asset),
      payee: (typeof params.target_pubkey === "string" ? params.target_pubkey : undefined) ?? invoicePayee ?? router?.at(-1)?.target,
      description,
      keysend: params.keysend === true,
      network: "CKB testnet",
    },
    outflow,
  };
}
