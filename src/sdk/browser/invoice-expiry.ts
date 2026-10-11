import type { NewInvoiceParams } from "@fiber-pay/sdk/browser";

// Fiber invoice expiry is hex seconds: 0x15180 = 86,400 s = 24 hours.
export const DEFAULT_INVOICE_EXPIRY = "0x15180";

export function withDefaultInvoiceExpiry(params: NewInvoiceParams): NewInvoiceParams {
  return params.expiry === undefined ? { ...params, expiry: DEFAULT_INVOICE_EXPIRY } : params;
}
