export type KeyWayErrorCode =
  | "CROSS_ORIGIN_ISOLATION_REQUIRED"
  | "DEVICE_IN_USE"
  | "INVOICE_EXPIRED"
  | "SELF_PAYMENT"
  | "NO_ROUTE"
  | "INSUFFICIENT_ROUTE_LIQUIDITY"
  | "FEE_LIMIT_EXCEEDED"
  | "PEER_OFFLINE"
  | "PAYMENT_TIMEOUT"
  | "PAYMENT_FAILED"
  | "CHANNEL_FAILED"
  | "UNKNOWN";

export class KeyWayError extends Error {
  constructor(
    public readonly code: KeyWayErrorCode,
    message: string,
    public readonly retryable: boolean,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "KeyWayError";
  }
}

export function toKeyWayError(value: unknown, fallback: KeyWayErrorCode = "UNKNOWN"): KeyWayError {
  if (value instanceof KeyWayError) return value;
  const cause = value instanceof Error ? value : new Error(String(value));
  const message = cause.message;
  const normalized = message.toLowerCase();

  if (normalized.includes("cross-origin isolated")) {
    return error("CROSS_ORIGIN_ISOLATION_REQUIRED", "Fiber requires COOP and COEP headers before its browser node can start.", false, cause);
  }
  if (normalized.includes("another device") || normalized.includes("another browser")) {
    return error("DEVICE_IN_USE", "This wallet is active in another browser. Close it and try again in about two minutes.", true, cause);
  }
  if (normalized.includes("allow_self_payment")) {
    return error("SELF_PAYMENT", "This invoice belongs to the same wallet.", false, cause);
  }
  if (normalized.includes("expired invoice") || normalized.includes("invoice has expired")) {
    return error("INVOICE_EXPIRED", "This Fiber invoice has expired.", false, cause);
  }
  if (normalized.includes("insufficient liquidity")) {
    return error("INSUFFICIENT_ROUTE_LIQUIDITY", "No route currently has enough liquidity for this payment.", true, cause);
  }
  if (normalized.includes("failed to build route") || normalized.includes("no route")) {
    return error("NO_ROUTE", "No Fiber route is currently available for this payment.", true, cause);
  }
  if (normalized.includes("fee") && (normalized.includes("limit") || normalized.includes("exceed"))) {
    return error("FEE_LIMIT_EXCEEDED", "The available route exceeds the payment fee limit.", true, cause);
  }
  if (normalized.includes("timeout") || normalized.includes("timed out")) {
    return error("PAYMENT_TIMEOUT", "The Fiber payment timed out before settlement.", true, cause);
  }
  if (normalized.includes("offline") || normalized.includes("peer") && normalized.includes("disconnect")) {
    return error("PEER_OFFLINE", "A required Fiber peer is offline.", true, cause);
  }
  return error(fallback, message, fallback !== "UNKNOWN", cause);
}

function error(code: KeyWayErrorCode, message: string, retryable: boolean, cause: Error): KeyWayError {
  return new KeyWayError(code, message, retryable, { cause });
}
