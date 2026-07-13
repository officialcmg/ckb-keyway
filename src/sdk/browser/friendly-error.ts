export function friendlyKeyWayError(value: string): string {
  const normalized = value.toLowerCase();
  if (value.includes("CHANNEL_STATE_DEVICE_BOUND")) {
    return "This wallet has channel history in another browser. Transfer its Fiber data before continuing here.";
  }
  if (normalized.includes("currently running on another device")) {
    return "This wallet is open in another browser. Close it and try again in about a minute.";
  }
  if (normalized.includes("allow_self_payment")) {
    return "This invoice belongs to the same wallet. Use an invoice from another Fiber receiver.";
  }
  if (normalized.includes("expired invoice") || normalized.includes("invoice has expired")) {
    return "This Fiber invoice has expired. Ask the receiver to create a new one.";
  }
  if (normalized.includes("failed to build route") || normalized.includes("insufficient liquidity")) {
    return "No Fiber route currently has enough liquidity for this payment. Try a smaller amount or another receiver.";
  }
  if (normalized.includes("available fiber peers declined")) {
    return "Available Fiber peers declined the channel request. Try activation again after the network updates.";
  }
  if (normalized.includes("funding transaction was not confirmed")) {
    return "Channel activation was cancelled before signing.";
  }
  if (normalized.includes("lit signature") || normalized.includes("chipotle")) {
    return "Lit could not authorize this operation. Retry once; if it continues, check the KeyWay server configuration.";
  }
  return value;
}
