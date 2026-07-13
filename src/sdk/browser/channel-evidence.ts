export function formatFiberOutpoint(value: unknown, fallback = "Unavailable"): string {
  if (typeof value === "string" && value) return value;
  if (!value || typeof value !== "object") return fallback;

  const outpoint = value as Record<string, unknown>;
  const txHash = outpoint.tx_hash ?? outpoint.txHash;
  const index = outpoint.index;
  if (typeof txHash !== "string" || !txHash) return fallback;
  if (typeof index === "bigint") return `${txHash}:0x${index.toString(16)}`;
  if (typeof index === "string" && index) return `${txHash}:${index}`;
  return fallback;
}
