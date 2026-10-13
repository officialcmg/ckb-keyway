const SHANNONS = 100_000_000n;

/** What an amount is counted in: CKB, or a Fiber token such as RUSD. */
export type Unit = { symbol: string; decimals: number };
export const CKB: Unit = { symbol: "CKB", decimals: 8 };

/** 899999000000n → "8,999.99" (two decimals, more only when needed). */
export function formatCkb(shannons: bigint, minDecimals = 2): string {
  return formatUnits(shannons, CKB, minDecimals);
}

/** An amount in a unit's smallest denomination, written in whole units: 2500000000n RUSD → "25.00". */
export function formatUnits(amount: bigint, unit: Unit, minDecimals = 2): string {
  const negative = amount < 0n;
  const value = negative ? -amount : amount;
  const scale = 10n ** BigInt(unit.decimals);
  const whole = (value / scale).toLocaleString("en-US");
  let fraction = unit.decimals ? (value % scale).toString().padStart(unit.decimals, "0").replace(/0+$/, "") : "";
  if (unit.decimals && fraction.length < minDecimals) fraction = fraction.padEnd(Math.min(minDecimals, unit.decimals), "0");
  return `${negative ? "−" : ""}${whole}${fraction ? `.${fraction}` : ""}`;
}

/** Headline balances: rounded down to two decimals so they never overstate what the account holds. */
export function formatBalance(shannons: bigint): string {
  return formatCkb((shannons / 1_000_000n) * 1_000_000n);
}

/** Parses a user-typed CKB amount such as "1,000" or "5.5" into shannons. */
export function parseCkb(value: string): bigint {
  const match = /^(\d{1,9})(?:\.(\d{1,8}))?$/.exec(value.trim().replaceAll(",", ""));
  if (!match) throw new Error("Enter a CKB amount with at most 8 decimal places");
  const result = BigInt(match[1]) * SHANNONS + BigInt((match[2] ?? "").padEnd(8, "0") || "0");
  if (result <= 0n) throw new Error("Enter an amount greater than zero");
  return result;
}

export function toHex(value: bigint): `0x${string}` {
  return `0x${value.toString(16)}`;
}

export function shortHash(value: string): string {
  return value.length <= 14 ? value : `${value.slice(0, 6)}…${value.slice(-4)}`;
}

export function clockTime(at: number, seconds = true): string {
  return new Date(at).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", ...(seconds ? { second: "2-digit" } : {}) });
}

/** Stage durations in the connection checklist: "0.4 s". */
export function seconds(ms: number): string {
  return `${(ms / 1000).toFixed(1)} s`;
}

/** Durations in the lifecycle log: "418 ms" below half a second, "0.9 s" above. */
export function duration(ms: number): string {
  return ms < 500 ? `${Math.max(0, Math.round(ms))} ms` : seconds(ms);
}
