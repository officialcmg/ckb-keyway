import { createHash } from "node:crypto";
import { database } from "./database.ts";

export async function recordSigningEvent(userId: string): Promise<void> {
  const sql = await database();
  const [row] = await sql<Array<{ count: number }>>`
    with inserted as (
      insert into keyway_security_events (kind, subject_hash)
      values ('signing', ${createHash("sha256").update(userId).digest("hex")})
      returning 1
    )
    select count(*)::int as count
    from keyway_security_events
    where kind = 'signing' and created_at >= now() - interval '5 minutes'
  `;
  const threshold = positiveInteger(process.env.KEYWAY_SIGNING_ALERT_THRESHOLD, 20);
  if (row.count === threshold) await sendSecurityAlert("unusual_signing_volume", { count: row.count, windowMinutes: 5 });
}

export async function sendSecurityAlert(kind: string, details: Record<string, string | number>): Promise<void> {
  console.warn("[keyway-security]", JSON.stringify({ kind, ...details }));
  const webhook = process.env.KEYWAY_SECURITY_ALERT_WEBHOOK_URL;
  if (!webhook) return;
  try {
    const url = new URL(webhook);
    if (url.protocol !== "https:") throw new Error("Security alert webhook must use HTTPS");
    const response = await fetch(url, {
      method: "POST",
      signal: AbortSignal.timeout(5_000),
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ kind, ...details }),
    });
    if (!response.ok) throw new Error(`Security alert webhook returned HTTP ${response.status}`);
  } catch (error) {
    console.error("[keyway-security] alert delivery failed", error instanceof Error ? error.message : "unknown error");
  }
}

function positiveInteger(value: string | undefined, fallback: number): number {
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : fallback;
}
