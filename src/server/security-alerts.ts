import { createHash } from "node:crypto";
import { database, type DatabaseSql } from "./database.ts";

const SIGNING_WINDOW_MINUTES = 5;
/** Signing events are kept this long for operators, then removed a batch at a time. */
const SIGNING_EVENT_RETENTION = "1 day";
const PRUNE_BATCH = 500;
/** Delivery attempts per alert, and the wait before the second. */
export const ALERT_ATTEMPTS = 3;
export const alertRetry = { delayMs: 1_000 };

/**
 * Records one signing and raises `unusual_signing_volume` once the last five minutes hold `threshold` or more.
 * The count is taken after this signing is stored, so concurrent signings can't step past the threshold unseen,
 * and one alert per five minutes is claimed atomically. A delivery that still fails after its retries gives the
 * claim back, so a later signing in the burst raises it again. Delivery never holds up the signing: `connection`
 * may be a reserved connection the caller holds, and it is used only for the short writes here.
 */
export async function recordSigningEvent(userId: string, connection?: DatabaseSql): Promise<void> {
  const sql = connection ?? await database();
  await sql`
    insert into keyway_security_events (kind, subject_hash)
    values ('signing', ${createHash("sha256").update(userId).digest("hex")})
  `;
  await sql`
    delete from keyway_security_events where id in (
      select id from keyway_security_events
      where kind = 'signing' and created_at < now() - ${SIGNING_EVENT_RETENTION}::interval
      order by created_at limit ${PRUNE_BATCH}
    )
  `;
  const [row] = await sql<Array<{ count: number }>>`
    select count(*)::int as count from keyway_security_events
    where kind = 'signing' and created_at >= now() - make_interval(mins => ${SIGNING_WINDOW_MINUTES})
  `;
  const threshold = positiveInteger(process.env.KEYWAY_SIGNING_ALERT_THRESHOLD, 20);
  if (row.count < threshold) return;
  const claimId = crypto.randomUUID();
  const [claimed] = await sql`
    insert into keyway_security_alert_state (kind, alerted_at, claim_id) values ('unusual_signing_volume', now(), ${claimId})
    on conflict (kind) do update set alerted_at = excluded.alerted_at, claim_id = excluded.claim_id
    where keyway_security_alert_state.alerted_at < now() - make_interval(mins => ${SIGNING_WINDOW_MINUTES})
    returning 1
  `;
  if (!claimed) return;
  void sendSecurityAlert("unusual_signing_volume", { count: row.count, windowMinutes: SIGNING_WINDOW_MINUTES }).then(async (delivered) => {
    if (delivered) return;
    const pool = await database();
    await pool`delete from keyway_security_alert_state where kind = 'unusual_signing_volume' and claim_id = ${claimId}`;
  }).catch(() => console.error("[keyway-security] couldn't release an undelivered alert"));
}

/** Logs an alert and sends it to the configured webhook, retrying a failed delivery. Resolves whether it was delivered. */
export async function sendSecurityAlert(kind: string, details: Record<string, string | number>): Promise<boolean> {
  console.warn("[keyway-security]", JSON.stringify({ kind, ...details }));
  const webhook = process.env.KEYWAY_SECURITY_ALERT_WEBHOOK_URL;
  if (!webhook) return true;
  let url: URL;
  try {
    url = new URL(webhook);
    if (url.protocol !== "https:") throw new Error("Security alert webhook must use HTTPS");
  } catch (error) {
    console.error("[keyway-security] alert delivery failed", error instanceof Error ? error.message : "unknown error");
    return false;
  }
  for (let attempt = 1; ; attempt++) {
    try {
      const response = await fetch(url, {
        method: "POST",
        signal: AbortSignal.timeout(5_000),
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ kind, ...details }),
      });
      if (!response.ok) throw new Error(`Security alert webhook returned HTTP ${response.status}`);
      return true;
    } catch (error) {
      console.error("[keyway-security] alert delivery failed", { attempt, cause: error instanceof Error ? error.message.slice(0, 120) : "unknown error" });
      if (attempt >= ALERT_ATTEMPTS) return false;
      await new Promise((resolve) => setTimeout(resolve, alertRetry.delayMs * 2 ** (attempt - 1)));
    }
  }
}

function positiveInteger(value: string | undefined, fallback: number): number {
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : fallback;
}
