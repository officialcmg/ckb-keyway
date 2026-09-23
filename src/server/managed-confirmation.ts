import { sha256 } from "@noble/hashes/sha2.js";
import { database } from "./database.ts";

export type ManagedConfirmationPurpose = "payment" | "channel_close";

const TTL_MS = 5 * 60_000;

export async function issueManagedConfirmation(
  userId: string,
  purpose: ManagedConfirmationPurpose,
  payload: string,
): Promise<string> {
  const sql = await database();
  const nonce = crypto.randomUUID();
  await sql`
    insert into keyway_managed_confirmations
      (stytch_user_id, purpose, nonce, operation_digest, expires_at)
    values (${userId}, ${purpose}, ${nonce}, ${digest(payload)}, ${new Date(Date.now() + TTL_MS)})
    on conflict (stytch_user_id, purpose) do update set
      nonce = excluded.nonce,
      operation_digest = excluded.operation_digest,
      expires_at = excluded.expires_at
  `;
  return nonce;
}

export async function consumeManagedConfirmation(
  userId: string,
  purpose: ManagedConfirmationPurpose,
  nonce: string,
  payload: string,
): Promise<void> {
  const sql = await database();
  const rows = await sql`
    delete from keyway_managed_confirmations
    where stytch_user_id = ${userId}
      and purpose = ${purpose}
      and nonce = ${nonce}
      and operation_digest = ${digest(payload)}
      and expires_at > now()
    returning 1
  `;
  if (!rows[0]) throw new Error("Managed-node confirmation is invalid or expired");
}

function digest(value: string): string {
  return Buffer.from(sha256(new TextEncoder().encode(value))).toString("hex");
}
