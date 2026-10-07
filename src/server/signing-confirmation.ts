import { sha256 } from "@noble/hashes/sha2.js";
import type { User } from "./auth-user.ts";
import { database } from "./database.ts";

const TTL_MS = 5 * 60_000;

export async function issueConfirmation(user: User, serializedTransaction: string): Promise<string> {
  const sql = await database();
  const nonce = crypto.randomUUID();
  await sql`
    insert into keyway_v2_signing_confirmations (user_id, nonce, transaction_digest, expires_at)
    values (${user.id}, ${nonce}, ${digest(serializedTransaction)}, ${new Date(Date.now() + TTL_MS)})
    on conflict (user_id) do update set
      nonce = excluded.nonce,
      transaction_digest = excluded.transaction_digest,
      expires_at = excluded.expires_at
  `;
  return nonce;
}

export async function consumeConfirmation(user: User, nonce: string, serializedTransaction: string): Promise<void> {
  const sql = await database();
  const rows = await sql`
    delete from keyway_v2_signing_confirmations
    where user_id = ${user.id}
      and nonce = ${nonce}
      and transaction_digest = ${digest(serializedTransaction)}
      and expires_at > now()
    returning 1
  `;
  if (!rows[0]) throw new Error("Transaction confirmation is invalid or expired");
}

function digest(value: string): string {
  return Buffer.from(sha256(new TextEncoder().encode(value))).toString("hex");
}
