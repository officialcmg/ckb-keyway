import { createHash } from "node:crypto";
import { database } from "./database.ts";

type StoredResult = {
  request_digest: string;
  status: "running" | "completed" | "failed";
  response: unknown;
  error_message: string | null;
};

export async function runIdempotentMutation<T>(
  userId: string,
  operation: string,
  key: string,
  request: unknown,
  mutation: () => Promise<T>,
): Promise<T> {
  if (!/^[A-Za-z0-9_-]{16,128}$/.test(key)) throw new Error("A valid idempotency key is required");
  const digest = createHash("sha256").update(JSON.stringify(request)).digest("hex");

  const sql = await database();
  const [claimed] = await sql<Array<{ id: number }>>`
    insert into keyway_idempotency_keys (
      stytch_user_id, operation, idempotency_key, request_digest, status, expires_at
    ) values (${userId}, ${operation}, ${key}, ${digest}, 'running', now() + interval '24 hours')
    on conflict (stytch_user_id, operation, idempotency_key) do nothing
    returning 1 as id
  `;

  if (!claimed) {
    const rows = await sql<StoredResult[]>`
      select request_digest, status, response, error_message
      from keyway_idempotency_keys
      where stytch_user_id = ${userId} and operation = ${operation} and idempotency_key = ${key}
        and expires_at > now()
      limit 1
    `;
    const stored = rows[0];
    if (!stored) throw new Error("Idempotency record expired; use a new key");
    if (stored.request_digest !== digest) throw new Error("Idempotency key was already used for another request");
    if (stored.status === "completed") return stored.response as T;
    if (stored.status === "failed") throw new Error(stored.error_message ?? "The previous request failed");
    throw new Error("The request is still in progress");
  }

  try {
    const result = await mutation();
    await sql`
      update keyway_idempotency_keys
      set status = 'completed', response = ${sql.json(result as never)}, updated_at = now()
      where stytch_user_id = ${userId} and operation = ${operation} and idempotency_key = ${key}
    `;
    return result;
  } catch (error) {
    const message = error instanceof Error ? error.message : "Managed operation failed";
    await sql`
      update keyway_idempotency_keys
      set status = 'failed', error_message = ${message}, updated_at = now()
      where stytch_user_id = ${userId} and operation = ${operation} and idempotency_key = ${key}
    `;
    throw error;
  }
}
