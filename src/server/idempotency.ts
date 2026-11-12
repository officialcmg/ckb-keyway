import { createHash } from "node:crypto";
import { database, type DatabaseSql } from "./database.ts";

type StoredResult = {
  request_digest: string;
  status: "running" | "completed" | "failed";
  response: unknown;
  error_message: string | null;
  stale: boolean;
};

export type IdempotencyOptions<T> = {
  /** A repeat that arrives while the first request still runs waits up to this long for its outcome. */
  waitMs?: number;
  /**
   * For a mutation whose effect lives elsewhere (a payment): works out the outcome of a request that is still
   * "running" after `staleAfterMs` (its process exited, or its result couldn't be stored) from the handle the
   * mutation recorded before acting, without running it again. Returns undefined while the outcome isn't known.
   */
  reconcile?: (handle: unknown) => Promise<{ completed: T } | undefined>;
  /** Without `reconcile`, a stale request is reported as having an unknown outcome rather than as still running. */
  staleAfterMs?: number;
};

/**
 * How long a request may stay "running" before repeats stop calling it in progress. Its result was then most
 * likely never stored, so a repeat says its outcome is unknown, and never runs it again.
 */
export const DEFAULT_STALE_MS = 10 * 60_000;

/** A mutation error after which the operation may still have happened: the record stays "running", not "failed". */
export class OutcomeUnknownError extends Error {
  readonly outcomeUnknown = true;
}

/** Records a handle on the running request, before the mutation acts, so a later repeat can reconcile it. */
export type RecordHandle = (handle: unknown) => Promise<void>;

/** How many repeats in this process may wait for a running request at once; past it, a repeat answers at once. */
export const MAX_WAITING_REPEATS = 32;
let waitingRepeats = 0;
/** Repeats in this process now waiting for a running request (for tests). */
export const waitingRepeatCount = () => waitingRepeats;

const STORE_ATTEMPTS = 3;
/** Expired records pruned per new record, so the table never holds more than a few days of them. */
export const PRUNE_BATCH = 100;
/**
 * How long an expired record stays as a tombstone, its response dropped: a repeat with its key is still refused
 * ("use a new key") rather than run again.
 */
const TOMBSTONE = "7 days";

/**
 * Before a new record is stored, drops the stored responses of up to `PRUNE_BATCH` expired records (anyone's, oldest
 * first) and removes as many tombstones past `TOMBSTONE`. Each new record clears more than it adds, so the table
 * holds responses for at most a day and small tombstones for a week, whatever one account sends.
 */
async function pruneExpiredRecords(sql: DatabaseSql): Promise<void> {
  await sql`
    update keyway_v2_idempotency_keys set response = null
    where (user_id, operation, idempotency_key) in (
      select user_id, operation, idempotency_key from keyway_v2_idempotency_keys
      where expires_at <= now() and response is not null
      order by expires_at
      limit ${PRUNE_BATCH}
      for update skip locked
    )
  `;
  await sql`
    delete from keyway_v2_idempotency_keys
    where (user_id, operation, idempotency_key) in (
      select user_id, operation, idempotency_key from keyway_v2_idempotency_keys
      where expires_at <= now() - ${TOMBSTONE}::interval
      order by expires_at
      limit ${PRUNE_BATCH}
      for update skip locked
    )
  `;
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export async function runIdempotentMutation<T>(
  userId: string,
  operation: string,
  key: string,
  request: unknown,
  mutation: (record: RecordHandle) => Promise<T>,
  options: IdempotencyOptions<T> = {},
): Promise<T> {
  if (!/^[A-Za-z0-9_-]{16,128}$/.test(key)) throw new Error("A valid idempotency key is required");
  const digest = createHash("sha256").update(JSON.stringify(request)).digest("hex");
  const staleSeconds = (options.staleAfterMs ?? DEFAULT_STALE_MS) / 1000;

  const sql = await database();
  await pruneExpiredRecords(sql);
  const [claimed] = await sql<Array<{ id: number }>>`
    insert into keyway_v2_idempotency_keys (
      user_id, operation, idempotency_key, request_digest, status, expires_at
    ) values (${userId}, ${operation}, ${key}, ${digest}, 'running', now() + interval '24 hours')
    on conflict (user_id, operation, idempotency_key) do nothing
    returning 1 as id
  `;

  if (!claimed) {
    const read = async () => (await sql<StoredResult[]>`
      select request_digest, status, response, error_message,
        updated_at < now() - make_interval(secs => ${staleSeconds}) as stale
      from keyway_v2_idempotency_keys
      where user_id = ${userId} and operation = ${operation} and idempotency_key = ${key}
        and expires_at > now()
      limit 1
    `)[0];
    let stored = await read();
    const waiting = (row: StoredResult | undefined) => row?.status === "running" && row.request_digest === digest && !row.stale;
    // With `waitMs`, a repeat that arrives while the first request still runs waits for its outcome. Waiting
    // repeats are bounded, so a burst of them can't keep the database busy; the rest answer at once, and none
    // ever runs the mutation again.
    if (waiting(stored) && (options.waitMs ?? 0) > 0 && waitingRepeats < MAX_WAITING_REPEATS) {
      waitingRepeats++;
      try {
        const deadline = Date.now() + options.waitMs!;
        let delay = 250;
        while (waiting(stored) && Date.now() < deadline) {
          await sleep(delay);
          delay = Math.min(delay * 2, 2_000);
          stored = await read();
        }
      } finally {
        waitingRepeats--;
      }
    }
    if (!stored) throw new Error("Idempotency record expired; use a new key");
    if (stored.request_digest !== digest) throw new Error("Idempotency key was already used for another request");
    if (stored.status === "completed") return stored.response as T;
    if (stored.status === "failed") throw new Error(stored.error_message ?? "The previous request failed");
    if (stored.stale) {
      const handle = (stored.response as { recovery?: unknown } | null)?.recovery;
      const outcome = handle !== undefined && options.reconcile ? await options.reconcile(handle) : undefined;
      if (outcome) {
        await sql`
          update keyway_v2_idempotency_keys
          set status = 'completed', response = ${sql.json(outcome.completed as never)}, updated_at = now()
          where user_id = ${userId} and operation = ${operation} and idempotency_key = ${key} and status = 'running'
        `;
        return outcome.completed;
      }
      throw new Error("The first request's outcome isn't known yet. Check its status before trying again");
    }
    throw new Error("The request is still in progress");
  }

  const record: RecordHandle = async (handle) => {
    await sql`
      update keyway_v2_idempotency_keys
      set response = ${sql.json({ recovery: handle } as never)}, updated_at = now()
      where user_id = ${userId} and operation = ${operation} and idempotency_key = ${key} and status = 'running'
    `;
  };
  let result: T;
  try {
    result = await mutation(record);
  } catch (error) {
    // Its outcome isn't known, so it isn't recorded as failed: repeats reconcile it, or say it's unknown.
    if (error instanceof OutcomeUnknownError) throw error;
    // Database and network error text (Postgres errors, Node system errors) isn't replayed to repeats.
    const { name, syscall, errno } = (error ?? {}) as { name?: unknown; syscall?: unknown; errno?: unknown };
    const internal = name === "PostgresError" || typeof syscall === "string" || errno !== undefined;
    const message = error instanceof Error && !internal ? error.message : "Managed operation failed";
    await sql`
      update keyway_v2_idempotency_keys
      set status = 'failed', error_message = ${message}, updated_at = now()
      where user_id = ${userId} and operation = ${operation} and idempotency_key = ${key} and status = 'running'
    `;
    throw error;
  }
  // Both writes only touch a running record: a repeat may already have reconciled a slow request, and what it
  // stored stays the answer for this key.
  // The operation succeeded, so its result goes back to the caller even if it can't be stored. The record then
  // stays "running", never "failed": a repeat never reports a failure for something that went through, never
  // runs it again, and, with `reconcile`, recovers the outcome from the handle once the record is stale.
  for (let attempt = 1; ; attempt++) {
    try {
      await sql`
        update keyway_v2_idempotency_keys
        set status = 'completed', response = ${sql.json(result as never)}, updated_at = now()
        where user_id = ${userId} and operation = ${operation} and idempotency_key = ${key} and status = 'running'
      `;
      break;
    } catch (error) {
      if (attempt >= STORE_ATTEMPTS) {
        console.error(`Couldn't store the result of ${operation}; a repeat will reconcile it`, error instanceof Error ? error.message : error);
        break;
      }
      await sleep(100 * 2 ** attempt);
    }
  }
  return result;
}
