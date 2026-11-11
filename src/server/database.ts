import postgres from "postgres";
import { migrations } from "./migrations";

let client: ReturnType<typeof postgres> | undefined;
let migration: Promise<void> | undefined;

export type DatabaseSql = ReturnType<typeof postgres>;

export async function database() {
  const url = process.env.DATABASE_URL;
  if (!url) throw new Error("DATABASE_URL is required");
  client ??= postgres(url, { max: 12, idle_timeout: 20 });
  migration ??= process.env.NODE_ENV === "production" ? verifySchema(client) : migrateDatabase(client);
  await migration;
  return client;
}

// Lock holders keep a pool connection each, and work done inside a lock still takes more from the pool, so holders
// never get more than 8 of its 12. Login-code locks and wallet locks each have their own 3: slow first-time wallet
// setup (Lit and CKB calls) can't hold up anyone's sign-in, and a flood of sign-in requests can't hold up wallets.
// Daily-amount changes (Lit and CKB calls too) have their own 2, so they hold up neither.
type LockBudget = { held: number; waiting: Array<() => void>; max: number };
const walletLocks: LockBudget = { held: 0, waiting: [], max: 3 };
const loginCodeLocks: LockBudget = { held: 0, waiting: [], max: 3 };
const dailyAmountLocks: LockBudget = { held: 0, waiting: [], max: 2 };
// Calls for one key, running or waiting. More get a fast refusal instead of queueing without end.
const MAX_CALLS_PER_LOCK = 8;
const lockQueues = new Map<string, { calls: number; tail: Promise<void> }>();

export function withUserLock<T>(userId: string, task: (sql: DatabaseSql) => Promise<T>): Promise<T> {
  return withLock(userId, walletLocks, task);
}

/** The lock for changing one user's daily email-confirmation amounts. */
export function withDailyAmountLock<T>(userId: string, task: (sql: DatabaseSql) => Promise<T>): Promise<T> {
  return withLock(`daily-amounts:${userId}`, dailyAmountLocks, task);
}

/** The lock for sending or checking one email's login code in one scope. */
export function withLoginCodeLock<T>(key: string, task: (sql: DatabaseSql) => Promise<T>): Promise<T> {
  return withLock(key, loginCodeLocks, task);
}

async function withLock<T>(key: string, budget: LockBudget, task: (sql: DatabaseSql) => Promise<T>): Promise<T> {
  const sql = await database();
  // Callers for the same key wait here, in this process, rather than on a pool connection blocked in Postgres.
  const queue = lockQueues.get(key) ?? { calls: 0, tail: Promise.resolve() };
  if (queue.calls >= MAX_CALLS_PER_LOCK) throw new Error("Too many requests in progress for this account. Try again in a moment");
  queue.calls += 1;
  lockQueues.set(key, queue);
  const previous = queue.tail;
  let finished!: () => void;
  queue.tail = new Promise<void>((resolve) => { finished = resolve; });
  try {
    await previous;
    if (budget.held < budget.max) budget.held += 1;
    else await new Promise<void>((resolve) => budget.waiting.push(resolve));
    try {
      return await withReservedLock(sql, key, task);
    } finally {
      const next = budget.waiting.shift();
      if (next) next(); else budget.held -= 1;
    }
  } finally {
    queue.calls -= 1;
    if (queue.calls === 0) lockQueues.delete(key);
    finished();
  }
}

async function withReservedLock<T>(sql: DatabaseSql, userId: string, task: (sql: DatabaseSql) => Promise<T>): Promise<T> {
  // The advisory lock still serializes the key across API processes.
  const connection = await sql.reserve();
  await connection`select pg_advisory_lock(hashtextextended(${userId}, 0))`;
  try {
    return await task(connection);
  } finally {
    try {
      await connection`select pg_advisory_unlock(hashtextextended(${userId}, 0))`;
    } finally {
      connection.release();
    }
  }
}

export async function migrateDatabase(sql: ReturnType<typeof postgres>): Promise<void> {
  await sql.begin(async (transaction) => {
    await transaction`select pg_advisory_xact_lock(hashtext('ckb-keyway-schema'))`;
    await transaction`
      create table if not exists keyway_schema_migrations (
        version integer primary key,
        name text not null,
        applied_at timestamptz not null default now()
      )
    `;
    const applied = await transaction<Array<{ version: number }>>`select version from keyway_schema_migrations`;
    const versions = new Set(applied.map(({ version }) => version));
    for (const item of migrations) {
      if (versions.has(item.version)) continue;
      await item.up(transaction as unknown as DatabaseSql);
      await transaction`
        insert into keyway_schema_migrations (version, name)
        values (${item.version}, ${item.name})
      `;
    }
  });
}

async function verifySchema(sql: DatabaseSql): Promise<void> {
  const [row] = await sql<Array<{ version: number }>>`select max(version) as version from keyway_schema_migrations`;
  if (row?.version !== migrations.at(-1)?.version) throw new Error("Run the KeyWay database migrations before starting the API");
}
