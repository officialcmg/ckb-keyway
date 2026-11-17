import postgres from "postgres";
import { migrations } from "./migrations";

let client: ReturnType<typeof postgres> | undefined;
let migration: Promise<void> | undefined;

export type DatabaseSql = ReturnType<typeof postgres>;

export async function database() {
  const url = process.env.DATABASE_URL;
  if (!url) throw new Error("DATABASE_URL is required");
  client ??= postgres(url, { max: 10, idle_timeout: 20 });
  // A failed first connection (the database not up yet) isn't kept, so the next call tries again.
  migration ??= (process.env.NODE_ENV === "production" ? verifySchema(client) : migrateDatabase(client))
    .catch((error: unknown) => { migration = undefined; throw error; });
  await migration;
  return client;
}

// Lock holders keep a pool connection each, and work done inside a lock still takes more from the pool, so holders
// never get more than 6 of its 10. Login-code locks and wallet locks each have their own 3: a flood of sign-in
// requests can't hold up wallets, and slow Lit and CKB calls run outside wallet locks where they can.
// Deciding whether to send a login code takes no lock and is quick, so it has 2 slots of its own: a request the
// limits refuse is turned away without waiting behind sends, which can each take seconds.
// Outside these budgets, the watchtower keeps 1 connection and old-address sweeps at most 1 (legacy-sweep.ts); sweeps
// run every query on their own connection and never wait on the pool while holding one. That leaves at least two
// connections for the work inside locks and everything else, so the pool can't deadlock.
const MAX_RESERVED_LOCKS = 3;
export const LOGIN_DECISION_SLOTS = 2;
// Sign-in requests waiting in this process for login-code work (decisions and locks each), and how long one waits
// for its turn. Past either, it is refused with a "try again", so a flood can't pile up requests without end or
// make anyone wait without end. Callers are also capped per requester (src/server/auth.ts).
export const loginQueue = { maxWaiting: 256, decisionWaitMs: 5_000, lockWaitMs: 20_000 };
const LOGIN_BUSY = "Too many sign-in requests right now. Try again in a moment";
type LockBudget = {
  max: number;
  held: number;
  /** Callers waiting for their turn: behind another caller for the same key, or for a slot. */
  queued: number;
  waiting: Array<() => void>;
  limits?: () => { maxWaiting: number; waitMs: number };
};
const walletLocks: LockBudget = { max: MAX_RESERVED_LOCKS, held: 0, queued: 0, waiting: [] };
const loginCodeLocks: LockBudget = {
  max: MAX_RESERVED_LOCKS, held: 0, queued: 0, waiting: [],
  limits: () => ({ maxWaiting: loginQueue.maxWaiting, waitMs: loginQueue.lockWaitMs }),
};
const loginDecisions: LockBudget = {
  max: LOGIN_DECISION_SLOTS, held: 0, queued: 0, waiting: [],
  limits: () => ({ maxWaiting: loginQueue.maxWaiting, waitMs: loginQueue.decisionWaitMs }),
};
// Calls for one wallet, running or waiting. More get a fast refusal instead of queueing without end. Login-code
// locks have no such cap: their key is an email anyone can type, so a cap there would let a stranger refuse the
// owner's own sign-in. Their callers are capped per requester instead, and all of them by `loginQueue`.
const MAX_CALLS_PER_LOCK = 8;
const lockQueues = new Map<string, { calls: number; tail: Promise<void> }>();

export function withUserLock<T>(userId: string, task: (sql: DatabaseSql) => Promise<T>): Promise<T> {
  return withLock(userId, walletLocks, task, MAX_CALLS_PER_LOCK);
}

/** The lock for sending or checking one email's login code in one scope. */
export function withLoginCodeLock<T>(key: string, task: (sql: DatabaseSql) => Promise<T>): Promise<T> {
  return withLock(key, loginCodeLocks, task);
}

/**
 * Runs login-code work that needs no email lock (deciding whether to send a code) in one of the decision slots, so
 * a flood of sign-in requests waits in this process instead of on pool connections, and never behind sends.
 */
export async function withLoginCodeSlot<T>(task: () => Promise<T>): Promise<T> {
  const deadline = enter(loginDecisions);
  let queued = true;
  try {
    await acquire(loginDecisions, deadline);
    loginDecisions.queued -= 1;
    queued = false;
    try {
      return await task();
    } finally {
      release(loginDecisions);
    }
  } finally {
    if (queued) loginDecisions.queued -= 1;
  }
}

/** Joins a budget's queue, refusing at once if it is full. Returns when the caller must give up waiting, if ever. */
function enter(budget: LockBudget): number | undefined {
  const limits = budget.limits?.();
  if (limits && budget.queued >= limits.maxWaiting) throw new Error(LOGIN_BUSY);
  budget.queued += 1;
  return limits ? Date.now() + limits.waitMs : undefined;
}

function acquire(budget: LockBudget, deadline?: number): Promise<void> {
  if (budget.held < budget.max) {
    budget.held += 1;
    return Promise.resolve();
  }
  return new Promise<void>((resolve, reject) => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const grant = () => { clearTimeout(timer); resolve(); };
    budget.waiting.push(grant);
    if (deadline !== undefined) {
      timer = setTimeout(() => {
        budget.waiting.splice(budget.waiting.indexOf(grant), 1);
        reject(new Error(LOGIN_BUSY));
      }, Math.max(0, deadline - Date.now()));
    }
  });
}

/** Hands the slot straight to the next caller waiting, if any. */
function release(budget: LockBudget): void {
  const next = budget.waiting.shift();
  if (next) next(); else budget.held -= 1;
}

async function waitUntil(turn: Promise<void>, deadline?: number): Promise<void> {
  if (deadline === undefined) return turn;
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([turn, new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error(LOGIN_BUSY)), Math.max(0, deadline - Date.now())); })]);
  } finally {
    clearTimeout(timer);
  }
}

async function withLock<T>(key: string, budget: LockBudget, task: (sql: DatabaseSql) => Promise<T>, maxCalls = Infinity): Promise<T> {
  const sql = await database();
  // Callers for the same key wait here, in this process, rather than on a pool connection blocked in Postgres.
  const queue = lockQueues.get(key) ?? { calls: 0, tail: Promise.resolve() };
  if (queue.calls >= maxCalls) throw new Error("Too many requests in progress for this account. Try again in a moment");
  const deadline = enter(budget);
  queue.calls += 1;
  lockQueues.set(key, queue);
  const previous = queue.tail;
  let finished!: () => void;
  queue.tail = new Promise<void>((resolve) => { finished = resolve; });
  let queued = true;
  try {
    await waitUntil(previous, deadline);
    await acquire(budget, deadline);
    budget.queued -= 1;
    queued = false;
    try {
      return await withReservedLock(sql, key, task, deadline);
    } finally {
      release(budget);
    }
  } finally {
    if (queued) budget.queued -= 1;
    queue.calls -= 1;
    if (queue.calls === 0) lockQueues.delete(key);
    // The next caller for this key goes only after the one before this one, even when this one gave up waiting.
    void previous.then(finished);
  }
}

async function withReservedLock<T>(sql: DatabaseSql, key: string, task: (sql: DatabaseSql) => Promise<T>, deadline?: number): Promise<T> {
  // The advisory lock still serializes the key across API processes. With a deadline, getting the connection and
  // waiting in Postgres for another process's holder stop there too.
  const connection = deadline === undefined ? await sql.reserve() : await reserveBy(sql, deadline);
  try {
    if (deadline === undefined) {
      await connection`select pg_advisory_lock(hashtextextended(${key}, 0))`;
    } else {
      try {
        await connection`select set_config('lock_timeout', ${String(Math.max(1, deadline - Date.now()))}, false)`;
        await connection`select pg_advisory_lock(hashtextextended(${key}, 0))`;
      } catch (error) {
        if ((error as { code?: string }).code === "55P03") throw new Error(LOGIN_BUSY);
        throw error;
      } finally {
        await connection`reset lock_timeout`;
      }
    }
  } catch (error) {
    // A wait that ended in an error (cancelled, or a lock or statement timeout) holds no lock: the connection goes
    // back to the pool, or each failure would keep one outside the lock budget until the pool ran dry.
    connection.release();
    throw error;
  }
  try {
    return await task(connection);
  } finally {
    try {
      await connection`select pg_advisory_unlock(hashtextextended(${key}, 0))`;
    } finally {
      connection.release();
    }
  }
}

/** A reserved connection, or a "try again" once the deadline passes; one that arrives later goes straight back. */
async function reserveBy(sql: DatabaseSql, deadline: number): Promise<Awaited<ReturnType<DatabaseSql["reserve"]>>> {
  const reserving = sql.reserve();
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([reserving, new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error(LOGIN_BUSY)), Math.max(0, deadline - Date.now())); })]);
  } catch (error) {
    void reserving.then((late) => late.release(), () => undefined);
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

export async function migrateDatabase(sql: ReturnType<typeof postgres>): Promise<void> {
  // One session migrates at a time. Each migration commits on its own, in a transaction unless it can't run in one.
  const connection = await sql.reserve();
  try {
    // Waits for the lock here rather than in Postgres: a session waiting in Postgres keeps a snapshot open, and a
    // concurrent index build waits for every older snapshot, so it would deadlock with the migrator it waits for.
    while (!(await connection<Array<{ locked: boolean }>>`select pg_try_advisory_lock(hashtext('ckb-keyway-schema')) as locked`)[0].locked) {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    try {
      await connection`
        create table if not exists keyway_schema_migrations (
          version integer primary key,
          name text not null,
          applied_at timestamptz not null default now()
        )
      `;
      const applied = await connection<Array<{ version: number }>>`select version from keyway_schema_migrations`;
      const versions = new Set(applied.map(({ version }) => version));
      for (const item of migrations) {
        if (versions.has(item.version)) continue;
        const record = () => connection`insert into keyway_schema_migrations (version, name) values (${item.version}, ${item.name})`;
        if (item.transaction === false) {
          await item.up(connection);
          await record();
          continue;
        }
        await connection`begin`;
        try {
          await item.up(connection);
          await record();
          await connection`commit`;
        } catch (error) {
          await connection`rollback`.catch(() => undefined);
          throw error;
        }
      }
    } finally {
      await connection`select pg_advisory_unlock(hashtext('ckb-keyway-schema'))`.catch(() => undefined);
    }
  } finally {
    connection.release();
  }
}

async function verifySchema(sql: DatabaseSql): Promise<void> {
  const [row] = await sql<Array<{ version: number }>>`select max(version) as version from keyway_schema_migrations`;
  if (row?.version !== migrations.at(-1)?.version) throw new Error("Run the KeyWay database migrations before starting the API");
}
