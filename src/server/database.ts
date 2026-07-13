import postgres from "postgres";

let client: ReturnType<typeof postgres> | undefined;
let migration: Promise<void> | undefined;

export type DatabaseSql = ReturnType<typeof postgres>;

export async function database() {
  const url = process.env.DATABASE_URL;
  if (!url) throw new Error("DATABASE_URL is required");
  client ??= postgres(url, { max: 10, idle_timeout: 20 });
  migration ??= migrate(client);
  await migration;
  return client;
}

export async function withUserLock<T>(userId: string, task: (sql: DatabaseSql) => Promise<T>): Promise<T> {
  const sql = await database();
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

async function migrate(sql: ReturnType<typeof postgres>): Promise<void> {
  await sql`
    create table if not exists keyway_wallets (
      stytch_user_id text primary key,
      wallet jsonb not null,
      updated_at timestamptz not null default now()
    )
  `;
  await sql`
    create table if not exists keyway_device_leases (
      stytch_user_id text primary key,
      device_id_hash text not null,
      lease_id uuid not null,
      expires_at timestamptz not null
    )
  `;
  await sql`
    create table if not exists keyway_signing_confirmations (
      stytch_user_id text primary key,
      nonce uuid not null,
      transaction_digest text not null,
      expires_at timestamptz not null
    )
  `;
}
