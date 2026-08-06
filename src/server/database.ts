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
  const connection = await sql.reserve();
  await connection`select pg_advisory_lock(hashtext('ckb-keyway-schema'))`;
  try {
    await connection`
      create table if not exists keyway_wallets (
        stytch_user_id text primary key,
        wallet jsonb not null,
        updated_at timestamptz not null default now()
      )
    `;
    await connection`
      create table if not exists keyway_device_leases (
        stytch_user_id text primary key,
        device_id_hash text not null,
        lease_id uuid not null,
        expires_at timestamptz not null
      )
    `;
    await connection`
      create table if not exists keyway_signing_confirmations (
        stytch_user_id text primary key,
        nonce uuid not null,
        transaction_digest text not null,
        expires_at timestamptz not null
      )
    `;
    await connection`
      create table if not exists keyway_node_backups (
        stytch_user_id text primary key,
        generation bigint not null,
        format_version integer not null,
        database_prefix text not null,
        salt text not null,
        iv text not null,
        ciphertext bytea not null,
        digest text not null,
        source_device_id_hash text not null,
        status text not null check (status in ('available', 'claimed', 'consumed')),
        claimed_device_id_hash text,
        claim_expires_at timestamptz,
        created_at timestamptz not null default now(),
        updated_at timestamptz not null default now()
      )
    `;
  } finally {
    try {
      await connection`select pg_advisory_unlock(hashtext('ckb-keyway-schema'))`;
    } finally {
      connection.release();
    }
  }
}
