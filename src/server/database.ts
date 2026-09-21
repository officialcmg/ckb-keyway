import postgres from "postgres";
import { migrations } from "./migrations";

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
