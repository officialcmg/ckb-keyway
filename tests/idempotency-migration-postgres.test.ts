import assert from "node:assert/strict";
import test from "node:test";
import postgres from "postgres";
import { migrateDatabase } from "../src/server/database.ts";
import { migrations } from "../src/server/migrations.ts";

// Runs the idempotency-pruning migration again on a populated table while other sessions use it, so it has a
// database of its own.
const target = process.env.KEYWAY_AUTH_TEST_DATABASE_URL;
const delay = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));
const within = <T>(promise: Promise<T>, ms: number) => Promise.race([promise.then(() => true), delay(ms).then(() => false)]);
const MIGRATION = migrations.find((item) => item.name === "idempotency-pruning")!;
// Every index the migration has created, under any of its versions.
const INDEXES = ["keyway_v2_idempotency_keys_unpruned", "keyway_v2_idempotency_keys_user_created"];

test("the idempotency-pruning migration never blocks live idempotency writes", { skip: !target }, async (t) => {
  const admin = postgres(target!, { max: 1 });
  const name = `keyway_migration_${crypto.randomUUID().replaceAll("-", "")}`;
  await admin.unsafe(`create database ${name}`);
  const url = new URL(target!);
  url.pathname = `/${name}`;
  const sql = postgres(url.toString(), { max: 2 });
  const other = postgres(url.toString(), { max: 1 });
  const writer = postgres(url.toString(), { max: 1 });
  t.after(async () => {
    for (const client of [writer, other, sql]) await client.end({ timeout: 0 });
    await admin.unsafe(`drop database if exists ${name} with (force)`);
    await admin.end();
  });

  await migrateDatabase(sql);
  const undo = async () => {
    await sql`delete from keyway_schema_migrations where version = ${MIGRATION.version}`;
    for (const index of INDEXES) await sql.unsafe(`drop index if exists ${index}`);
  };
  const insert = (client: postgres.Sql, key: string, expires: string) => client`
    insert into keyway_v2_idempotency_keys (user_id, operation, idempotency_key, request_digest, status, response, expires_at)
    values ('migration-user', 'test', ${key}, 'digest', 'completed', ${client.json({ payload: "x".repeat(1_000) })}, now() + ${expires}::interval)
  `;
  for (let index = 0; index < 50; index++) await insert(sql, `expired-key-${String(index).padStart(4, "0")}`, "-1 day");

  // Waits until the migration is waiting on another session, so whatever it would block is blocked by then.
  const migrationWaiting = async () => {
    const deadline = Date.now() + 5_000;
    while (Date.now() < deadline) {
      const waiting = await writer`
        select 1 from pg_stat_activity
        where datname = current_database() and wait_event_type = 'Lock'
          and (query ilike '%create index%' or query ilike '%update keyway_v2_idempotency_keys set response = null where expires_at%')
      `;
      if (waiting.length) return;
      await delay(25);
    }
    assert.fail("the migration never waited on the other session");
  };

  await t.test("expired records are still pruned while it waits for a row in use", async () => {
    await undo();
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    let locked!: () => void;
    const started = new Promise<void>((resolve) => { locked = resolve; });
    const holding = other.begin(async (tx) => {
      await tx`select 1 from keyway_v2_idempotency_keys where idempotency_key = 'expired-key-0049' for update`;
      locked();
      await gate;
    });
    await started;
    const migrating = migrateDatabase(sql);
    try {
      await migrationWaiting();
      const pruned = writer`update keyway_v2_idempotency_keys set response = null where idempotency_key = 'expired-key-0001'`;
      assert.ok(await within(pruned, 3_000), "another expired record can be pruned meanwhile");
    } finally {
      release();
      await holding;
    }
    await migrating;
  });

  await t.test("two processes migrating at once both finish", async () => {
    await undo();
    // Another process's migrator: it waits for the first to finish, then finds nothing left to do.
    const second = postgres(url.toString(), { max: 1, onnotice: () => undefined });
    try {
      // Both queue for the migration lock, held here until each is waiting for it.
      await other`select pg_advisory_lock(hashtext('ckb-keyway-schema'))`;
      const migrating = [migrateDatabase(sql), migrateDatabase(second)];
      await delay(500);
      await other`select pg_advisory_unlock(hashtext('ckb-keyway-schema'))`;
      const results = await Promise.allSettled(migrating);
      assert.deepEqual(results.map((result) => result.status === "rejected" ? String(result.reason) : "ok"), ["ok", "ok"]);
    } finally {
      await second.end({ timeout: 0 });
    }
  });

  await t.test("an interrupted run leaves nothing that stops the next one", async () => {
    await undo();
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    let inserted!: () => void;
    const started = new Promise<void>((resolve) => { inserted = resolve; });
    const writing = other.begin(async (tx) => {
      await insert(tx as unknown as postgres.Sql, "interrupted-key-0001", "1 day");
      inserted();
      await gate;
    });
    await started;
    const migrating = migrateDatabase(sql);
    try {
      await migrationWaiting();
      // Cancelled mid-build, as a deploy that stops or a statement timeout would end it.
      await writer`
        select pg_cancel_backend(pid) from pg_stat_activity
        where datname = current_database() and wait_event_type = 'Lock' and query ilike '%create index%'
      `;
      await assert.rejects(migrating);
    } finally {
      release();
      await writing;
    }
    const [invalid] = await sql`
      select 1 from pg_index where indrelid = 'keyway_v2_idempotency_keys'::regclass and not indisvalid
    `;
    assert.ok(invalid, "the cancelled build left an invalid index");
    const [recorded] = await sql`select 1 from keyway_schema_migrations where version = ${MIGRATION.version}`;
    assert.equal(recorded, undefined, "the migration isn't recorded");
    assert.ok(await within(migrateDatabase(sql), 10_000), "the next run finishes");
    const indexes = await sql<Array<{ valid: boolean }>>`
      select indisvalid as valid from pg_index
      where indrelid = 'keyway_v2_idempotency_keys'::regclass and indexrelid::regclass::text in ${sql(INDEXES)}
    `;
    assert.equal(indexes.length, INDEXES.length);
    assert.ok(indexes.every((index) => index.valid), "its indexes are rebuilt and valid");
  });

  await t.test("new records are stored while it waits for a write in progress", async () => {
    await undo();
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    let inserted!: () => void;
    const started = new Promise<void>((resolve) => { inserted = resolve; });
    const writing = other.begin(async (tx) => {
      await insert(tx as unknown as postgres.Sql, "slow-write-key-0001", "1 day");
      inserted();
      await gate;
    });
    await started;
    const migrating = migrateDatabase(sql);
    try {
      await migrationWaiting();
      assert.ok(await within(insert(writer, "live-write-key-0001", "1 day"), 3_000), "a new record isn't held up");
    } finally {
      release();
      await writing;
    }
    await migrating;
    const indexes = await sql<Array<{ name: string; valid: boolean }>>`
      select indexrelid::regclass::text as name, indisvalid as valid from pg_index
      where indrelid = 'keyway_v2_idempotency_keys'::regclass and indexrelid::regclass::text in ${sql(INDEXES)}
      order by name
    `;
    assert.ok(indexes.length > 0 && indexes.every((index) => index.valid), "its indexes are built and valid");
    const [applied] = await sql`select 1 from keyway_schema_migrations where version = ${MIGRATION.version}`;
    assert.ok(applied, "the migration is recorded");
  });
});
