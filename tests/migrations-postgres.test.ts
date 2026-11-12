import assert from "node:assert/strict";
import test from "node:test";
import postgres from "postgres";
import { database, migrateDatabase, type DatabaseSql } from "../src/server/database.ts";
import { migrations } from "../src/server/migrations.ts";

const enabled = Boolean(process.env.KEYWAY_AUTH_TEST_DATABASE_URL);

test("migrations apply once and drop the unused hosted-node confirmations table", { skip: !enabled }, async (t) => {
  process.env.DATABASE_URL = process.env.KEYWAY_AUTH_TEST_DATABASE_URL;
  const sql = await database();
  t.after(() => sql.end());

  await migrateDatabase(sql);
  const [latest] = await sql<Array<{ version: number }>>`select max(version) as version from keyway_schema_migrations`;
  assert.equal(latest?.version, migrations.at(-1)?.version);
  const applied = await sql<Array<{ version: number }>>`select version from keyway_schema_migrations order by version`;
  assert.deepEqual(applied.map(({ version }) => version), migrations.map(({ version }) => version));
  const [dropped] = await sql<Array<{ name: string | null }>>`select to_regclass('keyway_v2_managed_confirmations')::text as name`;
  assert.equal(dropped?.name, null);
  const [kept] = await sql<Array<{ name: string | null }>>`select to_regclass('keyway_v2_signature_requests')::text as name`;
  assert.equal(kept?.name, "keyway_v2_signature_requests");
});

test("migrations 23 and 25 sign out sessions without an origin and remove expired challenges", { skip: !enabled }, async (t) => {
  const admin = postgres(process.env.KEYWAY_AUTH_TEST_DATABASE_URL!, { max: 1 });
  const name = `keyway_migration_${crypto.randomUUID().replaceAll("-", "")}`;
  await admin.unsafe(`create database ${name}`);
  const url = new URL(process.env.KEYWAY_AUTH_TEST_DATABASE_URL!);
  url.pathname = `/${name}`;
  const sql = postgres(url.toString(), { max: 1 });
  t.after(async () => {
    await sql.end({ timeout: 0 });
    await admin.unsafe(`drop database if exists ${name} with (force)`);
    await admin.end();
  });
  // The schema as it was at version 22, with one session from before origins and one from after.
  await sql.begin(async (tx) => {
    await tx`create table keyway_schema_migrations (version integer primary key, name text not null, applied_at timestamptz not null default now())`;
    for (const item of migrations.filter(({ version }) => version <= 22)) {
      await item.up(tx as unknown as DatabaseSql);
      await tx`insert into keyway_schema_migrations (version, name) values (${item.version}, ${item.name})`;
    }
  });
  const [user] = await sql<Array<{ id: string }>>`insert into keyway_auth_users (name, email, "emailVerified") values ('', 'old@example.com', true) returning id`;
  await sql`insert into keyway_auth_sessions ("expiresAt", token, "updatedAt", "userId", "scopeId", "origin") values
    (now() + interval '1 day', 'before-origins', now(), ${user.id}, 'dashboard', null),
    (now() + interval '1 day', 'after-origins', now(), ${user.id}, 'dashboard', 'https://dashboard.example')`;
  const [expired, open] = [crypto.randomUUID(), crypto.randomUUID()];
  await sql`insert into keyway_auth_challenges (id, scope_id, email, expires_at, status) values
    (${expired}, 'dashboard', 'old@example.com', now() - interval '1 minute', 'sent'),
    (${open}, 'dashboard', 'old@example.com', now() + interval '5 minutes', 'sent')`;
  await migrateDatabase(sql);
  const challenges = await sql<Array<{ id: string }>>`select id from keyway_auth_challenges`;
  assert.deepEqual(challenges.map(({ id }) => id), [open]);
  const sessions = await sql<Array<{ token: string }>>`select token from keyway_auth_sessions order by token`;
  assert.deepEqual(sessions.map(({ token }) => token), ["after-origins"]);
});
