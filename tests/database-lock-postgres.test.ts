import assert from "node:assert/strict";
import test from "node:test";
import postgres from "postgres";
import { database, withUserLock } from "../src/server/database.ts";

// The database client and its lock budget are per process, and this test runs the pool to its limit, so it has a
// file of its own.
const target = process.env.KEYWAY_AUTH_TEST_DATABASE_URL;
const delay = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));
const within = <T>(promise: Promise<T>, ms: number) => Promise.race([promise.then(() => true), delay(ms).then(() => false)]);

test("a lock whose acquisition fails gives its pool connection back", { skip: !target }, async (t) => {
  // A database of its own, so cancelling waits here never touches another test file's.
  const admin = postgres(target!, { max: 1 });
  const name = `keyway_lock_${crypto.randomUUID().replaceAll("-", "")}`;
  await admin.unsafe(`create database ${name}`);
  const url = new URL(target!);
  url.pathname = `/${name}`;
  Object.assign(process.env, { NODE_ENV: "test", DATABASE_URL: url.toString() });
  const sql = await database();
  const holder = postgres(url.toString(), { max: 1 });
  t.after(async () => {
    await holder.end({ timeout: 0 });
    await sql.end({ timeout: 0 });
    await admin.unsafe(`drop database if exists ${name} with (force)`);
    await admin.end();
  });

  // More failed acquisitions than the pool has connections: each one waits in Postgres for a lock another session
  // holds, and is then cancelled, as a lock or statement timeout would end it.
  const keys = Array.from({ length: 12 }, () => `lock-failure-${crypto.randomUUID()}`);
  for (const key of keys) await holder`select pg_advisory_lock(hashtextextended(${key}, 0))`;
  let settled = 0;
  const attempts = keys.map((key) => withUserLock(key, async () => "ran").then(
    () => { settled += 1; return "ran"; },
    () => { settled += 1; return "failed"; },
  ));
  const deadline = Date.now() + 10_000;
  while (settled < keys.length && Date.now() < deadline) {
    await holder`
      select pg_cancel_backend(pid) from pg_stat_activity
      where datname = current_database() and pid <> pg_backend_pid() and wait_event_type = 'Lock' and query like '%pg_advisory_lock%'
    `;
    await delay(50);
  }
  // With connections leaked, the last acquisitions never get one to wait on, so they never end.
  assert.equal(settled, keys.length, "every acquisition ended");
  assert.deepEqual(await Promise.all(attempts), keys.map(() => "failed"));

  assert.ok(await within(sql`select 1`, 3_000), "the pool still has connections");
  assert.equal(await withUserLock(crypto.randomUUID(), async (connection) => (await connection`select 1 as one`)[0].one), 1);
});
