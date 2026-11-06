import assert from "node:assert/strict";
import test from "node:test";
import { database, migrateDatabase } from "../src/server/database.ts";
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
