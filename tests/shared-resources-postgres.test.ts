import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { after, test } from "node:test";
import postgres from "postgres";
import { Pool } from "pg";
import { getMigrations } from "better-auth/db/migration";
import type { User } from "../src/server/auth-user.ts";
import { authSchemaOptions } from "../src/server/auth-options.ts";
import { database, withUserLock } from "../src/server/database.ts";
import { addApplicationOrigin, createApplication } from "../src/server/applications.ts";
import { closeAuthPool, sendEmailCode, setAuthDeliveryForTests, verifyEmailCode } from "../src/server/auth.ts";
import { acquireLease } from "../src/server/device-lease.ts";
import { handleKeyWayRequest } from "../src/server/http.ts";
import { runIdempotentMutation } from "../src/server/idempotency.ts";
import { prepareBackupForDevice, saveNodeBackup } from "../src/server/node-backup.ts";
import { recordSigningEvent } from "../src/server/security-alerts.ts";
import { readWallet, saveWallet, type ReadyWallet } from "../src/server/user-wallet.ts";

// Shared resources (the Lit credit, the database, the lock budget, alerts) against a database of their own: these
// tests fill the wallet-lock budget and count every signing event, so other test files must not share it.
const adminUrl = process.env.KEYWAY_AUTH_TEST_DATABASE_URL;
const skip = !adminUrl;
const delay = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));
const within = <T>(promise: Promise<T>, ms: number) => Promise.race([promise.then(() => true), delay(ms).then(() => false)]);
const realFetch = globalThis.fetch;
const ORIGIN = "https://ops.example";
const DEVICE_A = "a".repeat(64);
const DEVICE_B = "b".repeat(64);

let ready: Promise<{ sql: postgres.Sql; codes: Map<string, string> }> | undefined;
let admin: postgres.Sql | undefined;
const name = `keyway_ops_${crypto.randomUUID().replaceAll("-", "")}`;

function setup() {
  ready ??= (async () => {
    Object.assign(process.env, { NODE_ENV: "test" });
    process.env.BETTER_AUTH_SECRET = "disposable-auth-test-secret-01234567890123456789";
    process.env.BETTER_AUTH_URL = "http://localhost:3001";
    process.env.KEYWAY_RATE_LIMIT_SECRET = "disposable-rate-test-secret-01234567890123456789";
    process.env.LIT_USAGE_API_KEY = "test-usage-key";
    process.env.LIT_PROVISIONING_API_KEY = "test-provisioning-key";
    delete process.env.KEYWAY_SECURITY_ALERT_WEBHOOK_URL;
    admin = postgres(adminUrl!, { max: 1 });
    await admin.unsafe(`create database ${name}`);
    const url = new URL(adminUrl!);
    url.pathname = `/${name}`;
    process.env.DATABASE_URL = url.toString();
    const sql = await database();
    const pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 1 });
    await (await getMigrations(authSchemaOptions(pool))).runMigrations();
    await pool.end();
    const codes = new Map<string, string>();
    setAuthDeliveryForTests(async ({ scope, email, otp }) => { codes.set(`${scope.id}:${email}`, otp); });
    return { sql, codes };
  })();
  return ready;
}

after(async () => {
  globalThis.fetch = realFetch;
  if (!ready) return;
  const { sql } = await ready;
  await closeAuthPool();
  await sql.end({ timeout: 0 });
  await admin!.unsafe(`drop database if exists ${name} with (force)`);
  await admin!.end();
});

/** A signed-in user of a fresh application, and a way to call the API as them. */
async function signedIn() {
  const { codes } = await setup();
  const owner = { id: crypto.randomUUID() } as User;
  const { appId } = await createApplication(owner, { name: "Operations" });
  await addApplicationOrigin(owner, { appId, origin: ORIGIN, environment: "development" });
  const bytes = crypto.getRandomValues(new Uint8Array(2));
  const ip = `127.31.${bytes[0]}.${bytes[1]}`;
  const headers = (token?: string): Record<string, string> => ({
    Origin: ORIGIN, "x-keyway-app-id": appId, "x-keyway-client-ip": ip, ...(token ? { Authorization: `Bearer ${token}` } : {}),
  });
  const email = `ops-${crypto.randomUUID()}@example.com`;
  const sessionRequest = () => new Request("http://localhost:3001/api/v1/keyway/auth/session", { headers: headers() });
  const { challengeId } = await sendEmailCode(sessionRequest(), email);
  const login = await verifyEmailCode(sessionRequest(), challengeId, codes.get(`${appId}:${email}`)!);
  const user = login.user as User;
  const call = (path: string, body: unknown, extra: Record<string, string> = {}) => handleKeyWayRequest(new Request(`http://localhost:3001/api/v1/keyway/${path}`, {
    method: "POST",
    headers: { ...headers(login.sessionToken), "Content-Type": "application/json", ...extra },
    body: JSON.stringify(body),
  }));
  return { user, call };
}

function readyWallet(deviceIdHash: string, overrides: Partial<ReadyWallet> = {}): ReadyWallet {
  const now = new Date().toISOString();
  return {
    version: 1, status: "ready", litPkpId: `0x${"11".repeat(20)}`, litPublicKey: `0x02${"22".repeat(32)}`, ckbAddress: "ckt1ready",
    encryptedFiberKey: "ciphertext", primaryDeviceIdHash: deviceIdHash, hasOpenedChannel: false, createdAt: now, updatedAt: now, ...overrides,
  };
}

test("M3: the paid Fiber key Action is rate limited per user", { skip }, async () => {
  const { user, call } = await signedIn();
  await saveWallet(user, readyWallet(DEVICE_A));
  const lease = await acquireLease(user, DEVICE_A);
  let litCalls = 0;
  globalThis.fetch = (async () => {
    litCalls += 1;
    return Response.json({ error: "test Lit refusal" }, { status: 400 });
  }) as typeof fetch;
  try {
    const statuses: number[] = [];
    for (let index = 0; index < 7; index++) {
      const response = await call("fiber-key", { deviceIdHash: DEVICE_A, leaseId: lease.leaseId, recipientPublicKey: "A".repeat(87) });
      statuses.push(response.status);
    }
    assert.deepEqual(statuses, [400, 400, 400, 400, 400, 429, 429]);
    assert.equal(litCalls, 5, "refused requests never reach Lit");
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("M13: expired idempotency records are removed, and node-backup loads aren't stored", { skip }, async (t) => {
  const { sql } = await setup();

  await t.test("a new record removes the caller's expired records and a batch of anyone's", async () => {
    const userId = crypto.randomUUID();
    const others = Array.from({ length: 3 }, () => crypto.randomUUID());
    const insert = (owner: string, key: string, expired: boolean) => sql`
      insert into keyway_v2_idempotency_keys (user_id, operation, idempotency_key, request_digest, status, response, expires_at)
      values (${owner}, 'test', ${key}, 'digest', 'completed', ${sql.json({ payload: "x".repeat(1_000) })},
        ${expired ? sql`now() - interval '1 minute'` : sql`now() + interval '1 hour'`})
    `;
    for (let index = 0; index < 5; index++) await insert(userId, `own-expired-key-${index}`, true);
    for (const other of others) await insert(other, "other-expired-key", true);
    await insert(others[0], "other-current-key", false);

    const result = await runIdempotentMutation(userId, "test", "fresh-idempotency-key", { a: 1 }, async () => ({ ok: true }));
    assert.deepEqual(result, { ok: true });
    const rows = await sql<Array<{ user_id: string; idempotency_key: string }>>`
      select user_id, idempotency_key from keyway_v2_idempotency_keys where user_id in ${sql([userId, ...others])} order by idempotency_key
    `;
    assert.deepEqual(rows.map((row) => row.idempotency_key), ["fresh-idempotency-key", "other-current-key"]);
  });

  await t.test("loading a claimed node backup stores no copy of it", async () => {
    const { user, call } = await signedIn();
    await saveWallet(user, readyWallet(DEVICE_A));
    const ciphertext = Buffer.alloc(200_000, 7).toString("base64");
    await saveNodeBackup(user, DEVICE_A, {
      formatVersion: 1, databasePrefix: `/wasm-0x${"11".repeat(20)}`, salt: Buffer.alloc(32, 1).toString("base64"),
      iv: Buffer.alloc(12, 2).toString("base64"), ciphertext, digest: createHash("sha256").update(Buffer.from(ciphertext, "base64")).digest("hex"),
    });
    await prepareBackupForDevice(user, DEVICE_A, DEVICE_B, undefined, sql);
    await saveWallet(user, readyWallet(DEVICE_B, { hasOpenedChannel: true }));
    const lease = await acquireLease(user, DEVICE_B);
    for (const key of ["load-backup-key-0001", "load-backup-key-0002"]) {
      const response = await call("node-backup/load", { deviceIdHash: DEVICE_B, leaseId: lease.leaseId }, { "Idempotency-Key": key });
      assert.equal(response.status, 200);
      assert.equal((await response.json() as { ciphertext: string }).ciphertext, ciphertext);
    }
    const [{ count }] = await sql<Array<{ count: number }>>`select count(*)::int as count from keyway_v2_idempotency_keys where user_id = ${user.id}`;
    assert.equal(count, 0);
  });
});
