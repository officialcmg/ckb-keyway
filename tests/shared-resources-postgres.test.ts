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
import { bootstrap, type Provisioning } from "../src/server/bootstrap.ts";
import { acquireLease } from "../src/server/device-lease.ts";
import { handleKeyWayRequest } from "../src/server/http.ts";
import { runIdempotentMutation } from "../src/server/idempotency.ts";
import { prepareBackupForDevice, saveNodeBackup } from "../src/server/node-backup.ts";
import { alertRetry, recordSigningEvent } from "../src/server/security-alerts.ts";
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

  await t.test("a new record drops expired responses and old tombstones, and expired keys stay refused", async () => {
    const userId = crypto.randomUUID();
    const others = Array.from({ length: 3 }, () => crypto.randomUUID());
    const insert = (owner: string, key: string, expires: string) => sql`
      insert into keyway_v2_idempotency_keys (user_id, operation, idempotency_key, request_digest, status, response, expires_at)
      values (${owner}, 'test', ${key}, 'digest', 'completed', ${sql.json({ payload: "x".repeat(1_000) })}, now() + ${expires}::interval)
    `;
    await insert(userId, "own-expired-key-0001", "-1 minute");
    for (const other of others) await insert(other, "other-expired-key", "-1 minute");
    await insert(others[0], "other-tombstone-key", "-8 days");
    await insert(others[0], "other-current-key", "1 hour");

    const result = await runIdempotentMutation(userId, "test", "fresh-idempotency-key", { a: 1 }, async () => ({ ok: true }));
    assert.deepEqual(result, { ok: true });
    const rows = await sql<Array<{ idempotency_key: string; stored: boolean }>>`
      select idempotency_key, response is not null as stored from keyway_v2_idempotency_keys
      where user_id in ${sql([userId, ...others])} order by idempotency_key, user_id
    `;
    assert.deepEqual(rows.map((row) => `${row.idempotency_key}:${row.stored}`).sort(), [
      "fresh-idempotency-key:true", "other-current-key:true",
      "other-expired-key:false", "other-expired-key:false", "other-expired-key:false", "own-expired-key-0001:false",
    ]);
    // An expired key is still refused, never run again.
    let ran = false;
    await assert.rejects(runIdempotentMutation(userId, "test", "own-expired-key-0001", {}, async () => { ran = true; }), /use a new key/);
    assert.equal(ran, false);
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

test("L3: the unusual-signing alert survives concurrent signings and failed deliveries", { skip }, async (t) => {
  const { sql } = await setup();
  const threshold = 3;
  process.env.KEYWAY_SIGNING_ALERT_THRESHOLD = String(threshold);
  process.env.KEYWAY_SECURITY_ALERT_WEBHOOK_URL = "https://alerts.example/hook";
  const warn = console.warn;
  console.warn = (...args: unknown[]) => { if (args[0] !== "[keyway-security]") warn(...args); };
  const retryDelay = alertRetry.delayMs;
  alertRetry.delayMs = 20;
  let failures = 0;
  let attempts = 0;
  let delivered = 0;
  globalThis.fetch = (async () => {
    attempts += 1;
    if (failures > 0) { failures -= 1; return new Response("unavailable", { status: 503 }); }
    delivered += 1;
    return new Response(null, { status: 204 });
  }) as typeof fetch;
  const reset = async () => {
    await sql`delete from keyway_security_events where kind = 'signing'`;
    await sql`delete from keyway_security_alert_state`.catch(() => undefined);
    failures = 0; attempts = 0; delivered = 0;
  };
  const eventually = async (check: () => boolean, ms = 8_000) => {
    const deadline = Date.now() + ms;
    while (!check() && Date.now() < deadline) await delay(50);
    return check();
  };
  const signers = () => Array.from({ length: 2 * threshold }, () => crypto.randomUUID());
  t.after(() => {
    alertRetry.delayMs = retryDelay;
    console.warn = warn;
    globalThis.fetch = realFetch;
    delete process.env.KEYWAY_SECURITY_ALERT_WEBHOOK_URL;
    delete process.env.KEYWAY_SIGNING_ALERT_THRESHOLD;
  });

  await t.test("signings that step past the threshold together still raise it", async () => {
    await reset();
    // Signings that committed together, so no signing saw the count at exactly the threshold.
    for (let index = 0; index <= threshold; index++) {
      await sql`insert into keyway_security_events (kind, subject_hash) values ('signing', ${`concurrent-${index}`})`;
    }
    await recordSigningEvent(crypto.randomUUID());
    assert.ok(await eventually(() => delivered === 1), "the alert is delivered");
  });

  await t.test("a burst raises one alert, and a failed delivery is retried", async () => {
    await reset();
    failures = 2;
    await Promise.all(signers().map((id) => recordSigningEvent(id)));
    assert.ok(await eventually(() => delivered === 1), "the alert is delivered after retries");
    await Promise.all(signers().map((id) => recordSigningEvent(id)));
    await delay(500);
    assert.equal(delivered, 1, "one alert per window");
    assert.equal(attempts, 3);
  });

  await t.test("an alert that can't be delivered is raised again by a later signing in the burst", async () => {
    await reset();
    failures = 3;
    await Promise.all(signers().map((id) => recordSigningEvent(id)));
    assert.ok(await eventually(() => attempts === 3 && failures === 0), "every attempt is made");
    const deadline = Date.now() + 5_000;
    while ((await sql`select 1 from keyway_security_alert_state`).length > 0 && Date.now() < deadline) await delay(50);
    assert.equal(delivered, 0);
    await recordSigningEvent(crypto.randomUUID());
    assert.ok(await eventually(() => delivered === 1), "the next signing raises it again");
  });
});

test("L5: first-time wallet setup holds no wallet lock while Lit works", { skip }, async (t) => {
  const { sql } = await setup();

  await t.test("three new accounts' setups don't stall another user's wallet lock", async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    let chipotleCalls = 0;
    globalThis.fetch = (async () => {
      chipotleCalls += 1;
      await gate;
      throw new Error("test Chipotle unavailable");
    }) as typeof fetch;
    try {
      const setups = Array.from({ length: 3 }, () => bootstrap({ id: crypto.randomUUID() } as User, DEVICE_A).then(() => "ok", () => "failed"));
      assert.ok(await within((async () => { while (chipotleCalls < 3) await delay(20); })(), 5_000), "every setup is calling Chipotle");
      assert.ok(await within(withUserLock(crypto.randomUUID(), async () => "ok"), 2_000), "another user's lock is taken at once");
      release();
      assert.deepEqual(await Promise.all(setups), ["failed", "failed", "failed"]);
    } finally {
      release();
      globalThis.fetch = realFetch;
    }
  });

  await t.test("one request sets an account up; a second one meanwhile is refused, and nothing is replaced", async (st) => {
    globalThis.fetch = (async () => { throw new Error("no Lit or Chipotle calls in this test"); }) as typeof fetch;
    st.after(() => { globalThis.fetch = realFetch; });
    const user = { id: crypto.randomUUID() } as User;
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    let created = 0;
    const provisioning: Provisioning = {
      createPkp: async () => { created += 1; await gate; return `0x${"ab".repeat(20)}`; },
      complete: async () => ({ litPublicKey: `0x02${"cd".repeat(32)}`, ckbAddress: "ckt1new", encryptedFiberKey: "new-fiber-key" }),
    };
    const first = bootstrap(user, DEVICE_A, "browser", provisioning);
    while (created === 0) await delay(10);
    await assert.rejects(bootstrap(user, DEVICE_A, "browser", provisioning), /still being set up/);
    release();
    const result = await first;
    assert.equal(result.provisioned, true);
    assert.equal(result.wallet.litPkpId, `0x${"ab".repeat(20)}`);
    assert.equal(created, 1, "one PKP");
    const again = await bootstrap(user, DEVICE_A, "browser", provisioning);
    assert.equal(again.provisioned, false);
    assert.equal(created, 1);
    const [{ count }] = await sql<Array<{ count: number }>>`select count(*)::int as count from keyway_v2_provisioning_claims where user_id = ${user.id}`;
    assert.equal(count, 0, "the claim is released");

    // A setup whose wallet became ready meanwhile (its claim expired and another request finished) keeps that wallet.
    const raced = { id: crypto.randomUUID() } as User;
    const late: Provisioning = {
      createPkp: async () => `0x${"ef".repeat(20)}`,
      complete: async (litPkpId) => {
        await saveWallet(raced, readyWallet(DEVICE_A, { litPkpId, encryptedFiberKey: "fiber-key-in-use" }));
        return { litPublicKey: `0x02${"cd".repeat(32)}`, ckbAddress: "ckt1late", encryptedFiberKey: "replacement" };
      },
    };
    assert.equal((await bootstrap(raced, DEVICE_A, "browser", late)).provisioned, false);
    const kept = await readWallet(raced);
    assert.equal(kept?.status === "ready" && kept.encryptedFiberKey, "fiber-key-in-use");

    // A setup whose claim another request took over (it expired meanwhile) stops before the next paid step.
    const overtaken = { id: crypto.randomUUID() } as User;
    let completed = 0;
    const slow: Provisioning = {
      createPkp: async () => {
        await sql`update keyway_v2_provisioning_claims set claim_id = ${crypto.randomUUID()} where user_id = ${overtaken.id}`;
        return `0x${"12".repeat(20)}`;
      },
      complete: async () => { completed += 1; return { litPublicKey: `0x02${"cd".repeat(32)}`, ckbAddress: "ckt1", encryptedFiberKey: "key" }; },
    };
    await assert.rejects(bootstrap(overtaken, DEVICE_A, "browser", slow), /still being set up/);
    assert.equal(completed, 0);
    assert.equal(await readWallet(overtaken), undefined);
  });

  await t.test("sign-in bootstraps are rate limited per user, and a setup in progress answers 409", async () => {
    const { user, call } = await signedIn();
    await saveWallet(user, readyWallet(DEVICE_A));
    const statuses: number[] = [];
    for (let index = 0; index < 31; index++) {
      const response = await call("bootstrap", { deviceIdHash: DEVICE_A, keyCustody: "lit" }, { "Idempotency-Key": `bootstrap-rate-${String(index).padStart(4, "0")}` });
      statuses.push(response.status);
    }
    assert.deepEqual(statuses, [...Array.from({ length: 30 }, () => 200), 429]);

    const fresh = await signedIn();
    await sql`insert into keyway_v2_provisioning_claims (user_id, claim_id) values (${fresh.user.id}, ${crypto.randomUUID()})`;
    const busy = await fresh.call("bootstrap", { deviceIdHash: DEVICE_A, keyCustody: "lit" }, { "Idempotency-Key": "bootstrap-busy-0001" });
    assert.equal(busy.status, 409);
    assert.equal(busy.headers.get("retry-after"), "5");
  });
});
