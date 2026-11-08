import assert from "node:assert/strict";
import { after, test } from "node:test";
import postgres from "postgres";
import { Pool } from "pg";
import { getMigrations } from "better-auth/db/migration";
import type { User } from "../src/server/auth-user.ts";
import { authSchemaOptions } from "../src/server/auth-options.ts";
import { database, withUserLock } from "../src/server/database.ts";
import { addApplicationOrigin, createApplication, prepareOtpSend, removeApplicationOrigin } from "../src/server/applications.ts";
import { closeAuthPool, sendEmailCode, sessionForRequest, setAuthDeliveryForTests, verifyEmailCode } from "../src/server/auth.ts";

// Login codes, their limits, the per-user lock and app sessions, against a database of their own: some of these
// fill the connection pool or count every login-code event, so other test files must not share it.
const adminUrl = process.env.KEYWAY_AUTH_TEST_DATABASE_URL;
const skip = !adminUrl;
const delay = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));
const within = <T>(promise: Promise<T>, ms: number) => Promise.race([promise.then(() => true), delay(ms).then(() => false)]);

let ready: Promise<{ sql: postgres.Sql; codes: Map<string, string>; alerts: string[] }> | undefined;
let admin: postgres.Sql | undefined;
const name = `keyway_otp_${crypto.randomUUID().replaceAll("-", "")}`;

function setup() {
  ready ??= (async () => {
    Object.assign(process.env, { NODE_ENV: "test" });
    process.env.BETTER_AUTH_SECRET = "disposable-auth-test-secret-01234567890123456789";
    process.env.BETTER_AUTH_URL = "http://localhost:3001";
    process.env.KEYWAY_RATE_LIMIT_SECRET = "disposable-rate-test-secret-01234567890123456789";
    process.env.KEYWAY_DASHBOARD_ORIGINS = "https://dashboard.example";
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
    const alerts: string[] = [];
    const warn = console.warn;
    console.warn = (...args: unknown[]) => {
      if (args[0] === "[keyway-security]") alerts.push(String(args[1]));
      else warn(...args);
    };
    return { sql, codes, alerts };
  })();
  return ready;
}

after(async () => {
  if (!ready) return;
  const { sql } = await ready;
  await closeAuthPool();
  await sql.end({ timeout: 0 });
  await admin!.unsafe(`drop database if exists ${name} with (force)`);
  await admin!.end();
});

async function application(origins: string[], otpLimitPerMinute?: number, owner = { id: crypto.randomUUID() } as User) {
  const app = await createApplication(owner, { name: "Limits", otpLimitPerMinute });
  for (const origin of origins) await addApplicationOrigin(owner, { appId: app.appId, origin, environment: "development" });
  return { owner, appId: app.appId };
}

function appRequest(appId: string, origin: string, ip: string, token?: string) {
  return new Request("http://localhost:3001/api/v1/keyway/auth/send-code", {
    headers: { Origin: origin, "x-keyway-app-id": appId, "x-keyway-client-ip": ip, ...(token ? { Authorization: `Bearer ${token}` } : {}) },
  });
}

function dashboardRequest(ip: string) {
  return new Request("http://localhost:3001/api/v1/keyway/auth/send-code", {
    headers: { Origin: "https://dashboard.example", "x-keyway-auth-scope": "dashboard", "x-keyway-client-ip": ip },
  });
}

const email = () => `limits-${crypto.randomUUID()}@example.com`;

test("concurrent login-code sends never take every pool connection", { skip, timeout: 30_000 }, async () => {
  const { sql } = await setup();
  const { appId } = await application(["https://pool.example"]);
  const url = new URL(process.env.DATABASE_URL!);
  const observer = postgres(url.toString(), { max: 2 });
  try {
    // Hold every send at its first query, so each one has taken whatever it holds before any moves on.
    const gate = await observer.reserve();
    await gate`begin`;
    await gate`lock table keyway_auth_challenges in access exclusive mode`;
    const sends = Array.from({ length: 12 }, (_, i) =>
      sendEmailCode(appRequest(appId, "https://pool.example", `192.0.2.${i + 1}`), email()).then(() => "sent", (error: Error) => error.message));
    let waiting = -1;
    let stableSince = Date.now();
    for (const started = Date.now(); Date.now() - started < 8_000; await delay(50)) {
      const [row] = await observer<Array<{ count: number }>>`select count(*)::int as count from pg_stat_activity
        where datname = ${name} and wait_event_type = 'Lock' and query like '%keyway_auth_challenges%'`;
      if (row.count !== waiting) { waiting = row.count; stableSince = Date.now(); }
      if (waiting >= 10 || (waiting > 0 && Date.now() - stableSince > 800)) break;
    }
    await gate`commit`;
    gate.release();
    const unrelated = sql`select 1`.then(() => "ok");
    assert.ok(await within(Promise.all([...sends, unrelated]), 5_000), "Every send and an unrelated query finish");
    assert.deepEqual(await Promise.all(sends), Array(12).fill("sent"));
  } finally {
    await observer.end({ timeout: 0 });
  }
});

test("one account's queued requests leave the pool and other accounts free", { skip, timeout: 30_000 }, async () => {
  const { sql } = await setup();
  let release!: () => void;
  const held = new Promise<void>((resolve) => { release = resolve; });
  const key = `lock-${crypto.randomUUID()}`;
  const holder = withUserLock(key, () => held);
  await delay(100);
  const waiters = Array.from({ length: 11 }, () => withUserLock(key, async () => "ran").catch((error: Error) => error.message));
  await delay(100);
  try {
    assert.ok(await within(sql`select 1`, 500), "The shared pool still answers");
    assert.ok(await within(withUserLock(`lock-${crypto.randomUUID()}`, async () => undefined), 500), "Another account's lock is not held up");
    assert.ok(await within(Promise.race(waiters), 100), "Calls past the queue limit are refused at once");
  } finally {
    release();
    await holder;
  }
  const outcomes = await Promise.all(waiters);
  assert.ok(outcomes.some((outcome) => /Too many requests in progress/.test(outcome)));
  assert.ok(outcomes.includes("ran"));
});

test("strangers filling an app's per-minute limit don't block another person's first code", { skip }, async () => {
  await setup();
  const { appId } = await application(["https://bucket.example"]);
  for (let source = 1; source <= 5; source++) {
    for (let i = 0; i < 6; i++) await prepareOtpSend({ appId, email: email(), ipAddress: `198.51.100.${source}` });
  }
  await assert.rejects(prepareOtpSend({ appId, email: email(), ipAddress: "198.51.100.1" }), /Too many login codes/);
  await prepareOtpSend({ appId, email: email(), ipAddress: "198.51.100.6" });
  for (let source = 1; source <= 5; source++) {
    for (let i = 0; i < 6; i++) await sendEmailCode(dashboardRequest(`203.0.113.${source}`), email());
  }
  await assert.rejects(sendEmailCode(dashboardRequest("203.0.113.1"), email()), /Too many login codes/);
  await sendEmailCode(dashboardRequest("203.0.113.6"), email());
});

test("wrong codes add up across rotated codes until sending and checking stop", { skip }, async () => {
  const { sql, codes, alerts } = await setup();
  const { appId } = await application(["https://guess.example"]);
  const victim = email();
  const request = (round: number) => appRequest(appId, "https://guess.example", `198.18.0.${round}`);
  const nextRound = async () => {
    await sql`update keyway_auth_challenges set created_at = created_at - interval '61 seconds' where email = ${victim}`;
    await sql`update keyway_otp_events set created_at = created_at - interval '11 minutes' where outcome in ('requested', 'sent')`;
  };
  const wrong = (code: string) => code === "000000" ? "111111" : "000000";
  for (let round = 1; round <= 3; round++) {
    const { challengeId } = await sendEmailCode(request(round), victim);
    for (let i = 0; i < 5; i++) await assert.rejects(verifyEmailCode(request(round), challengeId, wrong(codes.get(`${appId}:${victim}`)!)), /Incorrect/);
    await nextRound();
  }
  const first = await sendEmailCode(request(4), victim);
  const firstCode = codes.get(`${appId}:${victim}`)!;
  for (let i = 0; i < 4; i++) await assert.rejects(verifyEmailCode(request(4), first.challengeId, wrong(firstCode)), /Incorrect/);
  await nextRound();
  const second = await sendEmailCode(request(5), victim);
  const secondCode = codes.get(`${appId}:${victim}`)!;
  assert.equal(alerts.filter((alert) => alert.includes("otp_failure_limit")).length, 0);
  await assert.rejects(verifyEmailCode(request(5), second.challengeId, wrong(secondCode)), /Incorrect/);
  assert.equal(alerts.filter((alert) => alert.includes("otp_failure_limit")).length, 1, "An alert fires when the limit is reached");
  // Even the right code no longer signs in, and no new code goes out.
  await assert.rejects(verifyEmailCode(request(6), second.challengeId, secondCode), /Too many incorrect codes/);
  await assert.rejects(verifyEmailCode(request(6), first.challengeId, firstCode), /Too many incorrect codes/);
  await nextRound();
  await assert.rejects(sendEmailCode(request(6), victim), /Too many incorrect codes/);
});

test("one email's limit in one app doesn't block it in another", { skip }, async () => {
  const { sql } = await setup();
  const { appId: appA } = await application(["https://a.example"]);
  const { appId: appB } = await application(["https://b.example"]);
  const victim = email();
  for (let i = 0; i < 5; i++) {
    await sendEmailCode(appRequest(appA, "https://a.example", `192.0.2.${50 + i}`), victim);
    await sql`update keyway_auth_challenges set created_at = created_at - interval '61 seconds' where email = ${victim}`;
  }
  await assert.rejects(sendEmailCode(appRequest(appA, "https://a.example", "192.0.2.60"), victim), /Too many login codes/);
  await sendEmailCode(appRequest(appB, "https://b.example", "192.0.2.61"), victim);
});

test("someone else asking for a code doesn't cancel the code already sent", { skip }, async () => {
  const { sql, codes } = await setup();
  const { appId: appA } = await application(["https://a.example"]);
  const user = email();
  const mine = await sendEmailCode(appRequest(appA, "https://a.example", "192.0.2.70"), user);
  const myCode = codes.get(`${appA}:${user}`)!;
  await sql`update keyway_auth_challenges set created_at = created_at - interval '61 seconds' where email = ${user}`;
  await sendEmailCode(appRequest(appA, "https://a.example", "192.0.2.71"), user);
  const login = await verifyEmailCode(appRequest(appA, "https://a.example", "192.0.2.70"), mine.challengeId, myCode);
  assert.ok(login.sessionToken);
});

test("a developer's apps share one per-minute login-code budget", { skip }, async () => {
  await setup();
  const owner = { id: crypto.randomUUID() } as User;
  const { appId: first } = await application([], 120, owner);
  const { appId: second } = await application([], 120, owner);
  for (let i = 0; i < 120; i++) {
    await prepareOtpSend({ appId: i % 2 ? first : second, email: email(), ipAddress: `100.64.${Math.floor(i / 50)}.1` });
  }
  await assert.rejects(prepareOtpSend({ appId: second, email: email(), ipAddress: "100.64.2.1" }), /Too many login codes/);
});

test("the per-address login-code limit counts an IPv6 /64 and IPv4-mapped addresses as one source", { skip }, async () => {
  await setup();
  const { appId } = await application([], 120);
  for (let i = 1; i <= 60; i++) await prepareOtpSend({ appId, email: email(), ipAddress: `2001:db8:a:b::${i.toString(16)}` });
  await assert.rejects(prepareOtpSend({ appId, email: email(), ipAddress: "2001:db8:a:b:ffff::1" }), /Too many login codes/);
  const { appId: other } = await application([], 120);
  for (let i = 0; i < 30; i++) await prepareOtpSend({ appId: other, email: email(), ipAddress: "::ffff:192.0.2.200" });
  for (let i = 0; i < 30; i++) await prepareOtpSend({ appId: other, email: email(), ipAddress: "192.0.2.200" });
  await assert.rejects(prepareOtpSend({ appId: other, email: email(), ipAddress: "::ffff:c000:2c8" }), /Too many login codes/);
});

test("login-code events older than two days are removed", { skip }, async () => {
  const { sql } = await setup();
  const { appId } = await application([]);
  await sql`insert into keyway_otp_events (app_id, email_hash, ip_hash, outcome, created_at)
    select ${appId}, 'old', 'old', 'requested', now() - interval '3 days' from generate_series(1, 50)`;
  await prepareOtpSend({ appId, email: email(), ipAddress: "192.0.2.90" });
  const [row] = await sql<Array<{ count: number }>>`select count(*)::int as count from keyway_otp_events where created_at < now() - interval '2 days'`;
  assert.equal(row.count, 0);
});

test("refused login-code requests record and alert once, not once each", { skip }, async () => {
  const { sql, alerts } = await setup();
  const { appId } = await application([], 1);
  const before = alerts.length;
  await prepareOtpSend({ appId, email: email(), ipAddress: "192.0.2.100" });
  for (let i = 0; i < 5; i++) await assert.rejects(prepareOtpSend({ appId, email: email(), ipAddress: "192.0.2.100" }), /Too many login codes/);
  assert.equal(alerts.slice(before).filter((alert) => alert.includes("otp_rate_limit")).length, 1);
  const [row] = await sql<Array<{ count: number }>>`select count(*)::int as count from keyway_otp_events where app_id = ${appId} and outcome = 'rate_limited'`;
  assert.equal(row.count, 1);
});

test("removing an origin ends the sessions signed in there", { skip }, async () => {
  const { sql, codes } = await setup();
  const { owner, appId } = await application(["https://old.example", "https://kept.example"]);
  const user = email();
  const { challengeId } = await sendEmailCode(appRequest(appId, "https://old.example", "192.0.2.110"), user);
  const { sessionToken } = await verifyEmailCode(appRequest(appId, "https://old.example", "192.0.2.110"), challengeId, codes.get(`${appId}:${user}`)!);
  await sql`update keyway_auth_challenges set created_at = created_at - interval '61 seconds' where email = ${user}`;
  const kept = await sendEmailCode(appRequest(appId, "https://kept.example", "192.0.2.111"), user);
  const keptLogin = await verifyEmailCode(appRequest(appId, "https://kept.example", "192.0.2.111"), kept.challengeId, codes.get(`${appId}:${user}`)!);
  assert.ok(await sessionForRequest(appRequest(appId, "https://kept.example", "192.0.2.110", sessionToken)));
  await removeApplicationOrigin(owner, { appId, origin: "https://old.example" });
  await assert.rejects(sessionForRequest(appRequest(appId, "https://kept.example", "192.0.2.110", sessionToken)), /Session/);
  assert.ok(await sessionForRequest(appRequest(appId, "https://kept.example", "192.0.2.111", keptLogin.sessionToken)));
});
