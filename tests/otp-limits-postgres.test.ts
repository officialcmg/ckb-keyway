import assert from "node:assert/strict";
import { after, beforeEach, test } from "node:test";
import postgres from "postgres";
import { Pool } from "pg";
import { getMigrations } from "better-auth/db/migration";
import type { User } from "../src/server/auth-user.ts";
import { authSchemaOptions } from "../src/server/auth-options.ts";
import { database, withUserLock } from "../src/server/database.ts";
import { addApplicationOrigin, createApplication, otpSubject, prepareOtpSend, removeApplicationOrigin } from "../src/server/applications.ts";
import { closeAuthPool, sendEmailCode, sessionForRequest, setAuthDeliveryForTests, verifyEmailCode } from "../src/server/auth.ts";
import { handleKeyWayRequest } from "../src/server/http.ts";

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

// As if `seconds` had passed for the send limits and the wait between codes. Wrong codes stay where they are.
async function later(sql: postgres.Sql, seconds: number) {
  await sql`update keyway_otp_events set created_at = created_at - ${`${seconds} seconds`}::interval where outcome in ('requested', 'sent', 'rate_limited')`;
  await sql`update keyway_auth_challenges set created_at = created_at - ${`${seconds} seconds`}::interval`;
  await sql`update keyway_security_alert_marks set sent_at = sent_at - ${`${seconds} seconds`}::interval`;
}

// Wrong codes for `victim` in `appId`, `each` from every source in `sources`, as if tried `minutes` ago.
async function pastFailures(sql: postgres.Sql, appId: string, victim: string, sources: string[], each: number, minutes: number, bypass = false) {
  for (const ip of sources) {
    const { emailHash, ipHash, networkHash } = otpSubject(appId, victim, ip);
    await sql`insert into keyway_otp_events (app_id, email_hash, ip_hash, network_hash, outcome, bypass, created_at)
      select ${appId}, ${emailHash}, ${ipHash}, ${networkHash ?? null}, 'verify_failed', ${bypass}, now() - ${`${minutes} minutes`}::interval
      from generate_series(1, ${each})`;
  }
}

const count = (alerts: string[], kind: string) => alerts.filter((alert) => JSON.parse(alert).kind === kind).length;

// Every test starts with the per-minute and per-10-minute budgets clear of earlier tests' requests.
beforeEach(async () => {
  if (ready) await later((await ready).sql, 660);
});

const wrong = (code: string) => code === "000000" ? "111111" : "000000";

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

test("a stranger's wrong codes don't lock the user out", { skip }, async () => {
  const { sql, codes } = await setup();
  const { appId } = await application(["https://guess.example"]);
  const victim = email();
  const stranger = appRequest(appId, "https://guess.example", "198.18.1.1");
  const { challengeId } = await sendEmailCode(stranger, victim);
  const code = codes.get(`${appId}:${victim}`)!;
  for (let i = 0; i < 20; i++) await assert.rejects(verifyEmailCode(stranger, challengeId, wrong(code)), /Incorrect/);
  await assert.rejects(verifyEmailCode(stranger, challengeId, wrong(code)), /Too many authentication requests/);
  // Only the 5 codes Better Auth compared count. The rest met a used-up code or its rate limit.
  const [row] = await sql<Array<{ count: number }>>`select count(*)::int as count from keyway_otp_events where app_id = ${appId} and outcome = 'verify_failed'`;
  assert.equal(row.count, 5);
  await later(sql, 61);
  const user = appRequest(appId, "https://guess.example", "198.18.1.2");
  const mine = await sendEmailCode(user, victim);
  assert.ok((await verifyEmailCode(user, mine.challengeId, codes.get(`${appId}:${victim}`)!)).sessionToken);
});

test("wrong codes from one source add up across rotated codes until that source stops", { skip }, async () => {
  const { sql, codes, alerts } = await setup();
  const { appId } = await application(["https://guess.example"]);
  const victim = email();
  const stranger = appRequest(appId, "https://guess.example", "198.18.0.1");
  const before = alerts.filter((alert) => alert.includes("otp_failure_limit")).length;
  for (let round = 1; round <= 4; round++) {
    const { challengeId } = await sendEmailCode(stranger, victim);
    const code = codes.get(`${appId}:${victim}`)!;
    for (let i = 0; i < 5; i++) await assert.rejects(verifyEmailCode(stranger, challengeId, wrong(code)), /Incorrect/);
    await later(sql, 660);
  }
  assert.equal(alerts.filter((alert) => alert.includes("otp_failure_limit")).length, before + 1, "One alert when the limit is reached");
  await assert.rejects(sendEmailCode(stranger, victim), /Too many incorrect codes/);
  const user = appRequest(appId, "https://guess.example", "198.18.0.2");
  const mine = await sendEmailCode(user, victim);
  const myCode = codes.get(`${appId}:${victim}`)!;
  // That source is refused even with the right code, before Better Auth sees it, so the code stays usable.
  await assert.rejects(verifyEmailCode(stranger, mine.challengeId, myCode), /Too many incorrect codes/);
  assert.ok((await verifyEmailCode(user, mine.challengeId, myCode)).sessionToken);
});

test("strangers' wrong codes pause other checks but not the owner's fresh code", { skip }, async () => {
  const { sql, codes } = await setup();
  const origin = "https://guess.example";
  const { appId } = await application([origin]);
  const victim = email();
  for (let source = 1; source <= 6; source++) {
    const stranger = appRequest(appId, origin, `198.18.2.${source}`);
    const { challengeId } = await sendEmailCode(stranger, victim);
    const code = codes.get(`${appId}:${victim}`)!;
    for (let i = 0; i < 5; i++) await assert.rejects(verifyEmailCode(stranger, challengeId, wrong(code)), /Incorrect/);
    await later(sql, 61);
  }
  // Checks are paused. A source that has guessed wrong before gets nothing checked, even on a code it just asked for.
  const guesser = appRequest(appId, origin, "198.18.2.1");
  const again = await sendEmailCode(guesser, victim);
  await assert.rejects(verifyEmailCode(guesser, again.challengeId, codes.get(`${appId}:${victim}`)!), /Try again later/);
  // A new source's own fresh code gets its first try, and no more.
  const stranger = appRequest(appId, origin, "198.18.2.8");
  const theirs = await sendEmailCode(stranger, victim);
  const theirCode = codes.get(`${appId}:${victim}`)!;
  await assert.rejects(verifyEmailCode(stranger, theirs.challengeId, wrong(theirCode)), /Incorrect/);
  await assert.rejects(verifyEmailCode(stranger, theirs.challengeId, theirCode), /Try again later/);
  // The owner, from somewhere else, asks for a code and signs in with it. A stranger can't try it for them.
  const user = appRequest(appId, origin, "198.18.2.7");
  const mine = await sendEmailCode(user, victim);
  const myCode = codes.get(`${appId}:${victim}`)!;
  await assert.rejects(verifyEmailCode(stranger, mine.challengeId, myCode), /Try again later/);
  assert.ok((await verifyEmailCode(user, mine.challengeId, myCode)).sessionToken);
});

test("wrong codes add up over a day, not only an hour", { skip }, async () => {
  const { sql, codes } = await setup();
  const origin = "https://day.example";
  const { appId } = await application([origin]);
  const victim = email();
  await pastFailures(sql, appId, victim, [1, 2, 3, 4, 5, 6].map((i) => `198.18.3.${i}`), 5, 120);
  const user = appRequest(appId, origin, "198.18.3.10");
  const mine = await sendEmailCode(user, victim);
  const myCode = codes.get(`${appId}:${victim}`)!;
  const stranger = appRequest(appId, origin, "198.18.3.9");
  await assert.rejects(verifyEmailCode(stranger, mine.challengeId, wrong(myCode)), /Try again later/);
  await sql`update keyway_otp_events set created_at = created_at - interval '22 hours 1 minute' where app_id = ${appId} and outcome = 'verify_failed'`;
  await assert.rejects(verifyEmailCode(stranger, mine.challengeId, wrong(myCode)), /Incorrect/);
  assert.ok((await verifyEmailCode(user, mine.challengeId, myCode)).sessionToken);
});

test("while checks are paused, fresh codes' first tries are limited per network and in all", { skip }, async () => {
  const { sql, codes, alerts } = await setup();
  const origin = "https://bypass.example";
  const { appId } = await application([origin]);
  const victim = email();
  const code = () => codes.get(`${appId}:${victim}`)!;
  await pastFailures(sql, appId, victim, [1, 2, 3, 4, 5, 6].map((i) => `198.18.4.${i}`), 5, 10);
  // Separate /64s in one IPv6 /48 are one network: three wrong first tries, then none.
  for (let i = 1; i <= 3; i++) {
    const request = appRequest(appId, origin, `2001:db8:5:${i}::1`);
    const { challengeId } = await sendEmailCode(request, victim);
    await assert.rejects(verifyEmailCode(request, challengeId, wrong(code())), /Incorrect/);
  }
  const sameNetwork = appRequest(appId, origin, "2001:db8:5:4::1");
  const refused = await sendEmailCode(sameNetwork, victim);
  await assert.rejects(verifyEmailCode(sameNetwork, refused.challengeId, code()), /Try again later/);
  // At most 60 wrong first tries a day for the email, from anyone. Reaching it raises one alert.
  await pastFailures(sql, appId, victim, ["198.18.4.200"], 56, 10, true);
  const before = count(alerts, "otp_failure_bypass_limit");
  const last = appRequest(appId, origin, "198.18.4.20");
  const lastChallenge = await sendEmailCode(last, victim);
  await assert.rejects(verifyEmailCode(last, lastChallenge.challengeId, wrong(code())), /Incorrect/);
  assert.equal(count(alerts, "otp_failure_bypass_limit"), before + 1);
  const next = appRequest(appId, origin, "198.18.4.21");
  const nextChallenge = await sendEmailCode(next, victim);
  await assert.rejects(verifyEmailCode(next, nextChallenge.challengeId, code()), /Try again later/);
});

test("a stranger's requests don't hold up the user's own code", { skip }, async () => {
  const { sql, codes } = await setup();
  const { appId } = await application(["https://wait.example"]);
  const scopes = [
    { key: appId, request: (ip: string) => appRequest(appId, "https://wait.example", ip) },
    { key: "dashboard", request: dashboardRequest },
  ];
  for (const scope of scopes) {
    const victim = email();
    for (let i = 0; i < 5; i++) {
      await sendEmailCode(scope.request("198.19.0.1"), victim);
      await later(sql, 61);
    }
    await assert.rejects(sendEmailCode(scope.request("198.19.0.1"), victim), /Too many login codes/);
    const mine = await sendEmailCode(scope.request("198.19.0.2"), victim);
    assert.ok((await verifyEmailCode(scope.request("198.19.0.2"), mine.challengeId, codes.get(`${scope.key}:${victim}`)!)).sessionToken);
    // Right after a stranger's request, the user's own request from elsewhere doesn't have to wait a minute.
    await later(sql, 61);
    await sendEmailCode(scope.request("198.19.0.3"), victim);
    const again = await sendEmailCode(scope.request("198.19.0.2"), victim);
    assert.ok((await verifyEmailCode(scope.request("198.19.0.2"), again.challengeId, codes.get(`${scope.key}:${victim}`)!)).sessionToken);
  }
});

test("one source's limit for an email in one app doesn't block it in another", { skip }, async () => {
  const { sql } = await setup();
  const { appId: appA } = await application(["https://a.example"]);
  const { appId: appB } = await application(["https://b.example"]);
  const victim = email();
  for (let i = 0; i < 5; i++) {
    await sendEmailCode(appRequest(appA, "https://a.example", "192.0.2.50"), victim);
    await later(sql, 61);
  }
  await assert.rejects(sendEmailCode(appRequest(appA, "https://a.example", "192.0.2.50"), victim), /Too many login codes/);
  await sendEmailCode(appRequest(appB, "https://b.example", "192.0.2.50"), victim);
});

test("someone else asking for a code doesn't cancel the code already sent", { skip }, async () => {
  const { sql, codes } = await setup();
  const { appId: appA } = await application(["https://a.example"]);
  const user = email();
  const mine = await sendEmailCode(appRequest(appA, "https://a.example", "192.0.2.70"), user);
  const myCode = codes.get(`${appA}:${user}`)!;
  await later(sql, 61);
  await sendEmailCode(appRequest(appA, "https://a.example", "192.0.2.71"), user);
  const login = await verifyEmailCode(appRequest(appA, "https://a.example", "192.0.2.70"), mine.challengeId, myCode);
  assert.ok(login.sessionToken);
});

test("a developer's apps share one per-minute login-code budget", { skip }, async () => {
  const { alerts } = await setup();
  const owner = { id: crypto.randomUUID() } as User;
  const { appId: first } = await application([], 120, owner);
  const { appId: second } = await application([], 120, owner);
  const before = count(alerts, "otp_owner_ceiling");
  for (let i = 0; i < 120; i++) {
    await prepareOtpSend({ appId: i % 2 ? first : second, email: email(), ipAddress: `100.64.${Math.floor(i / 50)}.1` });
  }
  await assert.rejects(prepareOtpSend({ appId: second, email: email(), ipAddress: "100.64.2.1" }), /Too many login codes/);
  await prepareOtpSend({ appId: second, email: email(), ipAddress: "100.64.9.1" });
  assert.equal(count(alerts, "otp_owner_ceiling"), before + 1, "One alert when the developer's budget is reached");
});

test("apps of different developers together stay under one per-minute ceiling", { skip }, async () => {
  const { alerts } = await setup();
  const before = count(alerts, "otp_global_ceiling");
  const { appId: first } = await application([], 120);
  const { appId: second } = await application([], 120);
  for (let i = 0; i < 200; i++) {
    await prepareOtpSend({ appId: i % 2 ? first : second, email: email(), ipAddress: `100.65.${i % 4}.1` });
  }
  await assert.rejects(prepareOtpSend({ appId: second, email: email(), ipAddress: "100.65.0.1" }), /Too many login codes/);
  // Like every shared budget, it doesn't refuse a source's first request in a minute, so it raises an alert, once.
  await prepareOtpSend({ appId: second, email: email(), ipAddress: "100.65.9.1" });
  await prepareOtpSend({ appId: second, email: email(), ipAddress: "100.65.10.1" });
  assert.equal(count(alerts, "otp_global_ceiling"), before + 1);
});

test("a developer account has a limited number of apps", { skip }, async () => {
  await setup();
  const owner = { id: crypto.randomUUID() } as User;
  for (let i = 0; i < 10; i++) await createApplication(owner, { name: `App ${i}` });
  await assert.rejects(createApplication(owner, { name: "One more" }), /at most 10 applications/);
});

test("past an inbox's 30 codes in 10 minutes, only a network that had none for it gets one", { skip }, async () => {
  const { sql, alerts } = await setup();
  const { appId } = await application([], 120);
  const victim = email();
  const before = count(alerts, "otp_inbox_ceiling");
  for (let i = 1; i <= 30; i++) await prepareOtpSend({ appId, email: victim, ipAddress: `100.66.0.${i}` });
  await later(sql, 61);
  // A source that already had a code for this inbox is refused, in any app.
  await assert.rejects(prepareOtpSend({ appId, email: victim, ipAddress: "100.66.0.1" }), /Too many login codes/);
  const { appId: other } = await application([], 120);
  await assert.rejects(prepareOtpSend({ appId: other, email: victim, ipAddress: "100.66.0.2" }), /Too many login codes/);
  // Strangers filling the inbox's limit don't stop the owner's first code from elsewhere.
  await prepareOtpSend({ appId, email: victim, ipAddress: "100.66.1.1" });
  // An IPv6 /48 is one network: one code, whichever of its /64s asks.
  await prepareOtpSend({ appId, email: victim, ipAddress: "2001:db8:66:1::1" });
  await assert.rejects(prepareOtpSend({ appId, email: victim, ipAddress: "2001:db8:66:2::1" }), /Too many login codes/);
  assert.equal(count(alerts, "otp_inbox_ceiling"), before + 1, "One alert while the inbox is past its limit");
});

test("wallet locks held for a long time don't hold up sign-in", { skip, timeout: 30_000 }, async () => {
  await setup();
  const { appId } = await application(["https://wallet.example"]);
  let release!: () => void;
  const held = new Promise<void>((resolve) => { release = resolve; });
  // Five first-time wallet setups, each holding its lock across slow Lit and CKB calls.
  const wallets = Array.from({ length: 5 }, () => withUserLock(`wallet-${crypto.randomUUID()}`, () => held));
  await delay(200);
  try {
    assert.ok(await within(sendEmailCode(appRequest(appId, "https://wallet.example", "192.0.2.130"), email()), 3_000), "A login code still goes out");
  } finally {
    release();
    await Promise.all(wallets);
  }
});

test("expired codes of challenges nobody used are removed", { skip }, async () => {
  const { sql, codes } = await setup();
  const { appId } = await application(["https://expire.example"]);
  for (let i = 0; i < 3; i++) await sendEmailCode(appRequest(appId, "https://expire.example", `192.0.2.${120 + i}`), email());
  await sql`update keyway_auth_verifications set "expiresAt" = now() - interval '1 second' where identifier like ${`keyway:${appId}:%`}`;
  const user = email();
  const { challengeId } = await sendEmailCode(appRequest(appId, "https://expire.example", "192.0.2.123"), user);
  await verifyEmailCode(appRequest(appId, "https://expire.example", "192.0.2.123"), challengeId, codes.get(`${appId}:${user}`)!);
  const [row] = await sql<Array<{ count: number }>>`select count(*)::int as count from keyway_auth_verifications where identifier like ${`keyway:${appId}:%`}`;
  assert.equal(row.count, 0);
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
  await later(sql, 61);
  const kept = await sendEmailCode(appRequest(appId, "https://kept.example", "192.0.2.111"), user);
  const keptLogin = await verifyEmailCode(appRequest(appId, "https://kept.example", "192.0.2.111"), kept.challengeId, codes.get(`${appId}:${user}`)!);
  assert.ok(await sessionForRequest(appRequest(appId, "https://kept.example", "192.0.2.110", sessionToken)));
  await removeApplicationOrigin(owner, { appId, origin: "https://old.example" });
  await assert.rejects(sessionForRequest(appRequest(appId, "https://kept.example", "192.0.2.110", sessionToken)), /Session/);
  assert.ok(await sessionForRequest(appRequest(appId, "https://kept.example", "192.0.2.111", keptLogin.sessionToken)));
});

test("sessions without the origin they were issued at are refused", { skip }, async () => {
  const { sql, codes } = await setup();
  const origin = "https://origin.example";
  const { appId } = await application([origin]);
  const user = email();
  const { challengeId } = await sendEmailCode(appRequest(appId, origin, "192.0.2.112"), user);
  const { sessionToken } = await verifyEmailCode(appRequest(appId, origin, "192.0.2.112"), challengeId, codes.get(`${appId}:${user}`)!);
  assert.ok(await sessionForRequest(appRequest(appId, origin, "192.0.2.112", sessionToken)));
  // As a session from before sessions recorded their origin.
  await sql`update keyway_auth_sessions set "origin" = null where "scopeId" = ${appId}`;
  await assert.rejects(sessionForRequest(appRequest(appId, origin, "192.0.2.112", sessionToken)), /Session/);
});

test("expired login challenges are removed, and a challenge ID must be a UUID", { skip }, async () => {
  const { sql } = await setup();
  const origin = "https://prune.example";
  const { appId } = await application([origin]);
  const old = await sendEmailCode(appRequest(appId, origin, "192.0.2.150"), email());
  await sql`update keyway_auth_challenges set expires_at = now() - interval '1 second' where id = ${old.challengeId}`;
  await sendEmailCode(appRequest(appId, origin, "192.0.2.151"), email());
  assert.equal((await sql`select 1 from keyway_auth_challenges where id = ${old.challengeId}`).length, 0);
  const response = await handleKeyWayRequest(new Request("http://localhost:3001/api/v1/keyway/auth/verify-code", {
    method: "POST",
    headers: { ...Object.fromEntries(appRequest(appId, origin, "192.0.2.152").headers), "Content-Type": "application/json" },
    body: JSON.stringify({ challengeId: "not-a-challenge", code: "123456" }),
  }));
  assert.equal(response.status, 400);
  assert.match((await response.json()).error, /valid OTP challenge/);
  await assert.rejects(verifyEmailCode(appRequest(appId, origin, "192.0.2.152"), `${old.challengeId}0`, "123456"), /Incorrect or expired/);
});
