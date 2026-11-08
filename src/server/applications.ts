import { createHmac, randomBytes } from "node:crypto";
import { isIP } from "node:net";
import type { User } from "./auth-user.ts";
import { database, type DatabaseSql } from "./database";
import { sendSecurityAlert } from "./security-alerts";

const APP_ID = /^keyway_[A-Za-z0-9_-]{24}$/;
const LEGACY_APP_ID = "dashboard";

export type ApplicationOrigin = {
  origin: string;
  environment: "development" | "production";
};

export type DeveloperApplication = {
  appId: string;
  name: string;
  disabled: boolean;
  otpLimitPerMinute: number;
  origins: ApplicationOrigin[];
  usage: { sent24h: number; failed24h: number; rateLimited24h: number };
  createdAt: string;
  updatedAt: string;
};

type ApplicationRow = {
  app_id: string;
  name: string;
  disabled: boolean;
  otp_login_template_id: string | null;
  otp_signup_template_id: string | null;
  otp_limit_per_minute: number;
  created_at: Date;
  updated_at: Date;
};

export async function createApplication(
  user: User,
  input: { name: string; otpLimitPerMinute?: number },
): Promise<DeveloperApplication> {
  const sql = await database();
  const name = applicationName(input.name);
  const otpLimit = otpLimitPerMinute(input.otpLimitPerMinute ?? 30);
  const appId = `keyway_${randomBytes(18).toString("base64url")}`;
  await sql`
    insert into keyway_applications (
      app_id, owner_user_id, name, otp_limit_per_minute
    ) values (${appId}, ${user.id}, ${name}, ${otpLimit})
  `;
  return (await listApplications(user)).find((app) => app.appId === appId)!;
}

export async function listApplications(user: User): Promise<DeveloperApplication[]> {
  const sql = await database();
  const apps = await sql<ApplicationRow[]>`
    select app_id, name, disabled, otp_login_template_id, otp_signup_template_id,
      otp_limit_per_minute, created_at, updated_at
    from keyway_applications
    where owner_user_id = ${user.id}
    order by created_at desc
  `;
  if (!apps.length) return [];
  const appIds = apps.map(({ app_id }) => app_id);
  const origins = await sql<Array<{ app_id: string; origin: string; environment: ApplicationOrigin["environment"] }>>`
    select app_id, origin, environment
    from keyway_application_origins
    where app_id in ${sql(appIds)}
    order by created_at asc
  `;
  const usage = await sql<Array<{ app_id: string; sent: number; failed: number; rate_limited: number }>>`
    select app_id,
      count(*) filter (where outcome = 'sent')::int as sent,
      count(*) filter (where outcome in ('send_failed', 'verify_failed'))::int as failed,
      count(*) filter (where outcome = 'rate_limited')::int as rate_limited
    from keyway_otp_events
    where app_id in ${sql(appIds)} and created_at >= now() - interval '24 hours'
    group by app_id
  `;
  const usageByApp = new Map(usage.map((row) => [row.app_id, row]));
  return apps.map((app) => publicApplication(
    app,
    origins.filter((origin) => origin.app_id === app.app_id),
    usageByApp.get(app.app_id),
  ));
}

export async function updateApplication(
  user: User,
  input: {
    appId: string;
    name?: string;
    disabled?: boolean;
    otpLimitPerMinute?: number;
  },
): Promise<DeveloperApplication> {
  const sql = await database();
  const existing = await ownedApplication(user, input.appId, sql);
  const name = input.name === undefined ? existing.name : applicationName(input.name);
  const disabled = input.disabled ?? existing.disabled;
  const otpLimit = input.otpLimitPerMinute === undefined
    ? existing.otp_limit_per_minute
    : otpLimitPerMinute(input.otpLimitPerMinute);
  await sql`
    update keyway_applications
    set name = ${name}, disabled = ${disabled}, otp_limit_per_minute = ${otpLimit}, updated_at = now()
    where app_id = ${input.appId} and owner_user_id = ${user.id}
  `;
  return (await listApplications(user)).find((app) => app.appId === input.appId)!;
}

export async function addApplicationOrigin(
  user: User,
  input: { appId: string; origin: string; environment: ApplicationOrigin["environment"] },
): Promise<DeveloperApplication> {
  const sql = await database();
  await ownedApplication(user, input.appId, sql);
  const origin = normalizeOrigin(input.origin);
  if (input.environment !== "development" && input.environment !== "production") {
    throw new Error("Origin environment must be development or production");
  }
  await sql`
    insert into keyway_application_origins (app_id, origin, environment)
    values (${input.appId}, ${origin}, ${input.environment})
    on conflict (app_id, origin) do update set environment = excluded.environment
  `;
  return (await listApplications(user)).find((app) => app.appId === input.appId)!;
}

export async function removeApplicationOrigin(
  user: User,
  input: { appId: string; origin: string },
): Promise<DeveloperApplication> {
  const sql = await database();
  await ownedApplication(user, input.appId, sql);
  const origin = normalizeOrigin(input.origin);
  await sql.begin(async (transaction) => {
    await transaction`delete from keyway_application_origins where app_id = ${input.appId} and origin = ${origin}`;
    // Sign-ins made at the removed origin end with it; its tokens stay in that site's storage.
    await transaction`delete from keyway_auth_sessions where "scopeId" = ${input.appId} and origin = ${origin}`;
  });
  return (await listApplications(user)).find((app) => app.appId === input.appId)!;
}

export async function applicationAllowsOrigin(appId: string, origin: string): Promise<boolean> {
  if (!APP_ID.test(appId)) return false;
  const sql = await database();
  const rows = await sql`
    select 1
    from keyway_applications applications
    join keyway_application_origins origins on origins.app_id = applications.app_id
    where applications.app_id = ${appId} and applications.disabled = false and origins.origin = ${normalizeOrigin(origin)}
    limit 1
  `;
  return rows.length === 1;
}

// Login-code limits, per 10 minutes unless named otherwise.
const OTP_EMAIL_APP_LIMIT = 5; // codes to one email for one app
const OTP_EMAIL_LIMIT = 15; // codes to one email across all apps
const OTP_SOURCE_LIMIT = 60; // codes asked for from one IP address (an IPv6 /64)
const DASHBOARD_OTP_LIMIT_PER_MINUTE = 30;
const OWNER_OTP_LIMIT_PER_MINUTE = 120; // all of one developer's apps together, the most a single app may set
const OTP_FAILURE_LIMIT = 20; // wrong codes for one email in one app per 24 hours
const OTP_FAILURE_MESSAGE = "Too many incorrect codes for this email. Try again tomorrow";

export async function prepareOtpSend(input: {
  appId?: string;
  email: string;
  ipAddress: string;
}): Promise<{
  appId: string;
  emailHash: string;
  ipHash: string;
}> {
  const sql = await database();
  const app = input.appId ? await activeApplication(input.appId, sql) : undefined;
  const context = otpSubject(app?.app_id ?? LEGACY_APP_ID, input.email, input.ipAddress);
  const { appId, emailHash, ipHash } = context;
  const owner = app?.owner_user_id ?? null;
  const appLimit = app?.otp_limit_per_minute ?? DASHBOARD_OTP_LIMIT_PER_MINUTE;
  const result = await sql.begin(async (transaction) => {
    const keys = [`otp:app:${appId}`, `otp:email:${emailHash}`, `otp:ip:${ipHash}`, ...owner ? [`otp:owner:${owner}`] : []];
    for (const key of keys.sort()) {
      await transaction`select pg_advisory_xact_lock(hashtextextended(${key}, 0))`;
    }
    if (await otpFailures(transaction as unknown as DatabaseSql, context) >= OTP_FAILURE_LIMIT) return "failures";
    // Bounded by time in the WHERE clause so the index skips older history.
    const [limits] = await transaction<Array<{
      app_count: number; owner_count: number; email_app_count: number; email_count: number;
      source_count: number; source_minute_count: number; source_limited: number; app_limited: number;
    }>>`
      select
        count(*) filter (where requested and events.app_id = ${appId} and events.created_at >= now() - interval '1 minute')::int as app_count,
        count(*) filter (where requested and applications.owner_user_id = ${owner} and events.created_at >= now() - interval '1 minute')::int as owner_count,
        count(*) filter (where requested and email_hash = ${emailHash} and events.app_id = ${appId})::int as email_app_count,
        count(*) filter (where requested and email_hash = ${emailHash})::int as email_count,
        count(*) filter (where requested and ip_hash = ${ipHash})::int as source_count,
        count(*) filter (where requested and ip_hash = ${ipHash} and events.created_at >= now() - interval '1 minute')::int as source_minute_count,
        count(*) filter (where not requested and ip_hash = ${ipHash} and events.app_id = ${appId} and events.created_at >= now() - interval '1 minute')::int as source_limited,
        count(*) filter (where not requested and events.app_id = ${appId})::int as app_limited
      from (
        select *, outcome = 'requested' as requested from keyway_otp_events
        where outcome in ('requested', 'rate_limited') and created_at >= now() - interval '10 minutes'
      ) events
      left join keyway_applications applications on applications.app_id = events.app_id
    `;
    // Budgets shared with other people (the app's, the developer's, the inbox's across apps) refuse only a source that
    // already asked in the last minute, so strangers filling them can't block anyone else's first request.
    const shared = limits.app_count >= appLimit || limits.owner_count >= OWNER_OTP_LIMIT_PER_MINUTE || limits.email_count >= OTP_EMAIL_LIMIT;
    if (limits.email_app_count >= OTP_EMAIL_APP_LIMIT || limits.source_count >= OTP_SOURCE_LIMIT || (shared && limits.source_minute_count > 0)) {
      // At most one record a minute per source and app, and one alert per app every 10 minutes, however many are refused.
      if (limits.source_limited === 0) await insertOtpEvent(transaction as unknown as DatabaseSql, appId, emailHash, ipHash, "rate_limited");
      return limits.app_limited === 0 ? "limited-first" : "limited";
    }
    await insertOtpEvent(transaction as unknown as DatabaseSql, appId, emailHash, ipHash, "requested");
    return "allowed";
  });
  await pruneOtpEvents(sql);
  if (result === "failures") throw new Error(OTP_FAILURE_MESSAGE);
  if (result !== "allowed") {
    // Not awaited: the caller holds a per-email lock and a pool connection.
    if (result === "limited-first") void sendSecurityAlert("otp_rate_limit", { appId });
    throw new Error("Too many login codes requested. Try again later");
  }
  return context;
}

/** The rate-limit subject for a login code, shared by sending and checking it. */
export function otpSubject(appId: string, email: string, ipAddress: string): { appId: string; emailHash: string; ipHash: string } {
  return { appId, emailHash: privateHash("email", email.trim().toLowerCase()), ipHash: privateHash("ip", otpSource(ipAddress)) };
}

/**
 * The address a login-code limit counts against: an IPv4 address as is, also when written as IPv6 (::ffff:a.b.c.d),
 * and an IPv6 address by its /64, which one holder can fill with as many addresses as they like.
 */
export function otpSource(address: string): string {
  if (isIP(address) !== 6) return address;
  let text = address.toLowerCase().split("%")[0];
  const dotted = /(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(text);
  if (dotted) {
    const [a, b, c, d] = dotted.slice(1).map(Number);
    text = `${text.slice(0, dotted.index)}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  const [head, tail] = text.split("::");
  const left = head ? head.split(":") : [];
  const right = tail ? tail.split(":") : [];
  const groups = tail === undefined ? left : [...left, ...Array<string>(8 - left.length - right.length).fill("0"), ...right];
  const words = groups.map((group) => parseInt(group, 16));
  if (words.slice(0, 5).every((word) => word === 0) && words[5] === 0xffff) {
    return [words[6] >> 8, words[6] & 0xff, words[7] >> 8, words[7] & 0xff].join(".");
  }
  return `${words.slice(0, 4).map((word) => word.toString(16)).join(":")}::/64`;
}

/** Refuses a code check once this email has had too many wrong codes for the app. */
export async function checkOtpFailures(context: { appId: string; emailHash: string }): Promise<void> {
  if (await otpFailures(await database(), context) >= OTP_FAILURE_LIMIT) throw new Error(OTP_FAILURE_MESSAGE);
}

export async function recordOtpResult(
  context: { appId: string; emailHash: string; ipHash: string },
  outcome: "sent" | "send_failed",
): Promise<void> {
  const sql = await database();
  await insertOtpEvent(sql, context.appId, context.emailHash, context.ipHash, outcome);
}

export async function recordOtpVerification(
  context: { appId: string; emailHash: string; ipHash: string },
  outcome: "verified" | "verify_failed",
): Promise<void> {
  const sql = await database();
  await insertOtpEvent(sql, context.appId, context.emailHash, context.ipHash, outcome);
  // Rotated codes each allow 5 tries, so wrong codes add up per email until checks stop. Alert once when they do.
  if (outcome === "verify_failed" && await otpFailures(sql, context) === OTP_FAILURE_LIMIT) {
    void sendSecurityAlert("otp_failure_limit", { appId: context.appId });
  }
}

async function otpFailures(sql: DatabaseSql, context: { appId: string; emailHash: string }): Promise<number> {
  const [row] = await sql<Array<{ count: number }>>`
    select count(*)::int as count from keyway_otp_events
    where outcome = 'verify_failed' and created_at >= now() - interval '24 hours'
      and app_id = ${context.appId} and email_hash = ${context.emailHash}
  `;
  return row.count;
}

// Limits look back at most 24 hours and the dashboard shows the last day, so older events go as new ones arrive.
async function pruneOtpEvents(sql: DatabaseSql): Promise<void> {
  await sql`
    delete from keyway_otp_events where id in (
      select id from keyway_otp_events
      where outcome in ('requested', 'sent', 'send_failed', 'verified', 'verify_failed', 'rate_limited')
        and created_at < now() - interval '2 days'
      limit 500
    )
  `;
}

function publicApplication(
  app: ApplicationRow,
  origins: Array<{ origin: string; environment: ApplicationOrigin["environment"] }>,
  usage?: { sent: number; failed: number; rate_limited: number },
): DeveloperApplication {
  return {
    appId: app.app_id,
    name: app.name,
    disabled: app.disabled,
    otpLimitPerMinute: app.otp_limit_per_minute,
    origins: origins.map(({ origin, environment }) => ({ origin, environment })),
    usage: {
      sent24h: usage?.sent ?? 0,
      failed24h: usage?.failed ?? 0,
      rateLimited24h: usage?.rate_limited ?? 0,
    },
    createdAt: app.created_at.toISOString(),
    updatedAt: app.updated_at.toISOString(),
  };
}

async function ownedApplication(user: User, appId: string, sql: DatabaseSql): Promise<ApplicationRow> {
  if (!APP_ID.test(appId)) throw new Error("Application ID is invalid");
  const rows = await sql<ApplicationRow[]>`
    select app_id, name, disabled, otp_login_template_id, otp_signup_template_id,
      otp_limit_per_minute, created_at, updated_at
    from keyway_applications
    where app_id = ${appId} and owner_user_id = ${user.id}
    limit 1
  `;
  if (!rows[0]) throw new Error("Application not found");
  return rows[0];
}

async function activeApplication(appId: string, sql: DatabaseSql): Promise<ApplicationRow & { owner_user_id: string | null }> {
  if (!APP_ID.test(appId)) throw new Error("Application ID is invalid");
  const rows = await sql<Array<ApplicationRow & { owner_user_id: string | null }>>`
    select app_id, owner_user_id, name, disabled, otp_login_template_id, otp_signup_template_id,
      otp_limit_per_minute, created_at, updated_at
    from keyway_applications where app_id = ${appId} limit 1
  `;
  if (!rows[0] || rows[0].disabled) throw new Error("Application is disabled or does not exist");
  return rows[0];
}

function applicationName(value: string): string {
  const name = value.trim();
  if (!name || name.length > 80) throw new Error("Application name must be between 1 and 80 characters");
  return name;
}

function otpLimitPerMinute(value: number): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > 120) {
    throw new Error("OTP limit must be between 1 and 120 requests per minute");
  }
  return value;
}

function normalizeOrigin(value: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value.trim());
  } catch {
    throw new Error("Origin must be a valid URL");
  }
  if ((parsed.protocol !== "https:" && parsed.protocol !== "http:") || parsed.username || parsed.password) {
    throw new Error("Origin must use HTTP or HTTPS without credentials");
  }
  if (parsed.pathname !== "/" || parsed.search || parsed.hash) {
    throw new Error("Origin cannot contain a path, query, or fragment");
  }
  return parsed.origin;
}

function privateHash(kind: string, value: string): string {
  const secret = process.env.KEYWAY_RATE_LIMIT_SECRET;
  if (!secret || secret.length < 32) throw new Error("KEYWAY_RATE_LIMIT_SECRET must contain at least 32 characters");
  return createHmac("sha256", secret).update(`${kind}:${value}`).digest("hex");
}

function insertOtpEvent(
  sql: DatabaseSql,
  appId: string,
  emailHash: string,
  ipHash: string,
  outcome: "requested" | "sent" | "send_failed" | "verified" | "verify_failed" | "rate_limited",
) {
  return sql`
    insert into keyway_otp_events (app_id, email_hash, ip_hash, outcome)
    values (${appId}, ${emailHash}, ${ipHash}, ${outcome})
  `;
}
