import { createHmac, randomBytes } from "node:crypto";
import { isIP } from "node:net";
import type { User } from "./auth-user.ts";
import { database, type DatabaseSql } from "./database";
import { sendSecurityAlert, sendSecurityAlertOnce } from "./security-alerts";

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

const MAX_APPLICATIONS_PER_OWNER = 10;

export async function createApplication(
  user: User,
  input: { name: string; otpLimitPerMinute?: number },
): Promise<DeveloperApplication> {
  const sql = await database();
  const name = applicationName(input.name);
  const otpLimit = otpLimitPerMinute(input.otpLimitPerMinute ?? 30);
  const appId = `keyway_${randomBytes(18).toString("base64url")}`;
  await sql.begin(async (transaction) => {
    await transaction`select pg_advisory_xact_lock(hashtextextended(${`apps:${user.id}`}, 0))`;
    // Each app brings its own login-code budget and alerts, so one account can't multiply them without end.
    const [{ count }] = await transaction<Array<{ count: number }>>`select count(*)::int as count from keyway_applications where owner_user_id = ${user.id}`;
    if (count >= MAX_APPLICATIONS_PER_OWNER) throw new Error(`A developer account can have at most ${MAX_APPLICATIONS_PER_OWNER} applications`);
    await transaction`
      insert into keyway_applications (
        app_id, owner_user_id, name, otp_limit_per_minute
      ) values (${appId}, ${user.id}, ${name}, ${otpLimit})
    `;
  });
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

// Login-code limits, per 10 minutes unless named otherwise. A source is one IP address (an IPv6 /64); a network is
// one IPv4 address or IPv6 /48, the most one holder can cheaply spread over. Limits on one source are hard; budgets
// shared with other people refuse only a source that already asked in the last minute.
const OTP_EMAIL_APP_LIMIT = 5; // codes for one email in one app from one source
const OTP_SOURCE_LIMIT = 60; // codes asked for from one source
const OTP_EMAIL_LIMIT = 15; // codes to one email across all apps, shared
// A known network is one that signed in to this email's account in the app in the last OTP_KNOWN_NETWORK_DAYS days.
// Strangers can't make one, so the owner's usual networks get through the limits below that strangers can fill.
const OTP_KNOWN_NETWORK_DAYS = 90;
// Codes to one email from anyone. Past the first, only a network that hasn't had a code for this email in the window
// gets one, so each further code costs strangers another network; past the second, only a known network.
const OTP_EMAIL_HARD_LIMIT = 30;
const OTP_EMAIL_ABSOLUTE_LIMIT = 100;
const DASHBOARD_OTP_LIMIT_PER_MINUTE = 30;
const OWNER_OTP_LIMIT_PER_MINUTE = 120; // all of one developer's apps together, the most a single app may set
const GLOBAL_OTP_LIMIT_PER_MINUTE = 200; // every app together, shared: all login email goes out through one sender
const GLOBAL_OTP_HARD_LIMIT_PER_MINUTE = 1000; // past it, only known networks, so the sender's quota is never used up
const OTP_CEILING_ALERT_MINUTES = 10; // one alert per shared ceiling (and inbox) reached in this long
// Wrong codes, for one email in one app over 24 hours. Codes stay six digits, so these bound guessing for the day.
const OTP_FAILURE_LIMIT = 20; // from one source: that source is refused
const OTP_FAILURE_ALERT = 20; // from anyone: one alert
const OTP_FAILURE_PAUSE = 30; // from anyone: checks pause until it drops back, except a fresh code's first try (below)
// While paused, a code's first try still goes ahead, so strangers' wrong codes can't lock the owner out. Each such
// try needs a newly sent code, and a network gets OTP_BYPASS_NETWORK_LIMIT wrong ones. Past OTP_BYPASS_LIMIT wrong
// ones from anyone, only known networks keep it. So at most OTP_FAILURE_PAUSE + OTP_BYPASS_LIMIT wrong codes (90 of
// a million), plus OTP_BYPASS_NETWORK_LIMIT from each of the owner's own known networks, reach Better Auth a day.
const OTP_BYPASS_NETWORK_LIMIT = 3;
const OTP_BYPASS_LIMIT = 60;
const OTP_PLATFORM_FAILURE_ALERT = 500; // wrong codes in an hour across every app and email: one alert an hour
const OTP_FAILURE_MESSAGE = "Too many incorrect codes for this email. Try again tomorrow";

export type OtpContext = { appId: string; emailHash: string; ipHash: string; networkHash: string };

export async function prepareOtpSend(input: {
  appId?: string;
  email: string;
  ipAddress: string;
}): Promise<OtpContext> {
  const sql = await database();
  const app = input.appId ? await activeApplication(input.appId, sql) : undefined;
  const context = otpSubject(app?.app_id ?? LEGACY_APP_ID, input.email, input.ipAddress);
  const { appId, emailHash, ipHash, networkHash } = context;
  const owner = app?.owner_user_id ?? null;
  const appLimit = app?.otp_limit_per_minute ?? DASHBOARD_OTP_LIMIT_PER_MINUTE;
  type Ceiling = "global" | "owner" | "inbox";
  const result = await sql.begin(async (transaction): Promise<"failures" | "cooldown" | "limited" | "limited-first" | { ceilings: Ceiling[] }> => {
    const keys = [`otp:app:${appId}`, `otp:email:${emailHash}`, `otp:ip:${ipHash}`, ...owner ? [`otp:owner:${owner}`] : []];
    for (const key of keys.sort()) {
      await transaction`select pg_advisory_xact_lock(hashtextextended(${key}, 0))`;
    }
    if ((await otpFailures(transaction as unknown as DatabaseSql, context)).source >= OTP_FAILURE_LIMIT) return "failures";
    // Bounded by time in the WHERE clause so the index skips older history.
    const [limits] = await transaction<Array<{
      app_count: number; owner_count: number; global_count: number; cooldown: number; email_app_count: number;
      email_count: number; network_email_count: number; source_count: number; source_minute_count: number;
      source_limited: number; app_limited: number;
    }>>`
      select
        count(*) filter (where requested and events.app_id = ${appId} and events.created_at >= now() - interval '1 minute')::int as app_count,
        count(*) filter (where requested and applications.owner_user_id = ${owner} and events.created_at >= now() - interval '1 minute')::int as owner_count,
        count(*) filter (where requested and events.created_at >= now() - interval '1 minute')::int as global_count,
        count(*) filter (where requested and email_hash = ${emailHash} and events.app_id = ${appId} and ip_hash = ${ipHash}
          and events.created_at >= now() - interval '60 seconds')::int as cooldown,
        count(*) filter (where requested and email_hash = ${emailHash} and events.app_id = ${appId} and ip_hash = ${ipHash})::int as email_app_count,
        count(*) filter (where requested and email_hash = ${emailHash})::int as email_count,
        count(*) filter (where requested and email_hash = ${emailHash} and network_hash = ${networkHash})::int as network_email_count,
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
    // One code a minute for one email in one app from one source.
    if (limits.cooldown > 0) return "cooldown";
    // Budgets shared with other people (the app's, the developer's, everyone's, the inbox's across apps) refuse only a
    // source that already asked in the last minute, so strangers filling them can't block anyone else's first request.
    // The inbox's hard limit refuses any network that already had a code for this email in the window. Past the inbox's
    // absolute limit or everyone's hard limit, only a network the owner signed in from recently gets a code.
    const shared = limits.app_count >= appLimit || limits.owner_count >= OWNER_OTP_LIMIT_PER_MINUTE
      || limits.global_count >= GLOBAL_OTP_LIMIT_PER_MINUTE || limits.email_count >= OTP_EMAIL_LIMIT;
    const knownOnly = limits.email_count >= OTP_EMAIL_ABSOLUTE_LIMIT || limits.global_count >= GLOBAL_OTP_HARD_LIMIT_PER_MINUTE;
    if (limits.email_app_count >= OTP_EMAIL_APP_LIMIT || limits.source_count >= OTP_SOURCE_LIMIT
      || (limits.email_count >= OTP_EMAIL_HARD_LIMIT && limits.network_email_count > 0) || (shared && limits.source_minute_count > 0)
      || (knownOnly && !await knownNetwork(transaction as unknown as DatabaseSql, context))) {
      // At most one record a minute per source and app, and one alert per app every 10 minutes, however many are refused.
      if (limits.source_limited === 0) await insertOtpEvent(transaction as unknown as DatabaseSql, context, "rate_limited");
      return limits.app_limited === 0 ? "limited-first" : "limited";
    }
    await insertOtpEvent(transaction as unknown as DatabaseSql, context, "requested");
    // A shared ceiling only slows sources that asked recently, so the codes it lets through are worth an alert.
    const ceilings: Ceiling[] = [];
    if (limits.global_count + 1 >= GLOBAL_OTP_LIMIT_PER_MINUTE) ceilings.push("global");
    if (owner && limits.owner_count + 1 >= OWNER_OTP_LIMIT_PER_MINUTE) ceilings.push("owner");
    if (limits.email_count + 1 >= OTP_EMAIL_HARD_LIMIT) ceilings.push("inbox");
    return { ceilings };
  });
  await pruneOtpEvents(sql);
  if (result === "failures") throw new Error(OTP_FAILURE_MESSAGE);
  if (result === "cooldown") throw new Error("Too many login codes requested. Wait 60 seconds before resending");
  if (typeof result === "string") {
    // Not awaited: the caller holds a per-email lock and a pool connection.
    if (result === "limited-first") void sendSecurityAlert("otp_rate_limit", { appId });
    throw new Error("Too many login codes requested. Try again later");
  }
  const subjects: Record<Ceiling, string> = { global: "all", owner: owner ?? "", inbox: emailHash };
  for (const ceiling of result.ceilings) {
    // The code is already counted against the requester; an alert that can't be recorded mustn't fail the request.
    await sendSecurityAlertOnce(`otp_${ceiling}_ceiling`, subjects[ceiling], OTP_CEILING_ALERT_MINUTES, { appId }).catch(() => undefined);
  }
  return context;
}

/** The rate-limit subject for a login code, shared by sending and checking it. */
export function otpSubject(appId: string, email: string, ipAddress: string): OtpContext {
  return {
    appId,
    emailHash: privateHash("email", email.trim().toLowerCase()),
    ipHash: privateHash("ip", otpSource(ipAddress)),
    networkHash: privateHash("network", otpNetwork(ipAddress)),
  };
}

/**
 * The address a login-code limit counts against: an IPv4 address as is, also when written as IPv6 (::ffff:a.b.c.d),
 * and an IPv6 address by its /64, which one holder can fill with as many addresses as they like.
 */
export function otpSource(address: string): string {
  return addressPrefix(address, 4);
}

/** The network a source belongs to: an IPv4 address as is, and an IPv6 address by its /48, a typical single site. */
export function otpNetwork(address: string): string {
  return addressPrefix(address, 3);
}

function addressPrefix(address: string, prefixGroups: number): string {
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
  return `${words.slice(0, prefixGroups).map((word) => word.toString(16)).join(":")}::/${prefixGroups * 16}`;
}

/**
 * Whether this code check may go ahead. Refuses one once this source has had too many wrong codes for this email in
 * the app, and pauses checks once anyone has: that keeps guessing from many addresses slow. While paused, a code's
 * first try still goes ahead (`bypass`), within the limits above, so strangers can't lock the owner out. The challenge
 * ID is the requester's own secret, so only they can try their code. Run under the email's login-code lock, so checks
 * for one email are counted one at a time.
 */
export async function checkOtpFailures(context: OtpContext, challenge: { wrongAttempts: number }): Promise<{ bypass: boolean }> {
  const sql = await database();
  const failures = await otpFailures(sql, context);
  if (failures.source >= OTP_FAILURE_LIMIT) throw new Error(OTP_FAILURE_MESSAGE);
  if (failures.day < OTP_FAILURE_PAUSE) return { bypass: false };
  if (challenge.wrongAttempts === 0 && failures.network < OTP_BYPASS_NETWORK_LIMIT
    && (failures.bypass < OTP_BYPASS_LIMIT || await knownNetwork(sql, context))) return { bypass: true };
  throw new Error("Too many incorrect codes for this email. Try again later");
}

export async function recordOtpResult(context: OtpContext, outcome: "sent" | "send_failed"): Promise<void> {
  const sql = await database();
  await insertOtpEvent(sql, context, outcome);
}

export async function recordOtpVerification(context: OtpContext, outcome: "verified" | "verify_failed", bypass = false): Promise<void> {
  const sql = await database();
  await insertOtpEvent(sql, context, outcome, bypass);
  if (outcome === "verified") {
    await sql`insert into keyway_otp_known_networks (app_id, email_hash, network_hash, verified_at)
      values (${context.appId}, ${context.emailHash}, ${context.networkHash}, now())
      on conflict (app_id, email_hash, network_hash) do update set verified_at = now()`;
    await sql`delete from keyway_otp_known_networks where (app_id, email_hash, network_hash) in (
      select app_id, email_hash, network_hash from keyway_otp_known_networks
      where verified_at < now() - ${`${OTP_KNOWN_NETWORK_DAYS} days`}::interval limit 100
    )`;
    return;
  }
  // Rotated codes each allow 5 tries, so wrong codes add up per email. Alert once when they reach the limit, and
  // once when the paused checks' first tries are used up too.
  const failures = await otpFailures(sql, context);
  if (failures.day === OTP_FAILURE_ALERT) void sendSecurityAlert("otp_failure_limit", { appId: context.appId });
  if (bypass && failures.bypass === OTP_BYPASS_LIMIT) void sendSecurityAlert("otp_failure_bypass_limit", { appId: context.appId });
  // Limits per email don't slow guessing spread over many emails, so watch the total too.
  const [total] = await sql<Array<{ count: number }>>`
    select count(*)::int as count from keyway_otp_events where outcome = 'verify_failed' and created_at >= now() - interval '1 hour'
  `;
  if (total.count >= OTP_PLATFORM_FAILURE_ALERT) {
    await sendSecurityAlertOnce("otp_platform_failures", "all", 60, { count: total.count }).catch(() => undefined);
  }
}

/** Whether this network signed in to this email's account in the app recently. */
async function knownNetwork(sql: DatabaseSql, context: OtpContext): Promise<boolean> {
  const rows = await sql`
    select 1 from keyway_otp_known_networks
    where app_id = ${context.appId} and email_hash = ${context.emailHash} and network_hash = ${context.networkHash}
      and verified_at > now() - ${`${OTP_KNOWN_NETWORK_DAYS} days`}::interval
  `;
  return rows.length > 0;
}

/** Wrong codes for one email in one app in 24 hours: from this source, from this network, from anyone, and while paused. */
async function otpFailures(sql: DatabaseSql, context: OtpContext) {
  const [row] = await sql<Array<{ source: number; network: number; day: number; bypass: number }>>`
    select
      count(*) filter (where ip_hash = ${context.ipHash})::int as source,
      count(*) filter (where network_hash = ${context.networkHash})::int as network,
      count(*)::int as day,
      count(*) filter (where bypass)::int as bypass
    from keyway_otp_events
    where outcome = 'verify_failed' and created_at >= now() - interval '24 hours'
      and app_id = ${context.appId} and email_hash = ${context.emailHash}
  `;
  return row;
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
  context: OtpContext,
  outcome: "requested" | "sent" | "send_failed" | "verified" | "verify_failed" | "rate_limited",
  bypass = false,
) {
  return sql`
    insert into keyway_otp_events (app_id, email_hash, ip_hash, network_hash, outcome, bypass)
    values (${context.appId}, ${context.emailHash}, ${context.ipHash}, ${context.networkHash}, ${outcome}, ${bypass})
  `;
}
