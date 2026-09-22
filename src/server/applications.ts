import { createHmac, randomBytes } from "node:crypto";
import type { User } from "stytch";
import { database, type DatabaseSql } from "./database";

const APP_ID = /^keyway_[A-Za-z0-9_-]{24}$/;
const TEMPLATE_ID = /^[A-Za-z0-9_-]{1,128}$/;
const LEGACY_APP_ID = "legacy";

export type ApplicationOrigin = {
  origin: string;
  environment: "development" | "production";
};

export type DeveloperApplication = {
  appId: string;
  name: string;
  disabled: boolean;
  otpLoginTemplateId?: string;
  otpSignupTemplateId?: string;
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
      app_id, owner_stytch_user_id, name, otp_limit_per_minute
    ) values (${appId}, ${user.user_id}, ${name}, ${otpLimit})
  `;
  return (await listApplications(user)).find((app) => app.appId === appId)!;
}

export async function listApplications(user: User): Promise<DeveloperApplication[]> {
  const sql = await database();
  const apps = await sql<ApplicationRow[]>`
    select app_id, name, disabled, otp_login_template_id, otp_signup_template_id,
      otp_limit_per_minute, created_at, updated_at
    from keyway_applications
    where owner_stytch_user_id = ${user.user_id}
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
    otpLoginTemplateId?: string | null;
    otpSignupTemplateId?: string | null;
    otpLimitPerMinute?: number;
  },
): Promise<DeveloperApplication> {
  const sql = await database();
  const existing = await ownedApplication(user, input.appId, sql);
  const name = input.name === undefined ? existing.name : applicationName(input.name);
  const disabled = input.disabled ?? existing.disabled;
  const loginTemplate = input.otpLoginTemplateId === undefined
    ? existing.otp_login_template_id
    : templateId(input.otpLoginTemplateId);
  const signupTemplate = input.otpSignupTemplateId === undefined
    ? existing.otp_signup_template_id
    : templateId(input.otpSignupTemplateId);
  const otpLimit = input.otpLimitPerMinute === undefined
    ? existing.otp_limit_per_minute
    : otpLimitPerMinute(input.otpLimitPerMinute);
  await sql`
    update keyway_applications
    set name = ${name}, disabled = ${disabled}, otp_login_template_id = ${loginTemplate},
      otp_signup_template_id = ${signupTemplate}, otp_limit_per_minute = ${otpLimit}, updated_at = now()
    where app_id = ${input.appId} and owner_stytch_user_id = ${user.user_id}
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
  await sql`
    delete from keyway_application_origins
    where app_id = ${input.appId} and origin = ${normalizeOrigin(input.origin)}
  `;
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

export async function prepareOtpSend(input: {
  appId?: string;
  email: string;
  ipAddress: string;
}): Promise<{
  appId: string;
  emailHash: string;
  ipHash: string;
  loginTemplateId?: string;
  signupTemplateId?: string;
}> {
  const sql = await database();
  const app = input.appId ? await activeApplication(input.appId, sql) : undefined;
  const appId = app?.app_id ?? LEGACY_APP_ID;
  const emailHash = privateHash("email", input.email.trim().toLowerCase());
  const ipHash = privateHash("ip", input.ipAddress);
  const appLimit = app?.otp_limit_per_minute ?? 30;
  const limited = await sql.begin(async (transaction) => {
    await transaction`select pg_advisory_xact_lock(hashtextextended(${`otp:${appId}:${emailHash}:${ipHash}`}, 0))`;
    const [limits] = await transaction<Array<{ app_count: number; email_count: number; ip_count: number }>>`
      select
        count(*) filter (where app_id = ${appId} and created_at >= now() - interval '1 minute')::int as app_count,
        count(*) filter (where email_hash = ${emailHash} and created_at >= now() - interval '10 minutes')::int as email_count,
        count(*) filter (where ip_hash = ${ipHash} and created_at >= now() - interval '10 minutes')::int as ip_count
      from keyway_otp_events
      where outcome = 'requested'
    `;
    if (limits.app_count >= appLimit || limits.email_count >= 5 || limits.ip_count >= 20) {
      await insertOtpEvent(transaction as unknown as DatabaseSql, appId, emailHash, ipHash, "rate_limited");
      return true;
    }
    await insertOtpEvent(transaction as unknown as DatabaseSql, appId, emailHash, ipHash, "requested");
    return false;
  });
  if (limited) throw new Error("Too many login codes requested. Try again later");
  return {
    appId,
    emailHash,
    ipHash,
    loginTemplateId: app?.otp_login_template_id ?? undefined,
    signupTemplateId: app?.otp_signup_template_id ?? undefined,
  };
}

export async function recordOtpResult(
  context: { appId: string; emailHash: string; ipHash: string },
  outcome: "sent" | "send_failed",
  methodId?: string,
): Promise<void> {
  const sql = await database();
  await insertOtpEvent(sql, context.appId, context.emailHash, context.ipHash, outcome);
  if (methodId) {
    await sql`
      insert into keyway_otp_methods (method_id, app_id, email_hash, ip_hash)
      values (${methodId}, ${context.appId}, ${context.emailHash}, ${context.ipHash})
      on conflict (method_id) do update set
        app_id = excluded.app_id,
        email_hash = excluded.email_hash,
        ip_hash = excluded.ip_hash,
        created_at = now()
    `;
  }
}

export async function verifyOtpApplication(methodId: string, requestedAppId?: string): Promise<{
  appId: string;
  emailHash: string;
  ipHash: string;
}> {
  const sql = await database();
  const rows = await sql<Array<{ app_id: string; email_hash: string; ip_hash: string }>>`
    select app_id, email_hash, ip_hash
    from keyway_otp_methods
    where method_id = ${methodId} and created_at >= now() - interval '15 minutes'
    limit 1
  `;
  const context = rows[0];
  if (!context) throw new Error("OTP session is invalid or expired");
  const expectedAppId = requestedAppId ?? LEGACY_APP_ID;
  if (context.app_id !== expectedAppId) throw new Error("OTP session does not belong to this application");
  if (requestedAppId) await activeApplication(requestedAppId, sql);
  return { appId: context.app_id, emailHash: context.email_hash, ipHash: context.ip_hash };
}

export async function recordOtpVerification(
  context: { appId: string; emailHash: string; ipHash: string },
  outcome: "verified" | "verify_failed",
): Promise<void> {
  await insertOtpEvent(await database(), context.appId, context.emailHash, context.ipHash, outcome);
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
    otpLoginTemplateId: app.otp_login_template_id ?? undefined,
    otpSignupTemplateId: app.otp_signup_template_id ?? undefined,
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
    where app_id = ${appId} and owner_stytch_user_id = ${user.user_id}
    limit 1
  `;
  if (!rows[0]) throw new Error("Application not found");
  return rows[0];
}

async function activeApplication(appId: string, sql: DatabaseSql): Promise<ApplicationRow> {
  if (!APP_ID.test(appId)) throw new Error("Application ID is invalid");
  const rows = await sql<ApplicationRow[]>`
    select app_id, name, disabled, otp_login_template_id, otp_signup_template_id,
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

function templateId(value: string | null): string | null {
  if (value === null || value.trim() === "") return null;
  const normalized = value.trim();
  if (!TEMPLATE_ID.test(normalized)) throw new Error("OTP template ID is invalid");
  return normalized;
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
