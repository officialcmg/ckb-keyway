import { AsyncLocalStorage } from "node:async_hooks";
import { createHmac, randomUUID } from "node:crypto";
import { isIP } from "node:net";
import { betterAuth } from "better-auth";
import { getAdapter } from "better-auth/db/adapter";
import { bearer, emailOTP } from "better-auth/plugins";
import { Pool } from "pg";
import { Resend } from "resend";
import { database, withLoginCodeLock, withLoginCodeSlot } from "./database.ts";
import { applicationAllowsOrigin, checkOtpFailures, OtpPausedError, otpNetwork, otpSource, otpSubject, prepareOtpSend, recordOtpResult, recordOtpVerification } from "./applications.ts";
import { authSchemaOptions } from "./auth-options.ts";
import { scopedAuthAdapter } from "./scoped-auth-adapter.ts";
import { createOtpEmailTemplate } from "./email-template.ts";
import type { User } from "./auth-user.ts";

export type AuthScope = { id: string; name: string; origins: string[] };
export type EmailDelivery = (message: { email: string; otp: string; scope: AuthScope; challengeId: string }) => Promise<void>;
// The login challenge being sent or checked. Better Auth keeps a separate code for each one.
const challengeContext = new AsyncLocalStorage<{ challengeId: string; delivered: boolean }>();
const requestSessions = new WeakMap<Request, Promise<{ user: User; expiresAt: string; sessionToken?: string }>>();
// Kept apart from the session result so the email never appears in the /session response.
const requestEmails = new WeakMap<Request, string>();
let pool: Pool | undefined;
const instances = new Map<string, Promise<Awaited<ReturnType<typeof createScopedAuth>>>>();
let delivery: EmailDelivery = sendOtpEmail;
// Tries per login code. Wrong ones are counted on the challenge too, so a used-up challenge is refused before its lock.
const LOGIN_CODE_ATTEMPTS = 5;
/** A login challenge ID: the UUID `sendEmailCode` returned. */
export const CHALLENGE_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
// Login-code requests in progress in this process: per source (IPv6 /64) for one email or challenge, per source, and
// per network (IPv6 /48). The lock for one email is open to anyone, so the cap is on who is asking: one requester
// can't queue without end, and people sharing an address (a NAT, a carrier) don't share the tightest cap.
// Past the network's soft cap, only a source with nothing in progress gets in, so one /64 can't shut out a shared /48.
const LOGIN_REQUESTS_PER_TARGET = 2;
const LOGIN_REQUESTS_PER_SOURCE = 16;
const LOGIN_REQUESTS_PER_NETWORK = 64;
const LOGIN_REQUESTS_PER_NETWORK_HARD = 512;
const loginRequests = new Map<string, number>();

export function setAuthDeliveryForTests(callback: EmailDelivery): void {
  if (process.env.NODE_ENV !== "test") throw new Error("Test delivery is unavailable outside tests");
  delivery = callback;
}

export async function resolveAuthScope(request: Request): Promise<AuthScope> {
  const origin = request.headers.get("origin");
  const appId = request.headers.get("x-keyway-app-id");
  const dashboard = request.headers.get("x-keyway-auth-scope") === "dashboard";
  if (!origin || origin === "null") throw new Error("A registered browser origin is required");
  if (dashboard) {
    if (appId) throw new Error("Dashboard session cannot use an application ID");
    const origins = (process.env.KEYWAY_DASHBOARD_ORIGINS ?? "https://ckbkeyway.dev,https://www.ckbkeyway.dev").split(",").map((s) => s.trim());
    if (!origins.includes(origin)) throw new Error("Dashboard origin is not allowed");
    return { id: "dashboard", name: "CKB KeyWay", origins };
  }
  if (!appId || !await applicationAllowsOrigin(appId, origin)) throw new Error("Application origin is not allowed");
  const sql = await database();
  const [app] = await sql<Array<{ name: string }>>`select name from keyway_applications where app_id = ${appId} and disabled = false`;
  const rows = await sql<Array<{ origin: string }>>`select origin from keyway_application_origins where app_id = ${appId}`;
  if (!app) throw new Error("Application is disabled or does not exist");
  return { id: appId, name: app.name, origins: rows.map((row) => row.origin) };
}

export function requestIp(request: Request): string {
  // server/index.ts supplies this header from the socket or a explicitly trusted edge.
  const value = request.headers.get("x-keyway-client-ip") ?? "";
  return isIP(value) ? value : "unknown";
}

function privateKey(value: string): string {
  const secret = process.env.KEYWAY_RATE_LIMIT_SECRET;
  if (!secret || secret.length < 32) throw new Error("KEYWAY_RATE_LIMIT_SECRET is required");
  return createHmac("sha256", secret).update(value).digest("hex");
}

export async function consumeRateLimit(key: string, rule: { max: number; window: number }) {
  const sql = await database();
  return sql.begin(async (tx) => {
    const hash = privateKey(key);
    await tx`select pg_advisory_xact_lock(hashtextextended(${`auth-rate:${hash}`}, 0))`;
    const [row] = await tx<Array<{ count: number; starts_at: Date }>>`select count, starts_at from keyway_auth_rate_limits where key = ${hash}`;
    const now = Date.now();
    if (row && now - row.starts_at.getTime() < rule.window * 1000 && row.count >= rule.max) {
      return { allowed: false, retryAfter: Math.ceil((row.starts_at.getTime() + rule.window * 1000 - now) / 1000) };
    }
    const fresh = !row || now - row.starts_at.getTime() >= rule.window * 1000;
    await tx`insert into keyway_auth_rate_limits (key, count, starts_at) values (${hash}, 1, now())
      on conflict (key) do update set count = ${fresh ? 1 : row.count + 1}, starts_at = ${fresh ? new Date(now) : row.starts_at}`;
    return { allowed: true, retryAfter: null };
  });
}

export async function createScopedAuth(scope: AuthScope) {
  if (!process.env.BETTER_AUTH_SECRET || process.env.BETTER_AUTH_SECRET.length < 32) throw new Error("BETTER_AUTH_SECRET must contain at least 32 characters");
  if (!process.env.BETTER_AUTH_URL) throw new Error("BETTER_AUTH_URL is required");
  pool ??= new Pool({ connectionString: process.env.DATABASE_URL, max: 10 });
  const options = authSchemaOptions(pool);
  const native = await getAdapter(options);
  return betterAuth({
    ...options,
    database: () => scopedAuthAdapter(native, scope.id, () => challengeContext.getStore()?.challengeId),
    trustedOrigins: scope.origins,
    advanced: { ...options.advanced, disableOriginCheck: false, ipAddress: { ipAddressHeaders: ["x-keyway-client-ip"] } },
    rateLimit: {
      enabled: true, window: 60, max: 100,
      customStorage: { consume: (key, rule) => consumeRateLimit(`${scope.id}:${key}`, rule) },
      customRules: { "/email-otp/send-verification-otp": { window: 60, max: 20 }, "/sign-in/email-otp": { window: 60, max: 20 } },
    },
    // The origin a session is issued at, so removing that origin from the app ends it.
    databaseHooks: { session: { create: { before: async (session, context) => ({ data: { ...session, scopeId: scope.id, origin: context?.headers?.get("origin") ?? null } }) } } },
    plugins: [bearer({ requireSignature: true }), emailOTP({
      otpLength: 6, expiresIn: 600, allowedAttempts: LOGIN_CODE_ATTEMPTS, storeOTP: "hashed", resendStrategy: "rotate",
      sendVerificationOTP: async ({ email, otp, type }) => {
        const context = challengeContext.getStore();
        if (type !== "sign-in" || !context) throw new Error("Login challenge context is required");
        await delivery({ email, otp, scope, challengeId: context.challengeId });
        context.delivered = true;
      },
    })],
    logger: { disabled: true },
  });
}

async function authFor(scope: AuthScope) {
  // Include origin configuration so changes cannot retain stale trusted origins.
  const key = JSON.stringify([scope.id, scope.origins]);
  if (!instances.has(key)) {
    if (instances.size >= 128) instances.delete(instances.keys().next().value!);
    instances.set(key, createScopedAuth(scope));
  }
  return instances.get(key)!;
}

export async function callAuthEndpoint(request: Request, scope: AuthScope, path: string, body?: unknown): Promise<Response> {
  const auth = await authFor(scope);
  const headers = new Headers({ "Content-Type": "application/json", Origin: request.headers.get("origin")!, "x-keyway-client-ip": requestIp(request) });
  const authorization = request.headers.get("authorization");
  if (authorization) headers.set("authorization", authorization);
  const url = new URL(`/internal-auth${path}`, process.env.BETTER_AUTH_URL);
  return auth.handler(new Request(url, { method: body === undefined ? "GET" : "POST", headers, ...(body === undefined ? {} : { body: JSON.stringify(body) }) }));
}

/** Runs `task` for one login challenge, so Better Auth reads and writes that challenge's code. */
export function withOtpChallenge<T>(challengeId: string, task: () => T): T {
  return challengeContext.run({ challengeId, delivered: false }, task);
}

/** Runs one login-code request for `target`, refusing it at once if its requester already has too many in progress. */
async function withLoginRequest<T>(request: Request, target: string, task: () => Promise<T>): Promise<T> {
  const ip = requestIp(request);
  const source = otpSource(ip);
  const slots = [
    [`target:${source}:${target}`, LOGIN_REQUESTS_PER_TARGET],
    [`source:${source}`, LOGIN_REQUESTS_PER_SOURCE],
    [`network:${otpNetwork(ip)}`, LOGIN_REQUESTS_PER_NETWORK_HARD],
  ] as const;
  const inProgress = (key: string) => loginRequests.get(key) ?? 0;
  if (slots.some(([key, max]) => inProgress(key) >= max)
    || (inProgress(slots[2][0]) >= LOGIN_REQUESTS_PER_NETWORK && inProgress(slots[1][0]) > 0)) {
    throw new Error("Too many sign-in requests in progress. Try again in a moment");
  }
  for (const [key] of slots) loginRequests.set(key, (loginRequests.get(key) ?? 0) + 1);
  try {
    return await task();
  } finally {
    for (const [key] of slots) {
      const left = loginRequests.get(key)! - 1;
      if (left > 0) loginRequests.set(key, left); else loginRequests.delete(key);
    }
  }
}

export function sendEmailCode(request: Request, emailInput: string): Promise<{ challengeId: string }> {
  const email = emailInput.trim().toLowerCase();
  return withLoginRequest(request, `email:${email}`, async () => {
    const scope = await resolveAuthScope(request);
    // Decided before the email's lock (the limits take their own locks), so refused requests never queue on it, but in
    // a login-code slot, so a flood waits here rather than on pool connections. Also applies the 60-second wait between
    // codes, counted per requester so a stranger's request doesn't delay yours.
    const context = await withLoginCodeSlot(() => prepareOtpSend({ appId: scope.id === "dashboard" ? undefined : scope.id, email, ipAddress: requestIp(request) }));
    return withLoginCodeLock(`otp:${scope.id}:${email}`, async (sql) => {
      const challengeId = randomUUID();
      // Expired challenges are no use to anyone, and hold the emails people typed.
      await sql`delete from keyway_auth_challenges where id in (select id from keyway_auth_challenges where expires_at < now() limit 100)`;
      // Earlier challenges for this email stay open: each has its own code, and anyone may ask for one.
      await sql`insert into keyway_auth_challenges (id, scope_id, email, expires_at, status) values (${challengeId}, ${scope.id}, ${email}, ${new Date(Date.now() + 600_000)}, 'pending')`;
      try {
        const deliveryState = { challengeId, delivered: false };
        const response = await challengeContext.run(deliveryState, () => callAuthEndpoint(request, scope, "/email-otp/send-verification-otp", { email, type: "sign-in" }));
        // Better Auth intentionally catches delivery callback errors. Require our
        // explicit provider acknowledgement before declaring this challenge sent.
        if (!response.ok || !deliveryState.delivered) throw new Error(response.status === 429 ? "Too many authentication requests" : "Could not send login email");
        await sql`update keyway_auth_challenges set status = 'sent' where id = ${challengeId}`;
        await recordOtpResult(context, "sent");
        return { challengeId };
      } catch (error) {
        await sql`update keyway_auth_challenges set status = 'failed' where id = ${challengeId}`;
        await sql`delete from keyway_auth_verifications where identifier = ${`keyway:${scope.id}:${challengeId}:sign-in-otp-${email}`}`;
        await recordOtpResult(context, "send_failed");
        throw error;
      }
    });
  });
}

export function verifyEmailCode(request: Request, challengeIdInput: string, code: string) {
  const challengeId = challengeIdInput.toLowerCase();
  return withLoginRequest(request, `challenge:${challengeId}`, async () => {
    if (!CHALLENGE_ID.test(challengeId)) throw new Error("Incorrect or expired code");
    const scope = await resolveAuthScope(request);
    const sql = await database();
    // A challenge that is used up or expired is refused here, before it takes the email's lock.
    const [challenge] = await sql<Array<{ email: string; wrong_attempts: number }>>`select email, wrong_attempts from keyway_auth_challenges
      where id = ${challengeId}::uuid and scope_id = ${scope.id} and status = 'sent' and expires_at > now()`;
    if (!challenge) throw new Error("Incorrect or expired code");
    // A check the limits refuse is turned away before the lock too (and the limits are checked again under it). One
    // refused while checks are paused retires its challenge: it can't become checkable again within its life.
    const retire = async (error: unknown) => {
      if (error instanceof OtpPausedError) await sql`update keyway_auth_challenges set status = 'failed' where id = ${challengeId}::uuid`;
      throw error;
    };
    await checkOtpFailures(otpSubject(scope.id, challenge.email, requestIp(request)), { wrongAttempts: challenge.wrong_attempts }).catch(retire);
    return withLoginCodeLock(`otp:${scope.id}:${challenge.email}`, async (connection) => {
      const [current] = await connection<Array<{ wrong_attempts: number }>>`
        select wrong_attempts from keyway_auth_challenges
        where id = ${challengeId}::uuid and scope_id = ${scope.id} and status = 'sent' and expires_at > now()`;
      if (!current) throw new Error("Incorrect or expired code");
      // Better Auth removes a code once its tries are used up: the challenge is then dead, and isn't checked again.
      const identifier = `keyway:${scope.id}:${challengeId}:sign-in-otp-${challenge.email}`;
      const [live] = await connection`select 1 from keyway_auth_verifications where identifier = ${identifier} and "expiresAt" > now()`;
      if (!live) {
        await connection`update keyway_auth_challenges set status = 'failed' where id = ${challengeId}::uuid`;
        throw new Error("Incorrect or expired code");
      }
      const context = otpSubject(scope.id, challenge.email, requestIp(request));
      const { bypass } = await checkOtpFailures(context, { wrongAttempts: current.wrong_attempts }).catch(retire);
      const response = await withOtpChallenge(challengeId, () => callAuthEndpoint(request, scope, "/sign-in/email-otp", { email: challenge.email, otp: code }));
      if (!response.ok) {
        // Count a wrong code only when Better Auth compared it. After a wrong code it keeps the record (one more attempt
        // used); a rate-limit refusal, a server error, or a code already used up or expired leaves nothing to guess at.
        const [open] = await connection`select 1 from keyway_auth_verifications where identifier = ${identifier}`;
        if (open && response.status === 400) {
          await connection`update keyway_auth_challenges set wrong_attempts = wrong_attempts + 1,
            status = case when wrong_attempts + 1 >= ${LOGIN_CODE_ATTEMPTS} then 'failed' else status end
            where id = ${challengeId}::uuid`;
          await recordOtpVerification(context, "verify_failed", bypass);
        }
        // Its code is used up: later checks are refused before they wait for the lock.
        if (!open) await connection`update keyway_auth_challenges set status = 'failed' where id = ${challengeId}::uuid`;
        throw new Error(response.status === 429 ? "Too many authentication requests" : "Incorrect or expired code");
      }
      const result = await response.json();
      const sessionToken = response.headers.get("set-auth-token");
      if (!sessionToken) throw new Error("Authentication session was not issued");
      await connection`update keyway_auth_challenges set status = 'consumed' where id = ${challengeId}`;
      const user = await keywayUser(result.user.id, scope.id);
      const sessionRequest = new Request(request.url, {
        headers: new Headers({ ...Object.fromEntries(request.headers), authorization: `Bearer ${sessionToken}` }),
      });
      const sessionResponse = await callAuthEndpoint(sessionRequest, scope, "/get-session");
      const session = await sessionResponse.json();
      if (!sessionResponse.ok || session?.session?.scopeId !== scope.id) throw new Error("Session scope mismatch");
      await recordOtpVerification(context, "verified");
      return { sessionToken, user: publicUser(user), expiresAt: session.session.expiresAt };
    });
  });
}

async function keywayUser(authUserId: string, scopeId: string): Promise<User> {
  const sql = await database();
  const [row] = await sql<Array<{ id: string }>>`insert into keyway_users (id, auth_user_id, scope_id) values (${randomUUID()}, ${authUserId}, ${scopeId}) on conflict (auth_user_id, scope_id) do update set auth_user_id = excluded.auth_user_id returning id`;
  return { id: row.id, scopeId };
}

export async function sessionForRequest(request: Request) {
  if (!requestSessions.has(request)) requestSessions.set(request, (async () => {
    const scope = await resolveAuthScope(request);
    if (!request.headers.get("authorization")?.startsWith("Bearer ")) throw new Error("Missing bearer session");
    const response = await callAuthEndpoint(request, scope, "/get-session");
    const result = await response.json();
    if (!response.ok || !result?.session || result.session.scopeId !== scope.id) throw new Error("Session is invalid for this application");
    // A session issued at an origin the app no longer allows ends with it. Every session has one (migration 23).
    if (typeof result.session.origin !== "string" || !scope.origins.includes(result.session.origin)) throw new Error("Session is invalid for this application");
    if (typeof result.user.email === "string") requestEmails.set(request, result.user.email);
    const user = { ...await keywayUser(result.user.id, scope.id), sessionId: String(result.session.id) };
    return { user, expiresAt: result.session.expiresAt as string, sessionToken: response.headers.get("set-auth-token") ?? undefined };
  })());
  return requestSessions.get(request)!;
}

export async function authenticateUser(request: Request): Promise<User> { return (await sessionForRequest(request)).user; }

/** The signed-in user's email address, for server-side confirmation emails only. */
export async function sessionEmail(request: Request): Promise<string> {
  await sessionForRequest(request);
  const email = requestEmails.get(request);
  if (!email) throw new Error("Session has no email address");
  return email;
}

/** Sends a server-rendered email through the configured provider. */
export async function sendTransactionalEmail(to: string, message: { subject: string; html: string; plaintext: string }, idempotencyKey: string): Promise<void> {
  const key = process.env.RESEND_API_KEY;
  const from = process.env.KEYWAY_AUTH_EMAIL_FROM;
  if (!key || !from) throw new Error("Confirmation email delivery is not configured");
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10_000);
  try {
    const { error } = await new Resend(key).emails.send({ from, to, subject: message.subject, html: message.html, text: message.plaintext }, { idempotencyKey, signal: controller.signal });
    if (error) throw new Error("Could not send the confirmation email");
  } finally { clearTimeout(timer); }
}
export function publicUser(user: User) { return { id: user.id }; }

export async function revokeSession(request: Request): Promise<void> {
  await sessionForRequest(request);
  const response = await callAuthEndpoint(request, await resolveAuthScope(request), "/sign-out", {});
  if (!response.ok) throw new Error("Could not revoke session");
}

async function sendOtpEmail({ email, otp, scope, challengeId }: Parameters<EmailDelivery>[0]): Promise<void> {
  const key = process.env.RESEND_API_KEY;
  const from = process.env.KEYWAY_AUTH_EMAIL_FROM;
  if (!key || !from) throw new Error("Authentication email delivery is not configured");
  const template = createOtpEmailTemplate(scope.name, otp);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10_000);
  try {
    const client = new Resend(key);
    const { error } = await client.emails.send({ from, to: email, subject: template.subject, html: template.html, text: template.plaintext }, { idempotencyKey: `keyway-otp/${challengeId}`, signal: controller.signal });
    if (error) throw new Error("Could not send login email");
  } finally { clearTimeout(timer); }
}

export async function closeAuthPool(): Promise<void> {
  instances.clear();
  await pool?.end();
  pool = undefined;
}
