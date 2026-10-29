import * as ccc from "@ckb-ccc/core";
import { currentLock } from "../sdk/browser/account-lock.ts";
import type { User } from "./auth-user.ts";
import { bootstrap } from "./bootstrap.ts";
import { markChannelOpened, readWallet } from "./user-wallet.ts";
import {
  authenticateUser,
  publicUser,
  revokeSession,
  sendEmailCode,
  verifyEmailCode,
  sessionForRequest,
  resolveAuthScope,
  sessionEmail,
  sendTransactionalEmail,
  consumeRateLimit,
} from "./auth.ts";
import { acquireLease, heartbeatLease, releaseLease, requireLease } from "./device-lease.ts";
import { loadLitAction } from "./lit-actions.ts";
import { wrapFiberKey } from "./lit.ts";
import {
  previewFundingTransaction,
  serializeTransaction,
  signFundingTransaction,
} from "./funding-transaction.ts";
import { consumeConfirmation, issueConfirmation } from "./signing-confirmation.ts";
import { database } from "./database.ts";
import { confirmNodeBackupRestored, readClaimedNodeBackup, saveNodeBackup } from "./node-backup.ts";
import {
  addApplicationOrigin,
  createApplication,
  listApplications,
  removeApplicationOrigin,
  updateApplication,
} from "./applications.ts";
import { managedFiberNode, managedNodeReady, managedNodeRequest, sweepHostedSettlement } from "./managed-node.ts";
import { fiberPayment } from "./fiber-payments.ts";
import { runIdempotentMutation } from "./idempotency.ts";
import { recordSigningEvent } from "./security-alerts.ts";
import { messageSigning, signingSettings, transactionSigning, type SigningContext } from "./general-signing.ts";
import { recoverySetup } from "./recovery.ts";
import { sweepLegacyAfterSignIn } from "./legacy-sweep.ts";

export async function handleKeyWayRequest(request: Request): Promise<Response> {
  const cors = await corsHeaders(request);
  if (cors instanceof Response) return cors;
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
  if (request.method === "GET" && new URL(request.url).pathname === "/healthz") {
    return Response.json({ status: "ok" }, { headers: cors });
  }
  if (request.method === "GET" && new URL(request.url).pathname === "/readyz") {
    const sql = await database();
    await sql`select 1`;
    return Response.json({ status: "ready" }, { headers: cors });
  }
  if (request.method === "GET" && new URL(request.url).pathname === "/managed-readyz") {
    await managedNodeReady();
    return Response.json({ status: "ready" }, { headers: cors });
  }
  if (request.method !== "POST") return jsonError("Not found", 404, cors);

  try {
    const path = apiPath(new URL(request.url).pathname);
    const scope = await resolveAuthScope(request);
    if (scope.id === "dashboard" && !path.startsWith("/api/keyway/auth/") && path !== "/api/keyway/developer/apps") {
      return jsonError("Dashboard credentials cannot authorize wallet operations", 403, cors);
    }
    const response = path === "/api/keyway/auth/send-code" ? await sendCodeRequest(request)
      : path === "/api/keyway/auth/legacy-cleanup" ? await legacyCleanupRequest(request)
      : path === "/api/keyway/auth/verify-code" ? await verifyCodeRequest(request)
      : path === "/api/keyway/auth/session" ? await sessionRequest(request)
      : path === "/api/keyway/auth/logout" ? await logoutRequest(request)
      : path === "/api/keyway/bootstrap" ? await bootstrapRequest(request)
      : path === "/api/keyway/fiber-key" ? await fiberKeyRequest(request)
      : path === "/api/keyway/channel-state" ? await channelStateRequest(request)
      : path === "/api/keyway/device-lease" ? await deviceLeaseRequest(request)
      : path === "/api/keyway/node-backup/save" ? await saveNodeBackupRequest(request)
      : path === "/api/keyway/node-backup/load" ? await loadNodeBackupRequest(request)
      : path === "/api/keyway/node-backup/confirm" ? await confirmNodeBackupRequest(request)
      : path === "/api/keyway/sign-transaction" ? await signTransactionRequest(request)
      : path === "/api/keyway/sign-message" ? await generalSigningRequest(request, "message")
      : path === "/api/keyway/signing-settings" ? await generalSigningRequest(request, "settings")
      : path === "/api/keyway/recovery" ? await generalSigningRequest(request, "recovery")
      : path === "/api/keyway/developer/apps" ? await developerAppsRequest(request)
      : path === "/api/keyway/managed-node" ? await managedNodeHttpRequest(request)
      : jsonError("Not found", 404);
    for (const [name, value] of cors) response.headers.set(name, value);
    return response;
  } catch (error) {
    const message = error instanceof Error ? error.message : "KeyWay request failed";
    const unauthorized = /session|bearer/i.test(message);
    const rateLimited = /too many/i.test(message);
    // A sanitized cause for operators: Lit refuses everything once the account's credit runs out.
    const cause = /payment_required|HTTP 402/i.test(message) ? "lit-out-of-credit" : PROVIDER_ERROR.test(message) ? "provider" : undefined;
    console.error("[keyway] request failed", { status: unauthorized ? 401 : rateLimited ? 429 : 400, ...(cause ? { cause } : {}) });
    return jsonError(publicErrorMessage(message), unauthorized ? 401 : rateLimited ? 429 : 400, cors);
  }
}

async function managedNodeHttpRequest(request: Request): Promise<Response> {
  const user = await authenticateUser(request);
  const body = await objectBody(request, "Invalid managed-node request");
  const operation = typeof body.operation === "string" ? body.operation : "unknown";
  // While the user's hosted node is in use, move any force-close settlement to their own address.
  if (operation === "status" || operation === "list-channels" || operation === "call") {
    sweepHostedSettlement(user.id, () => ownLockScript(user));
  }
  if (operation === "call") {
    const limit = await consumeRateLimit(`fiber-call:${user.id}`, { max: 120, window: 60 });
    if (!limit.allowed) throw new Error(`Too many Fiber node requests. Try again in ${limit.retryAfter ?? 60} seconds`);
  }
  if (operation === "act") {
    const limit = await consumeRateLimit(`fiber-act:${user.id}`, { max: 30, window: 60 });
    if (!limit.allowed) throw new Error(`Too many Fiber node changes. Try again in ${limit.retryAfter ?? 60} seconds`);
  }
  if (operation === "pay") {
    const scope = await resolveAuthScope(request);
    const context = { user, appName: scope.name, email: () => sessionEmail(request), sendEmail: sendTransactionalEmail, rateLimit: consumeRateLimit };
    const result = await fiberPayment(context, managedFiberNode(user.id), body);
    return Response.json(result, { headers: { "Cache-Control": "no-store" } });
  }
  const result = ["open-channel", "submit-channel-funding"].includes(operation)
    ? await runIdempotentMutation(
      user.id,
      `managed:${operation}`,
      request.headers.get("idempotency-key") ?? "",
      body,
      () => managedNodeRequest(user.id, body, undefined, () => ownLockScript(user)),
    )
    : await managedNodeRequest(user.id, body);
  return Response.json(result, {
    headers: { "Cache-Control": "no-store" },
  });
}

/** The user's own CKB lock, in Fiber RPC shape. */
async function ownLockScript(user: User) {
  const wallet = await readWallet(user);
  if (wallet?.status !== "ready") throw new Error("KeyWay wallet is not ready");
  const script = await currentLock(new ccc.ClientPublicTestnet(), wallet.litPublicKey, wallet.recovery);
  return { code_hash: script.codeHash, hash_type: script.hashType, args: script.args } as never;
}

async function sendCodeRequest(request: Request): Promise<Response> {
  const { email } = await objectBody(request, "Invalid email OTP request");
  if (typeof email !== "string" || !/^\S+@\S+\.\S+$/.test(email) || email.length > 254) {
    throw new Error("A valid email address is required");
  }
  return Response.json(await sendEmailCode(request, email));
}

async function legacyCleanupRequest(request: Request): Promise<Response> {
  await resolveAuthScope(request);
  const sql = await database();
  const rows = await sql<Array<{ database_prefix: string; epoch: string }>>`select database_prefix, epoch from keyway_legacy_cleanup where origin = ${request.headers.get("origin")!} order by database_prefix`;
  return Response.json({ epoch: rows.map((row) => row.epoch).join(":"), prefixes: rows.map((row) => row.database_prefix) }, { headers: { "Cache-Control": "no-store" } });
}

async function verifyCodeRequest(request: Request): Promise<Response> {
  const { challengeId, code } = await objectBody(request, "Invalid email OTP verification");
  if (typeof challengeId !== "string" || !challengeId) throw new Error("OTP challenge is required");
  if (typeof code !== "string" || !/^\d{6}$/.test(code)) throw new Error("Enter the six-digit code");
  return Response.json(await verifyEmailCode(request, challengeId, code));
}

async function sessionRequest(request: Request): Promise<Response> {
  const session = await sessionForRequest(request);
  return Response.json({ ...session, user: publicUser(session.user) }, { headers: { "Cache-Control": "no-store" } });
}

async function logoutRequest(request: Request): Promise<Response> {
  await revokeSession(request);
  return new Response(null, { status: 204 });
}

async function bootstrapRequest(request: Request): Promise<Response> {
  const user = await authenticateUser(request);
  const body = await objectBody(request, "Invalid bootstrap request");
  const { deviceIdHash, nodeMode, keyCustody } = body;
  if (typeof deviceIdHash !== "string") throw new Error("Device ID hash is required");
  // Lit creates the Fiber key; SDKs that send their own key are no longer accepted.
  if (keyCustody !== "lit") throw new Error("Update @ckb-keyway/react to 0.2.4 or later");
  if (nodeMode !== undefined && nodeMode !== "browser" && nodeMode !== "managed") throw new Error("Node mode is invalid");
  const result = await versionedMutation(request, user.id, "bootstrap", body, () =>
    bootstrap(user, deviceIdHash, nodeMode),
  );
  // Every sign-in bootstraps, in both node modes. With recovery on, anything at the old address moves to
  // the new one after this response.
  if (result.wallet.recovery) sweepLegacyAfterSignIn(user);
  return Response.json(result);
}

async function fiberKeyRequest(request: Request): Promise<Response> {
  const user = await authenticateUser(request);
  const { deviceIdHash, leaseId, recipientPublicKey } = await objectBody(request, "Invalid Fiber key request");
  if (typeof deviceIdHash !== "string") throw new Error("Device ID hash is required");
  if (typeof leaseId !== "string") throw new Error("Device lease is required");
  if (typeof recipientPublicKey !== "string") throw new Error("Update @ckb-keyway/react to 0.2.4 or later");
  const wallet = await readWallet(user);
  if (!wallet || wallet.status !== "ready") throw new Error("KeyWay wallet is not provisioned");
  if (wallet.primaryDeviceIdHash !== deviceIdHash) throw new Error("Fiber wallet is bound to another device");
  await requireLease(user, deviceIdHash, leaseId);

  // Lit seals the key to the browser's one-time key, so this server only relays ciphertext.
  const bundle = await wrapFiberKey(wallet.encryptedFiberKey, wallet.litPkpId, recipientPublicKey, deviceIdHash, {
    apiKey: requiredEnv("LIT_USAGE_API_KEY"),
    actionCid: requiredEnv("LIT_WRAP_ACTION_CID"),
    actionCode: await loadLitAction("wrap-fiber-key"),
  });
  return Response.json(bundle, { headers: { "Cache-Control": "no-store" } });
}

async function channelStateRequest(request: Request): Promise<Response> {
  const user = await authenticateUser(request);
  const { deviceIdHash } = await objectBody(request, "Invalid channel-state request");
  if (typeof deviceIdHash !== "string") throw new Error("Device ID hash is required");
  await markChannelOpened(user, deviceIdHash);
  return new Response(null, { status: 204 });
}

async function deviceLeaseRequest(request: Request): Promise<Response> {
  const user = await authenticateUser(request);
  const { operation, deviceIdHash, leaseId } = await objectBody(request, "Invalid lease request");
  if (typeof operation !== "string" || typeof deviceIdHash !== "string") {
    throw new Error("Lease operation and device ID hash are required");
  }
  const wallet = await readWallet(user);
  if (!wallet || wallet.status !== "ready") throw new Error("KeyWay wallet is not provisioned");
  if (wallet.primaryDeviceIdHash !== deviceIdHash) throw new Error("Fiber wallet is bound to another device");
  if (operation === "acquire") return Response.json(publicLease(await acquireLease(user, deviceIdHash)));
  if (typeof leaseId !== "string") throw new Error("Lease ID is required");
  if (operation === "heartbeat") return Response.json(publicLease(await heartbeatLease(user, deviceIdHash, leaseId)));
  if (operation === "release") {
    await releaseLease(user, deviceIdHash, leaseId);
    return new Response(null, { status: 204 });
  }
  throw new Error("Unsupported lease operation");
}

async function saveNodeBackupRequest(request: Request): Promise<Response> {
  const user = await authenticateUser(request);
  const body = await objectBody(request, "Invalid Fiber node backup request");
  const { deviceIdHash, leaseId, backup } = body;
  if (typeof deviceIdHash !== "string" || typeof leaseId !== "string") {
    throw new Error("Device ID hash and lease ID are required");
  }
  const wallet = await readWallet(user);
  if (!wallet || wallet.status !== "ready") throw new Error("KeyWay wallet is not provisioned");
  if (wallet.primaryDeviceIdHash !== deviceIdHash) throw new Error("Fiber wallet is bound to another device");
  await requireLease(user, deviceIdHash, leaseId);
  const parsed = parseNodeBackup(backup);
  if (parsed.databasePrefix !== `/wasm-${wallet.litPkpId}`) {
    throw new Error("Fiber node backup does not belong to this wallet");
  }
  return Response.json(await versionedMutation(request, user.id, "node-backup:save", body, () =>
    saveNodeBackup(user, deviceIdHash, parsed),
  ));
}

async function loadNodeBackupRequest(request: Request): Promise<Response> {
  const user = await authenticateUser(request);
  const body = await objectBody(request, "Invalid Fiber node backup request");
  const { deviceIdHash, leaseId } = body;
  if (typeof deviceIdHash !== "string" || typeof leaseId !== "string") {
    throw new Error("Device ID hash and lease ID are required");
  }
  const wallet = await readWallet(user);
  if (!wallet || wallet.status !== "ready" || wallet.primaryDeviceIdHash !== deviceIdHash) {
    throw new Error("Fiber wallet is bound to another device");
  }
  await requireLease(user, deviceIdHash, leaseId);
  const backup = await versionedMutation(request, user.id, "node-backup:claim", body, () =>
    readClaimedNodeBackup(user, deviceIdHash),
  );
  const { sourceDeviceIdHash: _source, status: _status, claimedDeviceIdHash: _claimed, ...publicBackup } = backup;
  return Response.json(publicBackup, { headers: { "Cache-Control": "no-store" } });
}

async function confirmNodeBackupRequest(request: Request): Promise<Response> {
  const user = await authenticateUser(request);
  const body = await objectBody(request, "Invalid Fiber node backup confirmation");
  const { deviceIdHash, leaseId, generation } = body;
  if (typeof deviceIdHash !== "string" || typeof leaseId !== "string" || !Number.isSafeInteger(generation)) {
    throw new Error("Device ID hash, lease ID, and backup generation are required");
  }
  await requireLease(user, deviceIdHash, leaseId);
  await versionedMutation(request, user.id, "node-backup:confirm", body, async () => {
    await confirmNodeBackupRestored(user, deviceIdHash, generation as number);
    return { confirmed: true };
  });
  return new Response(null, { status: 204 });
}

async function signTransactionRequest(request: Request): Promise<Response> {
  const user = await authenticateUser(request);
  const body = await objectBody(request, "Invalid signing request");
  // General transactions go through the general policy; requests without a purpose are channel funding.
  if (body.purpose === "transaction") return generalSigningRequest(request, "transaction", body);
  const { operation, transaction, confirmationNonce } = body;
  const wallet = await readWallet(user);
  if (!wallet || wallet.status !== "ready") throw new Error("KeyWay wallet is not provisioned");
  const validated = await previewFundingTransaction(wallet, transaction);
  const serialized = JSON.stringify(serializeTransaction(validated.transaction));
  if (operation === "preview") {
    return Response.json({
      preview: validated.preview,
      confirmationNonce: await issueConfirmation(user, serialized),
    });
  }
  if (operation !== "sign" || typeof confirmationNonce !== "string") {
    throw new Error("A valid signing operation is required");
  }
  return Response.json(await versionedMutation(request, user.id, "sign-transaction", body, async () => {
    await consumeConfirmation(user, confirmationNonce, serialized);
    await recordSigningEvent(user.id);
    const signed = await signFundingTransaction(user, wallet, validated);
    return { transaction: serializeTransaction(signed) };
  }));
}

async function generalSigningRequest(
  request: Request,
  kind: "transaction" | "message" | "settings" | "recovery",
  parsedBody?: Record<string, unknown>,
): Promise<Response> {
  const user = await authenticateUser(request);
  const body = parsedBody ?? await objectBody(request, "Invalid signing request");
  const wallet = await readWallet(user);
  if (!wallet || wallet.status !== "ready") throw new Error("KeyWay wallet is not provisioned");
  const scope = await resolveAuthScope(request);
  const context: SigningContext = {
    user,
    wallet,
    appName: scope.name,
    email: () => sessionEmail(request),
    sendEmail: sendTransactionalEmail,
    rateLimit: consumeRateLimit,
    recordSigning: recordSigningEvent,
  };
  const run = () => kind === "transaction" ? transactionSigning(context, body)
    : kind === "message" ? messageSigning(context, body)
    : kind === "recovery" ? recoverySetup(context, body)
    : signingSettings(context, body);
  const result = body.operation === "sign" || body.operation === "enable" ? await versionedMutation(request, user.id, `general-${kind}`, body, run) : await run();
  return Response.json(result, { headers: { "Cache-Control": "no-store" } });
}

async function developerAppsRequest(request: Request): Promise<Response> {
  const user = await authenticateUser(request);
  if (user.scopeId !== "dashboard") throw new Error("Dashboard session is required");
  const body = await objectBody(request, "Invalid developer application request");
  const operation = body.operation;
  if (operation === "list") return Response.json({ applications: await listApplications(user) });
  if (operation === "create") {
    if (typeof body.name !== "string") throw new Error("Application name is required");
    return Response.json(await createApplication(user, {
      name: body.name,
    }));
  }
  if (typeof body.appId !== "string") throw new Error("Application ID is required");
  if (operation === "update") {
    return Response.json(await updateApplication(user, {
      appId: body.appId,
      name: optionalString(body.name),
      disabled: optionalBoolean(body.disabled),
    }));
  }
  if (operation === "add-origin") {
    if (typeof body.origin !== "string") throw new Error("Application origin is required");
    if (body.environment !== "development" && body.environment !== "production") {
      throw new Error("Origin environment must be development or production");
    }
    return Response.json(await addApplicationOrigin(user, {
      appId: body.appId,
      origin: body.origin,
      environment: body.environment,
    }));
  }
  if (operation === "remove-origin") {
    if (typeof body.origin !== "string") throw new Error("Application origin is required");
    return Response.json(await removeApplicationOrigin(user, { appId: body.appId, origin: body.origin }));
  }
  throw new Error("Unsupported developer application operation");
}

async function objectBody(request: Request, message: string): Promise<Record<string, unknown>> {
  const body: unknown = await request.json();
  if (!body || typeof body !== "object") throw new Error(message);
  return body as Record<string, unknown>;
}

function parseNodeBackup(value: unknown) {
  if (!value || typeof value !== "object") throw new Error("Encrypted Fiber node backup is required");
  const backup = value as Record<string, unknown>;
  if (
    backup.formatVersion !== 1 ||
    typeof backup.databasePrefix !== "string" || !backup.databasePrefix.startsWith("/wasm-") ||
    typeof backup.salt !== "string" || Buffer.from(backup.salt, "base64").length !== 32 ||
    typeof backup.iv !== "string" || Buffer.from(backup.iv, "base64").length !== 12 ||
    typeof backup.ciphertext !== "string" || Buffer.from(backup.ciphertext, "base64").length > 12_000_000 ||
    typeof backup.digest !== "string" || !/^[0-9a-f]{64}$/.test(backup.digest)
  ) {
    throw new Error("Encrypted Fiber node backup is invalid");
  }
  return {
    formatVersion: 1 as const,
    databasePrefix: backup.databasePrefix,
    salt: backup.salt,
    iv: backup.iv,
    ciphertext: backup.ciphertext,
    digest: backup.digest,
  };
}

async function corsHeaders(request: Request): Promise<Headers | Response> {
  const origin = request.headers.get("origin");
  const allowed = (process.env.KEYWAY_ALLOWED_ORIGINS ?? "").split(",").map((value) => value.trim()).filter(Boolean);
  if (new URL(request.url).pathname.includes("/keyway/")) {
    if (request.method !== "OPTIONS") {
      try { await resolveAuthScope(request); } catch { return jsonError("Application origin is not allowed", 403); }
    } else if (!origin) return jsonError("Origin is required", 403);
  } else if (origin && !allowed.includes(origin) && origin !== new URL(request.url).origin) {
    return jsonError("Origin is not allowed", 403);
  }
  const headers = new Headers({
    "Access-Control-Allow-Headers": "Authorization, Content-Type, Idempotency-Key, X-KeyWay-App-Id, X-KeyWay-Auth-Scope",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Vary": "Origin",
    ...SECURITY_HEADERS,
  });
  if (origin) headers.set("Access-Control-Allow-Origin", origin);
  return headers;
}

function apiPath(path: string): string {
  return path.startsWith("/api/v1/keyway/") ? path.replace("/api/v1/keyway/", "/api/keyway/") : path;
}

function versionedMutation<T>(
  request: Request,
  userId: string,
  operation: string,
  body: unknown,
  mutation: () => Promise<T>,
): Promise<T> {
  if (!new URL(request.url).pathname.startsWith("/api/v1/keyway/")) return mutation();
  return runIdempotentMutation(
    userId,
    operation,
    request.headers.get("idempotency-key") ?? "",
    body,
    mutation,
  );
}

function optionalString(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string") throw new Error("Expected a string value");
  return value;
}

function optionalBoolean(value: unknown): boolean | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "boolean") throw new Error("Expected a boolean value");
  return value;
}

function optionalNumber(value: unknown): number | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "number") throw new Error("Expected a number value");
  return value;
}

/** Every API response is private, uncacheable JSON. */
const SECURITY_HEADERS = {
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "X-Frame-Options": "DENY",
} as const;

const PROVIDER_ERROR = /lit_node::|Actions failed|Lit Action failed|Lit returned|Lit has not granted|Lit could not|Chipotle|Resend|ECONN|fetch failed/i;

/**
 * Error text that is safe to show in a browser: provider internals (Lit stack traces, upstream responses)
 * become one plain sentence, control characters are stripped, and the length is capped.
 */
export function publicErrorMessage(message: string): string {
  if (PROVIDER_ERROR.test(message)) return "The Lit signature service is temporarily unavailable. Try again in a moment.";
  const clean = message.replace(/\u001b\[[0-9;]*m/g, "").replace(/[\u0000-\u001f\u007f]+/g, " ").trim();
  return clean.length > 240 ? `${clean.slice(0, 237)}...` : clean || "KeyWay request failed";
}

function jsonError(message: string, status: number, headers?: Headers): Response {
  return Response.json({ error: message }, { status, headers: headers ?? new Headers(SECURITY_HEADERS) });
}

function publicLease(lease: { leaseId: string; expiresAt: string }) {
  return { leaseId: lease.leaseId, expiresAt: lease.expiresAt };
}

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Missing server configuration: ${name}`);
  return value;
}
