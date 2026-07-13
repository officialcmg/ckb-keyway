import { bootstrap } from "./bootstrap.ts";
import { markChannelOpened, readWallet } from "./user-wallet.ts";
import { authenticateUser } from "./stytch.ts";
import { acquireLease, heartbeatLease, releaseLease, requireLease } from "./device-lease.ts";
import { loadLitAction } from "./lit-actions.ts";
import { decryptFiberKey } from "./lit.ts";
import {
  previewFundingTransaction,
  serializeTransaction,
  signFundingTransaction,
} from "./funding-transaction.ts";
import { consumeConfirmation, issueConfirmation } from "./signing-confirmation.ts";
import { database } from "./database.ts";

export async function handleKeyWayRequest(request: Request): Promise<Response> {
  const cors = corsHeaders(request);
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
  if (request.method !== "POST") return jsonError("Not found", 404, cors);

  try {
    const path = new URL(request.url).pathname;
    const response = path === "/api/keyway/bootstrap" ? await bootstrapRequest(request)
      : path === "/api/keyway/fiber-key" ? await fiberKeyRequest(request)
      : path === "/api/keyway/channel-state" ? await channelStateRequest(request)
      : path === "/api/keyway/device-lease" ? await deviceLeaseRequest(request)
      : path === "/api/keyway/sign-transaction" ? await signTransactionRequest(request)
      : jsonError("Not found", 404);
    for (const [name, value] of cors) response.headers.set(name, value);
    return response;
  } catch (error) {
    const message = error instanceof Error ? error.message : "KeyWay request failed";
    const unauthorized = /session|bearer/i.test(message);
    console.error("[keyway]", message);
    return jsonError(message, unauthorized ? 401 : 400, cors);
  }
}

async function bootstrapRequest(request: Request): Promise<Response> {
  const user = await authenticateUser(request.headers.get("authorization"));
  const body = await objectBody(request, "Invalid bootstrap request");
  const { deviceIdHash, fiberKey } = body;
  if (typeof deviceIdHash !== "string") throw new Error("Device ID hash is required");
  if (fiberKey !== undefined && typeof fiberKey !== "string") throw new Error("Fiber key is invalid");
  return Response.json(await bootstrap(user, deviceIdHash, fiberKey));
}

async function fiberKeyRequest(request: Request): Promise<Response> {
  const user = await authenticateUser(request.headers.get("authorization"));
  const { deviceIdHash, leaseId } = await objectBody(request, "Invalid Fiber key request");
  if (typeof deviceIdHash !== "string") throw new Error("Device ID hash is required");
  if (typeof leaseId !== "string") throw new Error("Device lease is required");
  const wallet = await readWallet(user);
  if (!wallet || wallet.status !== "ready") throw new Error("KeyWay wallet is not provisioned");
  if (wallet.primaryDeviceIdHash !== deviceIdHash) throw new Error("Fiber wallet is bound to another device");
  await requireLease(user, deviceIdHash, leaseId);

  const fiberKey = await decryptFiberKey(wallet.encryptedFiberKey, wallet.litPkpId, {
    apiKey: requiredEnv("LIT_USAGE_API_KEY"),
    actionCid: requiredEnv("LIT_DECRYPT_ACTION_CID"),
    actionCode: await loadLitAction("decrypt-fiber-key"),
  });
  try {
    return new Response(fiberKey.slice(), {
      headers: { "Cache-Control": "no-store", "Content-Type": "application/octet-stream", "Content-Length": "32" },
    });
  } finally {
    fiberKey.fill(0);
  }
}

async function channelStateRequest(request: Request): Promise<Response> {
  const user = await authenticateUser(request.headers.get("authorization"));
  const { deviceIdHash } = await objectBody(request, "Invalid channel-state request");
  if (typeof deviceIdHash !== "string") throw new Error("Device ID hash is required");
  await markChannelOpened(user, deviceIdHash);
  return new Response(null, { status: 204 });
}

async function deviceLeaseRequest(request: Request): Promise<Response> {
  const user = await authenticateUser(request.headers.get("authorization"));
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

async function signTransactionRequest(request: Request): Promise<Response> {
  const user = await authenticateUser(request.headers.get("authorization"));
  const { operation, transaction, confirmationNonce } = await objectBody(request, "Invalid signing request");
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
  await consumeConfirmation(user, confirmationNonce, serialized);
  const signed = await signFundingTransaction(user, wallet, validated);
  return Response.json({ transaction: serializeTransaction(signed) });
}

async function objectBody(request: Request, message: string): Promise<Record<string, unknown>> {
  const body: unknown = await request.json();
  if (!body || typeof body !== "object") throw new Error(message);
  return body as Record<string, unknown>;
}

function corsHeaders(request: Request): Headers | Response {
  const origin = request.headers.get("origin");
  const allowed = (process.env.KEYWAY_ALLOWED_ORIGINS ?? "").split(",").map((value) => value.trim()).filter(Boolean);
  if (origin && origin !== new URL(request.url).origin && !allowed.includes(origin)) {
    return jsonError("Origin is not allowed", 403);
  }
  const headers = new Headers({
    "Access-Control-Allow-Headers": "Authorization, Content-Type",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Vary": "Origin",
  });
  if (origin) headers.set("Access-Control-Allow-Origin", origin);
  return headers;
}

function jsonError(message: string, status: number, headers?: Headers): Response {
  return Response.json({ error: message }, { status, headers });
}

function publicLease(lease: { leaseId: string; expiresAt: string }) {
  return { leaseId: lease.leaseId, expiresAt: lease.expiresAt };
}

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Missing server configuration: ${name}`);
  return value;
}
