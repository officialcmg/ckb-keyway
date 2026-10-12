import { createHmac, randomInt, timingSafeEqual } from "node:crypto";
import * as ccc from "@ckb-ccc/core";
import { sha256 } from "@noble/hashes/sha2.js";
import type { User } from "./auth-user.ts";
import { database } from "./database.ts";
import { createConfirmationEmailTemplate } from "./email-template.ts";
import { formatCkbSignature, serializeTransaction } from "./funding-transaction.ts";
import { loadLitAction } from "./lit-actions.ts";
import { signCkbDigest } from "./lit.ts";
import { recoverPkpPublicKey } from "./pkp-identity.ts";
import { formatCkb, previewGeneralTransaction, previewSummaryLines, type ValidatedTransaction } from "./transaction-policy.ts";
import type { ReadyWallet } from "./user-wallet.ts";

type Purpose = "transaction" | "message" | "settings";

/** Everything the signing service needs from the HTTP layer, so it can be tested without it. */
export type SigningContext = {
  user: User;
  wallet: ReadyWallet;
  appName: string;
  email: () => Promise<string>;
  sendEmail: (to: string, message: { subject: string; html: string; plaintext: string }, idempotencyKey: string) => Promise<void>;
  rateLimit: (key: string, rule: { max: number; window: number }) => Promise<{ allowed: boolean; retryAfter: number | null }>;
  recordSigning: (userId: string) => Promise<void>;
  preview?: (wallet: ReadyWallet, transaction: unknown) => Promise<ValidatedTransaction>;
  signDigest?: (digest: ccc.Hex, wallet: ReadyWallet) => Promise<ccc.Hex>;
};

const REQUEST_TTL_MS = 5 * 60_000;
const CODE_TTL_MS = 10 * 60_000;
const MAX_CODE_ATTEMPTS = 5;
const MAX_MESSAGE_BYTES = 4096;

/** Transactions: preview, request-email-code, sign. */
export async function transactionSigning(context: SigningContext, body: Record<string, unknown>): Promise<unknown> {
  const preview = context.preview ?? previewGeneralTransaction;
  const validated = await preview(context.wallet, body.transaction);
  const digest = hashText(JSON.stringify(serializeTransaction(validated.transaction)));

  if (body.operation === "preview") {
    await limit(context, "sign", { max: 10, window: 60 });
    const threshold = await readThreshold(context.user);
    // With a threshold set, CKB at or above it, or any token leaving the account, needs the emailed code.
    const requiresEmailCode = threshold !== null && (validated.outflowShannons >= threshold || validated.tokensLeaving);
    const confirmationNonce = await issueRequest(context.user, "transaction", digest, { lines: previewSummaryLines(validated.preview) }, requiresEmailCode);
    return { preview: validated.preview, confirmationNonce, requiresEmailCode };
  }
  const nonce = requiredNonce(body.confirmationNonce);
  if (body.operation === "request-email-code") {
    const request = await loadRequest(context.user, "transaction", nonce, digest);
    if (!request.requires_email_code) throw new Error("This transaction doesn't need an email code");
    await sendCode(context, "transaction", nonce, "Confirm a transaction", request.summary.lines ?? []);
    return { sent: true };
  }
  if (body.operation !== "sign") throw new Error("A valid signing operation is required");
  const request = await loadRequest(context.user, "transaction", nonce, digest);
  if (request.requires_email_code) await verifyCode(context.user, "transaction", nonce, body.emailCode);
  await consumeRequest(context.user, "transaction", nonce);
  await context.recordSigning(context.user.id);
  return { transaction: serializeTransaction(await signTransaction(context, validated)) };
}

/** Messages: preview, sign. Signed in CKB's "Nervos Message:" format, so CCC's verifyMessage accepts them. */
export async function messageSigning(context: SigningContext, body: Record<string, unknown>): Promise<unknown> {
  const message = body.message;
  if (typeof message !== "string" || !message.trim()) throw new Error("A message to sign is required");
  if (new TextEncoder().encode(message).length > MAX_MESSAGE_BYTES) throw new Error("Messages can be at most 4 KB");
  const digest = hashText(message);
  if (body.operation === "preview") {
    await limit(context, "sign", { max: 10, window: 60 });
    const confirmationNonce = await issueRequest(context.user, "message", digest, { message }, false);
    return { preview: { message }, confirmationNonce };
  }
  if (body.operation !== "sign") throw new Error("A valid signing operation is required");
  const nonce = requiredNonce(body.confirmationNonce);
  await loadRequest(context.user, "message", nonce, digest);
  await consumeRequest(context.user, "message", nonce);
  await context.recordSigning(context.user.id);
  const signature = await sign(context, ccc.messageHashCkbSecp256k1(message));
  return { signature, identity: context.wallet.litPublicKey };
}

/**
 * The user's email-confirmation threshold. Strengthening it (turning it on, or lowering the amount)
 * applies at once; weakening it (raising the amount, or turning it off) needs a code from the user's inbox.
 */
export async function signingSettings(context: SigningContext, body: Record<string, unknown>): Promise<unknown> {
  const current = await readThreshold(context.user);
  if (body.operation === "get") return { emailThresholdShannons: current?.toString() ?? null };
  if (body.operation !== "set") throw new Error("A valid settings operation is required");
  const next = parseThreshold(body.emailThresholdShannons);
  const weakening = current !== null && (next === null || next > current);
  if (!weakening) {
    await writeThreshold(context.user, next);
    return { emailThresholdShannons: next?.toString() ?? null };
  }
  const digest = hashText(`threshold:${next?.toString() ?? "off"}`);
  if (body.confirmationNonce === undefined) {
    const lines = [
      `Email confirmation for transfers: currently ${formatCkb(current!)} CKB and above`,
      next === null ? "Change: turn it off" : `Change: only ${formatCkb(next)} CKB and above`,
    ];
    const confirmationNonce = await issueRequest(context.user, "settings", digest, { lines }, true);
    await sendCode(context, "settings", confirmationNonce, "Confirm a security change", lines);
    return { requiresEmailCode: true, confirmationNonce };
  }
  const nonce = requiredNonce(body.confirmationNonce);
  await loadRequest(context.user, "settings", nonce, digest);
  await verifyCode(context.user, "settings", nonce, body.emailCode);
  await consumeRequest(context.user, "settings", nonce);
  await writeThreshold(context.user, next);
  return { emailThresholdShannons: next?.toString() ?? null };
}

async function signTransaction(context: SigningContext, validated: ValidatedTransaction): Promise<ccc.Transaction> {
  const info = await validated.transaction.getSignHashInfo(validated.script, validated.signer.client);
  if (!info) throw new Error("Transaction has no KeyWay signing group");
  const signature = await sign(context, info.message);
  const witness = validated.transaction.getWitnessArgsAt(info.position) ?? ccc.WitnessArgs.from({});
  witness.lock = signature;
  validated.transaction.setWitnessArgsAt(info.position, witness);
  return validated.transaction;
}

/** Signs a digest the backend computed itself, then checks the recovered key before releasing it. */
async function sign(context: SigningContext, digest: ccc.Hex): Promise<ccc.Hex> {
  if (context.signDigest) return context.signDigest(digest, context.wallet);
  const signature = await signCkbDigest(digest, context.wallet.litPkpId, {
    apiKey: requiredEnv("LIT_USAGE_API_KEY"),
    actionCid: requiredEnv("LIT_SIGN_ACTION_CID"),
    actionCode: await loadLitAction("sign-ckb-digest"),
  });
  const recovered = ccc.hexFrom(recoverPkpPublicKey(ccc.bytesFrom(digest), signature));
  if (recovered.toLowerCase() !== context.wallet.litPublicKey.toLowerCase()) throw new Error("Lit signature does not match the KeyWay wallet");
  return formatCkbSignature(signature);
}

async function limit(context: SigningContext, name: string, rule: { max: number; window: number }) {
  const result = await context.rateLimit(`${name}:${context.user.id}`, rule);
  if (!result.allowed) throw new Error(`Too many signing requests. Try again in ${result.retryAfter ?? rule.window} seconds`);
}

async function issueRequest(user: User, purpose: Purpose, digest: string, summary: Record<string, unknown>, requiresEmailCode: boolean): Promise<string> {
  const sql = await database();
  const nonce = crypto.randomUUID();
  await sql`
    insert into keyway_v2_signature_requests (user_id, purpose, nonce, request_digest, summary, requires_email_code, expires_at)
    values (${user.id}, ${purpose}, ${nonce}, ${digest}, ${sql.json(summary as never)}, ${requiresEmailCode}, ${new Date(Date.now() + REQUEST_TTL_MS)})
    on conflict (user_id, purpose) do update set
      nonce = excluded.nonce, request_digest = excluded.request_digest, summary = excluded.summary,
      requires_email_code = excluded.requires_email_code, email_code_hash = null, email_code_expires_at = null,
      email_attempts = 0, expires_at = excluded.expires_at
  `;
  return nonce;
}

type RequestRow = { requires_email_code: boolean; summary: { lines?: string[] } };

async function loadRequest(user: User, purpose: Purpose, nonce: string, digest: string): Promise<RequestRow> {
  const sql = await database();
  const [row] = await sql<RequestRow[]>`
    select requires_email_code, summary from keyway_v2_signature_requests
    where user_id = ${user.id} and purpose = ${purpose} and nonce = ${nonce} and request_digest = ${digest} and expires_at > now()
  `;
  if (!row) throw new Error("Signing confirmation is invalid or expired");
  return row;
}

async function consumeRequest(user: User, purpose: Purpose, nonce: string): Promise<void> {
  const sql = await database();
  const rows = await sql`delete from keyway_v2_signature_requests where user_id = ${user.id} and purpose = ${purpose} and nonce = ${nonce} returning 1`;
  if (!rows[0]) throw new Error("Signing confirmation is invalid or expired");
}

async function sendCode(context: SigningContext, purpose: Purpose, nonce: string, heading: string, lines: string[]): Promise<void> {
  await limit(context, "step-up-email", { max: 5, window: 600 });
  const code = randomInt(0, 1_000_000).toString().padStart(6, "0");
  const sql = await database();
  const rows = await sql`
    update keyway_v2_signature_requests
    set email_code_hash = ${codeHash(nonce, code)}, email_code_expires_at = ${new Date(Date.now() + CODE_TTL_MS)}, email_attempts = 0
    where user_id = ${context.user.id} and purpose = ${purpose} and nonce = ${nonce} returning 1
  `;
  if (!rows[0]) throw new Error("Signing confirmation is invalid or expired");
  const template = createConfirmationEmailTemplate(context.appName, code, heading, lines);
  await context.sendEmail(await context.email(), template, `keyway-step-up/${nonce}/${Date.now()}`);
}

async function verifyCode(user: User, purpose: Purpose, nonce: string, code: unknown): Promise<void> {
  if (typeof code !== "string" || !/^\d{6}$/.test(code)) throw new Error("Enter the six-digit code from your email");
  const sql = await database();
  const [row] = await sql<Array<{ email_code_hash: string | null; email_attempts: number }>>`
    update keyway_v2_signature_requests set email_attempts = email_attempts + 1
    where user_id = ${user.id} and purpose = ${purpose} and nonce = ${nonce} and email_code_expires_at > now()
    returning email_code_hash, email_attempts
  `;
  if (!row?.email_code_hash) throw new Error("The email code has expired. Request a new one");
  if (row.email_attempts > MAX_CODE_ATTEMPTS) throw new Error("Too many wrong codes. Request a new one");
  const expected = Buffer.from(row.email_code_hash, "hex");
  const supplied = Buffer.from(codeHash(nonce, code), "hex");
  if (expected.length !== supplied.length || !timingSafeEqual(expected, supplied)) throw new Error("That email code isn't right");
}

async function readThreshold(user: User): Promise<bigint | null> {
  const sql = await database();
  const [row] = await sql<Array<{ email_threshold_shannons: string | null }>>`
    select email_threshold_shannons from keyway_v2_signing_settings where user_id = ${user.id}
  `;
  return row?.email_threshold_shannons ? BigInt(row.email_threshold_shannons) : null;
}

async function writeThreshold(user: User, value: bigint | null): Promise<void> {
  const sql = await database();
  await sql`
    insert into keyway_v2_signing_settings (user_id, email_threshold_shannons, updated_at)
    values (${user.id}, ${value?.toString() ?? null}, now())
    on conflict (user_id) do update set email_threshold_shannons = excluded.email_threshold_shannons, updated_at = now()
  `;
}

export function parseThreshold(value: unknown): bigint | null {
  if (value === null) return null;
  if (typeof value !== "string" || !/^\d{1,30}$/.test(value)) throw new Error("The threshold must be a whole number of shannons, or null to turn it off");
  const parsed = BigInt(value);
  if (parsed <= 0n) throw new Error("The threshold must be greater than zero");
  return parsed;
}

function requiredNonce(value: unknown): string {
  if (typeof value !== "string" || !/^[0-9a-f-]{36}$/i.test(value)) throw new Error("A signing confirmation is required");
  return value;
}

function codeHash(nonce: string, code: string): string {
  return createHmac("sha256", nonce).update(code).digest("hex");
}

function hashText(value: string): string {
  return Buffer.from(sha256(new TextEncoder().encode(value))).toString("hex");
}

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Missing server configuration: ${name}`);
  return value;
}
