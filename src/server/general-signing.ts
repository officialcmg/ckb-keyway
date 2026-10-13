import { createHmac, randomInt, timingSafeEqual } from "node:crypto";
import * as ccc from "@ckb-ccc/core";
import { sha256 } from "@noble/hashes/sha2.js";
import type { User } from "./auth-user.ts";
import type { TransactionSql } from "postgres";
import { database, type DatabaseSql } from "./database.ts";
import { createConfirmationEmailTemplate } from "./email-template.ts";
import { formatCkbSignature, serializeTransaction } from "./funding-transaction.ts";
import { loadLitAction } from "./lit-actions.ts";
import { signCkbDigest } from "./lit.ts";
import { recoverPkpPublicKey } from "./pkp-identity.ts";
import { formatCkb, previewGeneralTransaction, previewSummaryLines, type ValidatedTransaction } from "./transaction-policy.ts";
import type { ReadyWallet } from "./user-wallet.ts";

export type Purpose = "transaction" | "message" | "settings" | "payment";

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
    const requiresEmailCode = await outflowNeedsEmailCode(context.user, transactionOutflow(validated));
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
  // Checked again here, because the threshold or the day's total may have changed since the preview.
  if (!request.requires_email_code && await outflowNeedsEmailCode(context.user, transactionOutflow(validated))) {
    throw new Error("This transaction now needs an email code. Review it again");
  }
  if (request.requires_email_code) await verifyCode(context.user, "transaction", nonce, body.emailCode);
  await consumeRequest(context.user, "transaction", nonce);
  await context.recordSigning(context.user.id);
  const signed = await signTransaction(context, validated);
  await recordOutflow(context.user, transactionOutflow(validated));
  return { transaction: serializeTransaction(signed) };
}

function transactionOutflow(validated: ValidatedTransaction): Outflow {
  return { id: validated.preview.transactionHash, shannons: validated.outflowShannons, tokens: validated.tokenOutflows };
}

const OUTFLOW_WINDOW = "24 hours";

/** A connection or an open transaction. */
type Query = DatabaseSql | TransactionSql;

/**
 * Money leaving the account: an on-chain transaction (by hash) or a Fiber payment (by approval nonce), with
 * the CKB it sends and each token by its type script hash.
 */
export type Outflow = { id: string; shannons: bigint; tokens: Array<{ asset: string; amount: bigint }> };

/** Daily amounts by asset: "ckb", or a token's type script hash. Empty means email confirmation is off. */
export type DailyAmounts = Map<string, bigint>;

/**
 * Email confirmation is off until the user sets a daily amount. Once any is set, the emailed code is needed
 * when an asset's 24-hour total (signed transactions and Fiber payments together) reaches its amount, so
 * splitting a transfer doesn't avoid it. A token with no amount of its own always needs the code.
 */
export async function outflowNeedsEmailCode(user: User, outflow: Outflow, connection?: Query): Promise<boolean> {
  const amounts = await readDailyAmounts(user, connection);
  if (amounts.size === 0) return false;
  const ckb = amounts.get("ckb");
  if (ckb !== undefined && outflow.shannons > 0n && await recentOutflow(user, outflow.id, connection) + outflow.shannons >= ckb) return true;
  for (const token of outflow.tokens) {
    const limit = amounts.get(token.asset);
    if (limit === undefined || await recentTokenOutflow(user, outflow.id, token.asset, connection) + token.amount >= limit) return true;
  }
  return false;
}

/** CKB sent in the last 24 hours, not counting this outflow if it was recorded before. */
async function recentOutflow(user: User, id: string, connection?: Query): Promise<bigint> {
  const sql = connection ?? await database();
  const [row] = await sql<Array<{ total: string | null }>>`
    select sum(outflow_shannons)::text as total from keyway_v2_signed_outflows
    where user_id = ${user.id} and signed_at > now() - ${OUTFLOW_WINDOW}::interval and transaction_hash <> ${id}
  `;
  return BigInt(row?.total ?? "0");
}

async function recentTokenOutflow(user: User, id: string, asset: string, connection?: Query): Promise<bigint> {
  const sql = connection ?? await database();
  const [row] = await sql<Array<{ total: string | null }>>`
    select sum(amount)::text as total from keyway_v2_token_outflows
    where user_id = ${user.id} and asset = ${asset} and signed_at > now() - ${OUTFLOW_WINDOW}::interval and outflow_id <> ${id}
  `;
  return BigInt(row?.total ?? "0");
}

export async function recordOutflow(user: User, outflow: Outflow, connection?: Query): Promise<void> {
  const sql = connection ?? await database();
  await sql`delete from keyway_v2_signed_outflows where user_id = ${user.id} and signed_at <= now() - ${OUTFLOW_WINDOW}::interval`;
  await sql`delete from keyway_v2_token_outflows where user_id = ${user.id} and signed_at <= now() - ${OUTFLOW_WINDOW}::interval`;
  if (outflow.shannons > 0n) {
    await sql`
      insert into keyway_v2_signed_outflows (user_id, transaction_hash, outflow_shannons)
      values (${user.id}, ${outflow.id}, ${outflow.shannons.toString()})
      on conflict (user_id, transaction_hash) do update set outflow_shannons = excluded.outflow_shannons, signed_at = now()
    `;
  }
  for (const token of outflow.tokens) {
    await sql`
      insert into keyway_v2_token_outflows (user_id, outflow_id, asset, amount)
      values (${user.id}, ${outflow.id}, ${token.asset}, ${token.amount.toString()})
      on conflict (user_id, outflow_id, asset) do update set amount = excluded.amount, signed_at = now()
    `;
  }
}

/**
 * Counts an outflow before the money moves, under a per-user lock, so overlapping payments can't each
 * slip under the amount. Unless the user already confirmed by email, it refuses once an amount is
 * reached. Returns a function that removes the entry if the payment then fails.
 */
export async function reserveOutflow(user: User, outflow: Outflow, emailConfirmed: boolean): Promise<() => Promise<void>> {
  const sql = await database();
  await sql.begin(async (tx) => {
    await tx`select pg_advisory_xact_lock(hashtextextended(${`keyway-outflow:${user.id}`}, 0))`;
    if (!emailConfirmed && await outflowNeedsEmailCode(user, outflow, tx)) {
      throw new Error("This payment now needs an email code. Review it again");
    }
    await recordOutflow(user, outflow, tx);
  });
  return async () => {
    await sql`delete from keyway_v2_signed_outflows where user_id = ${user.id} and transaction_hash = ${outflow.id}`;
    await sql`delete from keyway_v2_token_outflows where user_id = ${user.id} and outflow_id = ${outflow.id}`;
  };
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
 * The user's daily email-confirmation amounts, one per asset. Strengthening (a lower amount, or protecting
 * something that wasn't) applies at once; weakening (a higher amount, removing one, or turning email
 * confirmation off) needs a code from the user's inbox. `emailThresholdShannons` is the CKB amount, kept
 * for SDK 0.2.3 and earlier.
 */
export async function signingSettings(context: SigningContext, body: Record<string, unknown>): Promise<unknown> {
  const current = await readDailyAmounts(context.user);
  const view = (amounts: DailyAmounts) => ({
    emailThresholdShannons: amounts.get("ckb")?.toString() ?? null,
    dailyAmounts: Object.fromEntries([...amounts].map(([asset, amount]) => [asset, amount.toString()])),
  });
  if (body.operation === "get") return view(current);
  const change = body.operation === "set" ? { asset: "ckb", amount: parseThreshold(body.emailThresholdShannons) }
    : body.operation === "set-daily-amount" ? { asset: parseAsset(body.asset), amount: parseThreshold(body.amount) }
    : undefined;
  if (!change) throw new Error("A valid settings operation is required");
  const next = new Map(current);
  if (change.amount === null) next.delete(change.asset); else next.set(change.asset, change.amount);
  if (!weakens(current, next)) {
    await writeDailyAmount(context.user, change.asset, change.amount);
    return view(next);
  }
  const digest = hashText(`daily-amount:${change.asset}:${change.amount?.toString() ?? "off"}`);
  if (body.confirmationNonce === undefined) {
    const lines = [
      `Email confirmation for ${assetName(change.asset)}: ${describeAmount(current, change.asset)}`,
      `Change: ${next.size === 0 ? "turn email confirmation off" : describeAmount(next, change.asset)}`,
    ];
    const confirmationNonce = await issueRequest(context.user, "settings", digest, { lines }, true);
    await sendCode(context, "settings", confirmationNonce, "Confirm a security change", lines);
    return { requiresEmailCode: true, confirmationNonce };
  }
  const nonce = requiredNonce(body.confirmationNonce);
  await loadRequest(context.user, "settings", nonce, digest);
  await verifyCode(context.user, "settings", nonce, body.emailCode);
  await consumeRequest(context.user, "settings", nonce);
  await writeDailyAmount(context.user, change.asset, change.amount);
  return view(next);
}

/**
 * How much of an asset can leave in 24 hours without the emailed code: unlimited when email confirmation is
 * off; CKB without an amount is unlimited; a token without an amount always needs the code.
 */
function allowance(amounts: DailyAmounts, asset: string): bigint | "unlimited" {
  if (amounts.size === 0) return "unlimited";
  return amounts.get(asset) ?? (asset === "ckb" ? "unlimited" : 0n);
}

/** A change weakens protection if any asset, including tokens with no amount of their own, can then send more. */
export function weakens(before: DailyAmounts, after: DailyAmounts): boolean {
  const assets = new Set(["ckb", "0x" + "0".repeat(64), ...before.keys(), ...after.keys()]);
  return [...assets].some((asset) => {
    const was = allowance(before, asset);
    const now = allowance(after, asset);
    return now === "unlimited" ? was !== "unlimited" : was !== "unlimited" && now > was;
  });
}

function assetName(asset: string): string {
  return asset === "ckb" ? "CKB" : `token ${asset.slice(0, 10)}…${asset.slice(-6)}`;
}

function describeAmount(amounts: DailyAmounts, asset: string): string {
  const value = allowance(amounts, asset);
  if (value === "unlimited") return "off";
  if (value === 0n) return "every transfer";
  return `once ${asset === "ckb" ? `${formatCkb(value)} CKB` : value.toString()} is sent in 24 hours`;
}

function parseAsset(value: unknown): string {
  if (value === "ckb") return "ckb";
  if (typeof value !== "string" || !/^0x[0-9a-f]{64}$/i.test(value)) throw new Error('The asset must be "ckb" or a token\'s type script hash');
  return value.toLowerCase();
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

export async function limit(context: Pick<SigningContext, "user" | "rateLimit">, name: string, rule: { max: number; window: number }) {
  const result = await context.rateLimit(`${name}:${context.user.id}`, rule);
  if (!result.allowed) throw new Error(`Too many signing requests. Try again in ${result.retryAfter ?? rule.window} seconds`);
}

const MAX_PENDING_PAYMENTS = 20;

/**
 * One pending approval per user for transactions, messages and settings (a new one replaces the old);
 * Fiber payments may overlap, up to a small number pending at once.
 */
export async function issueRequest(user: User, purpose: Purpose, digest: string, summary: Record<string, unknown>, requiresEmailCode: boolean): Promise<string> {
  const sql = await database();
  const nonce = crypto.randomUUID();
  await sql.begin(async (tx) => {
    if (purpose === "payment") {
      await tx`delete from keyway_v2_signature_requests where user_id = ${user.id} and purpose = 'payment' and expires_at <= now()`;
      const [{ pending }] = await tx<Array<{ pending: number }>>`
        select count(*)::int as pending from keyway_v2_signature_requests where user_id = ${user.id} and purpose = 'payment'
      `;
      if (pending >= MAX_PENDING_PAYMENTS) throw new Error("Too many payments are waiting for approval. Try again in a moment");
    } else {
      await tx`delete from keyway_v2_signature_requests where user_id = ${user.id} and purpose = ${purpose}`;
    }
    await tx`
      insert into keyway_v2_signature_requests (user_id, purpose, nonce, request_digest, summary, requires_email_code, expires_at)
      values (${user.id}, ${purpose}, ${nonce}, ${digest}, ${tx.json(summary as never)}, ${requiresEmailCode}, ${new Date(Date.now() + REQUEST_TTL_MS)})
    `;
  });
  return nonce;
}

export type RequestRow = { requires_email_code: boolean; summary: { lines?: string[] } & Record<string, unknown> };

export async function loadRequest(user: User, purpose: Purpose, nonce: string, digest: string): Promise<RequestRow> {
  const sql = await database();
  const [row] = await sql<RequestRow[]>`
    select requires_email_code, summary from keyway_v2_signature_requests
    where user_id = ${user.id} and purpose = ${purpose} and nonce = ${nonce} and request_digest = ${digest} and expires_at > now()
  `;
  if (!row) throw new Error("Signing confirmation is invalid or expired");
  return row;
}

export async function consumeRequest(user: User, purpose: Purpose, nonce: string): Promise<void> {
  const sql = await database();
  const rows = await sql`delete from keyway_v2_signature_requests where user_id = ${user.id} and purpose = ${purpose} and nonce = ${nonce} returning 1`;
  if (!rows[0]) throw new Error("Signing confirmation is invalid or expired");
}

export async function sendCode(context: Pick<SigningContext, "user" | "appName" | "email" | "sendEmail" | "rateLimit">, purpose: Purpose, nonce: string, heading: string, lines: string[]): Promise<void> {
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

export async function verifyCode(user: User, purpose: Purpose, nonce: string, code: unknown): Promise<void> {
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

async function readDailyAmounts(user: User, connection?: Query): Promise<DailyAmounts> {
  const sql = connection ?? await database();
  const rows = await sql<Array<{ asset: string; amount: string }>>`
    select asset, amount::text as amount from keyway_v2_daily_amounts where user_id = ${user.id}
  `;
  return new Map(rows.map(({ asset, amount }) => [asset, BigInt(amount)]));
}

async function writeDailyAmount(user: User, asset: string, amount: bigint | null): Promise<void> {
  const sql = await database();
  if (amount === null) {
    await sql`delete from keyway_v2_daily_amounts where user_id = ${user.id} and asset = ${asset}`;
    return;
  }
  await sql`
    insert into keyway_v2_daily_amounts (user_id, asset, amount, updated_at)
    values (${user.id}, ${asset}, ${amount.toString()}, now())
    on conflict (user_id, asset) do update set amount = excluded.amount, updated_at = now()
  `;
}

export function parseThreshold(value: unknown): bigint | null {
  if (value === null) return null;
  if (typeof value !== "string" || !/^\d{1,40}$/.test(value)) throw new Error("The amount must be a whole number in the asset's smallest unit, or null to remove it");
  const parsed = BigInt(value);
  if (parsed <= 0n) throw new Error("The amount must be greater than zero");
  return parsed;
}

export function requiredNonce(value: unknown): string {
  if (typeof value !== "string" || !/^[0-9a-f-]{36}$/i.test(value)) throw new Error("A signing confirmation is required");
  return value;
}

function codeHash(nonce: string, code: string): string {
  return createHmac("sha256", nonce).update(code).digest("hex");
}

export function hashText(value: string): string {
  return Buffer.from(sha256(new TextEncoder().encode(value))).toString("hex");
}

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Missing server configuration: ${name}`);
  return value;
}
