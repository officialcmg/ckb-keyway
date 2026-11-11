import type { RecoveryBackup } from "../sdk/browser/recovery-backups.ts";
import { createHmac, randomInt, timingSafeEqual } from "node:crypto";
import * as ccc from "@ckb-ccc/core";
import { sha256 } from "@noble/hashes/sha2.js";
import type { User } from "./auth-user.ts";
import type { TransactionSql } from "postgres";
import { database, type DatabaseSql } from "./database.ts";
import { createConfirmationEmailTemplate } from "./email-template.ts";
import { formatCkbSignature, serializeTransaction, signAccountGroups, signingGroups, type SigningGroup } from "./funding-transaction.ts";
import { accountLocks, secp256k1Lock } from "../sdk/browser/account-lock.ts";
import { DEFAULT_DAILY_LIMIT_SHANNONS, SEND_LIMIT_OFFER_MINIMUM, settingsFromDailyAmounts, type SendLimitHead } from "../sdk/browser/send-limits.ts";
import { loadLitAction } from "./lit-actions.ts";
import { LIT_ACTION_CIDS } from "./lit-config.ts";
import { signCkbDigest } from "./lit.ts";
import { litPolicyEnabled, parseLitEmailCode, policySendCode, policySignMessage, policySignTransaction, type LitEmailCode } from "./lit-policy.ts";
import { listPendingTransactions, nodeStatus, recordPendingTransaction } from "./pending-transactions.ts";
import { applySendLimitRecord, buildSendLimitChange, buildSendLimitGenesis, LIT_CODE_KINDS, planSendLimits, sendLimitHead, withFingerprint } from "./send-limits.ts";
import { recoverPkpPublicKey } from "./pkp-identity.ts";
import { sendSecurityAlert } from "./security-alerts.ts";
import { formatCkb, previewGeneralTransaction, previewSummaryLines, type ValidatedTransaction } from "./transaction-policy.ts";
import type { ReadyWallet } from "./user-wallet.ts";

export type Purpose = "transaction" | "message" | "settings" | "payment" | "recovery";

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
  /** The CKB client and broadcast for transactions the server builds itself (send-limit settings); tests replace them. */
  client?: ccc.Client;
  broadcast?: (transaction: ccc.Transaction) => Promise<ccc.Hex>;
};

// An approval waits this long for the user; sending a code moves its expiry to the code's, so it always outlives it.
const REQUEST_TTL_MS = 5 * 60_000;
const CODE_TTL_MS = 10 * 60_000;
export const REQUEST_EXPIRED = "This request expired. Start again.";
const MAX_CODE_ATTEMPTS = 5;
// Wrong six-digit codes in 24 hours, across every code sent. Each code allows five tries and codes can be sent again,
// so without this the tries add up day after day. Only someone signed in can make them, and they are counted per
// session, so a stolen session can't use up the owner's own: a new session needs a login code from the inbox.
const MAX_CODE_FAILURES_PER_SESSION = 20;
const MAX_CODE_FAILURES_PER_USER = 60;
const CODE_FAILURES_MESSAGE = "Too many wrong email codes today. Try again tomorrow";
const MAX_MESSAGE_BYTES = 4096;

/** Transactions: preview, request-email-code, sign. */
export async function transactionSigning(context: SigningContext, body: Record<string, unknown>): Promise<unknown> {
  const preview = context.preview ?? previewGeneralTransaction;
  const validated = await preview(context.wallet, body.transaction);
  const digest = hashText(JSON.stringify(serializeTransaction(validated.transaction)));
  // With the policy Action signing, Lit enforces the send limits itself; the server plans with the same rules.
  const policy = !context.signDigest && litPolicyEnabled();

  if (body.operation === "preview") {
    await limit(context, "sign", { max: 10, window: 60 });
    const plan = policy ? await planSendLimits(context.wallet, validated.transaction) : undefined;
    const litCode = Boolean(plan && LIT_CODE_KINDS.includes(plan.limits));
    // Lit's rule, or the server's own (which also counts Fiber payments): either one asks for the code.
    const requiresEmailCode = Boolean(plan?.needsCode) || await outflowNeedsEmailCode(context.user, transactionOutflow(validated));
    const summary = { lines: previewSummaryLines(validated.preview), ...(plan ? { sendLimits: { kind: plan.limits, litCode, ...(plan.record ? { record: plan.record, recordIndex: plan.recordIndex } : {}) } } : {}) };
    const confirmationNonce = await issueRequest(context.user, "transaction", digest, summary, requiresEmailCode);
    return { preview: validated.preview, confirmationNonce, requiresEmailCode };
  }
  const nonce = requiredNonce(body.confirmationNonce);
  if (body.operation === "request-email-code") {
    const request = await loadRequest(context.user, "transaction", nonce, digest);
    if (!request.requires_email_code) throw new Error("This transaction doesn't need an email code");
    const limits = sendLimitsOf(request);
    if (limits?.litCode) {
      // The Action makes the code and emails it to the address bound in the account's send-limit cell.
      await codeLimit(context);
      applySendLimitRecord(validated.transaction, limits);
      const sent = await policySendCode(validated.transaction, context.wallet, { email: await context.email(), appName: context.appName });
      await recordLitCode(context.user, "transaction", nonce, { litTicket: sent.ticket });
      return { sent: true, sentTo: sent.sentTo, codeLength: 8 };
    }
    const sentTo = await sendCode(context, "transaction", nonce, "Confirm a transaction", request.summary.lines ?? []);
    return { sent: true, sentTo };
  }
  if (body.operation !== "sign") throw new Error("A valid signing operation is required");
  const request = await loadRequest(context.user, "transaction", nonce, digest);
  // Checked again here, because the threshold or the day's total may have changed since the preview.
  if (!request.requires_email_code && await outflowNeedsEmailCode(context.user, transactionOutflow(validated))) {
    throw new Error("This transaction now needs an email code. Review it again");
  }
  const limits = sendLimitsOf(request);
  let emailCode: LitEmailCode | undefined;
  if (request.requires_email_code && limits?.litCode) {
    emailCode = parseLitEmailCode(body.emailCode, request.summary.litTicket);
    await countLitCodeAttempt(context.user, "transaction", nonce);
  } else if (request.requires_email_code) {
    await verifyCode(context.user, "transaction", nonce, body.emailCode);
    await consumeRequest(context.user, "transaction", nonce);
  } else {
    await consumeRequest(context.user, "transaction", nonce);
  }
  // Counted before it is signed, under the per-user lock, so an overlapping send or payment sees it; without a code,
  // checked once more under that lock.
  const release = await reserveOutflow(context.user, transactionOutflow(validated), request.requires_email_code, "transaction");
  let signed: ccc.Transaction;
  try {
    await context.recordSigning(context.user.id);
    if (limits) applySendLimitRecord(validated.transaction, limits);
    signed = await signGroups(context, validated.transaction, validated.groups, validated.signer.client, emailCode ? { email: await context.email(), emailCode } : {});
  } catch (error) {
    await release();
    // Lit counted something the preview didn't see yet (another send landed in between).
    if (!emailCode && error instanceof Error && /eight-digit code/.test(error.message)) throw new Error("This transaction now needs an email code. Review it again");
    throw error;
  }
  // A mistyped Lit code fails above and leaves the request for another try; a signature uses it up.
  if (emailCode) await consumeRequest(context.user, "transaction", nonce);
  await recordPendingTransaction(context.user.id, signed);
  return { transaction: serializeTransaction(signed) };
}

/** Whether Lit will ask for its code before signing this channel funding (the account has send limits on). */
export async function fundingNeedsLitCode(wallet: ReadyWallet, transaction: ccc.Transaction): Promise<boolean> {
  if (!litPolicyEnabled()) return false;
  const plan = await planSendLimits(wallet, transaction);
  return plan.needsCode && LIT_CODE_KINDS.includes(plan.limits);
}

/** A funding approval that needs the Lit code: an ordinary transaction request, bound to the funding's bytes. */
export function issueFundingCodeRequest(user: User, serialized: string): Promise<string> {
  return issueRequest(user, "transaction", hashText(serialized), { funding: true, sendLimits: { kind: "unchained", litCode: true } }, true);
}

type FundingCodeContext = Pick<SigningContext, "user" | "wallet" | "appName" | "email" | "rateLimit">;

async function fundingRequest(user: User, nonce: string, serialized: string): Promise<RequestRow | undefined> {
  try {
    const request = await loadRequest(user, "transaction", requiredNonce(nonce), hashText(serialized));
    return request.summary.funding === true ? request : undefined;
  } catch {
    return undefined;
  }
}

/** Has the Action email its code for a funding approval. */
export async function sendFundingCode(context: FundingCodeContext, nonce: string, serialized: string, transaction: ccc.Transaction): Promise<unknown> {
  const request = await fundingRequest(context.user, nonce, serialized);
  if (!request) throw new Error("This channel opening doesn't need an email code");
  await codeLimit(context);
  const sent = await policySendCode(transaction, context.wallet, { email: await context.email(), appName: context.appName });
  await recordLitCode(context.user, "transaction", nonce, { litTicket: sent.ticket });
  return { sent: true, sentTo: sent.sentTo, codeLength: 8 };
}

/**
 * For a funding approval that needs the Lit code: the code to pass to the Action, and a way to use up the request
 * once it has signed. Undefined for an ordinary funding approval.
 */
export async function fundingCode(context: FundingCodeContext, nonce: string, serialized: string, code: unknown): Promise<{ email: string; emailCode: LitEmailCode; consume: () => Promise<void> } | undefined> {
  const request = await fundingRequest(context.user, nonce, serialized);
  if (!request) return undefined;
  const emailCode = parseLitEmailCode(code, request.summary.litTicket);
  await countLitCodeAttempt(context.user, "transaction", nonce);
  return { email: await context.email(), emailCode, consume: () => consumeRequest(context.user, "transaction", nonce) };
}

type SendLimitsSummary = { kind: string; litCode: boolean; record?: ccc.Hex; recordIndex?: number };

function sendLimitsOf(request: RequestRow): SendLimitsSummary | undefined {
  const value = request.summary.sendLimits as SendLimitsSummary | undefined;
  return value && typeof value === "object" ? value : undefined;
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
 * Email confirmation is off until the user sets a daily amount. Once one is set, the emailed code is needed
 * when that asset's 24-hour total (signed transactions and Fiber payments together) reaches its amount, so
 * splitting a transfer doesn't avoid it. An asset without an amount of its own (a token, an NFT, any cell
 * KeyWay can't read) has no limit, as in the send-limit cell KeyWay writes (tokens unlimited).
 */
export async function outflowNeedsEmailCode(user: User, outflow: Outflow, connection?: Query): Promise<boolean> {
  const amounts = await readDailyAmounts(user, connection);
  const ckb = dailyAllowance(amounts, "ckb");
  if (ckb !== "unlimited" && outflow.shannons > 0n && await recentOutflow(user, outflow.id, connection) + outflow.shannons >= ckb) return true;
  for (const token of outflow.tokens) {
    const limit = dailyAllowance(amounts, token.asset);
    if (limit !== "unlimited" && await recentTokenOutflow(user, outflow.id, token.asset, connection) + token.amount >= limit) return true;
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
 * Counts an outflow before the money moves, under a per-user lock, so overlapping payments and transactions can't
 * each slip under the amount. Unless the user already confirmed by email, it refuses once an amount is reached.
 * Returns a function that removes the entry if the payment or signature then fails. An outflow that was already
 * counted (the same transaction signed before), or that another attempt counted again since, stays counted.
 */
export async function reserveOutflow(user: User, outflow: Outflow, emailConfirmed: boolean, what: "payment" | "transaction" = "payment"): Promise<() => Promise<void>> {
  const sql = await database();
  const reservedAt = await sql.begin(async (tx) => {
    await tx`select pg_advisory_xact_lock(hashtextextended(${`keyway-outflow:${user.id}`}, 0))`;
    if (!emailConfirmed && await outflowNeedsEmailCode(user, outflow, tx)) {
      throw new Error(`This ${what} now needs an email code. Review it again`);
    }
    const [{ at, counted }] = await tx<Array<{ at: string; counted: boolean }>>`
      select now()::text as at,
        exists(select 1 from keyway_v2_signed_outflows where user_id = ${user.id} and transaction_hash = ${outflow.id} and signed_at > now() - ${OUTFLOW_WINDOW}::interval)
        or exists(select 1 from keyway_v2_token_outflows where user_id = ${user.id} and outflow_id = ${outflow.id} and signed_at > now() - ${OUTFLOW_WINDOW}::interval) as counted
    `;
    await recordOutflow(user, outflow, tx);
    return counted ? undefined : at;
  });
  return async () => {
    if (reservedAt === undefined) return;
    // Rows written by this reservation only: a later attempt that counted the same outflow rewrote signed_at.
    await sql`delete from keyway_v2_signed_outflows where user_id = ${user.id} and transaction_hash = ${outflow.id} and signed_at = ${reservedAt}::text::timestamptz`;
    await sql`delete from keyway_v2_token_outflows where user_id = ${user.id} and outflow_id = ${outflow.id} and signed_at = ${reservedAt}::text::timestamptz`;
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
  const signature = !context.signDigest && litPolicyEnabled()
    ? await policySignMessage(context.wallet, message)
    : await sign(context, ccc.messageHashCkbSecp256k1(message));
  return { signature, identity: context.wallet.litPublicKey };
}

/**
 * The user's daily email-confirmation amounts, one per asset. Strengthening (a lower amount, or protecting
 * something that wasn't) applies at once; weakening (a higher amount, removing one, or turning email
 * confirmation off) needs a code from the user's inbox.
 */
export async function signingSettings(context: SigningContext, body: Record<string, unknown>): Promise<unknown> {
  const current = await readDailyAmounts(context.user);
  const view = (amounts: DailyAmounts) => ({
    dailyAmounts: Object.fromEntries([...amounts].map(([asset, amount]) => [asset, amount.toString()])),
  });
  if (body.operation === "get") return view(current);
  if (body.operation !== "set-daily-amount") throw new Error("A valid settings operation is required");
  const change = { asset: parseAsset(body.asset), amount: parseThreshold(body.amount) };
  const next = new Map(current);
  if (change.amount === null) next.delete(change.asset); else next.set(change.asset, change.amount);
  if (!context.signDigest && litPolicyEnabled()) {
    const onChain = await sendLimitSettings(context, body, current, next, change);
    if (onChain) return { ...view(onChain.amounts), enforcedByLit: true, ...onChain.response };
  }
  // Below: the amounts live on the server only (no policy signer, or the account can't make the cell yet).
  const serverOnly = !context.signDigest && litPolicyEnabled() ? { enforcedByLit: false } : {};
  if (!weakens(current, next)) {
    await writeDailyAmount(context.user, change.asset, change.amount);
    return { ...view(next), ...serverOnly };
  }
  const digest = hashText(`daily-amount:${change.asset}:${change.amount?.toString() ?? "off"}`);
  if (body.confirmationNonce === undefined) {
    const lines = [
      `Email confirmation for ${assetName(change.asset)}: ${describeAmount(current, change.asset)}`,
      `Change: ${next.size === 0 ? "turn email confirmation off" : describeAmount(next, change.asset)}`,
    ];
    // Checked before the new request replaces the old one, so a refused resend leaves the last code usable.
    await codeLimit(context);
    const confirmationNonce = await issueRequest(context.user, "settings", digest, { lines }, true);
    const sentTo = await sendCode(context, "settings", confirmationNonce, "Confirm a security change", lines, { limited: true });
    return { requiresEmailCode: true, confirmationNonce, sentTo, ...serverOnly };
  }
  const nonce = requiredNonce(body.confirmationNonce);
  await loadRequest(context.user, "settings", nonce, digest);
  await verifyCode(context.user, "settings", nonce, body.emailCode);
  await consumeRequest(context.user, "settings", nonce);
  await writeDailyAmount(context.user, change.asset, change.amount);
  return { ...view(next), ...serverOnly };
}

/**
 * The daily amounts as the account's send-limit cell, which Lit enforces. Turning limits on creates the cell (always
 * with the Lit code, which binds the email); later changes spend it, with the code only when they weaken it. The
 * transaction is built, signed and sent here. Returns undefined when the account can't afford the cell yet, so the
 * amounts stay on the server alone until it can.
 */
async function sendLimitSettings(
  context: SigningContext,
  body: Record<string, unknown>,
  current: DailyAmounts,
  next: DailyAmounts,
  change: { asset: string; amount: bigint | null },
): Promise<{ amounts: DailyAmounts; response?: Record<string, unknown> } | undefined> {
  const client = context.client ?? new ccc.ClientPublicTestnet();
  const digest = hashText(`daily-amount:${change.asset}:${change.amount?.toString() ?? "off"}`);
  const settings = settingsFromDailyAmounts(next, new Uint8Array(32));
  if (body.confirmationNonce === undefined) {
    const pending = await listPendingTransactions(context.user.id, nodeStatus(client));
    const head = await sendLimitHead(client, context.wallet, pending);
    // Cells the account's pending sends already spent are never picked again (the same as a client does).
    for (const { transaction, status } of pending) if (status === "pending" || status === "proposed") await client.cache.markTransactions(transaction);
    let transaction: ccc.Transaction;
    try {
      transaction = head ? await buildSendLimitChange(client, context.wallet, head, settings) : await buildSendLimitGenesis(client, context.wallet, settings);
    } catch (error) {
      if (!head && error instanceof Error && /plain CKB cell|Insufficient CKB|insufficient/i.test(error.message)) return undefined;
      if (!head && error instanceof Error && /pending send/.test(error.message)) throw error;
      throw error;
    }
    const plan = await planSendLimits(context.wallet, transaction);
    applySendLimitRecord(transaction, plan);
    if (!plan.needsCode) {
      await signAndSendSettings(context, client, transaction, {});
      await writeDailyAmount(context.user, change.asset, change.amount);
      return { amounts: next };
    }
    const lines = [
      head ? "Change your daily send limits" : "Turn on daily send limits, enforced by KeyWay's Lit Action",
      `CKB: ${describeAmount(current, "ckb")} → ${describeAmount(next, "ckb")}`,
      ...(change.asset === "ckb" ? [] : [`${assetName(change.asset)}: ${describeAmount(current, change.asset)} → ${describeAmount(next, change.asset)}`]),
    ];
    await codeLimit(context);
    const confirmationNonce = await issueRequest(context.user, "settings", digest, { lines, settingsTransaction: serializeTransaction(transaction) }, true);
    const sent = await policySendCode(transaction, context.wallet, { email: await context.email(), appName: context.appName });
    await recordLitCode(context.user, "settings", confirmationNonce, { litTicket: sent.ticket, ...(sent.fingerprint ? { litFingerprint: sent.fingerprint } : {}) });
    return { amounts: current, response: { requiresEmailCode: true, confirmationNonce, sentTo: sent.sentTo, codeLength: 8 } };
  }
  const nonce = requiredNonce(body.confirmationNonce);
  const request = await loadRequest(context.user, "settings", nonce, digest);
  // A request made while the account couldn't afford the cell carries no transaction; the server's code applies.
  if (!request.summary.settingsTransaction) return undefined;
  const transaction = ccc.Transaction.from(request.summary.settingsTransaction as ccc.TransactionLike);
  if (typeof request.summary.litFingerprint === "string") withFingerprint(transaction, request.summary.litFingerprint);
  const emailCode = parseLitEmailCode(body.emailCode, request.summary.litTicket);
  await countLitCodeAttempt(context.user, "settings", nonce);
  await signAndSendSettings(context, client, transaction, { email: await context.email(), emailCode });
  await consumeRequest(context.user, "settings", nonce);
  await writeDailyAmount(context.user, change.asset, change.amount);
  return { amounts: next };
}

async function signAndSendSettings(context: SigningContext, client: ccc.Client, transaction: ccc.Transaction, options: { email?: string; emailCode?: LitEmailCode }): Promise<void> {
  const locks = await accountLocks(client, context.wallet.litPublicKey, context.wallet.recovery);
  const groups = signingGroups(locks, await Promise.all(transaction.inputs.map((input) => input.getCell(client))));
  await context.recordSigning(context.user.id);
  const signed = await signGroups(context, transaction, groups, client, options);
  await recordPendingTransaction(context.user.id, signed);
  try {
    await (context.broadcast ?? ((tx: ccc.Transaction) => client.sendTransaction(tx, "passthrough")))(signed);
  } catch (error) {
    // The same transaction already in the pool (a repeated request built it again) is what we wanted.
    if (!(error instanceof Error && /PoolRejectedDuplicatedTransaction/.test(error.message))) throw error;
  }
}

/**
 * How much of an asset can leave in 24 hours without the emailed code: its own amount, or unlimited without one
 * (CKB, a token, an NFT or any cell KeyWay can't read). The Lit Action reads a cell with tokens unlimited the same way.
 */
export function dailyAllowance(amounts: DailyAmounts, asset: string): bigint | "unlimited" {
  return amounts.get(asset) ?? "unlimited";
}

/** A change weakens protection if any asset can then send more: an amount raised or removed. */
export function weakens(before: DailyAmounts, after: DailyAmounts): boolean {
  const assets = new Set(["ckb", ...before.keys(), ...after.keys()]);
  return [...assets].some((asset) => {
    const was = dailyAllowance(before, asset);
    const now = dailyAllowance(after, asset);
    return now === "unlimited" ? was !== "unlimited" : was !== "unlimited" && now > was;
  });
}

function assetName(asset: string): string {
  return asset === "ckb" ? "CKB" : `token ${asset.slice(0, 10)}…${asset.slice(-6)}`;
}

function describeAmount(amounts: DailyAmounts, asset: string): string {
  const value = dailyAllowance(amounts, asset);
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
  return signGroups(context, validated.transaction, validated.groups, validated.signer.client);
}

/**
 * Signs the account's lock groups in a transaction: with the policy Action (the whole transaction, which it
 * checks itself) once LIT_SIGNER is "policy", otherwise digest by digest. A test's `signDigest` always wins.
 */
export async function signGroups(
  context: Pick<SigningContext, "wallet" | "signDigest">,
  transaction: ccc.Transaction,
  groups: SigningGroup[],
  client: ccc.Client,
  options: { enableTransactionHash?: string; email?: string; emailCode?: LitEmailCode; previousListRecord?: ccc.Hex; backups?: RecoveryBackup[]; missingGroup?: string } = {},
): Promise<ccc.Transaction> {
  if (!context.signDigest && litPolicyEnabled()) {
    if (groups.length === 0) throw new Error(options.missingGroup ?? "Transaction has no KeyWay signing group");
    return policySignTransaction(transaction, groups, client, context.wallet, options);
  }
  return signAccountGroups(transaction, groups, client, (digest) => sign(context, digest), options.missingGroup);
}

/** Signs a digest the backend computed itself, then checks the recovered key before releasing it. */
export async function sign(context: Pick<SigningContext, "wallet" | "signDigest">, digest: ccc.Hex): Promise<ccc.Hex> {
  if (context.signDigest) return context.signDigest(digest, context.wallet);
  const signature = await signCkbDigest(digest, context.wallet.litPkpId, {
    apiKey: requiredEnv("LIT_USAGE_API_KEY"),
    actionCid: LIT_ACTION_CIDS["sign-ckb-digest"],
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
  const [row] = await sql<Array<RequestRow & { request_digest: string }>>`
    select requires_email_code, summary, request_digest from keyway_v2_signature_requests
    where user_id = ${user.id} and purpose = ${purpose} and nonce = ${nonce} and expires_at > now()
  `;
  if (!row) throw new Error(REQUEST_EXPIRED);
  if (row.request_digest !== digest) throw new Error("Signing confirmation is invalid or expired");
  return { requires_email_code: row.requires_email_code, summary: row.summary };
}

export async function consumeRequest(user: User, purpose: Purpose, nonce: string): Promise<void> {
  const sql = await database();
  const rows = await sql`delete from keyway_v2_signature_requests where user_id = ${user.id} and purpose = ${purpose} and nonce = ${nonce} returning 1`;
  if (!rows[0]) throw new Error(REQUEST_EXPIRED);
}

/**
 * Emails a new code for a pending request and returns the address it went to. Each send replaces the code,
 * resets its attempts and gives the code, and the request with it, the full code lifetime again; the per-user
 * email limit bounds how often that can happen.
 */
export async function sendCode(context: Pick<SigningContext, "user" | "appName" | "email" | "sendEmail" | "rateLimit">, purpose: Purpose, nonce: string, heading: string, lines: string[], options: { limited?: boolean } = {}): Promise<string> {
  const sql = await database();
  if (overFailureLimit(await codeFailures(sql, context.user))) throw new Error(CODE_FAILURES_MESSAGE);
  if (!options.limited) await codeLimit(context);
  const code = randomInt(0, 1_000_000).toString().padStart(6, "0");
  const rows = await sql`
    update keyway_v2_signature_requests
    set email_code_hash = ${codeHash(nonce, code)}, email_code_expires_at = now() + ${`${CODE_TTL_MS} milliseconds`}::interval, email_attempts = 0,
      expires_at = greatest(expires_at, now() + ${`${CODE_TTL_MS} milliseconds`}::interval)
    where user_id = ${context.user.id} and purpose = ${purpose} and nonce = ${nonce} and expires_at > now() returning 1
  `;
  if (!rows[0]) throw new Error(REQUEST_EXPIRED);
  const to = await context.email();
  const template = createConfirmationEmailTemplate(context.appName, code, heading, lines);
  await context.sendEmail(to, template, `keyway-step-up/${nonce}/${Date.now()}`);
  return to;
}

/**
 * Records that the policy Action emailed a code for a pending request: the ticket (and any binding) go in the
 * request's summary, and the request gets the code's lifetime and a fresh attempt count. The code itself never
 * reaches this server; the Action checks it when signing.
 */
export async function recordLitCode(user: User, purpose: Purpose, nonce: string, details: Record<string, unknown>): Promise<void> {
  const sql = await database();
  const rows = await sql`
    update keyway_v2_signature_requests
    set summary = summary || ${sql.json(details as never)}, email_code_hash = null,
      email_code_expires_at = now() + ${`${CODE_TTL_MS} milliseconds`}::interval, email_attempts = 0,
      expires_at = greatest(expires_at, now() + ${`${CODE_TTL_MS} milliseconds`}::interval)
    where user_id = ${user.id} and purpose = ${purpose} and nonce = ${nonce} and expires_at > now() returning 1
  `;
  if (!rows[0]) throw new Error(REQUEST_EXPIRED);
}

/** Counts one try of a Lit-sent code, so this server still stops a browser after five wrong codes. */
export async function countLitCodeAttempt(user: User, purpose: Purpose, nonce: string): Promise<void> {
  const sql = await database();
  const [row] = await sql<Array<{ email_attempts: number }>>`
    update keyway_v2_signature_requests set email_attempts = email_attempts + 1
    where user_id = ${user.id} and purpose = ${purpose} and nonce = ${nonce} and expires_at > now() and email_code_expires_at > now()
    returning email_attempts
  `;
  if (!row) throw new Error("The email code has expired. Request a new one");
  if (row.email_attempts > MAX_CODE_ATTEMPTS) throw new Error("Too many wrong codes. Request a new one");
}

/** Up to 5 emailed codes per user every 10 minutes, across all purposes. */
export async function codeLimit(context: Pick<SigningContext, "user" | "rateLimit">): Promise<void> {
  const allowed = await context.rateLimit(`step-up-email:${context.user.id}`, { max: 5, window: 600 });
  if (!allowed.allowed) throw new Error(`Too many codes sent. Try again in ${waitText(allowed.retryAfter ?? 600)}`);
}

function waitText(seconds: number): string {
  if (seconds < 90) return `${Math.max(1, Math.ceil(seconds))} seconds`;
  return `${Math.ceil(seconds / 60)} minutes`;
}

export async function verifyCode(user: User, purpose: Purpose, nonce: string, code: unknown): Promise<void> {
  if (typeof code !== "string" || !/^\d{6}$/.test(code)) throw new Error("Enter the six-digit code from your email");
  const sql = await database();
  // One check at a time per user, so the day's wrong codes are counted before the next one is compared. Another
  // check already running is refused rather than waited for, so checks never queue on pool connections.
  const outcome = await sql.begin(async (tx) => {
    const query = tx as unknown as DatabaseSql;
    const [{ locked }] = await query<Array<{ locked: boolean }>>`select pg_try_advisory_xact_lock(hashtextextended(${`step-up-failures:${user.id}`}, 0)) as locked`;
    if (!locked) return "busy";
    if (overFailureLimit(await codeFailures(query, user))) return "failures";
    const [row] = await query<Array<{ email_code_hash: string | null; email_attempts: number }>>`
      update keyway_v2_signature_requests set email_attempts = email_attempts + 1
      where user_id = ${user.id} and purpose = ${purpose} and nonce = ${nonce} and expires_at > now() and email_code_expires_at > now()
      returning email_code_hash, email_attempts
    `;
    if (!row?.email_code_hash) return "expired";
    if (row.email_attempts > MAX_CODE_ATTEMPTS) return "attempts";
    const expected = Buffer.from(row.email_code_hash, "hex");
    const supplied = Buffer.from(codeHash(nonce, code), "hex");
    if (expected.length === supplied.length && timingSafeEqual(expected, supplied)) return "ok";
    await query`insert into keyway_v2_step_up_failures (user_id, session_id) values (${user.id}, ${user.sessionId ?? ""})`;
    const failures = await codeFailures(query, user);
    return failures.session === MAX_CODE_FAILURES_PER_SESSION || failures.user === MAX_CODE_FAILURES_PER_USER ? "wrong-last" : "wrong";
  });
  if (outcome === "ok") return;
  if (outcome === "busy") throw new Error("Another email code check is in progress. Try again in a moment");
  if (outcome === "failures") throw new Error(CODE_FAILURES_MESSAGE);
  if (outcome === "expired") throw new Error("The email code has expired. Request a new one");
  if (outcome === "attempts") throw new Error("Too many wrong codes. Request a new one");
  if (outcome === "wrong-last") void sendSecurityAlert("step_up_failure_limit", { userId: user.id });
  // Failures older than a day count for nothing; a few go with each wrong code.
  await sql`delete from keyway_v2_step_up_failures where id in (
    select id from keyway_v2_step_up_failures where created_at < now() - interval '1 day' limit 100
  )`;
  throw new Error("That email code isn't right");
}

/** Wrong codes in the last day: from this session, and from all of the user's sessions. */
async function codeFailures(sql: DatabaseSql, user: User): Promise<{ session: number; user: number }> {
  const [row] = await sql<Array<{ session: number; user: number }>>`
    select count(*) filter (where session_id = ${user.sessionId ?? ""})::int as session, count(*)::int as user
    from keyway_v2_step_up_failures where user_id = ${user.id} and created_at > now() - interval '1 day'
  `;
  return row;
}

function overFailureLimit(failures: { session: number; user: number }): boolean {
  return failures.session >= MAX_CODE_FAILURES_PER_SESSION || failures.user >= MAX_CODE_FAILURES_PER_USER;
}

/**
 * Send limits are on by default: an account with the policy signer, no send-limit cell, no recovery (it can't make
 * the cell yet) and enough plain CKB for the cell is offered them on its next send, starting from its own CKB
 * amount if it set one, else the default. Undefined when there is nothing to offer.
 */
export async function sendLimitOffer(
  user: User,
  wallet: Pick<ReadyWallet, "litPublicKey" | "recovery">,
  head: SendLimitHead | undefined,
  client: ccc.Client,
): Promise<{ ckb: bigint } | undefined> {
  if (!litPolicyEnabled() || head || wallet.recovery) return undefined;
  const secp = await secp256k1Lock(client, wallet.litPublicKey);
  const plain = await client.getCellsCapacity({ script: secp, scriptType: "lock", scriptSearchMode: "exact", filter: { scriptLenRange: [0, 1], outputDataLenRange: [0, 1] } });
  if (plain < SEND_LIMIT_OFFER_MINIMUM) return undefined;
  const amounts = await readDailyAmounts(user);
  return { ckb: amounts.get("ckb") ?? DEFAULT_DAILY_LIMIT_SHANNONS };
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
