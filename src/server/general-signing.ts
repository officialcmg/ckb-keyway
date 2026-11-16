import type { RecoveryBackup } from "../sdk/browser/recovery-backups.ts";
import { createHmac, randomInt, timingSafeEqual } from "node:crypto";
import * as ccc from "@ckb-ccc/core";
import { sha256 } from "@noble/hashes/sha2.js";
import type { User } from "./auth-user.ts";
import type { TransactionSql } from "postgres";
import { database, type DatabaseSql } from "./database.ts";
import { createConfirmationEmailTemplate } from "./email-template.ts";
import { serializeTransaction, signAccountGroups, signingGroups, type SigningGroup } from "./funding-transaction.ts";
import { accountLocks, secp256k1Lock } from "../sdk/browser/account-lock.ts";
import {
  decodeSendLimitSettings,
  DEFAULT_DAILY_LIMIT_SHANNONS,
  isSendLimitCell,
  MAX_SEND_LIMIT_TOKENS,
  SEND_LIMIT_MAGIC,
  SEND_LIMIT_OFFER_MINIMUM,
  SEND_LIMIT_UNLIMITED,
  settingsFromDailyAmounts,
  type SendLimitHead,
  type SendLimitSettings,
} from "../sdk/browser/send-limits.ts";
import { parseLitEmailCode, policySendCode, policySignMessage, policySignTransaction, type LitEmailCode } from "./lit-policy.ts";
import { listPendingTransactions, nodeStatus, recordPendingTransaction } from "./pending-transactions.ts";
import { applySendLimitRecord, buildSendLimitChange, buildSendLimitGenesis, LIT_CODE_KINDS, planSendLimits, sendLimitHead, withFingerprint } from "./send-limits.ts";
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
const MAX_MESSAGE_BYTES = 4096;

/** Transactions: preview, request-email-code, sign. */
export async function transactionSigning(context: SigningContext, body: Record<string, unknown>): Promise<unknown> {
  const preview = context.preview ?? previewGeneralTransaction;
  const validated = await preview(context.wallet, body.transaction);
  await refuseSendLimitChange(context.wallet, validated);
  const digest = hashText(JSON.stringify(serializeTransaction(validated.transaction)));
  // With the policy Action signing, Lit enforces the send limits itself; the server plans with the same rules.
  const policy = !context.signDigest;

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

/**
 * The account's send limits change only through the settings operation, which keeps the server's copy (the only one
 * hosted Fiber payments check) in step with the cell. A transaction that makes the account's send-limit cell, or
 * gives it other amounts, isn't signed here: the Lit Action would sign a tightening without a code, and the server's
 * amounts would stay looser than the chain's. Chaining on the cell unchanged, as every send does, is fine.
 */
async function refuseSendLimitChange(wallet: ReadyWallet, validated: ValidatedTransaction): Promise<void> {
  const { transaction } = validated;
  // Only send-limit data needs the account's lock looked up.
  const outputs = transaction.outputs.map((output, index) => ({ output, data: ccc.hexFrom(transaction.outputsData[index] ?? "0x") })).filter(({ data }) => data.startsWith(SEND_LIMIT_MAGIC));
  if (outputs.length === 0) return;
  const client = validated.signer.client;
  const secp = await secp256k1Lock(client, wallet.litPublicKey);
  const made = outputs.filter(({ output, data }) => isSendLimitCell(output, data, secp));
  if (made.length === 0) return;
  const spent = (await Promise.all(transaction.inputs.map((input) => input.getCell(client))))
    .filter((cell): cell is ccc.Cell => Boolean(cell && isSendLimitCell(cell.cellOutput, cell.outputData, secp)));
  const unchanged = made.length === 1 && spent.length === 1 && made[0].output.type!.eq(spent[0].cellOutput.type!)
    && made[0].data === ccc.hexFrom(spent[0].outputData);
  if (!unchanged) throw new Error("Send limits change only through KeyWay's settings, not in a transaction");
}

/** Whether Lit will ask for its code before signing this channel funding (the account has send limits on). */
export async function fundingNeedsLitCode(wallet: ReadyWallet, transaction: ccc.Transaction): Promise<boolean> {
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
export type Outflow = { id: string; shannons: bigint; tokens: Array<{ asset: string; amount: bigint; perCell?: true }> };

/** Daily amounts by asset: "ckb", or a token's type script hash. Empty means email confirmation is off. */
export type DailyAmounts = Map<string, bigint>;

/**
 * Email confirmation is off until the user sets a daily amount. Once one is set, the emailed code is needed
 * when that asset's 24-hour total (signed transactions and Fiber payments together) reaches its amount, so
 * splitting a transfer doesn't avoid it. An asset without an amount of its own (a token, an NFT, any cell
 * KeyWay can't read) has no limit, as in the send-limit cell KeyWay writes (tokens unlimited). An asset counted per
 * cell (one whose amounts KeyWay can't read) always needs the code once it has an amount, as in the policy Action:
 * a single cell can hold its whole balance.
 */
export async function outflowNeedsEmailCode(user: User, outflow: Outflow, connection?: Query): Promise<boolean> {
  const amounts = await readDailyAmounts(user, connection);
  const ckb = dailyAllowance(amounts, "ckb");
  if (ckb !== "unlimited" && outflow.shannons > 0n && await recentOutflow(user, outflow.id, connection) + outflow.shannons >= ckb) return true;
  for (const token of outflow.tokens) {
    const limit = dailyAllowance(amounts, token.asset);
    if (limit === "unlimited") continue;
    if (token.perCell || await recentTokenOutflow(user, outflow.id, token.asset, connection) + token.amount >= limit) return true;
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
  const signature = !context.signDigest
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
  if (body.operation === "get") return dailyAmountsView(await readDailyAmounts(context.user));
  if (body.operation !== "set-daily-amount") throw new Error("A valid settings operation is required");
  // A change can sign and send a send-limit transaction and look up the chain, so it is rate limited, in a bucket of
  // its own: signing requests from apps can't use it up and keep the user from tightening their amounts.
  await limit(context, "settings", { max: 10, window: 60 });
  return setDailyAmount(context, body);
}

function dailyAmountsView(amounts: DailyAmounts) {
  return { dailyAmounts: Object.fromEntries([...amounts].map(([asset, amount]) => [asset, amount.toString()])) };
}

async function setDailyAmount(context: SigningContext, body: Record<string, unknown>): Promise<unknown> {
  const current = await readDailyAmounts(context.user);
  const view = dailyAmountsView;
  const change = { asset: parseAsset(body.asset), amount: parseThreshold(body.amount) };
  const next = new Map(current);
  if (change.amount === null) next.delete(change.asset); else next.set(change.asset, change.amount);
  refuseUnencodable(next, change);
  let version: bigint | undefined;
  if (!context.signDigest) {
    const onChain = await sendLimitSettings(context, body, current, next, change);
    if (onChain && "serverOnly" in onChain) version = onChain.serverOnly;
    else if (onChain) return { ...view(onChain.amounts), enforcedByLit: true, ...onChain.response };
  }
  // Below: the amounts live on the server only (the account can't make the cell yet, or a test signs locally).
  const serverOnly = !context.signDigest ? { enforcedByLit: false } : {};
  if (sameAmounts(current, next)) return { ...view(current), ...serverOnly };
  if (!weakens(current, next)) {
    await writeDailyAmount(context.user, change.asset, change.amount, "lower");
    return { ...view(await readDailyAmounts(context.user)), ...serverOnly };
  }
  const digest = hashText(`daily-amount:${change.asset}:${change.amount?.toString() ?? "off"}`);
  if (body.confirmationNonce === undefined) {
    const lines = [
      `Email confirmation for ${assetName(change.asset)}: ${describeAmount(current, change.asset)}`,
      `Change: ${next.size === 0 ? "turn email confirmation off" : describeAmount(next, change.asset)}`,
    ];
    // Checked before the new request replaces the old one, so a refused resend leaves the last code usable.
    await codeLimit(context);
    const confirmationNonce = await issueRequest(context.user, "settings", digest, { lines, basedOn: basedOn(current, change.asset) }, true);
    const sentTo = await sendCode(context, "settings", confirmationNonce, "Confirm a security change", lines, { limited: true });
    return { requiresEmailCode: true, confirmationNonce, sentTo, ...serverOnly };
  }
  const nonce = requiredNonce(body.confirmationNonce);
  const request = await loadRequest(context.user, "settings", nonce, digest);
  const from = approvedFrom(request);
  await verifyCode(context.user, "settings", nonce, body.emailCode);
  await consumeRequest(context.user, "settings", nonce);
  if (!await writeDailyAmount(context.user, change.asset, change.amount, { from, version })) throw new Error(AMOUNTS_CHANGED);
  return { ...view(next), ...serverOnly };
}

const AMOUNTS_CHANGED = "Your daily amounts changed while this was waiting. Check them and try again";

/** The asset's amount a change was asked for from, kept in its request: what the email showed as "before". */
function basedOn(amounts: DailyAmounts, asset: string): string | null {
  return amounts.get(asset)?.toString() ?? null;
}

/** The amount a confirmed change may replace: only the one the user saw when they approved it. */
function approvedFrom(request: RequestRow): bigint | undefined {
  const value = request.summary.basedOn;
  if (value === null) return undefined;
  if (typeof value !== "string" || !/^\d+$/.test(value)) throw new Error(REQUEST_EXPIRED);
  return BigInt(value);
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
): Promise<{ amounts: DailyAmounts; response?: Record<string, unknown> } | { serverOnly: bigint } | undefined> {
  const client = context.client ?? new ccc.ClientPublicTestnet();
  const digest = hashText(`daily-amount:${change.asset}:${change.amount?.toString() ?? "off"}`);
  const settings = settingsFromDailyAmounts(next, new Uint8Array(32));
  if (body.confirmationNonce === undefined) {
    let head = await pendingSendLimitHead(context, client);
    // Loosening amounts kept on the server only goes through the server's own code, whose email shows them before
    // and after; turning send limits on would ask only to "turn on" limits, hiding the stricter amounts it replaces.
    if (!head && weakens(current, next)) return undefined;
    // The cell already holds these amounts and the server's copy isn't loosened: nothing to sign. A change that
    // loosens the server's copy is still signed as a change on the cell, so it can't land alongside a tightening
    // made meanwhile (whose amount is written before it is sent) and undo it on the server.
    if (head && !weakens(current, next) && sameSettings(decodeSendLimitSettings(head.outputData), settings)) {
      await writeDailyAmount(context.user, change.asset, change.amount, "lower");
      return { amounts: await readDailyAmounts(context.user) };
    }
    let transaction: ccc.Transaction;
    try {
      transaction = head ? await buildSendLimitChange(client, context.wallet, head, settings) : await buildSendLimitGenesis(client, context.wallet, settings);
    } catch (error) {
      if (!head && error instanceof Error && /plain CKB cell|Insufficient CKB|insufficient/i.test(error.message)) return undefined;
      if (!head && error instanceof Error && /pending send/.test(error.message)) throw error;
      throw error;
    }
    let plan = await planSendLimits(context.wallet, transaction);
    // The Lit Action's email shows the cell's amounts as "before". A tightening that never reached the chain (its
    // broadcast failed) leaves the server, which alone gates hosted payments, stricter than the cell, and the email
    // would understate what this change gives up. So the server's amounts go on the cell first (a tightening there,
    // which needs no code), and the change is built on that.
    if (plan.needsCode && head && !sameSettings(decodeSendLimitSettings(head.outputData), settingsFromDailyAmounts(current, new Uint8Array(32)))) {
      const synced = await putAmountsOnCell(context, client, head, current);
      // Putting them there needs the Lit code itself (its fee isn't small and the day's amount is reached): asking it
      // separately keeps every email right, so the user does that first.
      if (!synced) throw new Error("Your stricter daily amounts haven't reached your send-limit cell yet. Set them again first, then make this change");
      head = synced;
      transaction = await buildSendLimitChange(client, context.wallet, head, settings);
      plan = await planSendLimits(context.wallet, transaction);
    }
    applySendLimitRecord(transaction, plan);
    const lines = [
      head ? "Change your daily send limits" : "Turn on daily send limits, enforced by KeyWay's Lit Action",
      `CKB: ${describeAmount(current, "ckb")} → ${describeAmount(next, "ckb")}`,
      ...(change.asset === "ckb" ? [] : [`${assetName(change.asset)}: ${describeAmount(current, change.asset)} → ${describeAmount(next, change.asset)}`]),
    ];
    if (!plan.needsCode && !weakens(current, next)) {
      return { amounts: await serverAmountsAround(context.user, current, next, change, current.get(change.asset), transaction, () => signAndSendSettings(context, client, transaction, {})) };
    }
    if (!plan.needsCode) {
      // The cell's change needs no Lit code (the cell already allows as much), but it loosens the server's own
      // amounts, which alone gate hosted Fiber payments: that takes the server's code, as for amounts it keeps alone.
      await codeLimit(context);
      const confirmationNonce = await issueRequest(context.user, "settings", digest, { lines, settingsTransaction: serializeTransaction(transaction), serverCode: true, basedOn: basedOn(current, change.asset) }, true);
      const sentTo = await sendCode(context, "settings", confirmationNonce, "Confirm a security change", lines, { limited: true });
      return { amounts: current, response: { requiresEmailCode: true, confirmationNonce, sentTo } };
    }
    // Stricter amounts apply on the server at once, even while turning limits on waits for the Lit code.
    if (!weakens(current, next)) await writeDailyAmount(context.user, change.asset, change.amount, "lower");
    await codeLimit(context);
    const confirmationNonce = await issueRequest(context.user, "settings", digest, { lines, settingsTransaction: serializeTransaction(transaction), basedOn: basedOn(current, change.asset) }, true);
    const sent = await policySendCode(transaction, context.wallet, { email: await context.email(), appName: context.appName });
    await recordLitCode(context.user, "settings", confirmationNonce, { litTicket: sent.ticket, ...(sent.fingerprint ? { litFingerprint: sent.fingerprint } : {}) });
    return { amounts: await readDailyAmounts(context.user), response: { requiresEmailCode: true, confirmationNonce, sentTo: sent.sentTo, codeLength: 8 } };
  }
  const nonce = requiredNonce(body.confirmationNonce);
  const request = await loadRequest(context.user, "settings", nonce, digest);
  // A request made while the account had no send-limit cell carries no transaction; the server's code applies, unless
  // limits were turned on since: then the change would apply to the server alone and leave it looser than the cell.
  if (!request.summary.settingsTransaction) {
    // Read before looking for the cell: a cell made after the look is written to the amounts (lowering them to its
    // own) after it is recorded, so either the look finds it or the server-only write sees the version move.
    const version = await readDailyAmountsVersion(context.user);
    // A genesis the node has: the cell exists even while an indexer doesn't list it yet (and it has left the pending list).
    const genesis = await genesisTransaction(context.user);
    const genesisStatus = genesis ? await nodeStatus(client)(genesis) : undefined;
    if (genesisStatus === "pending" || genesisStatus === "proposed" || genesisStatus === "committed"
      || await sendLimitHead(client, context.wallet, await listPendingTransactions(context.user.id, nodeStatus(client)))) {
      throw new Error("Send limits were turned on since this change was asked for. Start again");
    }
    return { serverOnly: version };
  }
  const transaction = ccc.Transaction.from(request.summary.settingsTransaction as ccc.TransactionLike);
  const from = approvedFrom(request);
  if (request.summary.serverCode === true) {
    await verifyCode(context.user, "settings", nonce, body.emailCode);
    return { amounts: await serverAmountsAround(context.user, current, next, change, from, transaction, async () => {
      await signAndSendSettings(context, client, transaction, {});
      await consumeRequest(context.user, "settings", nonce);
    }) };
  }
  if (typeof request.summary.litFingerprint === "string") withFingerprint(transaction, request.summary.litFingerprint);
  const emailCode = parseLitEmailCode(body.emailCode, request.summary.litTicket);
  await countLitCodeAttempt(context.user, "settings", nonce);
  return { amounts: await serverAmountsAround(context.user, current, next, change, from, transaction, async () => {
    await signAndSendSettings(context, client, transaction, { email: await context.email(), emailCode });
    await consumeRequest(context.user, "settings", nonce);
  }) };
}

/** The account's newest send-limit cell, pending ones included; cells its pending sends spent are never picked again. */
async function pendingSendLimitHead(context: SigningContext, client: ccc.Client): Promise<SendLimitHead | undefined> {
  const pending = await listPendingTransactions(context.user.id, nodeStatus(client));
  const head = await sendLimitHead(client, context.wallet, pending);
  // The same as a client does.
  for (const { transaction, status } of pending) if (status === "pending" || status === "proposed") await client.cache.markTransactions(transaction);
  return head;
}

/**
 * Sends a change that puts the server's amounts in the send-limit cell, when that only tightens the cell. Returns the
 * cell it makes, or undefined when it would need a code (the server is looser than the cell somewhere).
 */
async function putAmountsOnCell(context: SigningContext, client: ccc.Client, head: SendLimitHead, amounts: DailyAmounts): Promise<SendLimitHead | undefined> {
  const transaction = await buildSendLimitChange(client, context.wallet, head, settingsFromDailyAmounts(amounts, new Uint8Array(32)));
  const plan = await planSendLimits(context.wallet, transaction);
  if (plan.needsCode) return undefined;
  applySendLimitRecord(transaction, plan);
  await lowerToCell(context.user, transaction, { sent: false });
  await signAndSendSettings(context, client, transaction, {});
  const synced = await pendingSendLimitHead(context, client);
  if (synced?.outPoint.txHash !== transaction.hash()) throw new Error("Your send limits changed while this was being made. Try again");
  return synced;
}

/**
 * Writes the server's copy of a send-limit change around signing and sending it, and returns the amounts it then
 * holds. The server's amounts alone gate hosted Fiber payments, so they must never end up looser than the chain:
 * before the transaction is sent, the server's amounts are lowered to those it puts in the cell (a tightening is so
 * written before it is sent: a crash or a failed write after the broadcast can't lose it). A loosening is written only
 * after it was sent, only over `from`, the amount the user approved it from, and only if nothing else was written
 * since: a change written meanwhile was built on the cell this one makes, from amounts without this loosening, and
 * has replaced it on the chain.
 */
async function serverAmountsAround(user: User, current: DailyAmounts, next: DailyAmounts, change: { asset: string; amount: bigint | null }, from: bigint | undefined, transaction: ccc.Transaction, send: () => Promise<void>): Promise<DailyAmounts> {
  const tightens = !weakens(current, next);
  if (tightens) await writeDailyAmount(user, change.asset, change.amount, "lower");
  // A loosening approved from an amount that has since changed (a stricter one set meanwhile) isn't sent at all.
  const version = await lowerToCell(user, transaction, { sent: false, ...(tightens ? {} : { from: { asset: change.asset, amount: from } }) });
  try {
    await send();
    if (!tightens && !await writeDailyAmount(user, change.asset, change.amount, { from, version })) throw new Error(AMOUNTS_CHANGED);
  } finally {
    // Once more after the transaction is recorded as pending (even if sending failed, as it may still have landed): a
    // server-only raise that looked for the cell before it was recorded is then written either before this, which
    // lowers it, or after, which the version this moves refuses.
    await lowerToCell(user, transaction, { sent: true });
  }
  return readDailyAmounts(user);
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

/** Whether two sets of daily amounts are the same. */
function sameAmounts(a: DailyAmounts, b: DailyAmounts): boolean {
  return a.size === b.size && [...a].every(([asset, amount]) => b.get(asset) === amount);
}

/** Whether two send-limit settings hold the same amounts (the bound email aside). */
function sameSettings(a: Omit<SendLimitSettings, "fingerprint">, b: Omit<SendLimitSettings, "fingerprint">): boolean {
  return a.ckb === b.ckb && a.tokensUnlimited === b.tokensUnlimited && a.tokens.size === b.tokens.size
    && [...a.tokens].every(([asset, amount]) => b.tokens.get(asset) === amount);
}

/**
 * Daily amounts are written to the account's send-limit cell, so a new one must fit there: at most eight tokens, a
 * CKB amount below the cell's "no limit" value and a token amount within 16 bytes. Otherwise the cell could never
 * be made (and every send that has to make it would fail) or would read as a different amount. Removing an amount
 * is always allowed, so an account past eight tokens can get back within them.
 */
function refuseUnencodable(next: DailyAmounts, change: { asset: string; amount: bigint | null }): void {
  if (change.amount === null) return;
  if (change.asset === "ckb" ? change.amount >= SEND_LIMIT_UNLIMITED : change.amount >= 1n << 128n) throw new Error("That amount is too large");
  const tokens = (amounts: DailyAmounts) => [...amounts.keys()].filter((asset) => asset !== "ckb").length;
  if (tokens(next) > MAX_SEND_LIMIT_TOKENS) throw new Error(`At most ${MAX_SEND_LIMIT_TOKENS} tokens can have their own daily amount`);
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
 * Signs the account's lock groups in a transaction with the policy Action (the whole transaction, which it checks
 * itself). Only a test passes `signDigest`, which signs locally digest by digest instead.
 */
export async function signGroups(
  context: Pick<SigningContext, "wallet" | "signDigest">,
  transaction: ccc.Transaction,
  groups: SigningGroup[],
  client: ccc.Client,
  options: { enableTransactionHash?: string; email?: string; emailCode?: LitEmailCode; previousListRecord?: ccc.Hex; backups?: RecoveryBackup[]; missingGroup?: string } = {},
): Promise<ccc.Transaction> {
  if (!context.signDigest) {
    if (groups.length === 0) throw new Error(options.missingGroup ?? "Transaction has no KeyWay signing group");
    return policySignTransaction(transaction, groups, client, context.wallet, options);
  }
  return signAccountGroups(transaction, groups, client, (digest) => sign(context, digest), options.missingGroup);
}

/** Signs a digest with a test's local signer. Production never signs a digest: only the policy Action signs. */
export async function sign(context: Pick<SigningContext, "wallet" | "signDigest">, digest: ccc.Hex): Promise<ccc.Hex> {
  if (!context.signDigest) throw new Error("KeyWay signs only through the policy Action");
  return context.signDigest(digest, context.wallet);
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
  if (!options.limited) await codeLimit(context);
  const code = randomInt(0, 1_000_000).toString().padStart(6, "0");
  const sql = await database();
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
  const [row] = await sql<Array<{ email_code_hash: string | null; email_attempts: number }>>`
    update keyway_v2_signature_requests set email_attempts = email_attempts + 1
    where user_id = ${user.id} and purpose = ${purpose} and nonce = ${nonce} and expires_at > now() and email_code_expires_at > now()
    returning email_code_hash, email_attempts
  `;
  if (!row?.email_code_hash) throw new Error("The email code has expired. Request a new one");
  if (row.email_attempts > MAX_CODE_ATTEMPTS) throw new Error("Too many wrong codes. Request a new one");
  const expected = Buffer.from(row.email_code_hash, "hex");
  const supplied = Buffer.from(codeHash(nonce, code), "hex");
  if (expected.length !== supplied.length || !timingSafeEqual(expected, supplied)) throw new Error("That email code isn't right");
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
  if (head || wallet.recovery) return undefined;
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

/**
 * Writes one asset's daily amount, under a short per-user lock so concurrent changes see each other: "lower" only ever
 * lowers what is stored (or adds an amount), and `{ from }` writes only while the stored amount is still `from` (and,
 * with `version`, while no other write was made since the one that returned it). Returns false when that no longer
 * holds. A new token amount is refused once eight tokens have one, all the send-limit cell holds.
 */
async function writeDailyAmount(user: User, asset: string, amount: bigint | null, rule: "lower" | { from: bigint | undefined; version?: bigint }): Promise<boolean> {
  const sql = await database();
  return sql.begin(async (tx) => {
    await lockDailyAmounts(tx, user);
    const [row] = await tx<Array<{ amount: string }>>`select amount::text as amount from keyway_v2_daily_amounts where user_id = ${user.id} and asset = ${asset}`;
    const stored = row ? BigInt(row.amount) : undefined;
    let value = amount;
    if (rule === "lower") {
      if (amount === null) return true;
      if (stored !== undefined && stored < amount) value = stored;
    } else if (stored !== rule.from || (rule.version !== undefined && await dailyAmountsVersion(tx, user) !== rule.version)) {
      return false;
    }
    await nextDailyAmountsVersion(tx, user);
    if (value === null) {
      await tx`delete from keyway_v2_daily_amounts where user_id = ${user.id} and asset = ${asset}`;
      return true;
    }
    if (stored === undefined && asset !== "ckb") {
      const [{ tokens }] = await tx<Array<{ tokens: number }>>`select count(*)::int as tokens from keyway_v2_daily_amounts where user_id = ${user.id} and asset <> 'ckb'`;
      if (tokens >= MAX_SEND_LIMIT_TOKENS) throw new Error(`At most ${MAX_SEND_LIMIT_TOKENS} tokens can have their own daily amount`);
    }
    await tx`
      insert into keyway_v2_daily_amounts (user_id, asset, amount, updated_at)
      values (${user.id}, ${asset}, ${value.toString()}, now())
      on conflict (user_id, asset) do update set amount = excluded.amount, updated_at = now()
    `;
    return true;
  });
}

/**
 * Lowers the server's daily amounts to those a send-limit transaction puts in the account's cell (always its first
 * output). Before it is sent (`sent` false): the transaction may have been built from amounts that a change has since
 * replaced, and once it lands the chain holds its amounts, so the server must hold none looser; an amount the server
 * no longer has is put back, unless that would take it past the eight tokens the cell holds, when the transaction
 * isn't sent at all. With `from`, first checks that the asset a raise changes is still at the amount the user
 * approved it from. A genesis is remembered, so a server-only raise can see the cell exists before any indexer does.
 * After it is sent (`sent` true): only lowers the amounts the server still has, so an older transaction finishing
 * late can't bring back an amount a newer change removed. Returns the version this write leaves, which a raise checks
 * before it writes its own amount after sending.
 */
async function lowerToCell(user: User, transaction: ccc.Transaction, options: { sent: boolean; from?: { asset: string; amount: bigint | undefined } }): Promise<bigint> {
  const cell = decodeSendLimitSettings(transaction.outputsData[0]);
  // Settings KeyWay writes leave tokens without an amount unlimited, as the server does.
  if (!cell.tokensUnlimited) throw new Error("The send-limit cell holds settings KeyWay doesn't write");
  const sql = await database();
  return sql.begin(async (tx) => {
    await lockDailyAmounts(tx, user);
    const stored = await readDailyAmounts(user, tx);
    const { from, sent } = options;
    if (from && stored.get(from.asset) !== from.amount) throw new Error(AMOUNTS_CHANGED);
    const limits = [...(cell.ckb === undefined ? [] : [["ckb", cell.ckb] as const]), ...cell.tokens];
    const lower = limits.filter(([asset, amount]) => {
      const current = stored.get(asset);
      return current === undefined ? !sent : current > amount;
    });
    const tokens = new Set([...stored.keys(), ...lower.map(([asset]) => asset)].filter((asset) => asset !== "ckb"));
    if (tokens.size > MAX_SEND_LIMIT_TOKENS && tokens.size > [...stored.keys()].filter((asset) => asset !== "ckb").length) throw new Error(AMOUNTS_CHANGED);
    for (const [asset, amount] of lower) {
      await tx`
        insert into keyway_v2_daily_amounts (user_id, asset, amount, updated_at)
        values (${user.id}, ${asset}, ${amount.toString()}, now())
        on conflict (user_id, asset) do update set amount = excluded.amount, updated_at = now()
      `;
    }
    const version = await nextDailyAmountsVersion(tx, user);
    if (!sent && isGenesis(transaction)) {
      await tx`update keyway_v2_daily_amount_versions set genesis_transaction = ${transaction.hash()} where user_id = ${user.id}`;
    }
    return version;
  });
}

/** Whether a send-limit transaction makes the cell: its Type ID comes from its first input. */
function isGenesis(transaction: ccc.Transaction): boolean {
  const type = transaction.outputs[0]?.type;
  return Boolean(type && transaction.inputs[0] && type.args === ccc.hashTypeId(transaction.inputs[0], 0));
}

/** The last transaction sent to make the account's send-limit cell, if any. */
async function genesisTransaction(user: User): Promise<ccc.Hex | undefined> {
  const sql = await database();
  const [row] = await sql<Array<{ genesis_transaction: string | null }>>`select genesis_transaction from keyway_v2_daily_amount_versions where user_id = ${user.id}`;
  return row?.genesis_transaction ? ccc.hexFrom(row.genesis_transaction) : undefined;
}

/** The per-user lock every write to the daily amounts takes, for the length of its transaction. */
async function lockDailyAmounts(tx: TransactionSql, user: User): Promise<void> {
  await tx`select pg_advisory_xact_lock(hashtextextended(${`keyway-daily-amounts:${user.id}`}, 0))`;
}

async function readDailyAmountsVersion(user: User): Promise<bigint> {
  const sql = await database();
  return sql.begin((tx) => dailyAmountsVersion(tx, user));
}

async function dailyAmountsVersion(tx: TransactionSql, user: User): Promise<bigint> {
  const [row] = await tx<Array<{ version: string }>>`select version::text as version from keyway_v2_daily_amount_versions where user_id = ${user.id}`;
  return BigInt(row?.version ?? 0);
}

async function nextDailyAmountsVersion(tx: TransactionSql, user: User): Promise<bigint> {
  const [{ version }] = await tx<Array<{ version: string }>>`
    insert into keyway_v2_daily_amount_versions (user_id, version) values (${user.id}, 1)
    on conflict (user_id) do update set version = keyway_v2_daily_amount_versions.version + 1
    returning version::text as version
  `;
  return BigInt(version);
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
