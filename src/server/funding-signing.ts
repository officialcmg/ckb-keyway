import type * as ccc from "@ckb-ccc/core";
import { formatAsset } from "../sdk/browser/tokens.ts";
import { previewFundingTransaction, serializeTransaction, signFundingTransaction, type ValidatedFunding } from "./funding-transaction.ts";
import {
  consumeRequest,
  fundingCode,
  fundingNeedsLitCode,
  hashText,
  issueFundingCodeRequest,
  issueRequest,
  loadRequest,
  outflowNeedsEmailCode,
  reserveOutflow,
  sendCode,
  sendFundingCode,
  verifyCode,
  type Outflow,
  type RequestRow,
  type SigningContext,
} from "./general-signing.ts";
import { litPolicyEnabled, type LitEmailCode } from "./lit-policy.ts";
import { recordPendingTransaction } from "./pending-transactions.ts";
import { consumeConfirmation, issueConfirmation } from "./signing-confirmation.ts";
import type { ReadyWallet } from "./user-wallet.ts";

/** Everything channel-funding signing needs from the HTTP layer, so it can be tested without it. */
export type FundingContext = Pick<SigningContext, "user" | "wallet" | "appName" | "email" | "sendEmail" | "rateLimit" | "recordSigning"> & {
  preview?: (wallet: ReadyWallet, transaction: unknown) => Promise<ValidatedFunding>;
  /** Tests replace the Lit signer. */
  sign?: (validated: ValidatedFunding, options: { email?: string; emailCode?: LitEmailCode }) => Promise<ccc.Transaction>;
};

const HEADING = "Confirm a channel opening";

/**
 * Channel funding (a sign-transaction request without a purpose): preview, request-email-code, sign. A funding
 * counts toward the daily email-confirmation amounts like any other transaction, and past them needs a code: Lit's,
 * once the account has send limits, otherwise the one KeyWay emails.
 */
export async function fundingSigning(context: FundingContext, body: Record<string, unknown>): Promise<unknown> {
  const { user, wallet } = context;
  const validated = await (context.preview ?? previewFundingTransaction)(wallet, body.transaction);
  const serialized = JSON.stringify(serializeTransaction(validated.transaction));
  const outflow = fundingOutflow(validated);
  const policy = !context.sign && litPolicyEnabled();
  const { operation, confirmationNonce } = body;
  if (operation === "preview") {
    // Once the account has send limits, Lit signs a funding only with its code: Fiber chooses the inputs, so the
    // funding can't chain on the send-limit cell and count toward the daily amount.
    if (policy && await fundingNeedsLitCode(wallet, validated.transaction)) {
      return { preview: validated.preview, confirmationNonce: await issueFundingCodeRequest(user, serialized), requiresEmailCode: true };
    }
    // Otherwise the server's own daily amounts apply, with the code KeyWay emails.
    if (await outflowNeedsEmailCode(user, outflow)) {
      const lines = fundingLines(validated);
      const nonce = await issueRequest(user, "transaction", hashText(serialized), { lines, fundingEmail: true }, true);
      return { preview: validated.preview, confirmationNonce: nonce, requiresEmailCode: true };
    }
    return { preview: validated.preview, confirmationNonce: await issueConfirmation(user, serialized) };
  }
  if (operation === "request-email-code" && typeof confirmationNonce === "string") {
    const emailed = await emailedRequest(context, confirmationNonce, serialized);
    if (emailed) return { sent: true, sentTo: await sendCode(context, "transaction", confirmationNonce, HEADING, emailed.summary.lines ?? []) };
    return sendFundingCode(context, confirmationNonce, serialized, validated.transaction);
  }
  if (operation !== "sign" || typeof confirmationNonce !== "string") throw new Error("A valid signing operation is required");
  const emailed = await emailedRequest(context, confirmationNonce, serialized);
  let coded: Awaited<ReturnType<typeof fundingCode>>;
  if (emailed) {
    await verifyCode(user, "transaction", confirmationNonce, body.emailCode);
    await consumeRequest(user, "transaction", confirmationNonce);
  } else {
    coded = await fundingCode(context, confirmationNonce, serialized, body.emailCode);
    if (!coded) await consumeConfirmation(user, confirmationNonce, serialized);
  }
  // Counted before it is signed, under the per-user lock; without a code, checked once more under that lock.
  const release = await reserveOutflow(user, outflow, Boolean(emailed || coded), "transaction");
  let signed: ccc.Transaction;
  try {
    await context.recordSigning(user.id);
    signed = context.sign
      ? await context.sign(validated, coded ?? {})
      : await signFundingTransaction(user, wallet, validated, coded ?? {});
  } catch (error) {
    await release();
    throw error;
  }
  await coded?.consume();
  await recordPendingTransaction(user.id, signed);
  return { transaction: serializeTransaction(signed) };
}

/** What a funding takes from the account: its CKB, the fee included, and a token channel's token. */
function fundingOutflow({ preview, outflowShannons }: ValidatedFunding): Outflow {
  return {
    id: preview.transactionHash,
    shannons: outflowShannons,
    tokens: preview.token ? [{ asset: preview.token.asset, amount: BigInt(preview.token.amount) }] : [],
  };
}

function fundingLines({ preview }: ValidatedFunding): string[] {
  return [
    `Open a Fiber channel with ${preview.amountCkb} CKB`,
    ...(preview.token ? [`Token ${formatAsset(BigInt(preview.token.amount), preview.token.asset)} (${preview.token.asset})`] : []),
    `Network fee ${preview.feeCkb} CKB`,
    `Channel ${preview.destination}`,
  ];
}

/** A funding approval that needs the code KeyWay emails; undefined for any other approval. */
async function emailedRequest(context: Pick<FundingContext, "user">, nonce: string, serialized: string): Promise<RequestRow | undefined> {
  let request: RequestRow;
  try {
    request = await loadRequest(context.user, "transaction", nonce, hashText(serialized));
  } catch {
    return undefined;
  }
  return request.summary.fundingEmail === true && request.requires_email_code ? request : undefined;
}
