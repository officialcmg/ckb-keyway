import * as ccc from "@ckb-ccc/core";
import { KeyWayAccountSigner, type KeyWayRecovery } from "./account-lock";
import { KeyWayApiClient } from "./api-client";
import { serializeCccTransaction } from "./ccc-transaction";
import { withEmailCode, type RequestEmailCode } from "./email-code";
import { PendingTransactions } from "./pending-transactions";
import { chainOnSendLimit, SEND_LIMIT_UNLIMITED, type SendLimitOffer } from "./send-limits";

export type { RequestEmailCode };

/** What a transaction does to the user's account, decoded by the KeyWay backend from the chain. */
export type TransactionPreview = {
  network: "CKB testnet";
  /** Plain CKB leaving the account, excluding the fee when the user pays all of it. */
  sendingCkb: string;
  /** Plain CKB arriving in the account. */
  receivingCkb: string;
  feeCkb: string;
  /**
   * Net change per token: `amount` in raw units with a sign, `amountText` for people, such as "-25 RUSD".
   * `asset` is the token's type script hash; `id` is a short form of it, for keys only.
   */
  tokens: Array<{ id: string; asset: string; standard: "xUDT" | "sUDT"; amount: string; amountText?: string }>;
  /** `id` is the NFT's whole type args. */
  nfts: Array<{ kind: "Spore" | "Cluster"; id: string; change: "sent" | "received" | "minted" | "burned" }>;
  dao: Array<{ action: "deposit" | "withdrawal request" | "withdrawal"; amountCkb: string }>;
  recipients: Array<{
    address: string;
    kind: "wallet" | "contract" | "Fiber channel";
    walletType?: string;
    ckb: string;
    /** Raw units per token, by `asset` (its type script hash); `amountText` for people, such as "25 RUSD". */
    tokens: Array<{ id: string; asset: string; amount: string; amountText?: string }>;
    /** "Spore <whole type args>" or "Cluster <whole type args>". */
    nfts: string[];
  }>;
  /** Type scripts the backend couldn't explain. Always shown, never hidden. */
  unrecognized: Array<{ codeHash: string; cells: number }>;
  /** Inputs owned by other locks, which their owners must sign. */
  otherSigners: number;
  details: { inputs: CellSummary[]; outputs: CellSummary[] };
  transactionHash: string;
  /** True when this transaction, with everything sent in the last 24 hours, reaches one of the user's daily confirmation amounts. */
  requiresEmailCode: boolean;
};

export type CellSummary = { lock: string; type?: string; capacityCkb: string; dataBytes: number };
export type MessagePreview = { message: string };

export type ApproveCkbTransaction = (preview: TransactionPreview) => boolean | Promise<boolean>;
export type ApproveCkbMessage = (preview: MessagePreview) => boolean | Promise<boolean>;
/**
 * Asked once, before an account's first send with send limits available: the daily CKB amount (in shannons) to turn
 * them on with, starting from `offer.ckb`. Return the amount (the offer's to accept it), or null to cancel the send.
 * The code KeyWay's Lit Action emails follows.
 */
export type ApproveDailyLimit = (offer: SendLimitOffer) => bigint | null | Promise<bigint | null>;

export type KeyWaySignerHandlers = {
  approveCkbTransaction: ApproveCkbTransaction;
  approveCkbMessage: ApproveCkbMessage;
  requestEmailCode: RequestEmailCode;
  /** Without it, the offered amount is used as it is. */
  approveDailyLimit?: ApproveDailyLimit;
};

/**
 * A CCC signer for the signed-in KeyWay account. Every transaction and message is shown to the user
 * before the KeyWay backend signs it, and only the user's own account is ever signed. Pass the wallet's
 * `recovery` when it has one, so addresses and placeholders follow its Omnilock.
 */
export class KeyWaySigner extends KeyWayAccountSigner {
  /** The account's transactions other clients had signed and its newest send-limit cell, loaded before each send. */
  readonly pending: PendingTransactions;

  constructor(
    private readonly authToken: string,
    publicKey: ccc.HexLike,
    private readonly handlers: KeyWaySignerHandlers,
    client: ccc.Client = new ccc.ClientPublicTestnet(),
    private readonly api = new KeyWayApiClient(),
    recovery?: KeyWayRecovery,
  ) {
    super(client, publicKey, recovery);
    this.pending = new PendingTransactions(() => this.api.pendingTransactions(this.authToken), this.client);
    // Loaded as soon as the signer starts, so the first send is built on it.
    void this.pending.refresh(true);
  }

  /**
   * CCC picks inputs here: first load what other clients sent, so their spent cells are skipped and their change
   * used. When CCC is collecting inputs for a send, send limits are turned on first if the account doesn't have
   * them yet, so the send is built on the new send-limit cell.
   */
  async *findCells(filter: Parameters<ccc.Signer["findCells"]>[0], withData?: boolean | null, order?: "asc" | "desc", limit?: number): AsyncGenerator<ccc.Cell> {
    if (collectsForSend(filter)) await this.ensureSendLimits();
    await this.pending.refresh();
    yield* super.findCells(filter, withData, order, limit);
  }

  private sendLimitsStep?: Promise<void>;

  /**
   * Turns send limits on before a send if KeyWay offers them (an account without them that could have them). Two
   * sends at once share one offer. Cancelling cancels the send; the offer comes back on the next one.
   */
  private ensureSendLimits(): Promise<void> {
    this.sendLimitsStep ??= this.offerSendLimits().finally(() => { this.sendLimitsStep = undefined; });
    return this.sendLimitsStep;
  }

  private async offerSendLimits(): Promise<void> {
    const { sendLimit, sendLimitOffer } = await this.pending.refresh();
    if (sendLimit || !sendLimitOffer) return;
    const chosen = this.handlers.approveDailyLimit ? await this.handlers.approveDailyLimit(sendLimitOffer) : sendLimitOffer.ckb;
    if (chosen === null || chosen === undefined) throw new Error("The transaction was not approved");
    if (typeof chosen !== "bigint" || chosen <= 0n || chosen >= SEND_LIMIT_UNLIMITED) throw new Error("Enter a daily limit above 0 CKB");
    try {
      await this.setDailyConfirmationAmount("ckb", chosen);
    } catch (error) {
      // A send of this account's is still in the pool, so its oldest cell can't start the limits yet: send as
      // before, and offer them again next time.
      if (error instanceof Error && /pending send to confirm/i.test(error.message)) return;
      throw error;
    }
    // The new send-limit cell (still pending) is what this send chains on.
    await this.pending.refresh(true);
  }

  /**
   * Chains the transaction on the account's newest send-limit cell, when it has limits on: the cell goes in as an
   * input and out unchanged, with room in its witness for the record KeyWay fills in. CCC calls this before
   * computing the fee, so the fee covers it, and the transaction's hash doesn't change when the record is filled in.
   */
  async prepareTransaction(transactionLike: ccc.TransactionLike): Promise<ccc.Transaction> {
    const transaction = ccc.Transaction.from(transactionLike);
    const { sendLimit } = await this.pending.refresh();
    if (sendLimit) chainOnSendLimit(transaction, sendLimit);
    return super.prepareTransaction(transaction);
  }

  async signOnlyTransaction(transactionLike: ccc.TransactionLike): Promise<ccc.Transaction> {
    const transaction = serializeCccTransaction(ccc.Transaction.from(transactionLike));
    const reviewed = await this.api.signTransaction(this.authToken, { purpose: "transaction", operation: "preview", transaction }) as {
      preview: Omit<TransactionPreview, "requiresEmailCode">;
      confirmationNonce: string;
      requiresEmailCode: boolean;
    };
    if (!reviewed?.preview || typeof reviewed.confirmationNonce !== "string") throw new Error("KeyWay returned an invalid transaction preview");
    const preview = { ...reviewed.preview, requiresEmailCode: Boolean(reviewed.requiresEmailCode) };
    if (!await this.handlers.approveCkbTransaction(preview)) throw new Error("The transaction was not approved");

    const base = { purpose: "transaction", transaction, confirmationNonce: reviewed.confirmationNonce };
    const sign = (emailCode?: string) => this.api.signTransaction(this.authToken, { ...base, operation: "sign", ...(emailCode ? { emailCode } : {}) });
    const signed = preview.requiresEmailCode
      ? await this.withEmailCode("transaction", () => this.api.signTransaction(this.authToken, { ...base, operation: "request-email-code" }), sign)
      : await sign();
    const result = signed as { transaction?: ccc.TransactionLike };
    if (!result?.transaction) throw new Error("KeyWay returned an invalid signed transaction");
    const signedTransaction = ccc.Transaction.from(result.transaction);
    // The next send, from this page, chains on this one straight away.
    await this.pending.signed(signedTransaction, (await super.getAddressObjSecp256k1()).script);
    return signedTransaction;
  }

  /** Signs in CKB's "Nervos Message:" format, so `signMessage` and `verifyMessage` work as usual in CCC. */
  async signMessageRaw(message: string | ccc.BytesLike): Promise<ccc.Hex> {
    const text = typeof message === "string" ? message : ccc.hexFrom(message);
    const reviewed = await this.api.signMessage(this.authToken, { operation: "preview", message: text }) as { preview: MessagePreview; confirmationNonce: string };
    if (!reviewed?.preview || typeof reviewed.confirmationNonce !== "string") throw new Error("KeyWay returned an invalid message preview");
    if (!await this.handlers.approveCkbMessage(reviewed.preview)) throw new Error("The message was not approved");
    const signed = await this.api.signMessage(this.authToken, { operation: "sign", message: text, confirmationNonce: reviewed.confirmationNonce }) as { signature?: string };
    if (typeof signed?.signature !== "string") throw new Error("KeyWay returned an invalid message signature");
    return ccc.hexFrom(signed.signature);
  }

  /**
   * The user's daily email-confirmation amounts, by asset: "ckb" (in shannons) or a token's type script hash
   * (in the token's smallest unit). Empty means email confirmation is off.
   */
  async getDailyConfirmationAmounts(): Promise<Record<string, bigint>> {
    const result = await this.api.signingSettings(this.authToken, { operation: "get" }) as { dailyAmounts?: Record<string, string> };
    return Object.fromEntries(Object.entries(result.dailyAmounts ?? {}).map(([asset, amount]) => [asset, BigInt(amount)]));
  }

  /**
   * Requires an emailed code once this much of an asset leaves the account within 24 hours (CKB sends, token
   * transfers and Fiber payments together); null removes the amount. An asset without an amount of its own has no
   * limit. Strengthening (lowering or adding an amount) applies at once; weakening asks for an emailed code.
   */
  async setDailyConfirmationAmount(asset: "ckb" | `0x${string}`, amount: bigint | null): Promise<void> {
    const value = amount === null ? null : ccc.numFrom(amount).toString();
    const set = (extra: Record<string, unknown> = {}) => this.api.signingSettings(this.authToken, { operation: "set-daily-amount", asset, amount: value, ...extra }) as Promise<{ requiresEmailCode?: boolean; confirmationNonce?: string; sentTo?: string }>;
    let pending = await set();
    if (!pending.requiresEmailCode) return;
    // Each resend asks again, which replaces the request (and its code) with a new one.
    await this.withEmailCode(
      "settings",
      async () => (pending = await set()),
      (emailCode) => set({ confirmationNonce: pending.confirmationNonce, emailCode }),
      pending,
    );
  }

  private withEmailCode<T>(reason: "transaction" | "settings", send: () => Promise<unknown>, complete: (code: string) => Promise<T>, sent?: unknown): Promise<T> {
    return withEmailCode(this.handlers.requestEmailCode, reason, send, complete, sent);
  }
}

/**
 * Whether CCC is collecting inputs for a transaction: plain CKB (`completeInputsByCapacity`) or a token's cells
 * (`completeInputsByUdt`). Other lookups (an app listing its cells) never turn send limits on.
 */
export function collectsForSend(filter: Parameters<ccc.Signer["findCells"]>[0]): boolean {
  if (!filter) return false;
  const lengths = (filter as { scriptLenRange?: unknown }).scriptLenRange;
  const plain = Array.isArray(lengths) && Number(lengths[0]) === 0 && Number(lengths[1]) === 1;
  const token = Boolean((filter as { script?: unknown }).script);
  return plain || token;
}
