import * as ccc from "@ckb-ccc/core";
import { KeyWayAccountSigner, type KeyWayRecovery } from "./account-lock";
import { KeyWayApiClient } from "./api-client";
import { serializeCccTransaction } from "./ccc-transaction";
import { withEmailCode, type RequestEmailCode } from "./email-code";

export type { RequestEmailCode };

/** What a transaction does to the user's account, decoded by the KeyWay backend from the chain. */
export type TransactionPreview = {
  network: "CKB testnet";
  /** Plain CKB leaving the account, excluding the fee when the user pays all of it. */
  sendingCkb: string;
  /** Plain CKB arriving in the account. */
  receivingCkb: string;
  feeCkb: string;
  /** Net change per token: `amount` in raw units with a sign, `amountText` for people, such as "-25 RUSD". */
  tokens: Array<{ id: string; standard: "xUDT" | "sUDT"; amount: string; amountText?: string }>;
  nfts: Array<{ kind: "Spore" | "Cluster"; id: string; change: "sent" | "received" | "minted" | "burned" }>;
  dao: Array<{ action: "deposit" | "withdrawal request" | "withdrawal"; amountCkb: string }>;
  recipients: Array<{
    address: string;
    kind: "wallet" | "contract" | "Fiber channel";
    walletType?: string;
    ckb: string;
    tokens: Array<{ id: string; amount: string }>;
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

export type KeyWaySignerHandlers = {
  approveCkbTransaction: ApproveCkbTransaction;
  approveCkbMessage: ApproveCkbMessage;
  requestEmailCode: RequestEmailCode;
};

/**
 * A CCC signer for the signed-in KeyWay account. Every transaction and message is shown to the user
 * before the KeyWay backend signs it, and only the user's own account is ever signed. Pass the wallet's
 * `recovery` when it has one, so addresses and placeholders follow its Omnilock.
 */
export class KeyWaySigner extends KeyWayAccountSigner {
  constructor(
    private readonly authToken: string,
    publicKey: ccc.HexLike,
    private readonly handlers: KeyWaySignerHandlers,
    client: ccc.Client = new ccc.ClientPublicTestnet(),
    private readonly api = new KeyWayApiClient(),
    recovery?: KeyWayRecovery,
  ) {
    super(client, publicKey, recovery);
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
      ? await this.withEmailCode("transaction", () => this.api.signTransaction(this.authToken, { ...base, operation: "request-email-code" }).then(() => undefined), sign)
      : await sign();
    const result = signed as { transaction?: ccc.TransactionLike };
    if (!result?.transaction) throw new Error("KeyWay returned an invalid signed transaction");
    return ccc.Transaction.from(result.transaction);
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
   * transfers and Fiber payments together); null removes the amount. Once any amount is set, a token with no
   * amount of its own always needs the code. Strengthening applies at once; weakening asks for an emailed code.
   */
  async setDailyConfirmationAmount(asset: "ckb" | `0x${string}`, amount: bigint | null): Promise<void> {
    const value = amount === null ? null : ccc.numFrom(amount).toString();
    const set = (extra: Record<string, unknown> = {}) => this.api.signingSettings(this.authToken, { operation: "set-daily-amount", asset, amount: value, ...extra }) as Promise<{ requiresEmailCode?: boolean; confirmationNonce?: string }>;
    let pending = await set();
    if (!pending.requiresEmailCode) return;
    await this.withEmailCode(
      "settings",
      async () => { pending = await set(); },
      (emailCode) => set({ confirmationNonce: pending.confirmationNonce, emailCode }),
    );
  }

  private withEmailCode<T>(reason: "transaction" | "settings", send: () => Promise<void>, complete: (code: string) => Promise<T>): Promise<T> {
    return withEmailCode(this.handlers.requestEmailCode, reason, send, complete);
  }
}
