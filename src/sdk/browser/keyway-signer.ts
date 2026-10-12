import * as ccc from "@ckb-ccc/core";
import { KeyWayApiClient } from "./api-client";
import { serializeCccTransaction } from "./ccc-transaction";

/** What a transaction does to the user's account, decoded by the KeyWay backend from the chain. */
export type TransactionPreview = {
  network: "CKB testnet";
  /** Plain CKB leaving the account, excluding the fee when the user pays all of it. */
  sendingCkb: string;
  /** Plain CKB arriving in the account. */
  receivingCkb: string;
  feeCkb: string;
  tokens: Array<{ id: string; standard: "xUDT" | "sUDT"; amount: string }>;
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
  /** True when the amount is at or above the user's email-confirmation threshold. */
  requiresEmailCode: boolean;
};

export type CellSummary = { lock: string; type?: string; capacityCkb: string; dataBytes: number };
export type MessagePreview = { message: string };

export type ConfirmTransaction = (preview: TransactionPreview) => boolean | Promise<boolean>;
export type ConfirmMessage = (preview: MessagePreview) => boolean | Promise<boolean>;
/** Asks the user for the code KeyWay emailed them. Resolve undefined if they cancel. */
export type RequestEmailCode = (request: {
  reason: "transaction" | "settings";
  error?: string;
  resend: () => Promise<void>;
}) => Promise<string | undefined>;

export type KeyWaySignerHandlers = {
  confirmTransaction: ConfirmTransaction;
  confirmMessage: ConfirmMessage;
  requestEmailCode: RequestEmailCode;
};

const WRONG_CODE = /isn't right|six-digit code/i;

/**
 * A CCC signer for the signed-in KeyWay account. Every transaction and message is shown to the user
 * before the KeyWay backend signs it, and only the user's own account is ever signed.
 */
export class KeyWaySigner extends ccc.SignerCkbPublicKey {
  constructor(
    private readonly authToken: string,
    publicKey: ccc.HexLike,
    private readonly handlers: KeyWaySignerHandlers,
    client: ccc.Client = new ccc.ClientPublicTestnet(),
    private readonly api = new KeyWayApiClient(),
  ) {
    super(client, publicKey);
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
    if (!await this.handlers.confirmTransaction(preview)) throw new Error("The transaction was not approved");

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
    if (!await this.handlers.confirmMessage(reviewed.preview)) throw new Error("The message was not approved");
    const signed = await this.api.signMessage(this.authToken, { operation: "sign", message: text, confirmationNonce: reviewed.confirmationNonce }) as { signature?: string };
    if (typeof signed?.signature !== "string") throw new Error("KeyWay returned an invalid message signature");
    return ccc.hexFrom(signed.signature);
  }

  /** The user's email-confirmation threshold in shannons, or null when it's off. */
  async getEmailConfirmationThreshold(): Promise<bigint | null> {
    const result = await this.api.signingSettings(this.authToken, { operation: "get" }) as { emailThresholdShannons: string | null };
    return result.emailThresholdShannons === null ? null : BigInt(result.emailThresholdShannons);
  }

  /**
   * Requires an emailed code for transfers at or above `shannons` (null turns it off). Turning it on or
   * lowering it applies at once; raising it or turning it off asks the user for a code from their inbox.
   */
  async setEmailConfirmationThreshold(shannons: bigint | null): Promise<void> {
    const value = shannons === null ? null : ccc.numFrom(shannons).toString();
    const set = (extra: Record<string, unknown> = {}) => this.api.signingSettings(this.authToken, { operation: "set", emailThresholdShannons: value, ...extra }) as Promise<{ requiresEmailCode?: boolean; confirmationNonce?: string }>;
    let pending = await set();
    if (!pending.requiresEmailCode) return;
    await this.withEmailCode(
      "settings",
      async () => { pending = await set(); },
      (emailCode) => set({ confirmationNonce: pending.confirmationNonce, emailCode }),
    );
  }

  private async withEmailCode<T>(reason: "transaction" | "settings", send: () => Promise<void>, complete: (code: string) => Promise<T>): Promise<T> {
    if (reason === "transaction") await send();
    let error: string | undefined;
    for (;;) {
      const code = await this.handlers.requestEmailCode({ reason, error, resend: send });
      if (code === undefined) throw new Error("Email confirmation was cancelled");
      try {
        return await complete(code);
      } catch (cause) {
        const message = cause instanceof Error ? cause.message : "";
        if (!WRONG_CODE.test(message)) throw cause;
        error = message;
      }
    }
  }
}
