import * as ccc from "@ckb-ccc/core";
import { serializeCccTransaction } from "./ccc-transaction";

export type FundingPreview = {
  amountCkb: string;
  feeCkb: string;
  destination: string;
  transactionHash: string;
};

export type ConfirmFunding = (preview: FundingPreview) => boolean | Promise<boolean>;

export class RemoteCkbSigner extends ccc.SignerCkbPublicKey {
  constructor(
    public readonly sessionJwt: string,
    publicKey: ccc.HexLike,
    private readonly confirmFunding: ConfirmFunding,
    client: ccc.Client = new ccc.ClientPublicTestnet(),
  ) {
    super(client, publicKey);
  }

  async signOnlyTransaction(transactionLike: ccc.TransactionLike): Promise<ccc.Transaction> {
    const transaction = ccc.Transaction.from(transactionLike);
    const serialized = serializeCccTransaction(transaction);
    const preview = await this.request({ operation: "preview", transaction: serialized });
    if (!isPreviewResponse(preview)) throw new Error("KeyWay returned an invalid funding preview");
    if (!await this.confirmFunding(preview.preview)) throw new Error("Funding transaction was not confirmed");

    const signed = await this.request({
      operation: "sign",
      transaction: serialized,
      confirmationNonce: preview.confirmationNonce,
    });
    if (!signed || typeof signed !== "object" || !("transaction" in signed)) {
      throw new Error("KeyWay returned an invalid signed transaction");
    }
    return ccc.Transaction.from((signed as { transaction: ccc.TransactionLike }).transaction);
  }

  private async request(body: Record<string, unknown>): Promise<unknown> {
    const response = await fetch("/api/keyway/sign-transaction", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${this.sessionJwt}` },
      body: JSON.stringify(body),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error ?? "KeyWay transaction signing failed");
    return result;
  }
}

function isPreviewResponse(value: unknown): value is {
  preview: FundingPreview;
  confirmationNonce: string;
} {
  if (!value || typeof value !== "object") return false;
  const { preview, confirmationNonce } = value as Record<string, unknown>;
  if (!preview || typeof preview !== "object" || typeof confirmationNonce !== "string") return false;
  const candidate = preview as Partial<FundingPreview>;
  return typeof candidate.amountCkb === "string" &&
    typeof candidate.feeCkb === "string" &&
    typeof candidate.destination === "string" &&
    typeof candidate.transactionHash === "string";
}
