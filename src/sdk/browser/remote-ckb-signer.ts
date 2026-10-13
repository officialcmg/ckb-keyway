import * as ccc from "@ckb-ccc/core";
import { serializeCccTransaction } from "./ccc-transaction";
import { KeyWayApiClient } from "./api-client";
import { formatAsset } from "./tokens";

/** What the channel-open approval shows: what goes into the channel and the network fee. */
export type FiberChannelOpenPreview = {
  /** CKB put into the channel: its size for a CKB channel, or the reserve a token channel needs. */
  amountCkb: string;
  feeCkb: string;
  destination: string;
  transactionHash: string;
  /** For a token channel: the token's type script hash, the amount in its smallest unit, and the amount for people. */
  token?: { asset: string; amount: string; amountText: string };
};

export type ApproveFiberChannelOpen = (preview: FiberChannelOpenPreview) => boolean | Promise<boolean>;

export class RemoteCkbSigner extends ccc.SignerCkbPublicKey {
  constructor(
    public readonly authToken: string,
    publicKey: ccc.HexLike,
    private readonly approveChannelOpen: ApproveFiberChannelOpen,
    client: ccc.Client = new ccc.ClientPublicTestnet(),
    private readonly api = new KeyWayApiClient(),
  ) {
    super(client, publicKey);
  }

  async signOnlyTransaction(transactionLike: ccc.TransactionLike): Promise<ccc.Transaction> {
    const transaction = ccc.Transaction.from(transactionLike);
    const serialized = serializeCccTransaction(transaction);
    const preview = await this.request({ operation: "preview", transaction: serialized });
    if (!isPreviewResponse(preview)) throw new Error("KeyWay returned an invalid funding preview");
    const token = preview.preview.token;
    const shown = token ? { ...preview.preview, token: { ...token, amountText: formatAsset(BigInt(token.amount), token.asset) } } : preview.preview;
    if (!await this.approveChannelOpen(shown)) throw new Error("The channel opening was not approved");

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
    return this.api.signTransaction(this.authToken, body);
  }
}

function isPreviewResponse(value: unknown): value is {
  preview: FiberChannelOpenPreview;
  confirmationNonce: string;
} {
  if (!value || typeof value !== "object") return false;
  const { preview, confirmationNonce } = value as Record<string, unknown>;
  if (!preview || typeof preview !== "object" || typeof confirmationNonce !== "string") return false;
  const candidate = preview as Partial<FiberChannelOpenPreview>;
  return typeof candidate.amountCkb === "string" &&
    typeof candidate.feeCkb === "string" &&
    typeof candidate.destination === "string" &&
    typeof candidate.transactionHash === "string";
}
