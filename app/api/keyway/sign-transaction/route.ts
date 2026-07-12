import {
  previewFundingTransaction,
  serializeTransaction,
  signFundingTransaction,
} from "@/src/server/funding-transaction";
import {
  consumeConfirmation,
  issueConfirmation,
  verifyConfirmation,
} from "@/src/server/signing-confirmation";
import { authenticateUser } from "@/src/server/stytch";
import { readWallet } from "@/src/server/user-wallet";

export async function POST(request: Request) {
  try {
    const user = await authenticateUser(request.headers.get("authorization"));
    const body: unknown = await request.json();
    if (!body || typeof body !== "object") throw new Error("Invalid signing request");
    const { operation, transaction, confirmationNonce } = body as Record<string, unknown>;
    const wallet = readWallet(user);
    if (!wallet || wallet.status !== "ready") throw new Error("KeyWay wallet is not provisioned");

    const validated = await previewFundingTransaction(wallet, transaction);
    const serialized = JSON.stringify(serializeTransaction(validated.transaction));
    if (operation === "preview") {
      return Response.json({
        preview: validated.preview,
        confirmationNonce: await issueConfirmation(user, serialized),
      });
    }
    if (operation !== "sign" || typeof confirmationNonce !== "string") {
      throw new Error("A valid signing operation is required");
    }

    verifyConfirmation(user, confirmationNonce, serialized);
    const signed = await signFundingTransaction(user, wallet, validated);
    await consumeConfirmation(user);
    return Response.json({ transaction: serializeTransaction(signed) });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Transaction signing failed";
    const unauthorized = /session|bearer/i.test(message);
    return Response.json({ error: message }, { status: unauthorized ? 401 : 400 });
  }
}
