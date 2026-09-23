import {
  FiberRpcClient,
  type ChannelId,
  type NewInvoiceParams,
  type SendPaymentParams,
} from "@fiber-pay/sdk/node";
import { consumeManagedConfirmation, issueManagedConfirmation } from "./managed-confirmation.ts";
import { toKeyWayError } from "../sdk/browser/keyway-error.ts";

type ManagedNodeClient = Pick<
  FiberRpcClient,
  "nodeInfo" | "listChannels" | "newInvoice" | "sendPayment" | "waitForPayment" | "shutdownChannel"
>;

let client: ManagedNodeClient | undefined;
let mutation = Promise.resolve();

export async function managedNodeRequest(
  userId: string,
  body: Record<string, unknown>,
  override?: ManagedNodeClient,
): Promise<unknown> {
  authorize(userId, Boolean(override));
  const node = override ?? managedNodeClient();

  if (body.operation === "status") {
    return { node: await node.nodeInfo(), network: "testnet", custody: "keyway-managed" };
  }
  if (body.operation === "list-channels") {
    return node.listChannels({ include_closed: body.includeClosed === true });
  }
  if (body.operation === "new-invoice") {
    const params = invoiceParams(body);
    return serializeMutation(() => node.newInvoice(params));
  }
  if (body.operation === "preflight-payment") {
    const params = paymentParams(body);
    try {
      const result = await node.sendPayment({ ...params, dry_run: true });
      return {
        routable: true,
        fee: result.fee,
        confirmationNonce: await issueManagedConfirmation(userId, "payment", confirmationPayload(params)),
      };
    } catch (error) {
      const failure = toKeyWayError(error, "PAYMENT_FAILED");
      return { routable: false, error: { code: failure.code, message: failure.message, retryable: failure.retryable } };
    }
  }
  if (body.operation === "send-payment") {
    const params = paymentParams(body);
    if (typeof body.confirmationNonce !== "string") throw new Error("Payment confirmation is required");
    await consumeManagedConfirmation(userId, "payment", body.confirmationNonce, confirmationPayload(params));
    return serializeMutation(async () => {
      const payment = await node.sendPayment(params);
      return node.waitForPayment(payment.payment_hash, { timeout: 120_000, interval: 2_000 });
    });
  }
  if (body.operation === "prepare-close-channel") {
    const params = closeParams(body);
    return {
      confirmationNonce: await issueManagedConfirmation(userId, "channel_close", closeConfirmationPayload(params)),
    };
  }
  if (body.operation === "close-channel") {
    const params = closeParams(body);
    if (typeof body.confirmationNonce !== "string") throw new Error("Channel closure confirmation is required");
    await consumeManagedConfirmation(userId, "channel_close", body.confirmationNonce, closeConfirmationPayload(params));
    await serializeMutation(() => node.shutdownChannel(params));
    return { closed: true };
  }
  throw new Error("Unsupported managed-node operation");
}

export function managedNodeReady(): Promise<unknown> {
  return managedNodeClient().nodeInfo();
}

function managedNodeClient(): ManagedNodeClient {
  if (client) return client;
  const url = requiredEnv("KEYWAY_MANAGED_FIBER_RPC_URL");
  const parsed = new URL(url);
  if (parsed.protocol !== "https:" && parsed.hostname !== "127.0.0.1" && !parsed.hostname.endsWith(".railway.internal")) {
    throw new Error("Managed Fiber RPC must use HTTPS or a private Railway address");
  }
  client = new FiberRpcClient({
    url,
    timeout: 15_000,
    biscuitToken: process.env.KEYWAY_MANAGED_FIBER_RPC_TOKEN,
  });
  return client;
}

function authorize(userId: string, testOverride: boolean): void {
  const owner = testOverride ? userId : requiredEnv("KEYWAY_MANAGED_BETA_USER_ID");
  if (userId !== owner) throw new Error("Managed Fiber is not enabled for this account");
}

function paymentParams(body: Record<string, unknown>): SendPaymentParams {
  if (typeof body.invoice !== "string" || !body.invoice.startsWith("fibt") || body.invoice.length > 4_096) {
    throw new Error("A valid testnet Fiber invoice is required");
  }
  if (body.maxFeeAmount !== undefined && (typeof body.maxFeeAmount !== "string" || !/^0x[0-9a-f]+$/i.test(body.maxFeeAmount))) {
    throw new Error("Maximum fee must be a hexadecimal amount");
  }
  return {
    invoice: body.invoice,
    max_fee_amount: body.maxFeeAmount as `0x${string}` | undefined,
    timeout: "0x1d4c0",
  };
}

function invoiceParams(body: Record<string, unknown>): NewInvoiceParams {
  if (typeof body.amount !== "string" || !/^0x[0-9a-f]+$/i.test(body.amount) || BigInt(body.amount) <= 0n) {
    throw new Error("Invoice amount must be a positive hexadecimal amount");
  }
  if (BigInt(body.amount) > 10_000n * 100_000_000n) throw new Error("Managed beta invoices are limited to 10,000 CKB");
  if (body.description !== undefined && (typeof body.description !== "string" || body.description.length > 160)) {
    throw new Error("Invoice description is too long");
  }
  return {
    amount: body.amount as `0x${string}`,
    currency: "Fibt",
    description: body.description as string | undefined,
    expiry: "0x15180",
  };
}

function confirmationPayload(params: SendPaymentParams): string {
  return JSON.stringify({ managedPayment: params });
}

function closeParams(body: Record<string, unknown>) {
  if (typeof body.channelId !== "string" || !/^0x[0-9a-f]{64}$/i.test(body.channelId)) {
    throw new Error("A valid channel ID is required");
  }
  return { channel_id: body.channelId as ChannelId, force: body.force === true };
}

function closeConfirmationPayload(params: ReturnType<typeof closeParams>): string {
  return JSON.stringify({ managedChannelClose: params });
}

function serializeMutation<T>(operation: () => Promise<T>): Promise<T> {
  const next = mutation.then(operation, operation);
  mutation = next.then(() => undefined, () => undefined);
  return next;
}

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Missing server configuration: ${name}`);
  return value;
}
