import {
  FiberRpcClient,
  type ChannelId,
  type CkbTransaction,
  type Hash256,
  type NewInvoiceParams,
  type OpenChannelWithExternalFundingParams,
  type PaymentHash,
  type Pubkey,
  type SendPaymentParams,
  type SubmitSignedFundingTxParams,
} from "@fiber-pay/sdk/node";
import { consumeManagedConfirmation, issueManagedConfirmation } from "./managed-confirmation.ts";
import { toKeyWayError } from "../sdk/browser/keyway-error.ts";

type ManagedNodeClient = Pick<
  FiberRpcClient,
  | "nodeInfo"
  | "connectPeer"
  | "listPeers"
  | "listChannels"
  | "openChannelWithExternalFunding"
  | "submitSignedFundingTx"
  | "waitForChannelReady"
  | "newInvoice"
  | "getInvoice"
  | "parseInvoice"
  | "sendPayment"
  | "getPayment"
  | "waitForPayment"
  | "shutdownChannel"
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
    return {
      node: await node.nodeInfo(),
      peers: (await node.listPeers()).peers,
      network: "testnet",
      custody: "keyway-managed",
    };
  }
  if (body.operation === "list-channels") {
    return node.listChannels({ include_closed: body.includeClosed === true });
  }
  if (body.operation === "new-invoice") {
    const params = invoiceParams(body);
    return serializeMutation(() => node.newInvoice(params));
  }
  if (body.operation === "get-invoice") {
    return node.getInvoice({ payment_hash: paymentHash(body.paymentHash) });
  }
  if (body.operation === "parse-invoice") {
    return node.parseInvoice({ invoice: invoice(body.invoice) });
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
    return serializeMutation(() => node.sendPayment(params));
  }
  if (body.operation === "get-payment") {
    return node.getPayment({ payment_hash: paymentHash(body.paymentHash) });
  }
  if (body.operation === "wait-for-payment") {
    return node.waitForPayment(paymentHash(body.paymentHash), { timeout: 120_000, interval: 2_000 });
  }
  if (body.operation === "open-channel") {
    const params = openChannelParams(body.params);
    await connectManagedPeer(node, params.pubkey);
    return serializeMutation(() => node.openChannelWithExternalFunding(params));
  }
  if (body.operation === "submit-channel-funding") {
    return serializeMutation(() => node.submitSignedFundingTx(submitFundingParams(body.params)));
  }
  if (body.operation === "wait-channel-ready") {
    return node.waitForChannelReady(channelId(body.channelId), { timeout: 180_000, interval: 3_000 });
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
  const paymentInvoice = invoice(body.invoice);
  if (body.maxFeeAmount !== undefined && (typeof body.maxFeeAmount !== "string" || !/^0x[0-9a-f]+$/i.test(body.maxFeeAmount))) {
    throw new Error("Maximum fee must be a hexadecimal amount");
  }
  return {
    invoice: paymentInvoice,
    max_fee_amount: body.maxFeeAmount as `0x${string}` | undefined,
    timeout: "0x1d4c0",
  };
}

function invoice(value: unknown): string {
  if (typeof value !== "string" || !value.startsWith("fibt") || value.length > 4_096) {
    throw new Error("A valid testnet Fiber invoice is required");
  }
  return value;
}

function paymentHash(value: unknown): PaymentHash {
  if (typeof value !== "string" || !/^0x[0-9a-f]{64}$/i.test(value)) {
    throw new Error("A valid payment hash is required");
  }
  return value as Hash256 as PaymentHash;
}

function channelId(value: unknown): ChannelId {
  return paymentHash(value) as ChannelId;
}

function openChannelParams(value: unknown): OpenChannelWithExternalFundingParams {
  const params = object(value, "Channel parameters are required");
  return {
    pubkey: pubkey(params.pubkey),
    funding_amount: positiveHex(params.funding_amount, "Funding amount"),
    public: params.public === undefined ? true : boolean(params.public, "Channel visibility"),
    shutdown_script: script(params.shutdown_script),
    funding_lock_script: script(params.funding_lock_script),
    funding_lock_script_cell_deps: cellDeps(params.funding_lock_script_cell_deps),
    funding_fee_rate: optionalHex(params.funding_fee_rate, "Funding fee rate"),
    commitment_fee_rate: optionalHex(params.commitment_fee_rate, "Commitment fee rate"),
  };
}

function submitFundingParams(value: unknown): SubmitSignedFundingTxParams {
  const params = object(value, "Signed funding parameters are required");
  const transaction = object(params.signed_funding_tx, "Signed funding transaction is required");
  return {
    channel_id: channelId(params.channel_id),
    signed_funding_tx: transaction as CkbTransaction,
  };
}

async function connectManagedPeer(node: ManagedNodeClient, peer: Pubkey): Promise<void> {
  const address = MANAGED_CHANNEL_PEERS.get(peer.toLowerCase());
  if (!address) throw new Error("Managed beta only supports approved testnet channel peers");
  await node.connectPeer({ address, save: true });
}

const MANAGED_CHANNEL_PEERS = new Map<string, string>([
  [
    "0x02b6d4e3ab86a2ca2fad6fae0ecb2e1e559e0b911939872a90abdda6d20302be71",
    "/dns4/bottle.fiber.channel/tcp/443/wss/p2p/QmXen3eUHhywmutEzydCsW4hXBoeVmdET2FJvMX69XJ1Eo",
  ],
  [
    "0x0291a6576bd5a94bd74b27080a48340875338fff9f6d6361fe6b8db8d0d1912fcc",
    "/dns4/bracer.fiber.channel/tcp/443/wss/p2p/QmbKyzq9qUmymW2Gi8Zq7kKVpPiNA1XUJ6uMvsUC4F3p89",
  ],
]);

function pubkey(value: unknown): Pubkey {
  if (typeof value !== "string" || !/^0x0[23][0-9a-f]{64}$/i.test(value)) {
    throw new Error("A valid compressed Fiber peer public key is required");
  }
  return value as Pubkey;
}

function script(value: unknown): OpenChannelWithExternalFundingParams["funding_lock_script"] {
  const candidate = object(value, "A valid CKB script is required");
  if (
    typeof candidate.code_hash !== "string" || !/^0x[0-9a-f]{64}$/i.test(candidate.code_hash) ||
    (candidate.hash_type !== "type" && candidate.hash_type !== "data" && candidate.hash_type !== "data1" && candidate.hash_type !== "data2") ||
    typeof candidate.args !== "string" || !/^0x(?:[0-9a-f]{2})*$/i.test(candidate.args)
  ) throw new Error("A valid CKB script is required");
  return {
    code_hash: candidate.code_hash,
    hash_type: candidate.hash_type,
    args: candidate.args,
  } as OpenChannelWithExternalFundingParams["funding_lock_script"];
}

function cellDeps(value: unknown): OpenChannelWithExternalFundingParams["funding_lock_script_cell_deps"] {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.length > 16) throw new Error("Funding lock cell deps are invalid");
  return value.map((entry) => {
    const dep = object(entry, "Funding lock cell dep is invalid");
    const outPoint = object(dep.out_point, "Funding lock out point is invalid");
    if (
      (dep.dep_type !== "code" && dep.dep_type !== "dep_group") ||
      typeof outPoint.tx_hash !== "string" || !/^0x[0-9a-f]{64}$/i.test(outPoint.tx_hash) ||
      typeof outPoint.index !== "string" || !/^0x[0-9a-f]+$/i.test(outPoint.index)
    ) throw new Error("Funding lock cell dep is invalid");
    return {
      dep_type: dep.dep_type,
      out_point: { tx_hash: outPoint.tx_hash, index: outPoint.index },
    } as NonNullable<OpenChannelWithExternalFundingParams["funding_lock_script_cell_deps"]>[number];
  });
}

function positiveHex(value: unknown, label: string): `0x${string}` {
  if (typeof value !== "string" || !/^0x[0-9a-f]+$/i.test(value) || BigInt(value) <= 0n) {
    throw new Error(`${label} must be a positive hexadecimal amount`);
  }
  return value as `0x${string}`;
}

function optionalHex(value: unknown, label: string): `0x${string}` | undefined {
  return value === undefined ? undefined : positiveHex(value, label);
}

function boolean(value: unknown, label: string): boolean {
  if (typeof value !== "boolean") throw new Error(`${label} must be boolean`);
  return value;
}

function object(value: unknown, message: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(message);
  return value as Record<string, unknown>;
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
