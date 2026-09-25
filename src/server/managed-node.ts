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
import { createHash } from "node:crypto";
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

const clients = new Map<string, ManagedNodeClient>();
const mutations = new Map<string, Promise<void>>();

export async function managedNodeRequest(
  userId: string,
  body: Record<string, unknown>,
  override?: ManagedNodeClient,
): Promise<unknown> {
  const node = override ?? managedNodeClient(userId);

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
    return serializeMutation(userId, () => node.newInvoice(params));
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
    return serializeMutation(userId, () => node.sendPayment(params));
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
    await assertChannelCapacity(node);
    return serializeMutation(userId, () => node.openChannelWithExternalFunding(params));
  }
  if (body.operation === "submit-channel-funding") {
    return serializeMutation(userId, () => node.submitSignedFundingTx(submitFundingParams(body.params)));
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
    await serializeMutation(userId, () => node.shutdownChannel(params));
    return { closed: true };
  }
  throw new Error("Unsupported managed-node operation");
}

export async function managedNodeReady(): Promise<unknown> {
  const ready: unknown[] = [];
  if (process.env.KEYWAY_MANAGED_FIBER_HOST_URL) {
    const response = await fetch(new URL("/readyz", managedHostUrl()), {
      headers: { Authorization: `Bearer ${requiredEnv("KEYWAY_MANAGED_FIBER_HOST_TOKEN")}` },
      signal: AbortSignal.timeout(15_000),
    });
    if (!response.ok) throw new Error(`Managed Fiber host is unavailable (${response.status})`);
    ready.push(await response.json());
  }
  const assignments = managedNodeAssignments(false);
  ready.push(...await Promise.all([...assignments.keys()].map((userId) => managedNodeClient(userId).nodeInfo())));
  if (ready.length === 0) throw new Error("Managed Fiber is not configured");
  return ready;
}

function managedNodeClient(userId: string): ManagedNodeClient {
  const existing = clients.get(userId);
  if (existing) return existing;
  const assignedUrl = managedNodeAssignments(false).get(userId);
  const url = assignedUrl ?? (process.env.KEYWAY_MANAGED_FIBER_HOST_URL
    ? new URL(`/users/${createHash("sha256").update(userId).digest("hex")}`, managedHostUrl()).toString()
    : undefined);
  if (!url) throw new Error("Managed Fiber is not enabled for this account");
  const client = new FiberRpcClient({
    url,
    timeout: 15_000,
    biscuitToken: assignedUrl
      ? process.env.KEYWAY_MANAGED_FIBER_RPC_TOKEN
      : process.env.KEYWAY_MANAGED_FIBER_HOST_TOKEN,
  });
  clients.set(userId, client);
  return client;
}

function managedHostUrl(): string {
  return managedRpcUrl(requiredEnv("KEYWAY_MANAGED_FIBER_HOST_URL"));
}

export function parseManagedNodeAssignments(raw: string): Map<string, string> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("Managed Fiber node assignments must be valid JSON");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Managed Fiber node assignments must be an object");
  }
  const assignments = new Map<string, string>();
  const urls = new Set<string>();
  for (const [userId, value] of Object.entries(parsed)) {
    if (!userId || typeof value !== "string") throw new Error("Managed Fiber node assignment is invalid");
    const url = managedRpcUrl(value);
    if (urls.has(url)) throw new Error("Each managed Fiber user must have a dedicated node");
    assignments.set(userId, url);
    urls.add(url);
  }
  if (assignments.size === 0) throw new Error("At least one managed Fiber node assignment is required");
  return assignments;
}

function managedNodeAssignments(required = true): Map<string, string> {
  const raw = process.env.KEYWAY_MANAGED_FIBER_NODES;
  if (!raw && !required) return new Map();
  return parseManagedNodeAssignments(raw ?? requiredEnv("KEYWAY_MANAGED_FIBER_NODES"));
}

function managedRpcUrl(value: string): string {
  const url = new URL(value);
  if (url.protocol !== "https:" && url.hostname !== "127.0.0.1" && !url.hostname.endsWith(".railway.internal")) {
    throw new Error("Managed Fiber RPC must use HTTPS or a private Railway address");
  }
  return url.toString();
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

async function assertChannelCapacity(node: ManagedNodeClient): Promise<void> {
  const limit = Number(process.env.KEYWAY_MANAGED_MAX_CHANNELS ?? 5);
  if (!Number.isInteger(limit) || limit <= 0) return;
  const { channels } = await node.listChannels({ include_closed: false });
  if (channels.length >= limit) throw new Error(`Managed beta allows at most ${limit} open channels`);
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

function serializeMutation<T>(userId: string, operation: () => Promise<T>): Promise<T> {
  const previous = mutations.get(userId) ?? Promise.resolve();
  const next = previous.then(operation, operation);
  const settled = next.then(() => undefined, () => undefined);
  mutations.set(userId, settled);
  void settled.finally(() => {
    if (mutations.get(userId) === settled) mutations.delete(userId);
  });
  return next;
}

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Missing server configuration: ${name}`);
  return value;
}
