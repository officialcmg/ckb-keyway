import {
  FiberRpcClient,
  type ChannelId,
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
import { connectCandidates, TESTNET_CHANNEL_PEERS } from "../sdk/browser/channel-peers.ts";
import { normalizeCkbTransactionForCcc } from "@fiber-pay/sdk/browser";
import { serializeCccTransactionForRpc } from "../sdk/browser/ccc-transaction.ts";
import { DEFAULT_INVOICE_EXPIRY } from "../sdk/browser/invoice-expiry.ts";
import { approveFiberParams, FIBER_METHODS, freeFiberParams, paymentFiberParams, type FiberMethod } from "../sdk/browser/fiber-methods.ts";
import { assertPublicPeerAddress } from "./peer-address.ts";

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
  | "call"
>;

const clients = new Map<string, ManagedNodeClient>();
const mutations = new Map<string, Promise<void>>();

type RpcScript = NonNullable<OpenChannelWithExternalFundingParams["shutdown_script"]>;

export async function managedNodeRequest(
  userId: string,
  body: Record<string, unknown>,
  override?: ManagedNodeClient,
  ownLock?: () => Promise<RpcScript>,
): Promise<unknown> {
  const node = override ?? managedNodeClient(userId);

  if (body.operation === "call") {
    // Free methods from the shared table; anything else is refused before it reaches the node.
    const method = typeof body.method === "string" ? body.method : "";
    // A payment's dry run moves nothing, so it is free; real payments go through the payment flow.
    if ((method === "sendPayment" || method === "sendPaymentWithRouter") && (body.params as { dry_run?: unknown } | undefined)?.dry_run === true) {
      return node.call(FIBER_METHODS[method].rpc, [paymentFiberParams(method, body.params, "testnet")]);
    }
    const params = freeFiberParams(method, body.params, "testnet");
    if (method === "nodeInfo") return publicNodeInfo(await node.nodeInfo());
    const rpc = FIBER_METHODS[method as FiberMethod].rpc;
    const run = () => node.call(rpc, method === "listPeers" ? [] : [params]);
    return ["newInvoice", "settleInvoice", "cancelInvoice"].includes(method) ? serializeMutation(userId, run) : run();
  }
  if (body.operation === "act") {
    // Closes, peers and channel settings, after the user approved them in the page.
    const method = typeof body.method === "string" ? body.method : "";
    if (!["shutdownChannel", "connectPeer", "disconnectPeer", "updateChannel"].includes(method)) {
      throw new Error(`${method} isn't available through KeyWay`);
    }
    const params = approveFiberParams(method, body.params);
    if (method === "connectPeer") {
      if (typeof params.address === "string") await assertPublicPeerAddress(params.address);
      else await assertKnownPublicPeer(node, String(params.pubkey));
      if ((await node.listPeers()).peers.length >= MAX_PEERS) throw new Error(`A hosted node can connect to at most ${MAX_PEERS} peers`);
    }
    await serializeMutation(userId, () => node.call(FIBER_METHODS[method as FiberMethod].rpc, [params]));
    return { done: true };
  }
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
    if (!ownLock) throw new Error("The account's own lock is required to open a channel");
    // Fiber pays the channel out to the shutdown script when it closes, so it must be the user's own lock.
    params.shutdown_script = ownShutdownScript(body.params, await ownLock());
    await connectManagedPeer(node, params.pubkey);
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

/** The user's hosted node, for the payment flow. */
export function managedFiberNode(userId: string): Pick<ManagedNodeClient, "call"> {
  return managedNodeClient(userId);
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
    // The node accepts only tokens on its whitelist; funding signing accepts only standard tokens.
    ...(params.funding_udt_type_script === undefined ? {} : { funding_udt_type_script: script(params.funding_udt_type_script) }),
    shutdown_script: params.shutdown_script === undefined ? undefined as never : script(params.shutdown_script),
    funding_lock_script: script(params.funding_lock_script),
    funding_lock_script_cell_deps: cellDeps(params.funding_lock_script_cell_deps),
    funding_fee_rate: optionalHex(params.funding_fee_rate, "Funding fee rate"),
    commitment_fee_rate: optionalHex(params.commitment_fee_rate, "Commitment fee rate"),
  };
}

function ownShutdownScript(value: unknown, own: RpcScript): RpcScript {
  const requested = (value as { shutdown_script?: unknown } | undefined)?.shutdown_script;
  if (requested === undefined) return own;
  const candidate = script(requested);
  const same = candidate.code_hash.toLowerCase() === own.code_hash.toLowerCase() &&
    candidate.hash_type === own.hash_type && candidate.args.toLowerCase() === own.args.toLowerCase();
  if (!same) throw new Error("Channels can only close to your own KeyWay address");
  return own;
}

function submitFundingParams(value: unknown): SubmitSignedFundingTxParams {
  const params = object(value, "Signed funding parameters are required");
  const transaction = object(params.signed_funding_tx, "Signed funding transaction is required");
  return {
    channel_id: channelId(params.channel_id),
    signed_funding_tx: serializeCccTransactionForRpc(normalizeCkbTransactionForCcc(transaction)),
  };
}

const MAX_PEERS = 32;

/**
 * Connecting by pubkey makes the node dial the addresses the peer announced to the network, so those must
 * be public too. A peer that is already connected, or one of the official peers, needs no check.
 */
async function assertKnownPublicPeer(node: ManagedNodeClient, peer: string): Promise<string[]> {
  const bare = peer.toLowerCase().replace(/^0x/, "");
  if (TESTNET_CHANNEL_PEERS.some(({ pubkey }) => pubkey.slice(2) === bare)) return [];
  if ((await node.listPeers()).peers.some(({ pubkey }) => pubkey.toLowerCase().replace(/^0x/, "") === bare)) return [];
  let after: string | undefined;
  for (let page = 0; page < 8; page++) {
    const result = await node.call<{ nodes: Array<{ pubkey: string; addresses: string[] }>; last_cursor: string }>("graph_nodes", [{ limit: "0x100", ...(after ? { after } : {}) }]);
    const found = result.nodes.find((item) => item.pubkey.toLowerCase().replace(/^0x/, "") === bare);
    if (found) {
      const tcp = found.addresses.filter((address) => /\/tcp\/\d+(\/p2p\/|$)/.test(address) && !/\/(ws|wss)(\/|$)/.test(address));
      if (tcp.length === 0) throw new Error("This peer announces no address a hosted node can reach; pass one with connectPeer");
      for (const address of tcp) await assertPublicPeerAddress(address);
      return tcp;
    }
    if (result.nodes.length < 256) break;
    after = result.last_cursor;
  }
  throw new Error("This peer isn't in the Fiber network graph yet; connect to it first with connectPeer and its address");
}

async function connectManagedPeer(node: ManagedNodeClient, peer: Pubkey): Promise<void> {
  const candidate = TESTNET_CHANNEL_PEERS.find(({ pubkey }) => pubkey === peer.toLowerCase());
  if (!candidate) {
    // Any public peer: its announced addresses must be public, and the handshake must match its key.
    const addresses = await assertKnownPublicPeer(node, peer);
    if (addresses.length === 0) return;
    if ((await connectCandidates(node, [{ pubkey: peer as `0x${string}`, nodeName: "selected peer", addresses, minimumFunding: 0n }], 10_000, 250)).length === 0) {
      throw new Error("Could not connect to the selected Fiber channel peer");
    }
    return;
  }
  // Native nodes resolve current TCP addresses from gossip, not browser WSS seeds.
  let addresses: string[] = [];
  try {
    await node.connectPeer({ pubkey: peer, addr_type: "tcp", save: true });
  } catch {
    // Bootstrap hints may go stale; the handshake still must match the approved key.
    addresses = candidate.nativeAddresses ?? [];
  }
  const nativeCandidate = { ...candidate, addresses };
  if ((await connectCandidates(node, [nativeCandidate], 10_000, 250)).length === 0) {
    throw new Error("Could not connect to the selected Fiber channel peer");
  }
}

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
  if (body.description !== undefined && (typeof body.description !== "string" || body.description.length > 160)) {
    throw new Error("Invoice description is too long");
  }
  return {
    amount: body.amount as `0x${string}`,
    currency: "Fibt",
    description: body.description as string | undefined,
    expiry: invoiceExpiry(body.expiry),
  };
}

function invoiceExpiry(value: unknown): `0x${string}` {
  if (value === undefined) return DEFAULT_INVOICE_EXPIRY;
  if (typeof value !== "string" || !/^0x[0-9a-f]+$/i.test(value) || BigInt(value) < 60n || BigInt(value) > 86_400n) {
    throw new Error("Invoice expiry must be between 60 seconds and 24 hours");
  }
  return value as `0x${string}`;
}

function confirmationPayload(params: SendPaymentParams): string {
  return JSON.stringify({ managedPayment: params });
}

/** The host's internal addresses and the node's own funding lock aren't the app's business. */
function publicNodeInfo<T extends object>(info: T): Omit<T, "addresses" | "default_funding_lock_script"> {
  const { addresses: _addresses, default_funding_lock_script: _lock, ...rest } = info as T & { addresses?: unknown; default_funding_lock_script?: unknown };
  return rest as Omit<T, "addresses" | "default_funding_lock_script">;
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
