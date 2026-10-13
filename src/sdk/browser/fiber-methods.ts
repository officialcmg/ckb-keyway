import { DEFAULT_INVOICE_EXPIRY } from "./invoice-expiry";
import { KeyWayError } from "./keyway-error";

/**
 * Every Fiber node method an app can call through `useFiber().node`, and how KeyWay treats it.
 * The backend (hosted nodes) and the SDK (browser nodes) share this table, so both modes follow the
 * same rules. A method that isn't listed here is refused.
 *
 * - free: reads and invoices. No dialog; money only ever comes in.
 * - payment: no built-in dialog (apps can add `approveFiberPayment`); counts toward the daily amount.
 * - approve: shows a dialog the app can replace.
 * - blocked: never exposed.
 */
export type FiberMethodKind = "free" | "payment" | "approve" | "blocked";

export const FIBER_METHODS = {
  nodeInfo: { rpc: "node_info", kind: "free" },
  listPeers: { rpc: "list_peers", kind: "free" },
  graphNodes: { rpc: "graph_nodes", kind: "free" },
  graphChannels: { rpc: "graph_channels", kind: "free" },
  listChannels: { rpc: "list_channels", kind: "free" },
  getPayment: { rpc: "get_payment", kind: "free" },
  listPayments: { rpc: "list_payments", kind: "free" },
  buildRouter: { rpc: "build_router", kind: "free" },
  newInvoice: { rpc: "new_invoice", kind: "free" },
  getInvoice: { rpc: "get_invoice", kind: "free" },
  parseInvoice: { rpc: "parse_invoice", kind: "free" },
  settleInvoice: { rpc: "settle_invoice", kind: "free" },
  cancelInvoice: { rpc: "cancel_invoice", kind: "free" },
  sendPayment: { rpc: "send_payment", kind: "payment" },
  sendPaymentWithRouter: { rpc: "send_payment_with_router", kind: "payment" },
  openChannelWithExternalFunding: { rpc: "open_channel_with_external_funding", kind: "approve" },
  submitSignedFundingTx: { rpc: "submit_signed_funding_tx", kind: "approve" },
  shutdownChannel: { rpc: "shutdown_channel", kind: "approve" },
  connectPeer: { rpc: "connect_peer", kind: "approve" },
  disconnectPeer: { rpc: "disconnect_peer", kind: "approve" },
  updateChannel: { rpc: "update_channel", kind: "approve" },
  // These spend the node's own internal key instead of the user's account, or discard channel state.
  openChannel: { rpc: "open_channel", kind: "blocked" },
  acceptChannel: { rpc: "accept_channel", kind: "blocked" },
  abandonChannel: { rpc: "abandon_channel", kind: "blocked" },
} as const satisfies Record<string, { rpc: string; kind: FiberMethodKind }>;

export type FiberMethod = keyof typeof FIBER_METHODS;
export type FreeFiberMethod = { [K in FiberMethod]: (typeof FIBER_METHODS)[K]["kind"] extends "free" ? K : never }[FiberMethod];

export const FREE_FIBER_METHODS = (Object.keys(FIBER_METHODS) as FiberMethod[])
  .filter((method): method is FreeFiberMethod => FIBER_METHODS[method].kind === "free");

export type FiberNetwork = "testnet" | "mainnet";

const MAX_GRAPH_PAGE = 256n;
const MAX_PAYMENT_PAGE = 100n;
const MAX_INVOICE_LENGTH = 4096;
const MAX_DESCRIPTION_LENGTH = 640;

/** Refuses anything that isn't a free method, then keeps only the parameters Fiber documents for it, checked. */
export function freeFiberParams(method: string, input: unknown, network: FiberNetwork): Record<string, unknown> {
  if (!isFiberMethod(method) || FIBER_METHODS[method].kind !== "free") {
    throw new KeyWayError("UNSUPPORTED_METHOD", `${method} isn't available through KeyWay`, false);
  }
  const params = input === undefined ? {} : record(input, "Parameters must be an object");
  switch (method) {
    case "nodeInfo":
    case "listPeers":
      return {};
    case "graphNodes":
    case "graphChannels":
      return pick(params, { limit: (value) => cappedHex(value, MAX_GRAPH_PAGE, "limit"), after: hex });
    case "listChannels":
      return pick(params, { pubkey, include_closed: bool, only_pending: bool });
    case "getPayment":
    case "getInvoice":
    case "cancelInvoice":
      return required(pick(params, { payment_hash: hash256 }), ["payment_hash"]);
    case "listPayments":
      return pick(params, {
        status: (value) => oneOf(value, ["Created", "Inflight", "Success", "Failed"], "status"),
        limit: (value) => cappedHex(value, MAX_PAYMENT_PAGE, "limit"),
        after: hash256,
      });
    case "buildRouter":
      return required(pick(params, {
        amount: hex,
        udt_type_script: script,
        hops_info: (value) => list(value, 64, (hop) => required(pick(record(hop, "Each hop must be an object"), { pubkey, channel_outpoint: hex }), ["pubkey"])),
        final_tlc_expiry_delta: hex,
      }), ["hops_info"]);
    case "newInvoice": {
      // A fallback address would let a compromised app send the payer's money somewhere else on-chain.
      if (params.fallback_address !== undefined) throw new Error("Invoices can't set a fallback address");
      const invoice = required(pick(params, {
        amount: hex,
        description: (value) => text(value, MAX_DESCRIPTION_LENGTH, "description"),
        currency: (value) => oneOf(value, [currencyFor(network)], "currency"),
        payment_preimage: hash256,
        payment_hash: hash256,
        expiry: hex,
        final_expiry_delta: hex,
        udt_type_script: script,
        hash_algorithm: (value) => oneOf(value, ["ckb_hash", "sha256"], "hash_algorithm"),
        allow_mpp: bool,
        allow_trampoline_routing: bool,
      }), ["amount"]);
      if (invoice.payment_preimage !== undefined && invoice.payment_hash !== undefined) {
        throw new Error("Pass a payment preimage or, for a hold invoice, a payment hash, not both");
      }
      return { currency: currencyFor(network), expiry: DEFAULT_INVOICE_EXPIRY, ...invoice };
    }
    case "parseInvoice":
      return required(pick(params, { invoice: (value) => invoiceText(value, network) }), ["invoice"]);
    case "settleInvoice":
      return required(pick(params, { payment_hash: hash256, payment_preimage: hash256 }), ["payment_hash", "payment_preimage"]);
    default:
      throw new KeyWayError("UNSUPPORTED_METHOD", `${method} isn't available through KeyWay`, false);
  }
}

export type PaymentFiberMethod = "sendPayment" | "sendPaymentWithRouter";
const MAX_CUSTOM_RECORDS_BYTES = 2048;

/**
 * Checks a payment's parameters: a testnet invoice, or a keysend with an explicit target and amount, or an
 * explicit route, in CKB or a token (`udt_type_script`).
 */
export function paymentFiberParams(method: string, input: unknown, network: FiberNetwork): Record<string, unknown> {
  if (method !== "sendPayment" && method !== "sendPaymentWithRouter") {
    throw new KeyWayError("UNSUPPORTED_METHOD", `${method} isn't available through KeyWay`, false);
  }
  const params = record(input, "Parameters must be an object");
  if (method === "sendPaymentWithRouter") {
    const payment = required(pick(params, {
      payment_hash: hash256,
      router: (value) => list(value, 32, (hop) => required(pick(record(hop, "Each hop must be an object"), {
        target: pubkey, channel_outpoint: hex, amount_received: hex, incoming_tlc_expiry: hex,
      }), ["target", "channel_outpoint", "amount_received", "incoming_tlc_expiry"])),
      invoice: (value) => invoiceText(value, network),
      custom_records: customRecords,
      keysend: bool,
      udt_type_script: script,
      dry_run: bool,
    }), ["router"]);
    if (payment.invoice === undefined && payment.keysend !== true && payment.payment_hash === undefined) {
      throw new Error("Pass an invoice, a payment hash, or keysend: true");
    }
    return payment;
  }
  const payment = pick(params, {
    invoice: (value) => invoiceText(value, network),
    target_pubkey: pubkey,
    amount: hex,
    keysend: bool,
    payment_hash: hash256,
    final_tlc_expiry_delta: hex,
    tlc_expiry_limit: hex,
    timeout: hex,
    max_fee_amount: hex,
    max_fee_rate: hex,
    max_parts: hex,
    trampoline_hops: (value) => list(value, 8, pubkey),
    allow_self_payment: bool,
    udt_type_script: script,
    custom_records: customRecords,
    hop_hints: (value) => list(value, 16, (hint) => required(pick(record(hint, "Each hop hint must be an object"), {
      pubkey, channel_outpoint: hex, fee_rate: hex, tlc_expiry_delta: hex,
    }), ["pubkey", "channel_outpoint", "fee_rate", "tlc_expiry_delta"])),
    dry_run: bool,
  });
  if (payment.invoice === undefined && !(payment.keysend === true && payment.target_pubkey !== undefined && payment.amount !== undefined)) {
    throw new Error("Pass an invoice, or keysend: true with target_pubkey and amount");
  }
  return payment;
}

function customRecords(value: unknown): Record<string, string> {
  const records = record(value, "custom_records must be an object");
  let size = 0;
  for (const [key, data] of Object.entries(records)) {
    hex(key);
    if (typeof data !== "string" || !/^0x(?:[0-9a-f]{2})*$/i.test(data)) throw new Error("custom_records values must be hex bytes");
    size += (data.length - 2) / 2;
  }
  if (size > MAX_CUSTOM_RECORDS_BYTES) throw new Error(`custom_records can hold at most ${MAX_CUSTOM_RECORDS_BYTES} bytes`);
  return records as Record<string, string>;
}

export type ApproveFiberMethod = "openChannelWithExternalFunding" | "shutdownChannel" | "connectPeer" | "disconnectPeer" | "updateChannel";

/** Closing fees: at most 100 times Fiber's default of 1,000 shannons per KB. */
export const MAX_CLOSE_FEE_RATE = 100_000n;
/** Forwarding fees: at most 10% of what a channel forwards. */
export const MAX_FORWARDING_FEE_MILLIONTHS = 100_000n;
/** TLC expiry: at most 14 days, in milliseconds. */
const MAX_TLC_EXPIRY_DELTA = 14n * 24n * 60n * 60n * 1000n;

/**
 * Checks the parameters of methods that show a dialog. KeyWay sets the funding and close scripts itself, so
 * channels always fund from and close back to the user's own account; a custom close address is refused.
 */
export function approveFiberParams(method: string, input: unknown): Record<string, unknown> {
  const params = record(input, "Parameters must be an object");
  switch (method) {
    case "openChannelWithExternalFunding":
      if (params.shutdown_script !== undefined || params.funding_lock_script !== undefined || params.funding_lock_script_cell_deps !== undefined) {
        throw new Error("KeyWay sets the channel's funding and close scripts to the user's own account");
      }
      return required(pick(params, {
        pubkey,
        funding_amount: hex,
        public: bool,
        funding_udt_type_script: script,
        funding_fee_rate: hex,
        commitment_fee_rate: hex,
        tlc_expiry_delta: (value) => cappedHex(value, MAX_TLC_EXPIRY_DELTA, "tlc_expiry_delta"),
        tlc_min_value: hex,
        tlc_fee_proportional_millionths: (value) => cappedHex(value, MAX_FORWARDING_FEE_MILLIONTHS, "tlc_fee_proportional_millionths"),
        max_tlc_value_in_flight: hex,
        max_tlc_number_in_flight: hex,
      }), ["pubkey", "funding_amount"]);
    case "shutdownChannel":
      if (params.close_script !== undefined) throw new Error("Channels close back to the user's own account; a close_script isn't accepted");
      return required(pick(params, {
        channel_id: hash256,
        force: bool,
        fee_rate: (value) => cappedHex(value, MAX_CLOSE_FEE_RATE, "fee_rate"),
      }), ["channel_id"]);
    case "connectPeer": {
      const peer = pick(params, { pubkey, address: multiaddr, addr_type: (value) => oneOf(value, ["tcp", "ws", "wss"], "addr_type") });
      if (peer.pubkey === undefined && peer.address === undefined) throw new Error("Pass a peer pubkey or address");
      // Peers are never saved to the node's permanent peer store on an app's say-so.
      return { ...peer, save: false };
    }
    case "disconnectPeer":
      return required(pick(params, { pubkey }), ["pubkey"]);
    case "updateChannel":
      return required(pick(params, {
        channel_id: hash256,
        enabled: bool,
        tlc_expiry_delta: (value) => cappedHex(value, MAX_TLC_EXPIRY_DELTA, "tlc_expiry_delta"),
        tlc_minimum_value: hex,
        tlc_fee_proportional_millionths: (value) => cappedHex(value, MAX_FORWARDING_FEE_MILLIONTHS, "tlc_fee_proportional_millionths"),
      }), ["channel_id"]);
    default:
      throw new KeyWayError("UNSUPPORTED_METHOD", `${method} isn't available through KeyWay`, false);
  }
}

function multiaddr(value: unknown): string {
  if (typeof value !== "string" || value.length > 512 || !/^\/(ip4|ip6|dns|dns4|dns6)\/[^/]+\/tcp\/\d+(\/(ws|wss|tls\/ws))?(\/p2p\/\w+)?$/.test(value)) {
    throw new Error("Expected a peer multiaddr such as /dns4/host/tcp/443/wss/p2p/Qm…");
  }
  return value;
}

export function isFiberMethod(method: string): method is FiberMethod {
  return Object.prototype.hasOwnProperty.call(FIBER_METHODS, method);
}

export function currencyFor(network: FiberNetwork): "Fibt" | "Fibb" {
  return network === "mainnet" ? "Fibb" : "Fibt";
}

type Check = (value: unknown) => unknown;

function pick(params: Record<string, unknown>, checks: Record<string, Check>): Record<string, unknown> {
  const unknown = Object.keys(params).filter((key) => !(key in checks));
  if (unknown.length) throw new Error(`Unsupported parameter: ${unknown.join(", ")}`);
  const result: Record<string, unknown> = {};
  for (const [key, check] of Object.entries(checks)) {
    if (params[key] !== undefined) result[key] = check(params[key]);
  }
  return result;
}

function required(params: Record<string, unknown>, keys: string[]): Record<string, unknown> {
  for (const key of keys) if (params[key] === undefined) throw new Error(`${key} is required`);
  return params;
}

function record(value: unknown, message: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(message);
  return value as Record<string, unknown>;
}

function hex(value: unknown): string {
  if (typeof value !== "string" || !/^0x[0-9a-f]+$/i.test(value) || value.length > 66) throw new Error("Expected a 0x-prefixed hex number");
  return value;
}

function cappedHex(value: unknown, max: bigint, name: string): string {
  const parsed = hex(value);
  if (BigInt(parsed) > max) throw new Error(`${name} can be at most ${max}`);
  return parsed;
}

function hash256(value: unknown): string {
  if (typeof value !== "string" || !/^0x[0-9a-f]{64}$/i.test(value)) throw new Error("Expected a 32-byte hash");
  return value;
}

/** Fiber node IDs, with or without 0x (browser nodes report them without), passed on with it. */
function pubkey(value: unknown): string {
  if (typeof value !== "string" || !/^(?:0x)?0[23][0-9a-f]{64}$/i.test(value)) throw new Error("Expected a compressed Fiber public key");
  return value.startsWith("0x") ? value : `0x${value}`;
}

function bool(value: unknown): boolean {
  if (typeof value !== "boolean") throw new Error("Expected true or false");
  return value;
}

function text(value: unknown, max: number, name: string): string {
  if (typeof value !== "string" || value.length > max) throw new Error(`${name} must be text of at most ${max} characters`);
  return value;
}

function oneOf<T extends string>(value: unknown, options: readonly T[], name: string): T {
  if (typeof value !== "string" || !options.includes(value as T)) throw new Error(`${name} must be one of: ${options.join(", ")}`);
  return value as T;
}

function list<T>(value: unknown, max: number, item: (entry: unknown) => T): T[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > max) throw new Error(`Expected a list of 1 to ${max} entries`);
  return value.map(item);
}

function script(value: unknown): { code_hash: string; hash_type: string; args: string } {
  const candidate = record(value, "Expected a CKB script");
  if (
    typeof candidate.code_hash !== "string" || !/^0x[0-9a-f]{64}$/i.test(candidate.code_hash) ||
    !["type", "data", "data1", "data2"].includes(String(candidate.hash_type)) ||
    typeof candidate.args !== "string" || !/^0x(?:[0-9a-f]{2})*$/i.test(candidate.args)
  ) throw new Error("Expected a CKB script");
  return { code_hash: candidate.code_hash, hash_type: String(candidate.hash_type), args: candidate.args };
}

function invoiceText(value: unknown, network: FiberNetwork): string {
  const prefix = currencyFor(network).toLowerCase();
  if (typeof value !== "string" || value.length > MAX_INVOICE_LENGTH || !value.toLowerCase().startsWith(prefix)) {
    throw new Error(`Expected a ${network} Fiber invoice`);
  }
  return value;
}
