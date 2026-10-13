import type {
  BuildRouterParams,
  BuildRouterResult,
  CancelInvoiceParams,
  CancelInvoiceResult,
  GetInvoiceParams,
  GetInvoiceResult,
  GetPaymentParams,
  GetPaymentResult,
  GraphChannelsParams,
  GraphChannelsResult,
  GraphNodesParams,
  GraphNodesResult,
  HexString,
  ListChannelsParams,
  ListChannelsResult,
  ListPeersResult,
  NewInvoiceParams,
  NewInvoiceResult,
  NodeInfoResult,
  ParseInvoiceParams,
  ParseInvoiceResult,
  PaymentHash,
  SendPaymentParams,
  SendPaymentResult,
  SendPaymentWithRouterParams,
  SettleInvoiceParams,
} from "@fiber-pay/sdk/browser";
import type { FreeFiberMethod, PaymentFiberMethod } from "./fiber-methods";

export type ListPaymentsParams = {
  status?: "Created" | "Inflight" | "Success" | "Failed";
  limit?: HexString;
  /** The payment hash to continue after, from `last_cursor`. */
  after?: PaymentHash;
};
export type ListPaymentsResult = { payments: GetPaymentResult[]; last_cursor?: PaymentHash };
/** Invoice parameters with the currency filled in for the node's network. */
export type KeyWayNewInvoiceParams = Omit<NewInvoiceParams, "currency"> & { currency?: NewInvoiceParams["currency"] };

/**
 * The user's Fiber node, with Fiber's own method names and parameters. Reads and invoices need no
 * approval. Payments have no built-in dialog (pass `approveFiberPayment` to add one) and count toward the
 * user's daily email-confirmation amount. Methods KeyWay doesn't expose aren't here and are refused.
 */
export type KeyWayFiberNode = {
  nodeInfo(): Promise<NodeInfoResult>;
  listPeers(): Promise<ListPeersResult>;
  graphNodes(params?: GraphNodesParams): Promise<GraphNodesResult>;
  graphChannels(params?: GraphChannelsParams): Promise<GraphChannelsResult>;
  listChannels(params?: ListChannelsParams): Promise<ListChannelsResult>;
  getPayment(params: GetPaymentParams): Promise<GetPaymentResult>;
  listPayments(params?: ListPaymentsParams): Promise<ListPaymentsResult>;
  buildRouter(params: BuildRouterParams): Promise<BuildRouterResult>;
  newInvoice(params: KeyWayNewInvoiceParams): Promise<NewInvoiceResult>;
  getInvoice(params: GetInvoiceParams): Promise<GetInvoiceResult>;
  parseInvoice(params: ParseInvoiceParams): Promise<ParseInvoiceResult>;
  settleInvoice(params: SettleInvoiceParams): Promise<void>;
  cancelInvoice(params: CancelInvoiceParams): Promise<CancelInvoiceResult>;
  /** Pays an invoice, or sends a keysend payment. `dry_run: true` only estimates the fee. */
  sendPayment(params: SendPaymentParams): Promise<SendPaymentResult>;
  /** Pays over an explicit route from `buildRouter`. */
  sendPaymentWithRouter(params: SendPaymentWithRouterParams): Promise<SendPaymentResult>;
};

export type FiberCall = (method: FreeFiberMethod, params?: unknown) => Promise<unknown>;
export type FiberPay = (method: PaymentFiberMethod, params: unknown) => Promise<unknown>;

export function createFiberNode(call: FiberCall, pay: FiberPay): KeyWayFiberNode {
  const invoke = <T>(method: FreeFiberMethod) => (params?: unknown) => call(method, params) as Promise<T>;
  return {
    nodeInfo: () => call("nodeInfo") as Promise<NodeInfoResult>,
    listPeers: () => call("listPeers") as Promise<ListPeersResult>,
    graphNodes: invoke<GraphNodesResult>("graphNodes"),
    graphChannels: invoke<GraphChannelsResult>("graphChannels"),
    listChannels: invoke<ListChannelsResult>("listChannels"),
    getPayment: invoke<GetPaymentResult>("getPayment"),
    listPayments: invoke<ListPaymentsResult>("listPayments"),
    buildRouter: invoke<BuildRouterResult>("buildRouter"),
    newInvoice: invoke<NewInvoiceResult>("newInvoice"),
    getInvoice: invoke<GetInvoiceResult>("getInvoice"),
    parseInvoice: invoke<ParseInvoiceResult>("parseInvoice"),
    settleInvoice: invoke<void>("settleInvoice"),
    cancelInvoice: invoke<CancelInvoiceResult>("cancelInvoice"),
    sendPayment: (params) => pay("sendPayment", params) as Promise<SendPaymentResult>,
    sendPaymentWithRouter: (params) => pay("sendPaymentWithRouter", params) as Promise<SendPaymentResult>,
  };
}

/** Pages through the SDK's own payment log for browser nodes, which have no `list_payments`. */
export async function listLoggedPayments(
  hashes: string[],
  params: ListPaymentsParams,
  getPayment: (params: GetPaymentParams) => Promise<GetPaymentResult>,
): Promise<ListPaymentsResult> {
  const limit = params.limit === undefined ? 15 : Number(BigInt(params.limit));
  const start = params.after ? hashes.indexOf(params.after) + 1 : 0;
  const payments: GetPaymentResult[] = [];
  let cursor: string | undefined;
  for (const hash of hashes.slice(Math.max(0, start))) {
    if (payments.length >= limit) break;
    cursor = hash;
    const payment = await getPayment({ payment_hash: hash as PaymentHash }).catch(() => undefined);
    if (payment && (!params.status || payment.status === params.status)) payments.push(payment);
  }
  return { payments, last_cursor: cursor as PaymentHash | undefined };
}
