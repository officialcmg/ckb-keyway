import * as ccc from "@ckb-ccc/core";
import {
  cccScriptToFiberScript,
  createCccExternalFundingResolver,
  getLockBalanceShannons,
  openChannelWithExternalFundingFlow,
  type Channel,
  type ChannelId,
  type GetInvoiceParams,
  type GetInvoiceResult,
  type GetPaymentParams,
  type GetPaymentResult,
  type ListChannelsParams,
  type ListChannelsResult,
  type NewInvoiceParams,
  type NewInvoiceResult,
  type NodeInfoResult,
  type OpenChannelWithExternalFundingParams,
  type OpenChannelWithExternalFundingResult,
  type ParseInvoiceParams,
  type ParseInvoiceResult,
  type PaymentHash,
  type SendPaymentParams,
  type SendPaymentResult,
  type SubmitSignedFundingTxParams,
  type SubmitSignedFundingTxResult,
} from "@fiber-pay/sdk/browser";
import { KeyWayApiClient } from "./api-client";
import { ANY_FUNDING, TESTNET_CHANNEL_PEERS } from "./channel-peers";
import {
  normalizeChannel,
  type ChannelOpenProgress,
  type KeyWayChannel,
  type KeyWayFundingParams,
  type OpenKeyWayChannelOptions,
  type PaymentEstimate,
} from "./create-keyway";
import { createFiberNode } from "./fiber-node";
import { approveFiberParams, type PaymentFiberMethod } from "./fiber-methods";
import { createFiberActions, type FiberActionApprovals } from "./fiber-actions";
import type { ApproveFiberPayment, FiberPaymentPreview } from "./fiber-payment";
import { withEmailCode, type RequestEmailCode } from "./email-code";
import { normalizeFiberPubkey } from "./fiber-pubkey";
import { RemoteCkbSigner, type ApproveFiberChannelOpen } from "./remote-ckb-signer";
import { serializeCccTransactionForRpc } from "./ccc-transaction";
import { toKeyWayError } from "./keyway-error";
import { createFeeReserve, FEE_RESERVE } from "./fee-reserve";

type ManagedStatus = {
  node: NodeInfoResult;
  peers: Array<{ pubkey: string }>;
  network: "testnet";
  custody: "keyway-managed";
};

const DEFAULT_CHANNEL_FUNDING = 1_000n * 100_000_000n;

export function createManagedKeyWay(options: {
  authToken: string;
  ckbPublicKey: string;
  approveFiberChannelOpen: ApproveFiberChannelOpen;
  /** The app's own payment confirmation, if any. KeyWay draws no payment dialog. */
  approveFiberPayment?: ApproveFiberPayment;
  requestEmailCode?: RequestEmailCode;
  approvals?: () => FiberActionApprovals;
  apiClient?: KeyWayApiClient;
}) {
  let openingPeer: string | undefined;
  let openingWithReserve = false;
  const api = options.apiClient ?? new KeyWayApiClient();
  const fundingSigner = new RemoteCkbSigner(
    options.authToken,
    options.ckbPublicKey,
    (preview) => options.approveFiberChannelOpen({
      ...preview,
      ...(openingPeer ? { peer: openingPeer } : {}),
      ...(openingWithReserve ? { feeReserveCkb: ccc.fixedPointToString(FEE_RESERVE) } : {}),
    }),
    undefined,
    api,
  );
  // The hosted node settles force-closed channels with its own key, so the reserve goes there.
  const feeReserve = createFeeReserve({
    authToken: options.authToken,
    ckbPublicKey: options.ckbPublicKey,
    api,
    requestEmailCode: options.requestEmailCode,
    client: fundingSigner.client,
    lock: async () => {
      const { lockScript } = await api.managedNode<{ lockScript: { code_hash: string; hash_type: ccc.HashTypeLike; args: string } }>(options.authToken, { operation: "fee-reserve" });
      return { codeHash: lockScript.code_hash, hashType: lockScript.hash_type, args: lockScript.args };
    },
  });
  const resolveExternalFunding = createCccExternalFundingResolver({
    signer: fundingSigner,
    knownScripts: [ccc.KnownScript.Secp256k1Blake160],
    ckbRpcUrl: "https://testnet.ckb.dev/",
    signFundingTxOptions: { toRpcTransaction: serializeCccTransactionForRpc },
  });
  let running = false;
  let status: ManagedStatus | undefined;

  async function start(): Promise<NodeInfoResult> {
    status = await api.managedNode<ManagedStatus>(options.authToken, { operation: "status" });
    running = true;
    return status.node;
  }

  async function stop(): Promise<void> {
    running = false;
  }

  async function listChannels(params: ListChannelsParams = {}): Promise<ListChannelsResult> {
    return api.managedNode(options.authToken, {
      operation: "list-channels",
      includeClosed: params.include_closed === true,
    });
  }

  async function getChannels(params?: { includeClosed?: boolean }): Promise<KeyWayChannel[]> {
    return (await listChannels({ include_closed: params?.includeClosed })).channels.map(normalizeChannel);
  }

  async function openChannelWithExternalFunding(
    params: OpenChannelWithExternalFundingParams,
  ): Promise<OpenChannelWithExternalFundingResult> {
    return api.managedNode(
      options.authToken,
      { operation: "open-channel", params },
      crypto.randomUUID(),
    );
  }

  async function submitSignedFundingTx(
    params: SubmitSignedFundingTxParams,
  ): Promise<SubmitSignedFundingTxResult> {
    return api.managedNode(
      options.authToken,
      { operation: "submit-channel-funding", params },
      crypto.randomUUID(),
    );
  }

  async function openFundedChannel(params: KeyWayFundingParams) {
    openingPeer = params.pubkey;
    openingWithReserve = await feeReserve.needed();
    const funding = await resolveExternalFunding(undefined);
    const result = await openChannelWithExternalFundingFlow({
      node: { openChannelWithExternalFunding, submitSignedFundingTx },
      params: {
        ...params,
        shutdown_script: funding.shutdownScript,
        funding_lock_script: funding.fundingLockScript,
        funding_lock_script_cell_deps: funding.fundingLockScriptCellDeps,
      },
      signFundingTx: funding.signFundingTx,
    });
    const feeReserveTxHash = openingWithReserve ? await feeReserve.send(result.fundingTxHash) : undefined;
    return { ...result, ...(feeReserveTxHash ? { feeReserveTxHash } : {}) };
  }

  async function prepareCkbChannel(fundingAmount: bigint) {
    const peers = TESTNET_CHANNEL_PEERS.filter(({ minimumFunding }) => minimumFunding <= fundingAmount);
    if (peers.length === 0) throw new Error("No managed Fiber peer accepts this channel amount");
    return peers;
  }

  async function activateCkbChannel(
    input: bigint | OpenKeyWayChannelOptions = DEFAULT_CHANNEL_FUNDING,
    onProgress?: ChannelOpenProgress,
  ) {
    const config: OpenKeyWayChannelOptions = typeof input === "bigint" ? { fundingAmount: input } : input;
    if (config.udtTypeScript && config.fundingAmount === undefined) throw new Error("A token channel needs a fundingAmount");
    const fundingAmount = config.fundingAmount ?? DEFAULT_CHANNEL_FUNDING;
    onProgress?.("connecting");
    const peer = config.peer
      ? normalizeFiberPubkey(config.peer)
      // The official peers' minimums are in CKB, so any of them will do for a token channel.
      : (await prepareCkbChannel(config.udtTypeScript ? ANY_FUNDING : fundingAmount))[0].pubkey;
    onProgress?.("negotiating");
    const result = await openFundedChannel({
      pubkey: peer,
      funding_amount: toHex(fundingAmount),
      public: config.public ?? true,
      ...(config.udtTypeScript ? { funding_udt_type_script: config.udtTypeScript } : {}),
      funding_fee_rate: config.fundingFeeRate === undefined ? undefined : toHex(config.fundingFeeRate),
      commitment_fee_rate: config.commitmentFeeRate === undefined ? undefined : toHex(config.commitmentFeeRate),
    });
    onProgress?.("broadcasting");
    return result;
  }

  async function waitForChannelReady(channelId: ChannelId): Promise<Channel> {
    return api.managedNode(options.authToken, { operation: "wait-channel-ready", channelId });
  }

  async function closeChannel(channelId: ChannelId, closeOptions?: { force?: boolean; feeRate?: bigint }): Promise<void> {
    await fiberNode.shutdownChannel({
      channel_id: channelId,
      ...(closeOptions?.force ? { force: true } : {}),
      ...(closeOptions?.feeRate === undefined ? {} : { fee_rate: toHex(closeOptions.feeRate) }),
    });
  }

  // Free methods go through the backend's copy of the shared method table; payments through its payment flow.
  const call = (method: string, params?: unknown) => api.managedNode(options.authToken, { operation: "call", method, params });
  const fiberNode = createFiberNode(call, pay, createFiberActions({
    listChannels,
    act: (method, params) => api.managedNode(options.authToken, { operation: "act", method, params }, crypto.randomUUID()),
  }, () => options.approvals?.() ?? {}), (input) => {
    const params = approveFiberParams("openChannelWithExternalFunding", input) as unknown as KeyWayFundingParams;
    return openFundedChannel(params).then(({ channelId, fundingTxHash }) => ({ channelId, fundingTxHash }));
  });

  async function pay(method: PaymentFiberMethod, params: unknown): Promise<unknown> {
    if ((params as { dry_run?: unknown } | undefined)?.dry_run === true) return call(method, params);
    const reviewed = await api.managedNode<{ preview: FiberPaymentPreview; confirmationNonce: string; requiresEmailCode: boolean }>(
      options.authToken, { operation: "pay", stage: "preview", method, params },
    );
    if (options.approveFiberPayment && !await options.approveFiberPayment(reviewed.preview)) throw new Error("The payment was not approved");
    const base = { operation: "pay", method, params, confirmationNonce: reviewed.confirmationNonce };
    const send = (emailCode?: string) => api.managedNode(options.authToken, { ...base, stage: "send", ...(emailCode ? { emailCode } : {}) }, crypto.randomUUID());
    if (!reviewed.requiresEmailCode) return send();
    if (!options.requestEmailCode) throw new Error("This payment needs an email code");
    return withEmailCode(options.requestEmailCode, "payment", () => api.managedNode(options.authToken, { ...base, stage: "request-email-code" }).then(() => undefined), send);
  }

  function newInvoice(params: Omit<NewInvoiceParams, "currency"> & { currency?: NewInvoiceParams["currency"] }): Promise<NewInvoiceResult> {
    return fiberNode.newInvoice(params);
  }

  async function parseInvoice(params: ParseInvoiceParams): Promise<ParseInvoiceResult> {
    return api.managedNode(options.authToken, { operation: "parse-invoice", invoice: params.invoice });
  }

  async function getInvoice(params: GetInvoiceParams): Promise<GetInvoiceResult> {
    return api.managedNode(options.authToken, { operation: "get-invoice", paymentHash: params.payment_hash });
  }

  async function estimatePayment(params: Omit<SendPaymentParams, "dry_run">): Promise<PaymentEstimate> {
    try {
      const result = await fiberNode.sendPayment({ ...params, dry_run: true });
      return { routable: true, fee: BigInt(result.fee) };
    } catch (error) {
      return { routable: false, error: toKeyWayError(error, "PAYMENT_FAILED") };
    }
  }

  async function sendPayment(params: SendPaymentParams): Promise<SendPaymentResult> {
    try {
      return await fiberNode.sendPayment(params);
    } catch (error) {
      throw toKeyWayError(error, "PAYMENT_FAILED");
    }
  }

  async function getPayment(params: GetPaymentParams): Promise<GetPaymentResult> {
    return api.managedNode(options.authToken, { operation: "get-payment", paymentHash: params.payment_hash });
  }

  async function waitForPayment(paymentHash: PaymentHash): Promise<GetPaymentResult> {
    return api.managedNode(options.authToken, { operation: "wait-for-payment", paymentHash });
  }

  async function getCkbBalance(): Promise<bigint> {
    const address = await fundingSigner.getRecommendedAddressObj();
    return getLockBalanceShannons("https://testnet.ckbapp.dev/", cccScriptToFiberScript(address.script));
  }

  return {
    node: fiberNode,
    start,
    stop,
    stopForLogout: stop,
    nodeInfo: async () => status?.node ?? start(),
    listChannels,
    getChannels,
    closeChannel,
    waitForChannelReady,
    newInvoice,
    getInvoice,
    parseInvoice,
    estimatePayment,
    sendPayment,
    getPayment,
    waitForPayment,
    openFundedChannel,
    prepareCkbChannel,
    activateCkbChannel,
    getCkbBalance,
    openChannelWithExternalFunding,
    submitSignedFundingTx,
    get state() { return running ? "running" : "stopped"; },
    get isRunning() { return running; },
  };
}

function toHex(value: bigint): `0x${string}` {
  return `0x${value.toString(16)}`;
}

export type ManagedKeyWay = ReturnType<typeof createManagedKeyWay>;
