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
import { TESTNET_CHANNEL_PEERS } from "./channel-peers";
import {
  normalizeChannel,
  type ActivationProgress,
  type KeyWayChannel,
  type KeyWayFundingParams,
  type OpenKeyWayChannelOptions,
  type PaymentPreflight,
} from "./create-keyway";
import { normalizeFiberPubkey } from "./fiber-pubkey";
import { RemoteCkbSigner, type ConfirmFunding } from "./remote-ckb-signer";
import { serializeCccTransaction } from "./ccc-transaction";
import { toKeyWayError } from "./keyway-error";

type ManagedStatus = {
  node: NodeInfoResult;
  peers: Array<{ pubkey: string }>;
  network: "testnet";
  custody: "keyway-managed";
};

type ManagedPreflight =
  | { routable: true; fee: string; confirmationNonce: string }
  | { routable: false; error: { code: string; message: string; retryable: boolean } };

const DEFAULT_CHANNEL_FUNDING = 1_000n * 100_000_000n;

export function createManagedKeyWay(options: {
  authToken: string;
  ckbPublicKey: string;
  confirmFunding: ConfirmFunding;
  apiClient?: KeyWayApiClient;
}) {
  const api = options.apiClient ?? new KeyWayApiClient();
  const fundingSigner = new RemoteCkbSigner(
    options.authToken,
    options.ckbPublicKey,
    options.confirmFunding,
    undefined,
    api,
  );
  const resolveExternalFunding = createCccExternalFundingResolver({
    signer: fundingSigner,
    knownScripts: [ccc.KnownScript.Secp256k1Blake160],
    ckbRpcUrl: "https://testnet.ckb.dev/",
    signFundingTxOptions: { toRpcTransaction: serializeCccTransaction },
  });
  let running = false;
  let status: ManagedStatus | undefined;
  let paymentConfirmation: { payload: string; nonce: string } | undefined;

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
    const funding = await resolveExternalFunding(undefined);
    return openChannelWithExternalFundingFlow({
      node: { openChannelWithExternalFunding, submitSignedFundingTx },
      params: {
        ...params,
        shutdown_script: funding.shutdownScript,
        funding_lock_script: funding.fundingLockScript,
        funding_lock_script_cell_deps: funding.fundingLockScriptCellDeps,
      },
      signFundingTx: funding.signFundingTx,
    });
  }

  async function prepareCkbChannel(fundingAmount: bigint) {
    const peers = TESTNET_CHANNEL_PEERS.filter(({ minimumFunding }) => minimumFunding <= fundingAmount);
    if (peers.length === 0) throw new Error("No managed Fiber peer accepts this channel amount");
    return peers;
  }

  async function activateCkbChannel(
    input: bigint | OpenKeyWayChannelOptions = DEFAULT_CHANNEL_FUNDING,
    onProgress?: ActivationProgress,
  ) {
    const config = typeof input === "bigint" ? { fundingAmount: input } : input;
    const fundingAmount = config.fundingAmount ?? DEFAULT_CHANNEL_FUNDING;
    onProgress?.("connecting");
    const peer = config.peer
      ? normalizeFiberPubkey(config.peer)
      : (await prepareCkbChannel(fundingAmount))[0].pubkey;
    onProgress?.("negotiating");
    const result = await openFundedChannel({
      pubkey: peer,
      funding_amount: toHex(fundingAmount),
      public: config.public ?? true,
      funding_fee_rate: config.fundingFeeRate === undefined ? undefined : toHex(config.fundingFeeRate),
      commitment_fee_rate: config.commitmentFeeRate === undefined ? undefined : toHex(config.commitmentFeeRate),
    });
    onProgress?.("broadcasting");
    return result;
  }

  async function waitForChannelReady(channelId: ChannelId): Promise<Channel> {
    return api.managedNode(options.authToken, { operation: "wait-channel-ready", channelId });
  }

  async function closeChannel(channelId: ChannelId, closeOptions?: { force?: boolean }): Promise<void> {
    const prepared = await api.managedNode<{ confirmationNonce: string }>(options.authToken, {
      operation: "prepare-close-channel",
      channelId,
      force: closeOptions?.force,
    });
    await api.managedNode(options.authToken, {
      operation: "close-channel",
      channelId,
      force: closeOptions?.force,
      confirmationNonce: prepared.confirmationNonce,
    }, crypto.randomUUID());
  }

  async function newInvoice(params: NewInvoiceParams): Promise<NewInvoiceResult> {
    return api.managedNode(options.authToken, {
      operation: "new-invoice",
      amount: params.amount,
      description: params.description,
    }, crypto.randomUUID());
  }

  async function parseInvoice(params: ParseInvoiceParams): Promise<ParseInvoiceResult> {
    return api.managedNode(options.authToken, { operation: "parse-invoice", invoice: params.invoice });
  }

  async function getInvoice(params: GetInvoiceParams): Promise<GetInvoiceResult> {
    return api.managedNode(options.authToken, { operation: "get-invoice", paymentHash: params.payment_hash });
  }

  async function preflightPayment(params: Omit<SendPaymentParams, "dry_run">): Promise<PaymentPreflight> {
    try {
      const result = await managedPreflight(params);
      if (!result.routable) {
        return { routable: false, error: toKeyWayError(new Error(result.error.message), "PAYMENT_FAILED") };
      }
      paymentConfirmation = { payload: paymentPayload(params), nonce: result.confirmationNonce };
      return { routable: true, feeShannons: BigInt(result.fee) };
    } catch (error) {
      return { routable: false, error: toKeyWayError(error, "PAYMENT_FAILED") };
    }
  }

  async function sendPayment(params: SendPaymentParams): Promise<SendPaymentResult> {
    const payload = paymentPayload(params);
    if (paymentConfirmation?.payload !== payload) {
      const preflight = await managedPreflight(params);
      if (!preflight.routable) throw toKeyWayError(new Error(preflight.error.message), "PAYMENT_FAILED");
      paymentConfirmation = { payload, nonce: preflight.confirmationNonce };
    }
    const nonce = paymentConfirmation.nonce;
    paymentConfirmation = undefined;
    return api.managedNode(options.authToken, {
      operation: "send-payment",
      invoice: requiredInvoice(params),
      maxFeeAmount: params.max_fee_amount,
      confirmationNonce: nonce,
    }, crypto.randomUUID());
  }

  async function getPayment(params: GetPaymentParams): Promise<GetPaymentResult> {
    return api.managedNode(options.authToken, { operation: "get-payment", paymentHash: params.payment_hash });
  }

  async function waitForPayment(paymentHash: PaymentHash): Promise<GetPaymentResult> {
    return api.managedNode(options.authToken, { operation: "wait-for-payment", paymentHash });
  }

  async function managedPreflight(params: Omit<SendPaymentParams, "dry_run">): Promise<ManagedPreflight> {
    return api.managedNode(options.authToken, {
      operation: "preflight-payment",
      invoice: requiredInvoice(params),
      maxFeeAmount: params.max_fee_amount,
    });
  }

  async function getCkbBalance(): Promise<bigint> {
    const address = await fundingSigner.getRecommendedAddressObj();
    return getLockBalanceShannons("https://testnet.ckbapp.dev/", cccScriptToFiberScript(address.script));
  }

  return {
    start,
    stop,
    stopForLogout: stop,
    nodeInfo: async () => status?.node ?? start(),
    listChannels,
    getChannels,
    shutdownChannel: ({ channel_id, force }: { channel_id: ChannelId; force?: boolean }) => closeChannel(channel_id, { force }),
    closeChannel,
    waitForChannelReady,
    newInvoice,
    getInvoice,
    parseInvoice,
    preflightPayment,
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

function requiredInvoice(params: SendPaymentParams): string {
  if (typeof params.invoice !== "string") throw new Error("Managed payments require a Fiber invoice");
  return params.invoice;
}

function paymentPayload(params: SendPaymentParams): string {
  return JSON.stringify({ invoice: requiredInvoice(params), maxFeeAmount: params.max_fee_amount });
}

function toHex(value: bigint): `0x${string}` {
  return `0x${value.toString(16)}`;
}

export type ManagedKeyWay = ReturnType<typeof createManagedKeyWay>;
