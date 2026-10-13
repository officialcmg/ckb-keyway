import * as ccc from "@ckb-ccc/core";
import {
  createCccExternalFundingResolver,
  cccScriptToFiberScript,
  FiberBrowserNode,
  getLockBalanceShannons,
  openChannelWithExternalFundingFlow,
  shouldDiagnoseFundingAbortError,
  type Channel,
  type ChannelId,
  type NewInvoiceParams,
  type OpenChannelWithExternalFundingParams,
  type Script,
  type SendPaymentParams,
} from "@fiber-pay/sdk/browser";
import { KeyWayCredentialProvider, type FiberKeyLoader } from "./credential-provider";
import { acquireDeviceLock, type DeviceLock } from "./device-lock";
import { acquireDeviceLease, type DeviceLease } from "./device-lease";
import { serializeCccTransactionForRpc } from "./ccc-transaction";
import { RemoteCkbSigner, type ApproveFiberChannelOpen } from "./remote-ckb-signer";
import { getDeviceIdHash, markChannelOpened } from "./bootstrap";
import { ANY_FUNDING, connectChannelPeers, type ChannelPeer } from "./channel-peers";
import { normalizeFiberPubkey } from "./fiber-pubkey";
import { KeyWayApiClient } from "./api-client";
import { createEncryptedNodeBackup, restoreEncryptedNodeBackup } from "./node-backup";
import { backUpBeforeLogout, restoreBeforeStart } from "./node-migration";
import { toKeyWayError, type KeyWayError } from "./keyway-error";
import { freeFiberParams, paymentFiberParams } from "./fiber-methods";
import { describePayment, type ApproveFiberPayment } from "./fiber-payment";
import { createFiberNode, listLoggedPayments, type ListPaymentsParams } from "./fiber-node";
import { createPaymentLog } from "./payment-log";

export type KeyWayFundingParams = Omit<
  OpenChannelWithExternalFundingParams,
  "funding_lock_script" | "funding_lock_script_cell_deps" | "shutdown_script"
>;

export type CreateKeyWayOptions = {
  identifier: string;
  authToken: string;
  ckbPublicKey: string;
  approveFiberChannelOpen: ApproveFiberChannelOpen;
  /** The app's own payment confirmation, if any. KeyWay draws no payment dialog. */
  approveFiberPayment?: ApproveFiberPayment;
  loadFiberKey: (leaseId: string) => ReturnType<FiberKeyLoader>;
  network?: "testnet" | "mainnet";
  apiClient?: KeyWayApiClient;
  restoreRequired?: boolean;
  onLeaseLost?: (error: Error) => void;
  onFiberStartup?: (stage: BrowserNodeStage) => void;
};

export type ChannelOpenStage = "connecting" | "negotiating" | "confirming" | "signing" | "broadcasting" | "waiting";
export type ChannelOpenProgress = (stage: ChannelOpenStage) => void;
export type BrowserNodeStage = "claiming_device" | "restoring_channels" | "starting_browser_node";
export type OpenKeyWayChannelOptions = {
  /** Shannons for a CKB channel (default 1,000 CKB), or the token's smallest unit for a token channel. */
  fundingAmount?: bigint;
  /** Opens a token channel instead, for a token the peer accepts (on testnet, RUSD). Requires `fundingAmount`. */
  udtTypeScript?: Script;
  peer?: string;
  public?: boolean;
  fundingFeeRate?: bigint;
  commitmentFeeRate?: bigint;
};
export type KeyWayChannelStatus = "pending" | "ready" | "closing" | "closed" | "failed" | "unknown";
/** The asset a channel or payment moves: CKB, or a token identified by its type script. */
export type KeyWayAsset = { kind: "ckb" } | { kind: "token"; typeScript: Script };
export type KeyWayChannel = {
  id: ChannelId;
  peer: string;
  status: KeyWayChannelStatus;
  asset: KeyWayAsset;
  /** What the user can still send through this channel, in the asset's smallest unit (shannons for CKB). */
  canSend: bigint;
  /** What the user can still receive through this channel. */
  canReceive: bigint;
  /** The channel's total size: canSend plus canReceive. */
  capacity: bigint;
  public: boolean;
  raw: Channel;
};
export type PaymentEstimate =
  | { routable: true; fee: bigint }
  | { routable: false; error: KeyWayError };

const DEFAULT_CHANNEL_FUNDING = 1_000n * 100_000_000n;

export function createKeyWay(options: CreateKeyWayOptions) {
  let deviceLease: DeviceLease | undefined;
  const credential = new KeyWayCredentialProvider(options.identifier, () => {
    if (!deviceLease) throw new Error("An active device lease is required");
    return options.loadFiberKey(deviceLease.leaseId);
  });
  const node = new FiberBrowserNode({
    network: options.network ?? "testnet",
    credential,
  });
  let deviceLock: DeviceLock | undefined;
  const api = options.apiClient ?? new KeyWayApiClient();
  let activationProgress: ChannelOpenProgress | undefined;
  let preparedPeers: Promise<ChannelPeer[]> | undefined;
  let preparedFundingAmount: bigint | undefined;
  const fundingSigner = new RemoteCkbSigner(options.authToken, options.ckbPublicKey, async (preview) => {
    activationProgress?.("confirming");
    const approved = await options.approveFiberChannelOpen(preview);
    if (approved) activationProgress?.("signing");
    return approved;
  }, undefined, api);
  const resolveExternalFunding = createCccExternalFundingResolver({
    signer: fundingSigner,
    knownScripts: [ccc.KnownScript.Secp256k1Blake160],
    ckbRpcUrl: "https://testnet.ckb.dev/",
    // fiber-pay normalizes field names, but CCC must first serialize bigint fields to CKB RPC hex.
    signFundingTxOptions: { toRpcTransaction: serializeCccTransactionForRpc },
  });
  const ckbRpcUrl = "https://testnet.ckbapp.dev/";
  const databasePrefix = `/wasm-${options.identifier}`;
  const paymentLog = createPaymentLog(databasePrefix);
  let restoreRequired = options.restoreRequired ?? false;

  async function start() {
    if (node.isRunning) return node.nodeInfo();
    if (typeof window !== "undefined" && window.crossOriginIsolated !== true) {
      throw toKeyWayError(new Error("Cross-origin isolated browser context is required"));
    }
    options.onFiberStartup?.("claiming_device");
    deviceLock = await acquireDeviceLock(options.identifier);
    try {
      deviceLease = await acquireDeviceLease(options.authToken, api, (cause) => {
        const error = cause instanceof Error ? cause : new Error("The active KeyWay device lease expired");
        void stop().finally(() => options.onLeaseLost?.(error));
      });
      if (restoreRequired) {
        options.onFiberStartup?.("restoring_channels");
        await restoreClaimedBackup();
      }
      options.onFiberStartup?.("starting_browser_node");
      return await node.start();
    } catch (error) {
      await releaseGuards();
      throw error;
    }
  }

  async function stop() {
    try {
      await node.stop();
    } finally {
      preparedPeers = undefined;
      preparedFundingAmount = undefined;
      await releaseGuards();
    }
  }

  async function stopForLogout() {
    if (!deviceLease) {
      await stop();
      return;
    }
    const lease = deviceLease;
    const deviceIdHash = await getDeviceIdHash();
    await backUpBeforeLogout({
      loadFiberKey: () => options.loadFiberKey(lease.leaseId),
      stopNode: () => node.stop(),
      createBackup: (fiberKey) => createEncryptedNodeBackup(databasePrefix, fiberKey),
      saveBackup: (backup) => api.saveNodeBackup(options.authToken, {
        deviceIdHash,
        leaseId: lease.leaseId,
        backup,
      }),
      releaseOwnership: releaseGuards,
    });
  }

  async function restoreClaimedBackup() {
    if (!deviceLease) throw new Error("An active device lease is required to restore Fiber state");
    const deviceIdHash = await getDeviceIdHash();
    const leaseId = deviceLease.leaseId;
    await restoreBeforeStart({
      loadFiberKey: () => options.loadFiberKey(leaseId),
      loadBackup: () => api.loadNodeBackup(options.authToken, { deviceIdHash, leaseId }),
      restoreBackup: (backup, fiberKey) => restoreEncryptedNodeBackup(backup, databasePrefix, fiberKey),
      confirmRestore: (generation) => api.confirmNodeBackup(options.authToken, {
        deviceIdHash,
        leaseId,
        generation,
      }),
    });
    restoreRequired = false;
  }

  async function releaseGuards() {
    const lease = deviceLease;
    const lock = deviceLock;
    deviceLease = undefined;
    deviceLock = undefined;
    await Promise.allSettled([lease?.release(), lock?.release()]);
  }

  async function openFundedChannel(params: KeyWayFundingParams) {
    if (!node.isRunning) throw new Error("Start the Fiber node before opening a channel");
    const funding = await resolveExternalFunding(undefined);
    const result = await openChannelWithExternalFundingFlow({
      node,
      params: {
        ...params,
        shutdown_script: funding.shutdownScript,
        funding_lock_script: funding.fundingLockScript,
        funding_lock_script_cell_deps: funding.fundingLockScriptCellDeps,
      },
      signFundingTx: funding.signFundingTx,
    });
    await markChannelOpened(options.authToken, api);
    return result;
  }

  function prepareCkbChannel(fundingAmount: bigint): Promise<ChannelPeer[]> {
    if (preparedFundingAmount !== fundingAmount) preparedPeers = undefined;
    preparedFundingAmount = fundingAmount;
    preparedPeers ??= connectChannelPeers(node, fundingAmount).catch((error) => {
      preparedPeers = undefined;
      preparedFundingAmount = undefined;
      throw error;
    });
    return preparedPeers;
  }

  async function activateCkbChannel(
    input: bigint | OpenKeyWayChannelOptions = DEFAULT_CHANNEL_FUNDING,
    onProgress?: ChannelOpenProgress,
  ) {
    const config: OpenKeyWayChannelOptions = typeof input === "bigint" ? { fundingAmount: input } : input;
    if (config.udtTypeScript && config.fundingAmount === undefined) throw new Error("A token channel needs a fundingAmount");
    const fundingAmount = config.fundingAmount ?? DEFAULT_CHANNEL_FUNDING;
    activationProgress = onProgress;
    activationProgress?.("connecting");
    try {
      const candidates = config.peer
        ? [{ pubkey: normalizeFiberPubkey(config.peer), nodeName: "selected peer" }]
        // The official peers' minimums are in CKB, so any of them will do for a token channel.
        : await prepareCkbChannel(config.udtTypeScript ? ANY_FUNDING : fundingAmount);
      let lastAbort: unknown;
      for (const candidate of candidates) {
        try {
          activationProgress?.("negotiating");
          const result = await openFundedChannel({
            pubkey: normalizeFiberPubkey(candidate.pubkey),
            funding_amount: `0x${fundingAmount.toString(16)}`,
            public: config.public ?? true,
            ...(config.udtTypeScript ? { funding_udt_type_script: config.udtTypeScript } : {}),
            funding_fee_rate: config.fundingFeeRate === undefined ? undefined : toHex(config.fundingFeeRate),
            commitment_fee_rate: config.commitmentFeeRate === undefined ? undefined : toHex(config.commitmentFeeRate),
          });
          activationProgress?.("broadcasting");
          return result;
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          if (!shouldDiagnoseFundingAbortError(message)) throw error;
          lastAbort = error;
        }
      }
      preparedPeers = undefined;
      preparedFundingAmount = undefined;
      throw new Error("Available Fiber peers declined the channel funding request", { cause: lastAbort });
    } finally {
      activationProgress = undefined;
    }
  }

  async function getCkbBalance(): Promise<bigint> {
    const address = await fundingSigner.getRecommendedAddressObj();
    return getLockBalanceShannons(ckbRpcUrl, cccScriptToFiberScript(address.script));
  }

  async function getChannels(options?: { includeClosed?: boolean }): Promise<KeyWayChannel[]> {
    const { channels } = await node.listChannels({ include_closed: options?.includeClosed ?? false });
    return channels.map(normalizeChannel);
  }

  async function closeChannel(channelId: ChannelId, options?: { force?: boolean; feeRate?: bigint }): Promise<void> {
    try {
      await node.shutdownChannel({
        channel_id: channelId,
        force: options?.force,
        fee_rate: options?.feeRate === undefined ? undefined : toHex(options.feeRate),
      });
    } catch (error) {
      throw toKeyWayError(error, "CHANNEL_FAILED");
    }
  }

  async function estimatePayment(params: Omit<SendPaymentParams, "dry_run">): Promise<PaymentEstimate> {
    try {
      const payment = await node.sendPayment({ ...params, dry_run: true });
      return { routable: true, fee: BigInt(payment.fee) };
    } catch (error) {
      return { routable: false, error: toKeyWayError(error, "PAYMENT_FAILED") };
    }
  }

  async function sendPayment(params: SendPaymentParams) {
    try {
      return await fiberNode.sendPayment(params);
    } catch (error) {
      throw toKeyWayError(error, "PAYMENT_FAILED");
    }
  }

  const network = options.network ?? "testnet";
  // The same method table as hosted nodes, applied in the page because this node runs here.
  const fiberNode = createFiberNode(async (method, input) => {
    if (!node.isRunning) throw new Error("Start Fiber before using the node");
    const params = freeFiberParams(method, input, network);
    switch (method) {
      case "nodeInfo": return node.nodeInfo();
      case "listPeers": return node.listPeers();
      case "listPayments": return listLoggedPayments(await paymentLog.hashes(), params as ListPaymentsParams, (query) => node.getPayment(query));
      default: return (node[method] as (params: unknown) => Promise<unknown>).call(node, params);
    }
  }, async (method, input) => {
    if (!node.isRunning) throw new Error("Start Fiber before using the node");
    const params = paymentFiberParams(method, input, network);
    const run = (next: Record<string, unknown>) => (node[method] as (params: unknown) => Promise<{ payment_hash: string; fee: string }>).call(node, next);
    if (params.dry_run === true) return run(params);
    // The node runs in this page, so there is no server to count this payment or ask for an email code.
    if (options.approveFiberPayment) {
      const { preview } = await describePayment(method, params, { parseInvoice: (invoice) => node.parseInvoice({ invoice }), dryRun: run });
      if (!await options.approveFiberPayment({ ...preview, requiresEmailCode: false })) throw new Error("The payment was not approved");
    }
    const payment = await run(params);
    // Browser nodes have no payment history of their own; failing to log never fails the payment.
    await paymentLog.record(payment.payment_hash).catch(() => undefined);
    return payment;
  });

  return {
    node: fiberNode,
    start,
    stop,
    stopForLogout,
    nodeInfo: () => node.nodeInfo(),
    connectPeer: node.connectPeer.bind(node),
    listPeers: node.listPeers.bind(node),
    listChannels: node.listChannels.bind(node),
    getChannels,
    shutdownChannel: node.shutdownChannel.bind(node),
    closeChannel,
    graphNodes: node.graphNodes.bind(node),
    graphChannels: node.graphChannels.bind(node),
    waitForChannelReady: node.waitForChannelReady.bind(node),
    newInvoice: (params: Omit<NewInvoiceParams, "currency"> & { currency?: NewInvoiceParams["currency"] }) => fiberNode.newInvoice(params),
    getInvoice: node.getInvoice.bind(node),
    parseInvoice: node.parseInvoice.bind(node),
    estimatePayment,
    sendPayment,
    buildRouter: node.buildRouter.bind(node),
    sendPaymentWithRouter: node.sendPaymentWithRouter.bind(node),
    getPayment: node.getPayment.bind(node),
    waitForPayment: node.waitForPayment.bind(node),
    openFundedChannel,
    prepareCkbChannel,
    activateCkbChannel,
    getCkbBalance,
    openChannelWithExternalFunding: node.openChannelWithExternalFunding.bind(node),
    submitSignedFundingTx: node.submitSignedFundingTx.bind(node),
    get state() { return node.state; },
    get isRunning() { return node.isRunning; },
  };
}

export function normalizeChannel(channel: Channel): KeyWayChannel {
  const canSend = BigInt(channel.local_balance);
  const canReceive = BigInt(channel.remote_balance);
  const typeScript = (channel as Channel & { funding_udt_type_script?: Script | null }).funding_udt_type_script;
  const state = String(channel.state.state_name);
  const status: KeyWayChannelStatus = state === "CHANNEL_READY" ? "ready"
    : state.includes("SHUTDOWN") || state.includes("SHUTTING") || state.includes("CLOSING") ? "closing"
    : state.includes("CLOSED") ? "closed"
    : state.includes("FAILED") ? "failed"
    : state.includes("NEGOTIATING") || state.includes("AWAITING") ? "pending"
    : "unknown";
  return {
    id: channel.channel_id,
    peer: channel.pubkey,
    status,
    asset: typeScript ? { kind: "token", typeScript } : { kind: "ckb" },
    canSend,
    canReceive,
    capacity: canSend + canReceive,
    public: channel.is_public,
    raw: channel,
  };
}

function toHex(value: bigint): `0x${string}` {
  return `0x${value.toString(16)}`;
}

export type KeyWay = ReturnType<typeof createKeyWay>;
