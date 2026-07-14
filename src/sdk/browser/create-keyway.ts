import * as ccc from "@ckb-ccc/core";
import {
  createCccExternalFundingResolver,
  cccScriptToFiberScript,
  FiberBrowserNode,
  getLockBalanceShannons,
  openChannelWithExternalFundingFlow,
  shouldDiagnoseFundingAbortError,
  type OpenChannelWithExternalFundingParams,
} from "@fiber-pay/sdk/browser";
import { KeyWayCredentialProvider, type FiberKeyLoader } from "./credential-provider";
import { acquireDeviceLock, type DeviceLock } from "./device-lock";
import { acquireDeviceLease, type DeviceLease } from "./device-lease";
import { serializeCccTransaction } from "./ccc-transaction";
import { RemoteCkbSigner, type ConfirmFunding } from "./remote-ckb-signer";
import { markChannelOpened } from "./bootstrap";
import { connectChannelPeers, type ChannelPeer } from "./channel-peers";
import { normalizeFiberPubkey } from "./fiber-pubkey";
import { KeyWayApiClient } from "./api-client";

export type KeyWayFundingParams = Omit<
  OpenChannelWithExternalFundingParams,
  "funding_lock_script" | "funding_lock_script_cell_deps" | "shutdown_script"
>;

export type CreateKeyWayOptions = {
  identifier: string;
  authToken: string;
  ckbPublicKey: string;
  confirmFunding: ConfirmFunding;
  loadFiberKey: (leaseId: string) => ReturnType<FiberKeyLoader>;
  network?: "testnet" | "mainnet";
  apiClient?: KeyWayApiClient;
  onLeaseLost?: (error: Error) => void;
};

export type ActivationStage = "connecting" | "negotiating" | "confirming" | "signing" | "broadcasting" | "waiting";
export type ActivationProgress = (stage: ActivationStage) => void;

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
  let activationProgress: ActivationProgress | undefined;
  let preparedPeers: Promise<ChannelPeer[]> | undefined;
  let preparedFundingAmount: bigint | undefined;
  const fundingSigner = new RemoteCkbSigner(options.authToken, options.ckbPublicKey, async (preview) => {
    activationProgress?.("confirming");
    const approved = await options.confirmFunding(preview);
    if (approved) activationProgress?.("signing");
    return approved;
  }, undefined, api);
  const resolveExternalFunding = createCccExternalFundingResolver({
    signer: fundingSigner,
    knownScripts: [ccc.KnownScript.Secp256k1Blake160],
    ckbRpcUrl: "https://testnet.ckb.dev/",
    // fiber-pay normalizes field names, but CCC must first serialize bigint fields to CKB RPC hex.
    signFundingTxOptions: { toRpcTransaction: serializeCccTransaction },
  });
  const ckbRpcUrl = "https://testnet.ckbapp.dev/";

  async function start() {
    if (node.isRunning) return node.nodeInfo();
    deviceLock = await acquireDeviceLock(options.identifier);
    try {
      deviceLease = await acquireDeviceLease(options.authToken, api, (cause) => {
        const error = cause instanceof Error ? cause : new Error("The active KeyWay device lease expired");
        void stop().finally(() => options.onLeaseLost?.(error));
      });
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

  async function activateCkbChannel(fundingAmount: bigint, onProgress?: ActivationProgress) {
    activationProgress = onProgress;
    activationProgress?.("connecting");
    try {
      const candidates = await prepareCkbChannel(fundingAmount);
      let lastAbort: unknown;
      for (const candidate of candidates) {
        try {
          activationProgress?.("negotiating");
          const result = await openFundedChannel({
            pubkey: normalizeFiberPubkey(candidate.pubkey),
            funding_amount: `0x${fundingAmount.toString(16)}`,
            public: true,
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

  return {
    start,
    stop,
    nodeInfo: () => node.nodeInfo(),
    connectPeer: node.connectPeer.bind(node),
    listPeers: node.listPeers.bind(node),
    listChannels: node.listChannels.bind(node),
    shutdownChannel: node.shutdownChannel.bind(node),
    graphNodes: node.graphNodes.bind(node),
    graphChannels: node.graphChannels.bind(node),
    waitForChannelReady: node.waitForChannelReady.bind(node),
    newInvoice: node.newInvoice.bind(node),
    getInvoice: node.getInvoice.bind(node),
    parseInvoice: node.parseInvoice.bind(node),
    sendPayment: node.sendPayment.bind(node),
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

export type KeyWay = ReturnType<typeof createKeyWay>;
