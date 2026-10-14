import type { ListPeersResult, NodeInfoResult } from "@fiber-pay/sdk/browser";
import { bootstrapKeyWay, loadFiberKey, type PublicWallet } from "./bootstrap";
import { createKeyWay, type KeyWay } from "./create-keyway";
import type { ApproveFiberChannelOpen } from "./remote-ckb-signer";
import type { ApproveFiberPayment } from "./fiber-payment";
import type { RequestEmailCode } from "./email-code";
import type { FiberActionApprovals } from "./fiber-actions";
import { connectTestnetPeers } from "./testnet-peers";
import { KeyWayApiClient } from "./api-client";

export type ConnectedKeyWay = {
  mode: "browser";
  keyway: KeyWay;
  wallet: PublicWallet;
  node: NodeInfoResult;
  peers: ListPeersResult["peers"];
  balanceShannons: bigint;
};

/** Steps a Fiber node goes through after `start()`, reported to `onFiberStartup`. */
export type FiberStartupStage =
  | "loading_account"
  | "claiming_device"
  | "restoring_channels"
  | "starting_browser_node"
  | "starting_hosted_node"
  | "connecting_peer"
  | "synchronizing"
  | "ready";

export type FiberStartupEvent = {
  stage: FiberStartupStage;
  at: number;
  elapsedMs: number;
};

export async function connectKeyWay(options: {
  authToken: string;
  approveFiberChannelOpen: ApproveFiberChannelOpen;
  approveFiberPayment?: ApproveFiberPayment;
  requestEmailCode?: RequestEmailCode;
  approvals?: () => FiberActionApprovals;
  apiClient?: KeyWayApiClient;
  onLeaseLost?: (error: Error) => void;
  onWalletReady?: (wallet: PublicWallet) => void;
  onFiberStartup?: (event: FiberStartupEvent) => void;
}): Promise<ConnectedKeyWay> {
  const startedAt = Date.now();
  const stage = (next: FiberStartupStage) => options.onFiberStartup?.({
    stage: next,
    at: Date.now(),
    elapsedMs: Date.now() - startedAt,
  });
  const apiClient = options.apiClient ?? new KeyWayApiClient();
  stage("loading_account");
  const { wallet, restoreRequired } = await bootstrapKeyWay(options.authToken, apiClient);
  options.onWalletReady?.(wallet);
  const keyway = createKeyWay({
    identifier: wallet.litPkpId,
    authToken: options.authToken,
    ckbPublicKey: wallet.litPublicKey,
    approveFiberChannelOpen: options.approveFiberChannelOpen,
    approveFiberPayment: options.approveFiberPayment,
    approvals: options.approvals,
    requestEmailCode: options.requestEmailCode,
    loadFiberKey: (leaseId) => loadFiberKey(options.authToken, leaseId, wallet.litPkpId, apiClient),
    apiClient,
    restoreRequired,
    onLeaseLost: options.onLeaseLost,
    onFiberStartup: stage,
  });

  try {
    const node = await keyway.start();
    stage("connecting_peer");
    const peers = await connectTestnetPeers(keyway);
    stage("synchronizing");
    const connection = {
      mode: "browser" as const,
      keyway,
      wallet,
      node,
      peers,
      balanceShannons: await keyway.getCkbBalance(),
    };
    stage("ready");
    return connection;
  } catch (error) {
    await keyway.stop();
    throw error;
  }
}
