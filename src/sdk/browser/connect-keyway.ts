import type { ListPeersResult, NodeInfoResult } from "@fiber-pay/sdk/browser";
import { bootstrapKeyWay, loadFiberKey, type PublicWallet } from "./bootstrap";
import { createKeyWay, type KeyWay } from "./create-keyway";
import type { ConfirmFunding } from "./remote-ckb-signer";
import { connectTestnetPeers } from "./testnet-peers";
import { KeyWayApiClient } from "./api-client";

export type ConnectedKeyWay = {
  keyway: KeyWay;
  wallet: PublicWallet;
  node: NodeInfoResult;
  peers: ListPeersResult["peers"];
  balanceShannons: bigint;
};

export type KeyWayLifecycleStage =
  | "recovering_identity"
  | "acquiring_lease"
  | "restoring_database"
  | "starting_wasm"
  | "connecting_peer"
  | "synchronizing"
  | "ready";

export type KeyWayLifecycleEvent = {
  stage: KeyWayLifecycleStage;
  at: number;
  elapsedMs: number;
};

export async function connectKeyWay(options: {
  authToken: string;
  confirmFunding: ConfirmFunding;
  apiClient?: KeyWayApiClient;
  onLeaseLost?: (error: Error) => void;
  onWalletReady?: (wallet: PublicWallet) => void;
  onLifecycle?: (event: KeyWayLifecycleEvent) => void;
}): Promise<ConnectedKeyWay> {
  const startedAt = Date.now();
  const stage = (next: KeyWayLifecycleStage) => options.onLifecycle?.({
    stage: next,
    at: Date.now(),
    elapsedMs: Date.now() - startedAt,
  });
  const apiClient = options.apiClient ?? new KeyWayApiClient();
  stage("recovering_identity");
  const { wallet, restoreRequired } = await bootstrapKeyWay(options.authToken, apiClient);
  options.onWalletReady?.(wallet);
  const keyway = createKeyWay({
    identifier: wallet.litPkpId,
    authToken: options.authToken,
    ckbPublicKey: wallet.litPublicKey,
    confirmFunding: options.confirmFunding,
    loadFiberKey: (leaseId) => loadFiberKey(options.authToken, leaseId, apiClient),
    apiClient,
    restoreRequired,
    onLeaseLost: options.onLeaseLost,
    onLifecycle: stage,
  });

  try {
    const node = await keyway.start();
    stage("connecting_peer");
    const peers = await connectTestnetPeers(keyway);
    stage("synchronizing");
    const connection = {
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
