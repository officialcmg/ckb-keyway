import { bootstrapKeyWay, type PublicWallet } from "./bootstrap";
import { KeyWayApiClient } from "./api-client";
import { createManagedKeyWay, type ManagedKeyWay } from "./create-managed-keyway";
import type { ConfirmFunding } from "./remote-ckb-signer";
import type { KeyWayLifecycleEvent, KeyWayLifecycleStage } from "./connect-keyway";

export type ConnectedManagedKeyWay = {
  mode: "managed";
  keyway: ManagedKeyWay;
  wallet: PublicWallet;
  node: Awaited<ReturnType<ManagedKeyWay["nodeInfo"]>>;
  peers: Array<{ pubkey: string }>;
  balanceShannons: bigint;
};

export async function connectManagedKeyWay(options: {
  authToken: string;
  confirmFunding: ConfirmFunding;
  apiClient?: KeyWayApiClient;
  onWalletReady?: (wallet: PublicWallet) => void;
  onLifecycle?: (event: KeyWayLifecycleEvent) => void;
}): Promise<ConnectedManagedKeyWay> {
  const startedAt = Date.now();
  const stage = (next: KeyWayLifecycleStage) => options.onLifecycle?.({
    stage: next,
    at: Date.now(),
    elapsedMs: Date.now() - startedAt,
  });
  const api = options.apiClient ?? new KeyWayApiClient();
  stage("recovering_identity");
  const { wallet } = await bootstrapKeyWay(options.authToken, api, "managed");
  options.onWalletReady?.(wallet);
  const keyway = createManagedKeyWay({
    authToken: options.authToken,
    ckbPublicKey: wallet.litPublicKey,
    confirmFunding: options.confirmFunding,
    apiClient: api,
  });
  stage("starting_managed");
  try {
    const node = await keyway.start();
    const status = await api.managedNode<{ peers: Array<{ pubkey: string }> }>(options.authToken, { operation: "status" });
    stage("synchronizing");
    const connection = {
      mode: "managed" as const,
      keyway,
      wallet,
      node,
      peers: status.peers,
      balanceShannons: await keyway.getCkbBalance(),
    };
    stage("ready");
    return connection;
  } catch (error) {
    await keyway.stop();
    throw error;
  }
}
