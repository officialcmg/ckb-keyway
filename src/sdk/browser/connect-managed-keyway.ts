import { bootstrapKeyWay, type PublicWallet } from "./bootstrap";
import { KeyWayApiClient } from "./api-client";
import { createManagedKeyWay, type ManagedKeyWay } from "./create-managed-keyway";
import type { ApproveFiberChannelOpen } from "./remote-ckb-signer";
import type { ApproveFiberPayment } from "./fiber-payment";
import type { RequestEmailCode } from "./email-code";
import type { FiberActionApprovals } from "./fiber-actions";
import type { FiberStartupEvent, FiberStartupStage } from "./connect-keyway";

export type ConnectedManagedKeyWay = {
  mode: "hosted";
  keyway: ManagedKeyWay;
  wallet: PublicWallet;
  node: Awaited<ReturnType<ManagedKeyWay["nodeInfo"]>>;
  peers: Array<{ pubkey: string }>;
  balanceShannons: bigint;
};

export async function connectManagedKeyWay(options: {
  authToken: string;
  approveFiberChannelOpen: ApproveFiberChannelOpen;
  approveFiberPayment?: ApproveFiberPayment;
  requestEmailCode?: RequestEmailCode;
  approvals?: () => FiberActionApprovals;
  apiClient?: KeyWayApiClient;
  onWalletReady?: (wallet: PublicWallet) => void;
  onFiberStartup?: (event: FiberStartupEvent) => void;
}): Promise<ConnectedManagedKeyWay> {
  const startedAt = Date.now();
  const stage = (next: FiberStartupStage) => options.onFiberStartup?.({
    stage: next,
    at: Date.now(),
    elapsedMs: Date.now() - startedAt,
  });
  const api = options.apiClient ?? new KeyWayApiClient();
  stage("loading_account");
  const { wallet } = await bootstrapKeyWay(options.authToken, api, "managed");
  options.onWalletReady?.(wallet);
  const keyway = createManagedKeyWay({
    authToken: options.authToken,
    ckbPublicKey: wallet.litPublicKey,
    approveFiberChannelOpen: options.approveFiberChannelOpen,
    approveFiberPayment: options.approveFiberPayment,
    approvals: options.approvals,
    requestEmailCode: options.requestEmailCode,
    apiClient: api,
  });
  stage("starting_hosted_node");
  try {
    const node = await keyway.start();
    const status = await api.managedNode<{ peers: Array<{ pubkey: string }> }>(options.authToken, { operation: "status" });
    stage("synchronizing");
    const connection = {
      mode: "hosted" as const,
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
