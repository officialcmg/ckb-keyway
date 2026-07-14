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

export async function connectKeyWay(options: {
  authToken: string;
  confirmFunding: ConfirmFunding;
  onLeaseLost?: (error: Error) => void;
}): Promise<ConnectedKeyWay> {
  const apiClient = new KeyWayApiClient();
  const { wallet } = await bootstrapKeyWay(options.authToken, apiClient);
  const keyway = createKeyWay({
    identifier: wallet.litPkpId,
    authToken: options.authToken,
    ckbPublicKey: wallet.litPublicKey,
    confirmFunding: options.confirmFunding,
    loadFiberKey: (leaseId) => loadFiberKey(options.authToken, leaseId, apiClient),
    apiClient,
    onLeaseLost: options.onLeaseLost,
  });

  try {
    const node = await keyway.start();
    const peers = await connectTestnetPeers(keyway);
    return {
      keyway,
      wallet,
      node,
      peers,
      balanceShannons: await keyway.getCkbBalance(),
    };
  } catch (error) {
    await keyway.stop();
    throw error;
  }
}
