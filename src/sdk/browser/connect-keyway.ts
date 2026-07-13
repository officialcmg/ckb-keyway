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
  sessionJwt: string;
  confirmFunding: ConfirmFunding;
  apiBaseUrl?: string;
}): Promise<ConnectedKeyWay> {
  const apiClient = new KeyWayApiClient({ apiBaseUrl: options.apiBaseUrl });
  const { wallet } = await bootstrapKeyWay(options.sessionJwt, apiClient);
  const keyway = createKeyWay({
    identifier: wallet.litPkpId,
    sessionJwt: options.sessionJwt,
    ckbPublicKey: wallet.litPublicKey,
    confirmFunding: options.confirmFunding,
    loadFiberKey: (leaseId) => loadFiberKey(options.sessionJwt, leaseId, apiClient),
    apiClient,
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
