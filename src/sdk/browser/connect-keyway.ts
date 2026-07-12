import type { ListPeersResult, NodeInfoResult } from "@fiber-pay/sdk/browser";
import { bootstrapKeyWay, loadFiberKey, type PublicWallet } from "./bootstrap";
import { createKeyWay, type KeyWay } from "./create-keyway";
import type { ConfirmFunding } from "./remote-ckb-signer";

export const TESTNET_RELAYS = [
  "/dns4/thrall.fiber.channel/tcp/443/wss/p2p/Qmes1EBD4yNo9Ywkfe6eRw9tG1nVNGLDmMud1xJMsoYFKy",
  "/dns4/onyxia.fiber.channel/tcp/443/wss/p2p/QmdyQWjPtbK4NWWsvy8s69NGJaQULwgeQDT5ZpNDrTNaeV",
] as const;

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
}): Promise<ConnectedKeyWay> {
  const { wallet } = await bootstrapKeyWay(options.sessionJwt);
  const keyway = createKeyWay({
    identifier: wallet.litPkpId,
    sessionJwt: options.sessionJwt,
    ckbPublicKey: wallet.litPublicKey,
    confirmFunding: options.confirmFunding,
    loadFiberKey: (leaseId) => loadFiberKey(options.sessionJwt, leaseId),
  });

  try {
    const node = await keyway.start();
    let { peers } = await keyway.listPeers();
    for (const address of TESTNET_RELAYS) {
      if (peers.length > 0) break;
      try {
        await keyway.connectPeer({ address, save: true });
        ({ peers } = await keyway.listPeers());
      } catch {
        // A second relay remains available if one endpoint is temporarily down.
      }
    }
    if (peers.length === 0) throw new Error("Could not connect to the Fiber testnet");
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
