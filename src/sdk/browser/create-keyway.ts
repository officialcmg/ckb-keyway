import { FiberBrowserNode } from "@fiber-pay/sdk/browser";
import { KeyWayCredentialProvider, type FiberKeyLoader } from "./credential-provider";

export type CreateKeyWayOptions = {
  identifier: string;
  loadFiberKey: FiberKeyLoader;
  network?: "testnet" | "mainnet";
};

export function createKeyWay(options: CreateKeyWayOptions) {
  const credential = new KeyWayCredentialProvider(options.identifier, options.loadFiberKey);
  const node = new FiberBrowserNode({
    network: options.network ?? "testnet",
    credential,
  });

  return {
    start: () => node.start(),
    stop: () => node.stop(),
    nodeInfo: () => node.nodeInfo(),
    connectPeer: node.connectPeer.bind(node),
    listPeers: node.listPeers.bind(node),
    listChannels: node.listChannels.bind(node),
    newInvoice: node.newInvoice.bind(node),
    parseInvoice: node.parseInvoice.bind(node),
    sendPayment: node.sendPayment.bind(node),
    getPayment: node.getPayment.bind(node),
    waitForPayment: node.waitForPayment.bind(node),
    openChannelWithExternalFunding: node.openChannelWithExternalFunding.bind(node),
    submitSignedFundingTx: node.submitSignedFundingTx.bind(node),
    get state() { return node.state; },
    get isRunning() { return node.isRunning; },
  };
}

export type KeyWay = ReturnType<typeof createKeyWay>;
