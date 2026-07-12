import { FiberBrowserNode } from "@fiber-pay/sdk/browser";
import { KeyWayCredentialProvider, type FiberKeyLoader } from "./credential-provider";
import { acquireDeviceLock, type DeviceLock } from "./device-lock";
import { acquireDeviceLease, type DeviceLease } from "./device-lease";

export type CreateKeyWayOptions = {
  identifier: string;
  sessionJwt: string;
  loadFiberKey: (leaseId: string) => ReturnType<FiberKeyLoader>;
  network?: "testnet" | "mainnet";
};

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

  async function start() {
    if (node.isRunning) return node.nodeInfo();
    deviceLock = await acquireDeviceLock(options.identifier);
    try {
      deviceLease = await acquireDeviceLease(options.sessionJwt);
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

  return {
    start,
    stop,
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
