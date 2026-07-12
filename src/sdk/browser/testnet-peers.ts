import type { ListPeersResult } from "@fiber-pay/sdk/browser";

export const TESTNET_RELAYS = [
  "/dns4/thrall.fiber.channel/tcp/443/wss/p2p/Qmes1EBD4yNo9Ywkfe6eRw9tG1nVNGLDmMud1xJMsoYFKy",
  "/dns4/onyxia.fiber.channel/tcp/443/wss/p2p/QmdyQWjPtbK4NWWsvy8s69NGJaQULwgeQDT5ZpNDrTNaeV",
] as const;

type PeerClient = {
  connectPeer(params: { address: string; save: boolean }): Promise<unknown>;
  listPeers(): Promise<ListPeersResult>;
};

export async function connectTestnetPeers(
  client: PeerClient,
  options: {
    relays?: readonly string[];
    timeoutMs?: number;
    intervalMs?: number;
  } = {},
): Promise<ListPeersResult["peers"]> {
  const existing = await client.listPeers();
  if (existing.peers.length > 0) return existing.peers;

  await Promise.allSettled((options.relays ?? TESTNET_RELAYS).map((address) => (
    client.connectPeer({ address, save: true })
  )));

  const deadline = Date.now() + (options.timeoutMs ?? 25_000);
  while (Date.now() < deadline) {
    const { peers } = await client.listPeers();
    if (peers.length > 0) return peers;
    await delay(options.intervalMs ?? 1_000);
  }
  throw new Error("Could not connect to the Fiber testnet");
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
