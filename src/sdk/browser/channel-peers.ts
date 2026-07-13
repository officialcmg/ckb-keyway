import type { ConnectPeerParams, GraphNodesParams, GraphNodesResult, ListPeersResult } from "@fiber-pay/sdk/browser";
import { normalizeFiberPubkey } from "./fiber-pubkey.ts";

export type ChannelPeer = {
  pubkey: `0x${string}`;
  nodeName: string;
  addresses: string[];
  minimumFunding: bigint;
};

// Official Fiber testnet channel nodes. Seeding avoids waiting for their gossip
// announcements to reach a newly started browser node.
export const TESTNET_CHANNEL_PEERS: readonly ChannelPeer[] = [
  {
    pubkey: "0x02b6d4e3ab86a2ca2fad6fae0ecb2e1e559e0b911939872a90abdda6d20302be71",
    nodeName: "fiber-testnet-public-bottle",
    addresses: ["/dns4/bottle.fiber.channel/tcp/443/wss/p2p/QmXen3eUHhywmutEzydCsW4hXBoeVmdET2FJvMX69XJ1Eo"],
    minimumFunding: 400n * 100_000_000n,
  },
  {
    pubkey: "0x0291a6576bd5a94bd74b27080a48340875338fff9f6d6361fe6b8db8d0d1912fcc",
    nodeName: "fiber-testnet-public-bracer",
    addresses: ["/dns4/bracer.fiber.channel/tcp/443/wss/p2p/QmbKyzq9qUmymW2Gi8Zq7kKVpPiNA1XUJ6uMvsUC4F3p89"],
    minimumFunding: 400n * 100_000_000n,
  },
] as const;

type ChannelPeerClient = {
  connectPeer(params: ConnectPeerParams): Promise<unknown>;
  graphNodes(params?: GraphNodesParams): Promise<GraphNodesResult>;
  listPeers(): Promise<ListPeersResult>;
};

export async function connectChannelPeers(
  client: ChannelPeerClient,
  fundingAmount: bigint,
  options: {
    timeoutMs?: number;
    intervalMs?: number;
    maxCandidates?: number;
    seedPeers?: readonly ChannelPeer[];
  } = {},
): Promise<ChannelPeer[]> {
  const intervalMs = options.intervalMs ?? 1_000;
  const maxCandidates = options.maxCandidates ?? 3;
  const seedCandidates = deduplicatePeers(options.seedPeers ?? TESTNET_CHANNEL_PEERS)
    .filter(({ minimumFunding }) => minimumFunding > 0n && minimumFunding <= fundingAmount)
    .slice(0, maxCandidates);
  const connected = new Set((await client.listPeers()).peers.map(({ pubkey }) => normalizeFiberPubkey(pubkey)));
  const connectedSeeds = seedCandidates.filter(({ pubkey }) => connected.has(pubkey));
  if (connectedSeeds.length > 0) return connectedSeeds;

  const reachableSeeds = await connectCandidates(client, seedCandidates, options.timeoutMs ?? 10_000, intervalMs);
  if (reachableSeeds.length > 0) return reachableSeeds;

  // Gossip is a fallback. A new browser node may not have synchronized it yet,
  // and waiting for it before trying the official nodes makes activation slow.
  const graph = await client.graphNodes({ limit: "0x100" });
  const graphCandidates = deduplicatePeers(eligibleGraphPeers(graph.nodes))
    .filter(({ minimumFunding }) => minimumFunding > 0n && minimumFunding <= fundingAmount)
    .filter(({ pubkey }) => !seedCandidates.some((seed) => seed.pubkey === pubkey))
    .slice(0, maxCandidates);
  const connectedGraphPeers = graphCandidates.filter(({ pubkey }) => connected.has(pubkey));
  if (connectedGraphPeers.length > 0) return connectedGraphPeers;

  const reachable = await connectCandidates(client, graphCandidates, options.timeoutMs ?? 10_000, intervalMs);

  if (reachable.length === 0) {
    throw new Error("Could not connect to a Fiber node that accepts new channels");
  }
  return reachable;
}

async function connectCandidates(
  client: Pick<ChannelPeerClient, "connectPeer" | "listPeers">,
  candidates: readonly ChannelPeer[],
  timeoutMs: number,
  intervalMs: number,
): Promise<ChannelPeer[]> {
  if (candidates.length === 0) return [];
  await Promise.allSettled(candidates.flatMap((candidate) =>
    candidate.addresses.map((address) => client.connectPeer({ address, save: true }))
  ));
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const connected = new Set((await client.listPeers()).peers.map(({ pubkey }) => normalizeFiberPubkey(pubkey)));
    const reachable = candidates.filter(({ pubkey }) => connected.has(pubkey));
    if (reachable.length > 0) return reachable;
    await delay(intervalMs);
  }
  return [];
}

function eligibleGraphPeers(nodes: GraphNodesResult["nodes"]): ChannelPeer[] {
  return nodes
    .filter((node) => node.addresses.some(isBrowserAddress))
    .map((node) => ({
      pubkey: normalizeFiberPubkey(node.pubkey),
      nodeName: node.node_name,
      addresses: node.addresses.filter(isBrowserAddress),
      minimumFunding: BigInt(node.auto_accept_min_ckb_funding_amount),
    }));
}

function deduplicatePeers(peers: readonly ChannelPeer[]): ChannelPeer[] {
  return Array.from(new Map(peers.map((peer) => [peer.pubkey, peer])).values());
}

function isBrowserAddress(address: string): boolean {
  return address.includes("/wss");
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
