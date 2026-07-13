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
  const graph = await client.graphNodes({ limit: "0x100" });
  const candidates = deduplicatePeers([
    ...(options.seedPeers ?? TESTNET_CHANNEL_PEERS),
    ...eligibleGraphPeers(graph.nodes),
  ])
    .filter(({ minimumFunding }) => minimumFunding > 0n && minimumFunding <= fundingAmount)
    .slice(0, maxCandidates);

  if (candidates.length === 0) {
    throw new Error("No browser-reachable Fiber node currently accepts this channel amount");
  }

  const connected = new Set((await client.listPeers()).peers.map(({ pubkey }) => normalizeFiberPubkey(pubkey)));
  const reachable: ChannelPeer[] = [];
  for (const candidate of candidates) {
    if (!connected.has(candidate.pubkey)) {
      await Promise.allSettled(candidate.addresses.map((address) => client.connectPeer({ address, save: true })));
      const deadline = Date.now() + (options.timeoutMs ?? 10_000);
      if (!await waitForPeer(client, candidate.pubkey, deadline, intervalMs)) continue;
      connected.add(candidate.pubkey);
    }
    reachable.push(candidate);
  }

  if (reachable.length === 0) {
    throw new Error("Could not connect to a Fiber node that accepts new channels");
  }
  return reachable;
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

async function waitForPeer(
  client: Pick<ChannelPeerClient, "listPeers">,
  pubkey: string,
  deadline: number,
  intervalMs: number,
): Promise<boolean> {
  while (Date.now() < deadline) {
    const peers = await client.listPeers();
    if (peers.peers.some((peer) => normalizeFiberPubkey(peer.pubkey) === pubkey)) return true;
    await delay(intervalMs);
  }
  return false;
}

function isBrowserAddress(address: string): boolean {
  return address.includes("/wss");
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
