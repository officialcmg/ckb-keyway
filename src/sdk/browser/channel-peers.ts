import type { ConnectPeerParams, GraphNodesParams, GraphNodesResult, ListPeersResult } from "@fiber-pay/sdk/browser";
import { normalizeFiberPubkey } from "./fiber-pubkey.ts";

export type ChannelPeer = GraphNodesResult["nodes"][number];

type ChannelPeerClient = {
  connectPeer(params: ConnectPeerParams): Promise<unknown>;
  graphNodes(params?: GraphNodesParams): Promise<GraphNodesResult>;
  listPeers(): Promise<ListPeersResult>;
};

export async function connectChannelPeers(
  client: ChannelPeerClient,
  fundingAmount: bigint,
  options: { timeoutMs?: number; intervalMs?: number; maxCandidates?: number } = {},
): Promise<ChannelPeer[]> {
  const deadline = Date.now() + (options.timeoutMs ?? 25_000);
  const intervalMs = options.intervalMs ?? 1_000;
  const maxCandidates = options.maxCandidates ?? 3;
  let candidates: ChannelPeer[] = [];

  while (Date.now() < deadline) {
    const graph = await client.graphNodes({ limit: "0x100" });
    candidates = eligiblePeers(graph.nodes, fundingAmount).slice(0, maxCandidates);
    if (candidates.length > 0) break;
    await delay(intervalMs);
  }

  if (candidates.length === 0) {
    throw new Error("No browser-reachable Fiber node currently accepts this channel amount");
  }

  const connected = new Set((await client.listPeers()).peers.map(({ pubkey }) => normalizeFiberPubkey(pubkey)));
  const reachable: ChannelPeer[] = [];
  for (const candidate of candidates) {
    const pubkey = normalizeFiberPubkey(candidate.pubkey);
    if (!connected.has(pubkey)) {
      await Promise.allSettled([
        client.connectPeer({ pubkey: normalizeFiberPubkey(candidate.pubkey), addr_type: "wss", save: true }),
      ]);
      const connectionDeadline = Date.now() + (options.timeoutMs ?? 10_000);
      if (!await waitForPeer(client, pubkey, connectionDeadline, intervalMs)) continue;
      connected.add(pubkey);
    }
    reachable.push(candidate);
  }

  if (reachable.length === 0) {
    throw new Error("Could not connect to a Fiber node that accepts new channels");
  }
  return reachable;
}

function eligiblePeers(nodes: GraphNodesResult["nodes"], fundingAmount: bigint): ChannelPeer[] {
  return nodes
    .filter((node) => {
      const minimum = BigInt(node.auto_accept_min_ckb_funding_amount);
      return minimum > 0n && minimum <= fundingAmount;
    })
    .filter((node) => node.addresses.some(isBrowserAddress))
    .sort((left, right) => {
      const leftMinimum = BigInt(left.auto_accept_min_ckb_funding_amount);
      const rightMinimum = BigInt(right.auto_accept_min_ckb_funding_amount);
      return leftMinimum < rightMinimum ? -1 : leftMinimum > rightMinimum ? 1 : 0;
    });
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
