import assert from "node:assert/strict";
import test from "node:test";
import { normalizeFiberPubkey } from "../src/sdk/browser/fiber-pubkey.ts";
import { connectTestnetPeers } from "../src/sdk/browser/testnet-peers.ts";
import { connectChannelPeers } from "../src/sdk/browser/channel-peers.ts";

test("accepts Fiber peer keys with or without a hex prefix", () => {
  const bare = `02${"11".repeat(32)}`;
  assert.equal(normalizeFiberPubkey(bare), `0x${bare}`);
  assert.equal(normalizeFiberPubkey(`0x${bare}`), `0x${bare}`);
});

test("rejects malformed or uncompressed peer keys", () => {
  assert.throws(() => normalizeFiberPubkey(`04${"11".repeat(32)}`), /invalid peer identity/);
  assert.throws(() => normalizeFiberPubkey("0x02"), /invalid peer identity/);
});

test("waits for an asynchronous Fiber relay handshake", async () => {
  let polls = 0;
  let connectionAttempts = 0;
  const peer = { pubkey: `0x02${"11".repeat(32)}` as const, address: "/dns4/test" };
  const peers = await connectTestnetPeers({
    connectPeer: async () => { connectionAttempts += 1; },
    listPeers: async () => ({ peers: ++polls >= 3 ? [peer] : [] }),
  }, { relays: ["relay-a", "relay-b"], timeoutMs: 100, intervalMs: 1 });

  assert.equal(connectionAttempts, 2);
  assert.deepEqual(peers, [peer]);
});

test("connects only browser-reachable peers that accept the funding amount", async () => {
  const eligible = `02${"22".repeat(32)}`;
  const tooExpensive = `02${"33".repeat(32)}`;
  let connected = false;
  const peers = await connectChannelPeers({
    graphNodes: async () => ({
      last_cursor: "0x0",
      nodes: [
        graphNode(tooExpensive, "0x174876e800", "/dns4/expensive/tcp/443/wss/p2p/expensive"),
        graphNode(eligible, "0x2540be400", "/dns4/eligible/tcp/443/wss/p2p/eligible"),
        graphNode(`02${"44".repeat(32)}`, "0x0", "/dns4/disabled/tcp/443/wss/p2p/disabled"),
      ],
    }),
    connectPeer: async ({ address }) => { connected = address?.includes("eligible") ?? false; },
    listPeers: async () => ({ peers: connected ? [{ pubkey: `0x${eligible}` as const, address: "connected" }] : [] }),
  }, 1000n * 100_000_000n, { timeoutMs: 100, intervalMs: 1, seedPeers: [] });

  assert.equal(peers.length, 1);
  assert.equal(peers[0].pubkey, `0x${eligible}`);
});

test("uses official channel peers before gossip has synchronized", async () => {
  let connectedPubkey = "";
  let graphRequests = 0;
  const peers = await connectChannelPeers({
    graphNodes: async () => { graphRequests += 1; return { last_cursor: "0x0", nodes: [] }; },
    connectPeer: async ({ address }) => {
      if (address?.includes("bottle.fiber.channel")) connectedPubkey = "0x02b6d4e3ab86a2ca2fad6fae0ecb2e1e559e0b911939872a90abdda6d20302be71";
    },
    listPeers: async () => ({ peers: connectedPubkey ? [{ pubkey: connectedPubkey as `0x${string}`, address: "connected" }] : [] }),
  }, 1000n * 100_000_000n, { timeoutMs: 20, intervalMs: 1, maxCandidates: 1 });

  assert.equal(peers[0].nodeName, "fiber-testnet-public-bottle");
  assert.equal(graphRequests, 0);
});

test("queries gossip only after official channel peers fail", async () => {
  const gossipPubkey = `02${"55".repeat(32)}`;
  let graphRequests = 0;
  let connectedPubkey = "";
  const peers = await connectChannelPeers({
    graphNodes: async () => {
      graphRequests += 1;
      return {
        last_cursor: "0x0",
        nodes: [graphNode(gossipPubkey, "0x2540be400", "/dns4/gossip/tcp/443/wss/p2p/gossip")],
      };
    },
    connectPeer: async ({ address }) => {
      if (address?.includes("gossip")) connectedPubkey = `0x${gossipPubkey}`;
    },
    listPeers: async () => ({ peers: connectedPubkey ? [{ pubkey: connectedPubkey as `0x${string}`, address: "connected" }] : [] }),
  }, 1000n * 100_000_000n, { timeoutMs: 2, intervalMs: 1 });

  assert.equal(graphRequests, 1);
  assert.equal(peers[0].pubkey, `0x${gossipPubkey}`);
});

function graphNode(pubkey: string, minimum: string, address: string) {
  return {
    node_name: "test",
    version: "0.8.1",
    addresses: [address],
    features: [],
    pubkey: `0x${pubkey}` as const,
    timestamp: "0x0" as const,
    chain_hash: `0x${"00".repeat(32)}` as const,
    auto_accept_min_ckb_funding_amount: minimum as `0x${string}`,
    udt_cfg_infos: [],
  };
}
