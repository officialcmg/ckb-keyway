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
    connectPeer: async ({ pubkey }) => { connected = pubkey === `0x${eligible}`; },
    listPeers: async () => ({ peers: connected ? [{ pubkey: `0x${eligible}` as const, address: "connected" }] : [] }),
  }, 1000n * 100_000_000n, { timeoutMs: 100, intervalMs: 1 });

  assert.equal(peers.length, 1);
  assert.equal(peers[0].pubkey, `0x${eligible}`);
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
