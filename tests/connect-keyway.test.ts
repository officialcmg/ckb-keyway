import assert from "node:assert/strict";
import test from "node:test";
import { normalizeFiberPubkey } from "../src/sdk/browser/fiber-pubkey.ts";
import { connectTestnetPeers } from "../src/sdk/browser/testnet-peers.ts";

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
