import assert from "node:assert/strict";
import dnsPromises from "node:dns/promises";
import { syncBuiltinESMExports } from "node:module";
import test from "node:test";
import { managedNodeRequest } from "../src/server/managed-node.ts";
import { isPrivateIp } from "../src/server/peer-address.ts";

const PEER = `0x03${"ab".repeat(32)}`;
const OFFICIAL = "0x02b6d4e3ab86a2ca2fad6fae0ecb2e1e559e0b911939872a90abdda6d20302be71";
const lock = { code_hash: `0x${"11".repeat(32)}`, hash_type: "type", args: "0x" };

/** A hosted node that records what it is asked to dial and answers graph_nodes with one peer. */
function hostedNode(announced: string[]) {
  const dialed: Array<Record<string, unknown>> = [];
  let connected = false;
  const node = {
    nodeInfo: async () => ({ pubkey: `0x02${"11".repeat(32)}` }),
    listPeers: async () => ({ peers: connected ? [{ pubkey: PEER }] : [] }),
    connectPeer: async (params: Record<string, unknown>) => { dialed.push(params); connected = true; },
    openChannelWithExternalFunding: async () => ({ channel_id: `0x${"33".repeat(32)}` }),
    call: async (method: string, [params]: [Record<string, unknown>]) => {
      if (method === "graph_nodes") return { nodes: [{ pubkey: PEER.slice(2), addresses: announced }], last_cursor: "0x" };
      if (method === "connect_peer") dialed.push(params);
      return {};
    },
  };
  return { node, dialed };
}

/** Answers every DNS lookup with the given addresses, for the length of one test. */
function fakeDns(t: { after: (fn: () => void) => void }, addresses: string[]) {
  const original = dnsPromises.lookup;
  (dnsPromises as { lookup: unknown }).lookup = async () => addresses.map((address) => ({ address, family: address.includes(":") ? 6 : 4 }));
  syncBuiltinESMExports();
  t.after(() => { dnsPromises.lookup = original; syncBuiltinESMExports(); });
}

test("status hides the hosted node's internal addresses and funding lock, like nodeInfo does", async () => {
  const node = {
    nodeInfo: async () => ({ pubkey: `0x02${"11".repeat(32)}`, addresses: ["/ip4/10.0.0.1/tcp/8228"], default_funding_lock_script: lock }),
    listPeers: async () => ({ peers: [] }),
  };
  const status = await managedNodeRequest("status-user", { operation: "status" }, node as never) as { node: Record<string, unknown> };
  assert.equal(status.node.pubkey, `0x02${"11".repeat(32)}`);
  assert.equal("addresses" in status.node, false);
  assert.equal("default_funding_lock_script" in status.node, false);
});

test("connecting a hosted node by pubkey dials only the peer addresses that were checked", async () => {
  // The peer announces a public TCP address and a WebSocket address inside KeyWay's network.
  const announced = ["/ip4/203.0.113.5/tcp/8228/p2p/Qm1", "/ip4/127.0.0.1/tcp/9/ws/p2p/Qm1"];
  for (const addr_type of ["ws", "wss", "tcp", undefined]) {
    const { node, dialed } = hostedNode(announced);
    await managedNodeRequest("pubkey-user", { operation: "act", method: "connectPeer", params: { pubkey: PEER, ...(addr_type ? { addr_type } : {}) } }, node as never);
    assert.ok(dialed.length > 0, `addr_type ${addr_type}`);
    for (const params of dialed) {
      if (params.address !== undefined) assert.equal(params.address, announced[0], `addr_type ${addr_type}`);
      else assert.equal(params.addr_type, "tcp", `addr_type ${addr_type}`);
      assert.equal(params.save, false);
    }
  }
  // Official peers are dialed by key, over TCP only.
  const { node, dialed } = hostedNode([]);
  await managedNodeRequest("pubkey-user", { operation: "act", method: "connectPeer", params: { pubkey: OFFICIAL, addr_type: "wss" } }, node as never);
  assert.deepEqual(dialed, [{ pubkey: OFFICIAL, addr_type: "tcp", save: false }]);
});

test("connecting by pubkey to a peer that is already connected never dials it by key", async () => {
  // The peer could drop the session before the node dials, and by key the node would pick from addresses
  // the peer announced itself, such as one inside KeyWay's network.
  const { node, dialed } = hostedNode(["/ip4/127.0.0.1/tcp/8227/p2p/Qm1"]);
  node.listPeers = async () => ({ peers: [{ pubkey: PEER }] });
  const result = await managedNodeRequest("connected-user", { operation: "act", method: "connectPeer", params: { pubkey: PEER } }, node as never);
  assert.deepEqual(result, { done: true });
  assert.deepEqual(dialed, []);
});

test("a hosted node dials the checked IP, not a host name it would resolve again", async (t) => {
  fakeDns(t, ["203.0.113.9"]);
  const { node, dialed } = hostedNode([]);
  await managedNodeRequest("dns-user", { operation: "act", method: "connectPeer", params: { address: "/dns4/peer.example.com/tcp/8228/p2p/Qm1" } }, node as never);
  assert.deepEqual(dialed, [{ address: "/ip4/203.0.113.9/tcp/8228/p2p/Qm1", save: false }]);
  // A secure WebSocket needs the name for its certificate, so a hosted node can't dial one by name.
  await assert.rejects(
    managedNodeRequest("dns-user", { operation: "act", method: "connectPeer", params: { address: "/dns4/peer.example.com/tcp/443/wss" } }, node as never),
    /host name/,
  );
});

test("opening a channel to any public peer dials its checked IPs and never saves them", async (t) => {
  fakeDns(t, ["203.0.113.9"]);
  const { node, dialed } = hostedNode(["/dns4/peer.example.com/tcp/8228/p2p/Qm1"]);
  await managedNodeRequest("dns-user", {
    operation: "open-channel",
    params: { pubkey: PEER, funding_amount: "0x5f5e100", funding_lock_script: lock },
  }, node as never, async () => lock as never);
  assert.deepEqual(dialed, [{ address: "/ip4/203.0.113.9/tcp/8228/p2p/Qm1", save: false }]);
});

test("IPv6 spellings of internal addresses are private", () => {
  for (const address of [
    "::ffff:7f00:1", "::ffff:a00:1", "0::1", "0:0:0:0:0:0:0:1", "::0:1", "::127.0.0.1", "::",
    "64:ff9b::7f00:1", "64:ff9b::10.0.0.1", "64:ff9b:1::1", "2002:7f00:1::1", "2002:a00:1::",
    "fec0::1", "FE80::1", "fe80::1%en0", "fc00::1", "FD12::1", "ff02::1", "100::1", "2001:db8::1", "2001::1",
  ]) assert.equal(isPrivateIp(address), true, address);
  for (const address of ["2606:4700:4700::1111", "2a00:1450:4001::1", "64:ff9b::808:808", "2002:808:808::1", "::ffff:8.8.8.8"]) {
    assert.equal(isPrivateIp(address), false, address);
  }
});
