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
    listChannels: async () => ({ channels: [] as unknown[] }),
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

test("connecting by pubkey succeeds only once that peer itself is connected, not another node at its address", async (t) => {
  // A graph address without /p2p/ (or a stale one) reaches whatever node now listens there, and Fiber accepts
  // the dial before the handshake.
  t.mock.timers.enable({ apis: ["Date"], now: Date.now() });
  const { node, dialed } = hostedNode(["/ip4/203.0.113.5/tcp/8228"]);
  let dialedOnce = false;
  node.connectPeer = async (params) => { dialed.push(params); dialedOnce = true; };
  node.call = async (method: string, [params]: [Record<string, unknown>]) => {
    if (method === "graph_nodes") return { nodes: [{ pubkey: PEER.slice(2), addresses: ["/ip4/203.0.113.5/tcp/8228"] }], last_cursor: "0x" };
    if (method === "connect_peer") { dialed.push(params); dialedOnce = true; }
    return {};
  };
  node.listPeers = async () => {
    t.mock.timers.tick(5_000);
    return { peers: dialedOnce ? [{ pubkey: `0x02${"cd".repeat(32)}` }] : [] };
  };
  await assert.rejects(
    managedNodeRequest("stale-user", { operation: "act", method: "connectPeer", params: { pubkey: PEER } }, node as never),
    /Could not connect/,
  );
  assert.deepEqual(dialed, [{ address: "/ip4/203.0.113.5/tcp/8228", save: false }]);
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

test("opening a channel connects a new peer only while the hosted node has room for it", async () => {
  const others = Array.from({ length: 32 }, (_, index) => ({ pubkey: `0x02${index.toString(16).padStart(64, "0")}` }));
  const open = (pubkey: string, node: unknown) => managedNodeRequest("full-user", {
    operation: "open-channel",
    params: { pubkey, funding_amount: "0x5f5e100", funding_lock_script: lock },
  }, node as never, async () => lock as never);
  for (const peer of [PEER, OFFICIAL]) {
    const { node, dialed } = hostedNode(["/ip4/203.0.113.5/tcp/8228/p2p/Qm1"]);
    node.listPeers = async () => ({ peers: others });
    await assert.rejects(open(peer, node), /at most 32 peers/, peer);
    assert.deepEqual(dialed, [], peer);
  }
  // A peer it's already connected to needs no room.
  const { node } = hostedNode([]);
  let channels = 0;
  node.listPeers = async () => ({ peers: [...others.slice(1), { pubkey: OFFICIAL }] });
  node.openChannelWithExternalFunding = async () => { channels++; return { channel_id: `0x${"33".repeat(32)}` }; };
  (node as { connectPeer: unknown }).connectPeer = async () => undefined;
  await open(OFFICIAL, node);
  assert.equal(channels, 1);
});

test("parallel peer connections can't take a hosted node past its peer limit", async () => {
  const connected: string[] = [];
  const others = Array.from({ length: 31 }, (_, index) => ({ pubkey: `0x02${index.toString(16).padStart(64, "0")}` }));
  const node = {
    // Answers with the peers as they were when asked, after a while, as a node over the network does.
    listPeers: async () => {
      const peers = [...others, ...connected.map((pubkey) => ({ pubkey }))];
      await new Promise((resolve) => setTimeout(resolve, 10));
      return { peers };
    },
    call: async (_method: string, [params]: [{ address: string }]) => {
      await new Promise((resolve) => setTimeout(resolve, 10));
      connected.push(`0x03${params.address.split(".")[3].split("/")[0].padStart(64, "0")}`);
      return {};
    },
  };
  const results = await Promise.allSettled([1, 2].map((host) => managedNodeRequest("race-user", {
    operation: "act", method: "connectPeer", params: { address: `/ip4/203.0.113.${host}/tcp/8228` },
  }, node as never)));
  assert.equal(results.filter(({ status }) => status === "fulfilled").length, 1);
  assert.equal(connected.length, 1);
});

test("connecting a peer by key needs room for every address it dials, and reconnecting an official peer needs none", async () => {
  // 30 peers: a peer announcing 4 addresses could reach 4 different nodes.
  const others = Array.from({ length: 30 }, (_, index) => ({ pubkey: `0x02${index.toString(16).padStart(64, "0")}` }));
  const announced = Array.from({ length: 4 }, (_, index) => `/ip4/203.0.113.${index + 1}/tcp/8228/p2p/Qm1`);
  const { node, dialed } = hostedNode(announced);
  node.listPeers = async () => ({ peers: others });
  await assert.rejects(managedNodeRequest("room-user", { operation: "act", method: "connectPeer", params: { pubkey: PEER } }, node as never), /at most 32 peers/);
  assert.deepEqual(dialed, []);
  // At the limit, an official peer that is already connected can still be connected again.
  const full = hostedNode([]);
  full.node.listPeers = async () => ({ peers: [...others, { pubkey: `0x02${"ff".repeat(32)}` }, { pubkey: OFFICIAL }] });
  await managedNodeRequest("room-user", { operation: "act", method: "connectPeer", params: { pubkey: OFFICIAL } }, full.node as never);
  assert.deepEqual(full.dialed, [{ pubkey: OFFICIAL, addr_type: "tcp", save: false }]);
});

test("a new address for a peer that is already connected still needs room", async () => {
  const others = Array.from({ length: 31 }, (_, index) => ({ pubkey: `0x02${index.toString(16).padStart(64, "0")}` }));
  const { node, dialed } = hostedNode([]);
  node.listPeers = async () => ({ peers: [...others, { pubkey: PEER }] });
  await assert.rejects(
    managedNodeRequest("bypass-user", { operation: "act", method: "connectPeer", params: { pubkey: PEER, address: "/ip4/203.0.113.7/tcp/8228" } }, node as never),
    /at most 32 peers/,
  );
  assert.deepEqual(dialed, []);
});

test("a hosted node opens no more channels once it has many unfinished channels or channel records", async () => {
  const open = (channels: unknown[]) => {
    const { node } = hostedNode([]);
    node.listChannels = async () => ({ channels });
    let opened = 0;
    node.openChannelWithExternalFunding = async () => { opened++; return { channel_id: `0x${"33".repeat(32)}` }; };
    (node as { connectPeer: unknown }).connectPeer = async () => undefined;
    node.listPeers = async () => ({ peers: [{ pubkey: OFFICIAL }] });
    return managedNodeRequest("records-user", {
      operation: "open-channel", params: { pubkey: OFFICIAL, funding_amount: "0x5f5e100", funding_lock_script: lock },
    }, node as never, async () => lock as never).then(() => opened);
  };
  const pending = { state: { state_name: "NEGOTIATING_FUNDING", state_flags: "AWAITING_EXTERNAL_FUNDING" } };
  const aborted = { state: { state_name: "CLOSED", state_flags: "FUNDING_ABORTED" } };
  await assert.rejects(open(Array(32).fill(pending)), /at most 32 channels/);
  await assert.rejects(open(Array(200).fill(aborted)), /at most 200 channel records/);
  assert.equal(await open([...Array(31).fill(pending), ...Array(100).fill(aborted)]), 1);
});

test("a user's queued peer connections are bounded while handshakes stall", async () => {
  // A peer whose handshake never completes: each connection waits until it is released.
  let release: () => void = () => {};
  const stalled = new Promise<void>((resolve) => { release = resolve; });
  const node = {
    listPeers: async () => ({ peers: [] }),
    call: async () => { await stalled; return {}; },
  };
  const connect = (host: number) => managedNodeRequest("queue-user", {
    operation: "act", method: "connectPeer", params: { address: `/ip4/203.0.113.${host}/tcp/8228` },
  }, node as never);
  const queued = [1, 2, 3].map(connect);
  await assert.rejects(connect(4), /Too many peer connections/);
  release();
  await Promise.all(queued);
  // Once they finish, more may queue again.
  await connect(5);
});

test("a hosted node dials only the first few addresses a peer announces", async () => {
  const announced = Array.from({ length: 20 }, (_, index) => `/ip4/203.0.113.${index + 1}/tcp/8228/p2p/Qm1`);
  for (const request of [
    { operation: "act", method: "connectPeer", params: { pubkey: PEER } },
    { operation: "open-channel", params: { pubkey: PEER, funding_amount: "0x5f5e100", funding_lock_script: lock } },
  ]) {
    const { node, dialed } = hostedNode(announced);
    await managedNodeRequest("many-addresses", request, node as never, async () => lock as never);
    assert.deepEqual(dialed.map(({ address }) => address), announced.slice(0, 4), request.operation);
  }
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
