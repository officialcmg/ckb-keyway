import assert from "node:assert/strict";
import test from "node:test";
import vm from "node:vm";
import { listenForWatchtowerCalls, WATCHTOWER_URL, withWatchtower, workerShimSource } from "../src/sdk/browser/watchtower-bridge.ts";
import { applyWatchtowerCall } from "../src/sdk/browser/watchtower-store.ts";

const CONFIG = `fiber:
  listening_addr: /ip4/127.0.0.1/tcp/8228
  chain: testnet
rpc:
  listening_addr: "127.0.0.1:8227"
services:
  - fiber
`;

test("the node's config names the in-page watchtower under fiber", () => {
  const config = withWatchtower(CONFIG);
  assert.match(config, /^fiber:\n {2}standalone_watchtower_rpc_url: "ws:\/\/keyway-watchtower\.invalid\/"\n {2}listening_addr/);
  assert.equal(withWatchtower(config), config);
  assert.throws(() => withWatchtower("rpc:\n  listening_addr: x\n"), /no fiber section/);
});

/** Runs the worker shim as Fiber's worker would, with a stand-in for the browser's WebSocket. */
function workerScope(channelName: string) {
  class NativeWebSocket { constructor(public url: string) {} }
  class CloseEvent extends Event { constructor(type: string, public init: unknown) { super(type); } }
  const scope: Record<string, unknown> = { BroadcastChannel, EventTarget, Event, MessageEvent, CloseEvent, DOMException, TextDecoder, setTimeout, clearTimeout, Promise, JSON, Map, Array, String, Object, NativeWebSocket };
  scope.self = scope;
  scope.WebSocket = NativeWebSocket;
  vm.runInNewContext(workerShimSource(channelName), scope);
  return { WebSocket: scope.WebSocket as new (url: string) => any, NativeWebSocket };
}

test("Fiber's JSON-RPC calls to the watchtower reach the page and are answered after they are stored", async () => {
  const name = `test-${Math.random()}`;
  const stored: unknown[] = [];
  const stop = listenForWatchtowerCalls(name, async (call) => {
    if (call.method === "remove_preimage") throw new Error("disk full");
    stored.push(call);
  });
  try {
    const { WebSocket, NativeWebSocket } = workerScope(name);
    assert.ok(new WebSocket("wss://bootnode.example/") instanceof NativeWebSocket, "other addresses use the real WebSocket");
    const socket = new WebSocket(WATCHTOWER_URL);
    await new Promise((resolve) => { socket.onopen = resolve; });
    assert.equal(socket.readyState, 1);
    const reply = (request: object) => new Promise<any>((resolve) => {
      socket.onmessage = (event: MessageEvent) => resolve(JSON.parse(event.data));
      socket.send(JSON.stringify(request));
    });
    const params = { channel_id: `0x${"ab".repeat(32)}`, settlement_data: { local_amount: "0x1", remote_amount: "0x2", tlcs: [] } };
    assert.deepEqual(await reply({ jsonrpc: "2.0", id: 7, method: "update_local_settlement", params: [params] }), { jsonrpc: "2.0", id: 7, result: null });
    assert.deepEqual(stored, [{ method: "update_local_settlement", params }]);
    const failed = await reply({ jsonrpc: "2.0", id: 8, method: "remove_preimage", params: [{ payment_hash: `0x${"cd".repeat(32)}` }] });
    assert.equal(failed.id, 8);
    assert.match(failed.error.message, /disk full/);
    const unknown = await reply({ jsonrpc: "2.0", id: 9, method: "drop_all", params: [{}] });
    assert.match(unknown.error.message, /Unknown watchtower method/);
    socket.close();
  } finally {
    stop();
  }
});

const key = (byte: string, length: number) => byte.repeat(length);
const create = {
  method: "create_watch_channel" as const,
  params: {
    channel_id: `0x${key("AB", 32)}`,
    funding_udt_type_script: null,
    local_settlement_key: key("11", 32),
    remote_settlement_key: `02${key("22", 32)}`,
    local_funding_pubkey: `03${key("33", 32)}`,
    remote_funding_pubkey: `02${key("44", 32)}`,
    settlement_data: { local_amount: "0xba43b7400", remote_amount: "0x5d21dba00", tlcs: [] },
  },
};

test("the store keeps what Fiber's watchtower keeps, keys normalised to 0x hex", () => {
  const created = applyWatchtowerCall(undefined, create, 1);
  assert.ok(created && created !== "remove");
  assert.equal(created.channelId, `0x${key("ab", 32)}`);
  assert.equal(created.localSettlementKey, `0x${key("11", 32)}`);
  assert.equal(created.remoteSettlementKey, `0x02${key("22", 32)}`);
  const local = { local_amount: "0x1", remote_amount: "0x2", tlcs: [] };
  const updated = applyWatchtowerCall(created, { method: "update_local_settlement", params: { channel_id: create.params.channel_id, settlement_data: local } }, 2);
  assert.ok(updated && updated !== "remove");
  assert.deepEqual(updated.localSettlement, local);
  assert.equal(updated.createdAt, 1);
  const pending = applyWatchtowerCall(updated, { method: "update_pending_remote_settlement", params: { channel_id: create.params.channel_id, settlement_data: local } });
  assert.ok(pending && pending !== "remove" && pending.pendingRemoteSettlement);
  const revoked = applyWatchtowerCall(pending, { method: "update_revocation", params: { channel_id: create.params.channel_id, revocation_data: { commitment_number: "0x1" }, settlement_data: local } });
  assert.ok(revoked && revoked !== "remove" && revoked.remoteSettlement && revoked.revocation);
  assert.equal(applyWatchtowerCall(revoked, { method: "remove_watch_channel", params: { channel_id: create.params.channel_id } }), "remove");
  // Updates for a channel the page never saw created are not invented.
  assert.equal(applyWatchtowerCall(undefined, { method: "update_local_settlement", params: { channel_id: create.params.channel_id, settlement_data: local } }), undefined);
});

test("malformed watchtower data is rejected rather than stored", () => {
  assert.throws(() => applyWatchtowerCall(undefined, { ...create, params: { ...create.params, local_settlement_key: "0x1234" } }), /settlement key/);
  assert.throws(() => applyWatchtowerCall(undefined, { ...create, params: { ...create.params, settlement_data: { tlcs: [] } } }), /settlement data/);
});

test("a repeated create_watch_channel keeps the peer's settlement and revocation data", () => {
  const created = applyWatchtowerCall(undefined, create, 1);
  assert.ok(created && created !== "remove");
  const local = { local_amount: "0x1", remote_amount: "0x2", tlcs: [] };
  const revoked = applyWatchtowerCall(created, { method: "update_revocation", params: { channel_id: create.params.channel_id, revocation_data: { commitment_number: "0x1" }, settlement_data: local } });
  assert.ok(revoked && revoked !== "remove");
  const again = applyWatchtowerCall(revoked, create, 3);
  assert.ok(again && again !== "remove");
  assert.deepEqual(again.remoteSettlement, local);
  assert.ok(again.revocation);
  assert.equal(again.createdAt, 1);
});
