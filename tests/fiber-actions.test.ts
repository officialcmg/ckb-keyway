import assert from "node:assert/strict";
import test from "node:test";
import { createFiberActions } from "../src/sdk/browser/fiber-actions.ts";
import { approveFiberParams } from "../src/sdk/browser/fiber-methods.ts";
import { assertPublicPeerAddress, isPrivateIp } from "../src/server/peer-address.ts";
import { managedNodeRequest } from "../src/server/managed-node.ts";

const id = `0x${"ab".repeat(32)}`;
const channel = { channel_id: id, pubkey: `0x02${"cd".repeat(32)}`, local_balance: "0x2540be400", remote_balance: "0x0", state: { state_name: "CHANNEL_READY" }, is_public: true, enabled: true, tlc_fee_proportional_millionths: "0x3e8" };

test("dialog methods: KeyWay keeps the scripts, caps fees, and never saves peers", () => {
  assert.throws(() => approveFiberParams("openChannelWithExternalFunding", { pubkey: channel.pubkey, funding_amount: "0x1", shutdown_script: {} }), /user's own account/);
  assert.throws(() => approveFiberParams("shutdownChannel", { channel_id: id, close_script: {} }), /close_script/);
  assert.throws(() => approveFiberParams("shutdownChannel", { channel_id: id, fee_rate: "0x186a1" }), /at most 100000/);
  assert.throws(() => approveFiberParams("updateChannel", { channel_id: id, tlc_fee_proportional_millionths: "0x186a1" }), /at most 100000/);
  assert.deepEqual(approveFiberParams("connectPeer", { pubkey: channel.pubkey }), { pubkey: channel.pubkey, save: false });
  assert.throws(() => approveFiberParams("connectPeer", {}), /pubkey or address/);
  assert.throws(() => approveFiberParams("abandonChannel", {}), /isn't available/);
});

test("actions show the user what changes, run only when approved, and refuse without an approval", async () => {
  const acted: Array<{ method: string; params: unknown }> = [];
  const seen: unknown[] = [];
  let allow = true;
  const io = { listChannels: async () => ({ channels: [channel] }) as never, act: async (method: string, params: Record<string, unknown>) => { acted.push({ method, params }); } };
  const actions = createFiberActions(io, () => ({
    approveFiberChannelClose: (preview) => { seen.push(preview); return allow; },
    approveFiberChannelSettings: (preview) => { seen.push(preview); return allow; },
  }));
  await actions.shutdownChannel({ channel_id: id });
  assert.deepEqual(seen[0], { channelId: id, peer: channel.pubkey, asset: "ckb", returning: "10000000000", returningText: "100 CKB", force: false, network: "CKB testnet" });
  await actions.updateChannel({ channel_id: id, tlc_fee_proportional_millionths: "0x7d0", enabled: false });
  assert.deepEqual((seen[1] as { changes: unknown }).changes, [
    { setting: "enabled", from: "true", to: "false" },
    { setting: "tlc_fee_proportional_millionths", from: "0x3e8", to: "0x7d0" },
  ]);
  allow = false;
  await assert.rejects(() => actions.shutdownChannel({ channel_id: id, force: true }), /not approved/);
  // No approval function at all: refused, never silent.
  await assert.rejects(() => actions.connectPeer({ pubkey: channel.pubkey }), /not approved/);
  assert.equal(acted.length, 2);
});

test("hosted nodes refuse private and internal peer addresses", async () => {
  for (const address of ["10.0.0.1", "172.20.1.1", "192.168.1.1", "127.0.0.1", "100.64.0.1", "169.254.1.1", "::1", "fd00::1", "::ffff:10.0.0.1"]) assert.equal(isPrivateIp(address), true, address);
  assert.equal(isPrivateIp("18.162.235.225"), false);
  await assert.rejects(() => assertPublicPeerAddress("/ip4/10.0.0.5/tcp/8228"), /must be public/);
  await assert.rejects(() => assertPublicPeerAddress("/dns4/fiber.railway.internal/tcp/8228"), /must be public/);
  await assert.rejects(() => assertPublicPeerAddress("/dns4/evil.example.com/tcp/8228", async () => ["127.0.0.1"]), /must be public/);
  await assertPublicPeerAddress("/dns4/bottle.fiber.channel/tcp/443/wss", async () => ["18.162.235.225"]);

  const calls: string[] = [];
  const node = { listPeers: async () => ({ peers: [] }), call: async (method: string) => { calls.push(method); return {}; } };
  await assert.rejects(() => managedNodeRequest("act-user", { operation: "act", method: "connectPeer", params: { address: "/ip4/192.168.0.2/tcp/8228" } }, node as never), /must be public/);
  await managedNodeRequest("act-user", { operation: "act", method: "connectPeer", params: { address: "/ip4/18.162.235.225/tcp/8119" } }, node as never);
  await assert.rejects(() => managedNodeRequest("act-user", { operation: "act", method: "abandonChannel", params: {} }, node as never), /isn't available/);
  assert.deepEqual(calls, ["connect_peer"]);
});
