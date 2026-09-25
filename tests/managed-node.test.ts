import assert from "node:assert/strict";
import test from "node:test";
import { managedNodeRequest, parseManagedNodeAssignments } from "../src/server/managed-node.ts";

const node = {
  nodeInfo: async () => ({ pubkey: `0x02${"11".repeat(32)}` }),
  connectPeer: async () => undefined,
  listPeers: async () => ({ peers: [] }),
  listChannels: async () => ({ channels: [] }),
  openChannelWithExternalFunding: async () => ({
    channel_id: `0x${"33".repeat(32)}`,
    unsigned_funding_tx: { version: "0x0" },
  }),
  submitSignedFundingTx: async () => ({
    channel_id: `0x${"33".repeat(32)}`,
    funding_tx_hash: `0x${"44".repeat(32)}`,
  }),
  waitForChannelReady: async () => ({ channel_id: `0x${"33".repeat(32)}` }),
  newInvoice: async ({ amount }: { amount: string }) => ({ invoice_address: `fibt-${amount}` }),
  getInvoice: async () => ({ status: "Open" }),
  parseInvoice: async ({ invoice }: { invoice: string }) => ({ invoice: { currency: invoice.slice(0, 4) } }),
  sendPayment: async () => ({ payment_hash: `0x${"22".repeat(32)}`, fee: "0x1" }),
  getPayment: async () => ({ status: "Created" }),
  waitForPayment: async () => ({ status: "Success" }),
  shutdownChannel: async () => undefined,
};

test("managed beta exposes only bounded authenticated node operations", async () => {
  const status = await managedNodeRequest("user-1", { operation: "status" }, node as never) as {
    network: string;
    custody: string;
  };
  assert.equal(status.network, "testnet");
  assert.equal(status.custody, "keyway-managed");

  const invoice = await managedNodeRequest("user-1", {
    operation: "new-invoice",
    amount: "0x5f5e100",
    description: "test",
  }, node as never) as { invoice_address: string };
  assert.equal(invoice.invoice_address, "fibt-0x5f5e100");

  const parsed = await managedNodeRequest("user-1", {
    operation: "parse-invoice",
    invoice: "fibt-test",
  }, node as never) as { invoice: { currency: string } };
  assert.equal(parsed.invoice.currency, "fibt");

  const channel = await managedNodeRequest("user-1", {
    operation: "open-channel",
    params: {
      pubkey: "0x02b6d4e3ab86a2ca2fad6fae0ecb2e1e559e0b911939872a90abdda6d20302be71",
      funding_amount: "0x5f5e100",
      public: true,
      shutdown_script: { code_hash: `0x${"11".repeat(32)}`, hash_type: "type", args: "0x12" },
      funding_lock_script: { code_hash: `0x${"11".repeat(32)}`, hash_type: "type", args: "0x12" },
      funding_lock_script_cell_deps: [],
    },
  }, node as never) as { channel_id: string };
  assert.equal(channel.channel_id, `0x${"33".repeat(32)}`);

  await assert.rejects(
    managedNodeRequest("user-1", { operation: "new-invoice", amount: "100" }, node as never),
    /hexadecimal/,
  );
  await assert.rejects(
    managedNodeRequest("user-1", { operation: "close-channel", channelId: "bad" }, node as never),
    /valid channel ID/,
  );
  await assert.rejects(
    managedNodeRequest("user-1", {
      operation: "open-channel",
      params: {
        pubkey: `0x02${"55".repeat(32)}`,
        funding_amount: "0x1",
        shutdown_script: { code_hash: `0x${"11".repeat(32)}`, hash_type: "type", args: "0x" },
        funding_lock_script: { code_hash: `0x${"11".repeat(32)}`, hash_type: "type", args: "0x" },
      },
    }, node as never),
    /approved testnet channel peers/,
  );
});

test("managed beta refuses funding beyond the open-channel capacity", async () => {
  const full = { ...node, listChannels: async () => ({ channels: Array.from({ length: 5 }, () => ({})) }) };
  await assert.rejects(
    managedNodeRequest("user-1", {
      operation: "open-channel",
      params: {
        pubkey: "0x02b6d4e3ab86a2ca2fad6fae0ecb2e1e559e0b911939872a90abdda6d20302be71",
        funding_amount: "0x5f5e100",
        shutdown_script: { code_hash: `0x${"11".repeat(32)}`, hash_type: "type", args: "0x" },
        funding_lock_script: { code_hash: `0x${"11".repeat(32)}`, hash_type: "type", args: "0x" },
      },
    }, full as never),
    /at most 5 open channels/,
  );
});

test("managed users must be assigned distinct private nodes", () => {
  const assignments = parseManagedNodeAssignments(JSON.stringify({
    "user-1": "http://fiber-user-1.railway.internal:8227",
    "user-2": "https://fiber-user-2.example.com",
  }));
  assert.equal(assignments.get("user-1"), "http://fiber-user-1.railway.internal:8227/");
  assert.equal(assignments.get("user-2"), "https://fiber-user-2.example.com/");

  assert.throws(
    () => parseManagedNodeAssignments(JSON.stringify({
      "user-1": "http://fiber.railway.internal:8227",
      "user-2": "http://fiber.railway.internal:8227",
    })),
    /dedicated node/,
  );
  assert.throws(
    () => parseManagedNodeAssignments(JSON.stringify({ "user-1": "http://fiber.example.com" })),
    /HTTPS or a private Railway address/,
  );
});
