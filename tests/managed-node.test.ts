import assert from "node:assert/strict";
import test from "node:test";
import { managedNodeRequest } from "../src/server/managed-node.ts";

const node = {
  nodeInfo: async () => ({ pubkey: `0x02${"11".repeat(32)}` }),
  listChannels: async () => ({ channels: [] }),
  newInvoice: async ({ amount }: { amount: string }) => ({ invoice_address: `fibt-${amount}` }),
  sendPayment: async () => ({ payment_hash: `0x${"22".repeat(32)}`, fee: "0x1" }),
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

  await assert.rejects(
    managedNodeRequest("user-1", { operation: "new-invoice", amount: "100" }, node as never),
    /hexadecimal/,
  );
  await assert.rejects(
    managedNodeRequest("user-1", { operation: "close-channel", channelId: "bad" }, node as never),
    /valid channel ID/,
  );
});
