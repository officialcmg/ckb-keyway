import assert from "node:assert/strict";
import test from "node:test";
import { managedNodeRequest, parseManagedNodeAssignments } from "../src/server/managed-node.ts";

const ownLock = async () => ({ code_hash: `0x${"11".repeat(32)}`, hash_type: "type", args: "0x" }) as never;

let lastInvoiceParams: Record<string, unknown> | undefined;

const node = {
  nodeInfo: async () => ({ pubkey: `0x02${"11".repeat(32)}` }),
  connectPeer: async () => undefined,
  listPeers: async () => ({ peers: [{ pubkey: "02b6d4e3ab86a2ca2fad6fae0ecb2e1e559e0b911939872a90abdda6d20302be71" }] }),
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
  newInvoice: async (params: { amount: string }) => {
    lastInvoiceParams = params;
    return { invoice_address: `fibt-${params.amount}` };
  },
  getInvoice: async () => ({ status: "Open" }),
  parseInvoice: async ({ invoice }: { invoice: string }) => ({ invoice: { currency: invoice.slice(0, 4) } }),
  sendPayment: async () => ({ payment_hash: `0x${"22".repeat(32)}`, fee: "0x1" }),
  getPayment: async () => ({ status: "Created" }),
  waitForPayment: async () => ({ status: "Success" }),
  shutdownChannel: async () => undefined,
};

test("managed invoices honor a bounded caller expiry and default to 24 hours", async () => {
  const request = (expiry?: unknown) => managedNodeRequest("user-1", {
    operation: "new-invoice",
    amount: "0x5f5e100",
    ...(expiry === undefined ? {} : { expiry }),
  }, node as never);

  await request("0xe10");
  assert.equal(lastInvoiceParams?.expiry, "0xe10");
  assert.equal(lastInvoiceParams?.currency, "Fibt");
  await request("0x3c");
  assert.equal(lastInvoiceParams?.expiry, "0x3c");
  await request("0x15180");
  assert.equal(lastInvoiceParams?.expiry, "0x15180");
  await request();
  assert.equal(lastInvoiceParams?.expiry, "0x15180");

  for (const expiry of ["0x3b", "0x15181", "3600", "0xzz", 3600]) {
    await assert.rejects(request(expiry), /Invoice expiry must be between 60 seconds and 24 hours/);
  }
});

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
  // Fiber invoice expiry is in seconds: 0x15180 = 86,400 s = 24 hours.
  assert.equal(lastInvoiceParams?.expiry, "0x15180");

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
  }, node as never, async () => ({ code_hash: `0x${"11".repeat(32)}`, hash_type: "type", args: "0x12" }) as never) as { channel_id: string };
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
    }, node as never, ownLock),
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
    }, full as never, ownLock),
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

test("managed funding strips older SDK input caches before native RPC submission", async () => {
  const cached = {
    version: "0x0", cell_deps: [], header_deps: [], outputs: [], outputs_data: [], witnesses: ["0x1234"],
    inputs: [{
      since: "0x0",
      previous_output: { tx_hash: `0x${"11".repeat(32)}`, index: "0x0" },
      cellOutput: { capacity: "0x5f5e100", lock: { code_hash: `0x${"22".repeat(32)}`, hash_type: "type", args: "0x" } },
      outputData: "0x",
    }],
  };
  await managedNodeRequest("older-sdk-test", {
    operation: "submit-channel-funding",
    params: { channel_id: `0x${"33".repeat(32)}`, signed_funding_tx: cached },
  }, {
    ...node,
    submitSignedFundingTx: async (params: { signed_funding_tx: { inputs: object[]; witnesses: string[] } }) => {
      assert.deepEqual(Object.keys(params.signed_funding_tx.inputs[0]).sort(), ["previous_output", "since"]);
      assert.deepEqual(params.signed_funding_tx.witnesses, ["0x1234"]);
      return node.submitSignedFundingTx();
    },
  } as never);
});

test("managed channels can only close to the user's own lock", async () => {
  const opened: Array<{ shutdown_script: unknown }> = [];
  const recording = { ...node, openChannelWithExternalFunding: async (params: { shutdown_script: unknown }) => { opened.push(params); return node.openChannelWithExternalFunding(); } };
  const open = (shutdown?: unknown) => managedNodeRequest("own-lock-test", {
    operation: "open-channel",
    params: {
      pubkey: "0x02b6d4e3ab86a2ca2fad6fae0ecb2e1e559e0b911939872a90abdda6d20302be71",
      funding_amount: "0x5f5e100",
      ...(shutdown === undefined ? {} : { shutdown_script: shutdown }),
      funding_lock_script: { code_hash: `0x${"11".repeat(32)}`, hash_type: "type", args: "0x" },
    },
  }, recording as never, ownLock);
  await assert.rejects(() => open({ code_hash: `0x${"11".repeat(32)}`, hash_type: "type", args: "0x99" }), /only close to your own KeyWay address/);
  await open();
  await open({ code_hash: `0x${"11".repeat(32)}`.toUpperCase().replace("0X", "0x"), hash_type: "type", args: "0x" });
  assert.equal(opened.length, 2);
  for (const params of opened) assert.deepEqual(params.shutdown_script, await ownLock());
  await assert.rejects(() => managedNodeRequest("own-lock-test", { operation: "open-channel", params: { pubkey: "0x02b6d4e3ab86a2ca2fad6fae0ecb2e1e559e0b911939872a90abdda6d20302be71", funding_amount: "0x5f5e100", funding_lock_script: { code_hash: `0x${"11".repeat(32)}`, hash_type: "type", args: "0x" } } }, recording as never), /own lock is required/);
});

test("managed funding waits until the requested peer handshake is visible", async () => {
  let polls = 0;
  const delayed = {
    ...node,
    connectPeer: async (params: { pubkey?: string; addr_type?: string; address?: string }) => {
      assert.equal(params.pubkey, "0x02b6d4e3ab86a2ca2fad6fae0ecb2e1e559e0b911939872a90abdda6d20302be71");
      assert.equal(params.addr_type, "tcp");
      assert.equal(params.address, undefined, "native nodes must not use browser WSS seeds");
    },
    listPeers: async () => ++polls === 1 ? { peers: [] } : node.listPeers(),
    openChannelWithExternalFunding: async () => {
      assert.ok(polls >= 2, "channel negotiation must wait for peer readiness");
      return node.openChannelWithExternalFunding();
    },
  };
  await managedNodeRequest("handshake-test", {
    operation: "open-channel",
    params: {
      pubkey: "0x02b6d4e3ab86a2ca2fad6fae0ecb2e1e559e0b911939872a90abdda6d20302be71",
      funding_amount: "0x5f5e100",
      shutdown_script: { code_hash: `0x${"11".repeat(32)}`, hash_type: "type", args: "0x" },
      funding_lock_script: { code_hash: `0x${"11".repeat(32)}`, hash_type: "type", args: "0x" },
    },
  }, delayed as never, ownLock);
});

test("a fresh managed node uses a TCP bootstrap hint when gossip has no address", async () => {
  const calls: Array<Record<string, unknown>> = [];
  const fresh = {
    ...node,
    connectPeer: async (params: Record<string, unknown>) => {
      calls.push(params);
      if (params.pubkey) throw new Error("No matching address");
      assert.match(String(params.address), /\/tcp\/8119\/p2p\//);
      assert.ok(!String(params.address).includes("/wss"));
    },
  };
  await managedNodeRequest("fresh-node-test", {
    operation: "open-channel",
    params: {
      pubkey: "0x02b6d4e3ab86a2ca2fad6fae0ecb2e1e559e0b911939872a90abdda6d20302be71",
      funding_amount: "0x5f5e100",
      shutdown_script: { code_hash: `0x${"11".repeat(32)}`, hash_type: "type", args: "0x" },
      funding_lock_script: { code_hash: `0x${"11".repeat(32)}`, hash_type: "type", args: "0x" },
    },
  }, fresh as never, ownLock);
  assert.equal(calls.length, 2);
  assert.equal(calls[0].addr_type, "tcp");
});
