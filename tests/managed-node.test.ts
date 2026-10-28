import assert from "node:assert/strict";
import test from "node:test";
import { managedNodeRequest, parseManagedNodeAssignments } from "../src/server/managed-node.ts";

const ownLock = async () => ({ code_hash: `0x${"11".repeat(32)}`, hash_type: "type", args: "0x" }) as never;

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
  getInvoice: async () => ({ status: "Open" }),
  parseInvoice: async ({ invoice }: { invoice: string }) => ({ invoice: { currency: invoice.slice(0, 4) } }),
  getPayment: async () => ({ status: "Created" }),
  waitForPayment: async () => ({ status: "Success" }),
};

test("managed beta exposes only bounded authenticated node operations", async () => {
  const status = await managedNodeRequest("user-1", { operation: "status" }, node as never) as {
    network: string;
    custody: string;
  };
  assert.equal(status.network, "testnet");
  assert.equal(status.custody, "keyway-managed");

  const invoice = await managedNodeRequest("user-1", {
    operation: "get-invoice",
    paymentHash: `0x${"22".repeat(32)}`,
  }, node as never) as { status: string };
  assert.equal(invoice.status, "Open");

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
    managedNodeRequest("user-1", { operation: "get-payment", paymentHash: "bad" }, node as never),
    /valid payment hash/,
  );
  // Invoices, payments and closes go through call, pay and act; the old dedicated operations are gone.
  for (const operation of ["new-invoice", "preflight-payment", "send-payment", "prepare-close-channel", "close-channel"]) {
    await assert.rejects(managedNodeRequest("user-1", { operation }, node as never), /Unsupported managed-node operation/);
  }
  await assert.rejects(
    managedNodeRequest("user-1", {
      operation: "open-channel",
      params: {
        pubkey: `0x02${"55".repeat(32)}`,
        funding_amount: "0x1",
        shutdown_script: { code_hash: `0x${"11".repeat(32)}`, hash_type: "type", args: "0x" },
        funding_lock_script: { code_hash: `0x${"11".repeat(32)}`, hash_type: "type", args: "0x" },
      },
    }, { ...node, call: async () => ({ nodes: [], last_cursor: "0x" }) } as never, ownLock),
    /isn't in the Fiber network graph/,
  );
  // Any public peer works, but one announcing only private addresses is refused.
  await assert.rejects(
    managedNodeRequest("user-1", {
      operation: "open-channel",
      params: {
        pubkey: `0x02${"55".repeat(32)}`,
        funding_amount: "0x1",
        funding_lock_script: { code_hash: `0x${"11".repeat(32)}`, hash_type: "type", args: "0x" },
      },
    }, { ...node, call: async () => ({ nodes: [{ pubkey: `02${"55".repeat(32)}`, addresses: ["/ip4/10.1.2.3/tcp/8228/p2p/Qm1"] }], last_cursor: "0x" }) } as never, ownLock),
    /must be public/,
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

test("hosted channels from an Omnilock account fund at 1500 shannons/KB; others keep Fiber's default", async () => {
  const rates: unknown[] = [];
  const recording = { ...node, openChannelWithExternalFunding: async (params: { funding_fee_rate?: string }) => { rates.push(params.funding_fee_rate); return node.openChannelWithExternalFunding(); } };
  const params = {
    pubkey: "0x02b6d4e3ab86a2ca2fad6fae0ecb2e1e559e0b911939872a90abdda6d20302be71",
    funding_amount: "0x5f5e100",
    funding_lock_script: { code_hash: `0x${"11".repeat(32)}`, hash_type: "type", args: "0x" },
  };
  await managedNodeRequest("fee-rate-test", { operation: "open-channel", params }, recording as never, ownLock);
  await managedNodeRequest("fee-rate-test", { operation: "open-channel", params: { ...params, funding_fee_rate: "0x7d0" } }, recording as never, ownLock);
  const omnilock = { code_hash: "0xf329effd1c475a2978453c8600e1eaf0bc2087ee093c3ee64cc96ec6847752cb", hash_type: "type", args: `0x00${"11".repeat(20)}01${"22".repeat(32)}` };
  await managedNodeRequest("fee-rate-test", { operation: "open-channel", params: { ...params, funding_lock_script: omnilock } }, recording as never, ownLock);
  assert.deepEqual(rates, [undefined, "0x7d0", "0x5dc"]);
});
