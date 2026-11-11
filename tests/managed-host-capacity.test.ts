import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { type TestContext } from "node:test";
import { createServer } from "node:http";
import { once } from "node:events";
import type { AddressInfo } from "node:net";

// A stand-in for fnn: answers node_info, and list_channels from channels.json in its data directory. It writes
// its pid there; with a slow-start file it takes a while to answer, and with a slow-stop file it takes a while
// to exit, writing a stopping file once asked to. With a fail-start file it exits at once, noting it in failed-starts.
// Each start is logged to starts.log beside the data directories, and slow_call (or, with a slow-rpc file, any
// call but list_channels) answers after 1.5s.
const FAKE_FNN = `#!${process.execPath}
const { createServer } = require("node:http");
const { appendFileSync, existsSync, readFileSync, writeFileSync } = require("node:fs");
const { join } = require("node:path");
const args = process.argv.slice(2);
const dir = args[args.indexOf("-d") + 1];
if (existsSync(join(dir, "fail-start"))) { appendFileSync(join(dir, "failed-starts"), "x"); process.exit(1); }
const port = Number(args.find((arg) => arg.startsWith("--rpc-listening-addr=")).split(":").pop());
const parent = process.ppid;
writeFileSync(join(dir, "pid"), String(process.pid));
appendFileSync(join(dir, "..", "starts.log"), dir.split("/").pop() + "\\n");
setInterval(() => { try { process.kill(parent, 0); } catch { process.exit(0); } }, 500);
process.on("SIGTERM", () => {
  if (!existsSync(join(dir, "slow-stop"))) process.exit(0);
  writeFileSync(join(dir, "stopping"), "");
  setTimeout(() => process.exit(0), 1_000);
});
const server = createServer((request, response) => {
  let body = "";
  request.on("data", (chunk) => { body += chunk; });
  request.on("end", () => {
    const { id, method } = JSON.parse(body);
    let result = null;
    if (method === "node_info") result = { pubkey: "02" + "11".repeat(32), version: "fake", default_funding_lock_script: { code_hash: "0x" + "22".repeat(32), hash_type: "type", args: "0x" } };
    if (method === "list_channels") {
      try { result = { channels: JSON.parse(readFileSync(join(dir, "channels.json"), "utf8")) }; } catch { result = { channels: [] }; }
    }
    if (method === "open_channel_with_external_funding") result = { channel_id: "0x" + "33".repeat(32) };
    response.writeHead(200, { "content-type": "application/json" });
    const slow = method === "slow_call" || (existsSync(join(dir, "slow-rpc")) && method !== "list_channels");
    setTimeout(() => response.end(JSON.stringify({ jsonrpc: "2.0", id, result })), slow ? 1_500 : 0);
  });
});
setTimeout(() => server.listen(port, "127.0.0.1"), existsSync(join(dir, "slow-start")) ? 1_500 : 0);
`;

// As Fiber 0.9.1's list_channels sends them to the host, which reads them unchanged.
const OPEN_CHANNEL = [{ state: { state_name: "ChannelReady" } }];
const CLOSED_CHANNEL = [{ state: { state_name: "Closed", state_flags: "COOPERATIVE" } }];
const SETTLING_FORCE_CLOSE = [{ state: { state_name: "Closed", state_flags: "UNCOOPERATIVE_LOCAL|WAITING_ONCHAIN_SETTLEMENT" } }];
const SETTLED_FORCE_CLOSE = [{ state: { state_name: "Closed", state_flags: "UNCOOPERATIVE_LOCAL" } }];
const SETTLED_REMOTE_CLOSE = [{ state: { state_name: "Closed", state_flags: "UNCOOPERATIVE_REMOTE" } }];
const UNFUNDED_CHANNEL = [{ state: { state_name: "NegotiatingFunding", state_flags: "OUR_INIT_SENT|THEIR_INIT_SENT|AWAITING_EXTERNAL_FUNDING" } }];
const ABORTED_FUNDING = [{ state: { state_name: "Closed", state_flags: "FUNDING_ABORTED" } }];
// Signed on our side: the peer may broadcast the funding at any time.
const FUNDING_TX = `0x${"77".repeat(32)}`;
const SIGNED_CHANNEL = [{ state: { state_name: "AwaitingTxSignatures", state_flags: "OUR_TX_SIGNATURES_SENT" }, channel_outpoint: `${FUNDING_TX}00000000` }];
const BOTH_SIGNED_CHANNEL = [{ state: { state_name: "AwaitingTxSignatures", state_flags: "TX_SIGNATURES_SENT" }, channel_outpoint: `${FUNDING_TX}00000000` }];
// Before our funding signatures are sent, Fiber can still abort the funding.
const UNSIGNED_CHANNEL = [{ state: { state_name: "AwaitingTxSignatures", state_flags: "THEIR_TX_SIGNATURES_SENT" }, channel_outpoint: `${FUNDING_TX}00000000` }];
const COMMITTING_CHANNEL = [{ state: { state_name: "SigningCommitment", state_flags: "COMMITMENT_SIGNED_SENT" } }];
const BROADCAST_CHANNEL = [{ state: { state_name: "AwaitingChannelReady", state_flags: "OUR_CHANNEL_READY" }, channel_outpoint: `${FUNDING_TX}00000000` }];
const exists = (path: string) => stat(path).then(() => true, () => false);

async function until(check: () => Promise<boolean>) {
  for (let attempt = 0; attempt < 400; attempt++) {
    if (await check()) return;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error("Timed out waiting");
}
const [A, B, C, F] = ["a", "b", "c", "f"].map((letter) => letter.repeat(64));
const FEW_MINUTES = 5 * 60_000;
let instances = 0;

/** A stand-in for the CKB node: live cells by "hash:index", and the CKB at the hosted nodes' own lock. */
async function fakeCkb(context: TestContext) {
  const chain = { live: new Set<string>(), capacity: 0n };
  const server = createServer((request, response) => {
    let body = "";
    request.on("data", (chunk) => { body += chunk; });
    request.on("end", () => {
      const { id, method, params } = JSON.parse(body);
      let result: unknown = null;
      // It has never seen any funding transaction: a node must not take that to mean a channel holds nothing.
      if (method === "get_transaction") result = { tx_status: { status: "unknown" } };
      if (method === "get_cells_capacity") result = { capacity: `0x${chain.capacity.toString(16)}` };
      if (method === "get_live_cell") result = { status: chain.live.has(`${params[0].tx_hash}:${params[0].index}`) ? "live" : "unknown" };
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ jsonrpc: "2.0", id, result }));
    });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  context.after(() => server.close());
  return { chain, url: `http://127.0.0.1:${(server.address() as AddressInfo).port}/` };
}

/** A host of at most two nodes on a fresh volume, as its own module instance so tests don't share nodes. */
async function host(context: TestContext) {
  const root = await mkdtemp(join(tmpdir(), "keyway-host-capacity-"));
  const ckb = await fakeCkb(context);
  const fnn = join(root, "fnn.cjs");
  await writeFile(fnn, FAKE_FNN);
  await chmod(fnn, 0o755);
  await mkdir(join(root, "users"));
  Object.assign(process.env, {
    FNN_PATH: fnn,
    KEYWAY_MANAGED_DATA_DIR: join(root, "users"),
    KEYWAY_MANAGED_BACKUP_DIR: join(root, "backups"),
    KEYWAY_MANAGED_RETIRED_DIR: join(root, "retired"),
    KEYWAY_MANAGED_MAX_NODES: "2",
    CKB_NODE_RPC_URL: ckb.url,
  });
  const path = `../managed-host/index.mjs?instance=${++instances}`;
  const module = await import(path) as typeof import("../managed-host/index.mjs");
  context.after(async () => {
    await module.shutdown();
    await rm(root, { recursive: true, force: true });
  });
  const request = (user: string, method = "node_info", signal?: AbortSignal) => module
    .proxyUserRequest(user, Buffer.from(JSON.stringify({ jsonrpc: "2.0", id: 1, method, params: [] })), signal)
    .then(({ status }) => status, () => 502);
  const running = () => module.runningUsers().sort();
  const marked = (user: string) => stat(join(root, "users", user, "keyway-channels")).then(() => true, () => false);
  const withChannels = async (user: string, channels: unknown[] = OPEN_CHANNEL) => {
    await mkdir(join(root, "users", user), { recursive: true });
    await writeFile(join(root, "users", user, "channels.json"), JSON.stringify(channels));
  };
  /** A node from before this restart, marked as holding channels. */
  const markedNode = async (user: string, channels: unknown[] = OPEN_CHANNEL) => {
    await withChannels(user, channels);
    await writeFile(join(root, "users", user, "keyway-channels-checked"), "");
    await writeFile(join(root, "users", user, "keyway-channels"), "");
  };
  const starts = async () => (await readFile(join(root, "users", "starts.log"), "utf8").catch(() => "")).split("\n").filter(Boolean);
  return { module, root, chain: ckb.chain, request, running, marked, withChannels, markedNode, starts };
}

test("at capacity, a node idle for a few minutes makes room for a new user; one with channels or just used is never stopped", async (context) => {
  context.mock.timers.enable({ apis: ["Date"], now: Date.now() });
  const later = () => context.mock.timers.tick(FEW_MINUTES);
  const { request, running, marked, withChannels } = await host(context);

  assert.equal(await request(F), 200);
  await withChannels(F);
  assert.equal(await request(A, "connect_peer"), 200);
  // A just connected to a peer: its user may be about to open a channel with it.
  assert.equal(await request(B), 502);
  assert.deepEqual(running(), [A, F]);
  later();
  // Now a new user takes the idle node's place, never the one with a channel, which is marked for restarts.
  assert.equal(await request(B), 200);
  assert.deepEqual(running(), [B, F]);
  assert.equal(await marked(F), true);
  assert.equal(await marked(B), false);
  later();
  assert.equal(await request(C), 200);
  assert.deepEqual(running(), [C, F]);
  // A returning user gets their node back the same way.
  later();
  assert.equal(await request(A), 200);
  assert.deepEqual(running(), [A, F]);
  // Once every node has a channel, nothing is stopped and the host is full.
  await withChannels(A);
  later();
  assert.equal(await request(B), 502);
  assert.deepEqual(running(), [A, F]);
});

test("handing a channel's funding to the node marks it to start first after a restart; opening alone doesn't", async (context) => {
  const { request, marked } = await host(context);
  assert.equal(await request(A), 200);
  assert.equal(await marked(A), false);
  assert.equal(await request(A, "open_channel_with_external_funding"), 200);
  assert.equal(await marked(A), false);
  assert.equal(await request(A, "submit_signed_funding_tx"), 200);
  assert.equal(await marked(A), true);
});

test("after a restart, only nodes with channels start, however many idle ones are listed first", async (context) => {
  const { module, root, request, running } = await host(context);
  const idle = Array.from({ length: 20 }, (_, index) => index.toString(16).padStart(64, "0"));
  for (const user of [...idle, F]) {
    await mkdir(join(root, "users", user), { recursive: true });
    await writeFile(join(root, "users", user, "keyway-channels-checked"), "");
  }
  await writeFile(join(root, "users", F, "keyway-channels"), "");

  await module.startKnownNodes([...idle, F]);
  assert.deepEqual(running(), [F]);
  // Any other node starts when its user next needs it.
  assert.equal(await request(idle[0]), 200);
  assert.deepEqual(running(), [idle[0], F]);
});

test("after a restart, nodes from before channel markers start once and are marked by their channels", async (context) => {
  const { module, root, running, marked } = await host(context);
  // Neither was ever checked: A holds an open channel, B has none.
  for (const user of [A, B]) await mkdir(join(root, "users", user), { recursive: true });
  await writeFile(join(root, "users", A, "channels.json"), JSON.stringify(OPEN_CHANNEL));

  await module.startKnownNodes([A, B]);
  assert.deepEqual(running().sort(), [A, B].sort());
  assert.equal(await marked(A), true);
  assert.equal(await marked(B), false);
  assert.equal(await exists(join(root, "users", A, "keyway-channels-checked")), true);
  assert.equal(await exists(join(root, "users", B, "keyway-channels-checked")), true);
});

test("a node making room keeps its channel marker until it has stopped", async (context) => {
  context.mock.timers.enable({ apis: ["Date"], now: Date.now() });
  const { root, request, running, marked } = await host(context);
  // A once opened a channel, since closed cooperatively, so it may make room but is still marked.
  assert.equal(await request(A), 200);
  assert.equal(await request(A, "submit_signed_funding_tx"), 200);
  await writeFile(join(root, "users", A, "channels.json"), JSON.stringify(CLOSED_CHANNEL));
  await writeFile(join(root, "users", A, "slow-stop"), "");
  assert.equal(await request(B), 200);
  context.mock.timers.tick(FEW_MINUTES);

  const admission = request(C);
  await until(() => exists(join(root, "users", A, "stopping")));
  assert.equal(await marked(A), true);
  assert.equal(await admission, 200);
  assert.equal(await marked(A), false);
  assert.deepEqual(running(), [B, C]);
});

test("a node waiting for room never starts once the host is shutting down", async (context) => {
  context.mock.timers.enable({ apis: ["Date"], now: Date.now() });
  const { module, root, request, running } = await host(context);
  assert.equal(await request(A), 200);
  assert.equal(await request(B), 200);
  await writeFile(join(root, "users", A, "slow-stop"), "");
  context.mock.timers.tick(FEW_MINUTES);

  // C waits while A stops to make room, and the host shuts down meanwhile.
  const admission = request(C);
  await until(() => exists(join(root, "users", A, "stopping")));
  const stopped = module.shutdown();
  assert.equal(await admission, 502);
  await stopped;
  assert.equal(await exists(join(root, "users", C, "pid")), false);
  assert.deepEqual(running(), []);
});

test("a node still starting when the host shuts down stops with it", async (context) => {
  const { module, root, request, running } = await host(context);
  await mkdir(join(root, "users", C), { recursive: true });
  await writeFile(join(root, "users", C, "slow-start"), "");

  const admission = request(C);
  await until(() => exists(join(root, "users", C, "pid")));
  await module.shutdown();
  const pid = Number(await readFile(join(root, "users", C, "pid"), "utf8"));
  assert.throws(() => process.kill(pid, 0), { code: "ESRCH" });
  assert.equal(await admission, 502);
  assert.deepEqual(running(), []);
});

test("a read never creates a hosted node; connecting one or setting up a channel does", async (context) => {
  const { root, request, running } = await host(context);
  for (const method of ["list_channels", "list_peers", "graph_nodes", "get_invoice", "submit_signed_funding_tx"]) assert.equal(await request(A, method), 502, method);
  assert.equal(await exists(join(root, "users", A)), false);
  assert.deepEqual(running(), []);
  assert.equal(await request(A, "node_info"), 200);
  assert.equal(await request(A, "list_channels"), 200);
  assert.equal(await request(B, "connect_peer"), 200);
  assert.deepEqual(running(), [A, B]);
});

test("reads don't keep a node from making room; the steps of a channel setup do, for a few minutes", async (context) => {
  context.mock.timers.enable({ apis: ["Date"], now: Date.now() });
  const later = () => context.mock.timers.tick(FEW_MINUTES);
  const { request, running } = await host(context);
  assert.equal(await request(A), 200);
  assert.equal(await request(B), 200);
  later();
  // Both keep reading, as a page polling its node does, yet a new user still gets a node.
  assert.equal(await request(A, "list_channels"), 200);
  assert.equal(await request(B, "list_peers"), 200);
  assert.equal(await request(C), 200);
  assert.deepEqual(running(), [B, C]);
  later();
  // B connects to a peer to open a channel, so it keeps its node even though C was used after it.
  assert.equal(await request(B, "connect_peer"), 200);
  assert.equal(await request(C, "list_channels"), 200);
  assert.equal(await request(A), 200);
  assert.deepEqual(running(), [A, B]);
});

test("a setup holds its node at most 15 minutes from its first step, a few setups an hour, on at most half the host", async (context) => {
  context.mock.timers.enable({ apis: ["Date"], now: Date.now() });
  const { request, running } = await host(context);
  // A's user opens a channel long after connecting: the setup is held from its own first step.
  assert.equal(await request(A), 200);
  context.mock.timers.tick(20 * 60_000);
  assert.equal(await request(A, "connect_peer"), 200);
  // With A held, B's setup step doesn't hold B: half of this host is one node.
  assert.equal(await request(B, "connect_peer"), 200);
  assert.equal(await request(C), 200);
  assert.deepEqual(running(), [A, C]);
  // A keeps repeating a setup step, while C is read after it each time; the hold ends 15 minutes in.
  for (let minute = 4; minute < 16; minute += 4) {
    context.mock.timers.tick(4 * 60_000);
    assert.equal(await request(A, "connect_peer"), 200);
    assert.equal(await request(C, "list_channels"), 200);
  }
  context.mock.timers.tick(3 * 60_000);
  assert.equal(await request(B), 200);
  assert.deepEqual(running(), [B, C]);
  // A new setup is held again, but only a few times an hour.
  for (let setup = 2; setup <= 4; setup++) {
    assert.equal(await request(A, "connect_peer"), 200, `setup ${setup}`);
    assert.ok(running().includes(A));
    assert.equal(await request(B, "list_channels"), 200);
    assert.equal(await request(C), 200);
    // Held, A stays and B makes room; past the budget, A isn't held and makes room itself.
    assert.deepEqual(running(), setup <= 3 ? [A, C] : [B, C], `setup ${setup}`);
    context.mock.timers.tick(16 * 60_000);
    if (setup < 4) assert.equal(await request(B), 200);
  }
});

test("accounts that only connect can't keep the host full, and one account can't stop and start nodes without end", async (context) => {
  context.mock.timers.enable({ apis: ["Date"], now: Date.now() });
  const { request, running } = await host(context);
  const crowd = ["1", "2", "3", "4"].map((digit) => digit.repeat(64));
  // Each new node of the crowd's takes the place of the one before, as each was only read.
  for (const user of crowd) assert.equal(await request(user), 200);
  assert.equal(await request(A), 200);
  assert.ok(running().includes(A));
  // B is stopped and started over and over by others: after six times in ten minutes it waits.
  for (let round = 0; round < 6; round++) {
    assert.equal(await request(B), 200, `round ${round}`);
    assert.equal(await request(crowd[round % 4]), 200);
    assert.equal(await request(crowd[(round + 1) % 4]), 200);
  }
  assert.equal(await request(B), 502);
  context.mock.timers.tick(10 * 60_000);
  assert.equal(await request(B), 200);
});

test("a node started on demand is recorded as checked, so a restart starts it only if it has channels", async (context) => {
  const { root, request, marked } = await host(context);
  assert.equal(await request(A), 200);
  assert.equal(await exists(join(root, "users", A, "keyway-channels-checked")), true);
  assert.equal(await marked(A), false);
});

test("after a restart, nodes with channels start before nodes never checked", async (context) => {
  const { module, root, running, markedNode, starts } = await host(context);
  const unchecked = ["1", "2"].map((digit) => digit.repeat(64));
  for (const user of unchecked) await mkdir(join(root, "users", user), { recursive: true });
  await markedNode(F);

  await module.startKnownNodes([...unchecked, F]);
  assert.ok(running().includes(F));
  // F is in the first batch, before the second node never checked.
  const order = await starts();
  assert.ok(order.indexOf(F) < order.indexOf(unchecked[1]), order.join(","));
  assert.deepEqual(module.readiness().status, "ready");
});

test("a node with channels takes the place of a just-used node without channels", async (context) => {
  const { module, request, running, markedNode } = await host(context);
  assert.equal(await request(A), 200);
  assert.equal(await request(B), 200);
  await markedNode(F);
  await module.startKnownNodes([F]);
  assert.equal(running().length, 2);
  assert.ok(running().includes(F));
});

test("a node with channels takes the place of a node without channels even while that one serves requests", async (context) => {
  const { module, request, running, markedNode } = await host(context);
  assert.equal(await request(A), 200);
  assert.equal(await request(B), 200);
  const busy = [request(A, "slow_call"), request(B, "slow_call")];
  await markedNode(F);
  await module.startKnownNodes([F]);
  assert.ok(running().includes(F), running().join(","));
  await Promise.all(busy);
});

test("a node with channels that crashes is restarted until it runs, and /readyz reports it offline meanwhile", async (context) => {
  const { module, root, request, running, withChannels } = await host(context);
  await withChannels(F);
  assert.equal(await request(F), 200);
  assert.deepEqual(module.readiness?.(), { status: "ready", nodes: 1, maxNodes: 2, offline: 0 });
  // It crashes, and its first restarts fail.
  await writeFile(join(root, "users", F, "fail-start"), "");
  process.kill(Number(await readFile(join(root, "users", F, "pid"), "utf8")), "SIGKILL");
  await until(() => exists(join(root, "users", F, "failed-starts")));
  assert.deepEqual(running(), []);
  const whileOffline = module.readiness?.();
  await rm(join(root, "users", F, "fail-start"));
  await until(async () => running().includes(F));
  assert.deepEqual(whileOffline, { status: "degraded", nodes: 0, maxNodes: 2, offline: 1 });
  assert.deepEqual(module.readiness(), { status: "ready", nodes: 1, maxNodes: 2, offline: 0 });
});

test("a node with channels that keeps crashing right after it starts is restarted with growing delays", async (context) => {
  const { root, request, running, withChannels } = await host(context);
  await withChannels(F);
  assert.equal(await request(F), 200);
  const crash = async () => {
    const pid = Number(await readFile(join(root, "users", F, "pid"), "utf8"));
    const crashedAt = Date.now();
    process.kill(pid, "SIGKILL");
    await until(async () => running().includes(F) && Number(await readFile(join(root, "users", F, "pid"), "utf8")) !== pid);
    return Date.now() - crashedAt;
  };
  assert.ok(await crash() >= 900);
  assert.ok(await crash() >= 1_900);
});

test("an offline node with channels is tried again whatever stopped its last attempt", async (context) => {
  const { module, root, running, markedNode } = await host(context);
  await markedNode(F);
  // The retired list can't be read, so the attempt fails before the node starts.
  await writeFile(join(root, "retired"), "");
  await module.startKnownNodes([F]);
  assert.deepEqual(running(), []);
  assert.equal(module.readiness().offline, 1);
  await rm(join(root, "retired"));
  await until(async () => running().includes(F));
  assert.equal(module.readiness().offline, 0);
});

test("a channel a peer opened to the node marks it once the node's channels show it", async (context) => {
  const { request, marked, withChannels } = await host(context);
  assert.equal(await request(A), 200);
  assert.equal(await marked(A), false);
  await withChannels(A);
  assert.equal(await request(A, "list_channels"), 200);
  assert.equal(await marked(A), true);
});

test("a node whose channels can hold nothing more makes room once its user has stopped, and loses its marker", async (context) => {
  // Force-closed and settled on-chain (by either side), opened but not yet signed by us, and funding aborted by Fiber.
  for (const channels of [SETTLED_FORCE_CLOSE, SETTLED_REMOTE_CLOSE, UNFUNDED_CHANNEL, COMMITTING_CHANNEL, UNSIGNED_CHANNEL, ABORTED_FUNDING]) {
    context.mock.timers.enable({ apis: ["Date"], now: Date.now() });
    const { request, running, marked, markedNode } = await host(context);
    await markedNode(F, channels);
    assert.equal(await request(F), 200);
    assert.equal(await request(A), 200);
    context.mock.timers.tick(FEW_MINUTES);
    assert.equal(await request(B), 200, JSON.stringify(channels));
    assert.deepEqual(running(), [A, B], JSON.stringify(channels));
    assert.equal(await marked(F), false);
    context.mock.timers.reset();
  }
});

test("a node whose channel is settling, or whose funding we have signed, keeps running whatever CKB shows", async (context) => {
  // Once our signatures are sent, the peer may broadcast the funding at any time.
  for (const channels of [SETTLING_FORCE_CLOSE, SIGNED_CHANNEL, BOTH_SIGNED_CHANNEL, BROADCAST_CHANNEL]) {
    context.mock.timers.enable({ apis: ["Date"], now: Date.now() });
    const { request, running, marked, markedNode } = await host(context);
    await markedNode(F, channels);
    assert.equal(await request(F), 200);
    assert.equal(await request(A), 200);
    context.mock.timers.tick(FEW_MINUTES);
    assert.equal(await request(B), 200);
    assert.deepEqual(running(), [B, F], JSON.stringify(channels));
    assert.equal(await marked(F), true);
    context.mock.timers.reset();
  }
});

test("a node waiting for its channel's funding keeps its node while its user is signing", async (context) => {
  context.mock.timers.enable({ apis: ["Date"], now: Date.now() });
  const { request, running, withChannels } = await host(context);
  await withChannels(F, UNFUNDED_CHANNEL);
  assert.equal(await request(F, "open_channel_with_external_funding"), 200);
  assert.equal(await request(A), 200);
  context.mock.timers.tick(FEW_MINUTES - 60_000);
  assert.equal(await request(B), 200);
  assert.deepEqual(running(), [B, F]);
});

test("a node can be retired once its channels are finished and nothing of it is left on chain", async (context) => {
  const { module, root, chain, request, withChannels } = await host(context);
  const retire = () => module.withUserOperation(F, () => module.retireUser(F));
  await withChannels(F, [...SETTLED_FORCE_CLOSE, { ...CLOSED_CHANNEL[0], channel_outpoint: `${FUNDING_TX}01000000` }]);
  assert.equal(await request(F), 200);
  // The settlement, or the fee reserve, is still at the node's own key.
  chain.capacity = 62n * 100_000_000n;
  await assert.rejects(retire(), /still holds funds/);
  chain.capacity = 0n;
  chain.live.add(`${FUNDING_TX}:0x1`);
  await assert.rejects(retire(), /still on chain/);
  chain.live.clear();
  await withChannels(F, SETTLING_FORCE_CLOSE);
  await assert.rejects(retire(), /closure is incomplete/);
  await withChannels(F, SETTLED_REMOTE_CLOSE);
  assert.deepEqual(await retire(), { retired: true, databasePreserved: true });
  assert.equal(await exists(join(root, "retired", F)), true);
});

test("a node handing its signed funding to Fiber is never stopped to make room, even for a node with channels", async (context) => {
  const { module, root, request, running, markedNode } = await host(context);
  assert.equal(await request(A), 200);
  assert.equal(await request(B), 200);
  await writeFile(join(root, "users", A, "slow-rpc"), "");
  await writeFile(join(root, "users", B, "slow-rpc"), "");
  const busy = [request(A, "submit_signed_funding_tx"), request(B, "get_payment")];
  await new Promise((resolve) => setTimeout(resolve, 200));
  await markedNode(F);
  await module.startKnownNodes([F]);
  assert.deepEqual(running(), [A, F].sort());
  assert.deepEqual(await Promise.all(busy), [200, 502]);
});

test("a node without a marker that exits unexpectedly is started again, and marked if it holds a channel", async (context) => {
  const { root, request, running, marked, withChannels } = await host(context);
  assert.equal(await request(A), 200);
  // A peer opened a channel to it, which nothing has listed yet.
  await withChannels(A);
  assert.equal(await marked(A), false);
  const pid = Number(await readFile(join(root, "users", A, "pid"), "utf8"));
  process.kill(pid, "SIGKILL");
  await until(async () => running().includes(A) && Number(await readFile(join(root, "users", A, "pid"), "utf8")) !== pid);
  await until(() => marked(A));
});

test("a node that can't start never stops another node to make room for it", async (context) => {
  const { module, root, request, running, markedNode } = await host(context);
  assert.equal(await request(A), 200);
  assert.equal(await request(B), 200);
  // F's last restore was interrupted, so it can't start until an operator recovers it.
  await markedNode(F);
  await mkdir(join(root, "users", `${F}.previous`));
  await module.startKnownNodes([F]);
  assert.deepEqual(running(), [A, B]);
  assert.equal(module.readiness().offline, 1);
});

test("a Fiber binary that can't be run fails the start without stopping the host", async (context) => {
  const { request, running } = await host(context);
  process.env.FNN_PATH = "/nonexistent/fnn";
  context.mock.timers.enable({ apis: ["Date"], now: Date.now() });
  const started = request(A);
  // The start gives up after a minute of waiting for the node's RPC.
  for (let second = 0; second < 70 && running().length === 0; second++) {
    await new Promise((resolve) => setTimeout(resolve, 20));
    context.mock.timers.tick(1_000);
  }
  assert.equal(await started, 502);
  assert.deepEqual(running(), []);
});

test("a slow channel setup step keeps its node only briefly, and never from a node with channels", async (context) => {
  // Fiber can take long to answer an open, for example when the peer doesn't accept it.
  {
    const { module, root, request, running, markedNode } = await host(context);
    assert.equal(await request(A), 200);
    assert.equal(await request(B), 200);
    for (const user of [A, B]) await writeFile(join(root, "users", user, "slow-rpc"), "");
    const slow = [request(A, "open_channel_with_external_funding"), request(B, "open_channel_with_external_funding")];
    await new Promise((resolve) => setTimeout(resolve, 200));
    await markedNode(F);
    await module.startKnownNodes([F]);
    assert.ok(running().includes(F), running().join(","));
    await Promise.all(slow);
  }
  {
    context.mock.timers.enable({ apis: ["Date"], now: Date.now() });
    const { root, request, running } = await host(context);
    assert.equal(await request(A), 200);
    assert.equal(await request(B, "connect_peer"), 200);
    await writeFile(join(root, "users", A, "slow-rpc"), "");
    const slow = request(A, "open_channel_with_external_funding");
    await new Promise((resolve) => setTimeout(resolve, 200));
    // Within the first half minute A's request keeps it; after that, a new user may take its place.
    assert.equal(await request(C), 502);
    context.mock.timers.tick(31_000);
    assert.equal(await request(C), 200);
    assert.deepEqual(running(), [B, C]);
    await slow;
  }
});

test("a call is given up once the API stops waiting for it", async (context) => {
  const { root, request } = await host(context);
  assert.equal(await request(A), 200);
  await writeFile(join(root, "users", A, "slow-rpc"), "");
  const gone = new AbortController();
  const startedAt = Date.now();
  const call = request(A, "open_channel_with_external_funding", gone.signal);
  setTimeout(() => gone.abort(), 100);
  assert.equal(await call, 502);
  assert.ok(Date.now() - startedAt < 1_000);
});

test("a restore that leaves a node with channels stopped has it started", async (context) => {
  const { module, running, markedNode } = await host(context);
  process.env.KEYWAY_MANAGED_BACKUP_KEY = "07".repeat(32);
  await markedNode(F);
  const { name } = await module.createSnapshot({ userId: F });
  // F wasn't running; its restored data has channels, so it must run.
  await module.withUserOperation(F, () => module.restoreUser(F, name));
  await until(async () => running().includes(F));
  assert.equal(module.readiness().offline, 0);
});
