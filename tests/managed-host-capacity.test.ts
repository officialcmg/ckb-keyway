import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { type TestContext } from "node:test";

// A stand-in for fnn: answers node_info, and list_channels from channels.json in its data directory.
const FAKE_FNN = `#!${process.execPath}
const { createServer } = require("node:http");
const { readFileSync } = require("node:fs");
const { join } = require("node:path");
const args = process.argv.slice(2);
const dir = args[args.indexOf("-d") + 1];
const port = Number(args.find((arg) => arg.startsWith("--rpc-listening-addr=")).split(":").pop());
const parent = process.ppid;
setInterval(() => { try { process.kill(parent, 0); } catch { process.exit(0); } }, 500);
createServer((request, response) => {
  let body = "";
  request.on("data", (chunk) => { body += chunk; });
  request.on("end", () => {
    const { id, method } = JSON.parse(body);
    let result = null;
    if (method === "node_info") result = { pubkey: "02" + "11".repeat(32), version: "fake" };
    if (method === "list_channels") {
      try { result = { channels: JSON.parse(readFileSync(join(dir, "channels.json"), "utf8")) }; } catch { result = { channels: [] }; }
    }
    if (method === "open_channel_with_external_funding") result = { channel_id: "0x" + "33".repeat(32) };
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ jsonrpc: "2.0", id, result }));
  });
}).listen(port, "127.0.0.1");
`;

const OPEN_CHANNEL = [{ state: { state_name: "ChannelReady" } }];
const [A, B, C, F] = ["a", "b", "c", "f"].map((letter) => letter.repeat(64));
const FEW_MINUTES = 5 * 60_000;
let instances = 0;

/** A host of at most two nodes on a fresh volume, as its own module instance so tests don't share nodes. */
async function host(context: TestContext) {
  const root = await mkdtemp(join(tmpdir(), "keyway-host-capacity-"));
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
  });
  const path = `../managed-host/index.mjs?instance=${++instances}`;
  const module = await import(path) as typeof import("../managed-host/index.mjs");
  context.after(async () => {
    await module.shutdown();
    await rm(root, { recursive: true, force: true });
  });
  const request = (user: string, method = "node_info") => module
    .proxyUserRequest(user, Buffer.from(JSON.stringify({ jsonrpc: "2.0", id: 1, method, params: [] })))
    .then(({ status }) => status, () => 502);
  const running = () => module.runningUsers().sort();
  const marked = (user: string) => stat(join(root, "users", user, "keyway-channels")).then(() => true, () => false);
  const withChannels = async (user: string) => {
    await mkdir(join(root, "users", user), { recursive: true });
    await writeFile(join(root, "users", user, "channels.json"), JSON.stringify(OPEN_CHANNEL));
  };
  return { module, root, request, running, marked, withChannels };
}

test("at capacity, a node idle for a few minutes makes room for a new user; one with channels or just used is never stopped", async (context) => {
  context.mock.timers.enable({ apis: ["Date"], now: Date.now() });
  const later = () => context.mock.timers.tick(FEW_MINUTES);
  const { request, running, marked, withChannels } = await host(context);

  assert.equal(await request(F), 200);
  await withChannels(F);
  assert.equal(await request(A), 200);
  // A was just used: its user may be between connecting to a peer and opening a channel with it.
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

test("opening a channel marks the node to start first after a restart", async (context) => {
  const { request, marked } = await host(context);
  assert.equal(await request(A), 200);
  assert.equal(await marked(A), false);
  assert.equal(await request(A, "open_channel_with_external_funding"), 200);
  assert.equal(await marked(A), true);
});

test("after a restart, only nodes with channels start, however many idle ones are listed first", async (context) => {
  const { module, root, request, running } = await host(context);
  const idle = Array.from({ length: 20 }, (_, index) => index.toString(16).padStart(64, "0"));
  for (const user of [...idle, F]) await mkdir(join(root, "users", user), { recursive: true });
  await writeFile(join(root, "users", F, "keyway-channels"), "");

  await module.startKnownNodes([...idle, F]);
  assert.deepEqual(running(), [F]);
  // Any other node starts when its user next needs it.
  assert.equal(await request(idle[0]), 200);
  assert.deepEqual(running(), [idle[0], F]);
});
