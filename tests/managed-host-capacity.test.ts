import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { randomBytes } from "node:crypto";
import { once } from "node:events";
import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

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
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ jsonrpc: "2.0", id, result }));
  });
}).listen(port, "127.0.0.1");
`;

const OPEN_CHANNEL = [{ state: { state_name: "ChannelReady" } }];
const [A, B, C, F] = ["a", "b", "c", "f"].map((letter) => letter.repeat(64));

async function workspace(context: { after: (fn: () => Promise<void>) => void }) {
  const root = await mkdtemp(join(tmpdir(), "keyway-host-capacity-"));
  context.after(() => rm(root, { recursive: true, force: true }));
  const fnn = join(root, "fnn.cjs");
  await writeFile(fnn, FAKE_FNN);
  await chmod(fnn, 0o755);
  await mkdir(join(root, "users"));
  return {
    root,
    env: {
      FNN_PATH: fnn,
      KEYWAY_MANAGED_DATA_DIR: join(root, "users"),
      KEYWAY_MANAGED_BACKUP_DIR: join(root, "backups"),
      KEYWAY_MANAGED_RETIRED_DIR: join(root, "retired"),
      KEYWAY_MANAGED_MAX_NODES: "2",
    },
  };
}

async function freePort(): Promise<number> {
  const server = createServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const { port } = server.address() as { port: number };
  await new Promise((resolve) => server.close(resolve));
  return port;
}

async function withChannels(root: string, user: string) {
  await mkdir(join(root, "users", user), { recursive: true });
  await writeFile(join(root, "users", user, "channels.json"), JSON.stringify(OPEN_CHANNEL));
}

test("at capacity, an idle hosted node makes room for a new user, and a node with channels is never stopped", async (context) => {
  const { root, env } = await workspace(context);
  const token = randomBytes(16).toString("hex");
  const port = await freePort();
  const host: ChildProcess = spawn(process.execPath, ["managed-host/index.mjs"], {
    env: {
      ...process.env,
      ...env,
      PORT: String(port),
      KEYWAY_MANAGED_HOST_TOKEN: token,
      FIBER_SECRET_KEY_PASSWORD: "test-password",
      KEYWAY_MANAGED_BACKUP_KEY: randomBytes(32).toString("hex"),
    },
    stdio: ["ignore", "ignore", "ignore"],
  });
  context.after(async () => {
    if (host.exitCode === null) {
      host.kill("SIGTERM");
      await once(host, "exit");
    }
  });
  const base = `http://127.0.0.1:${port}`;
  const headers = { authorization: `Bearer ${token}`, "content-type": "application/json" };
  for (let attempt = 0; ; attempt++) {
    try {
      if ((await fetch(`${base}/readyz`, { headers })).ok) break;
    } catch {}
    if (attempt > 100) throw new Error("managed host did not start");
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  const status = async (user: string) => (await fetch(`${base}/users/${user}`, {
    method: "POST",
    headers,
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "node_info", params: [] }),
  })).status;
  const running = async () => ((await (await fetch(`${base}/inventory`, { headers })).json()) as { running: string[] }).running.sort();

  assert.equal(await status(F), 200);
  await withChannels(root, F);
  assert.equal(await status(A), 200);
  // The host is full: a new user takes the idle node's place, never the one with a channel.
  assert.equal(await status(B), 200);
  assert.deepEqual(await running(), [B, F]);
  assert.equal(await status(C), 200);
  assert.deepEqual(await running(), [C, F]);
  // A returning user gets their node back the same way.
  assert.equal(await status(A), 200);
  assert.deepEqual(await running(), [A, F]);
  // Once every node has a channel, nothing is stopped and the host is full.
  await withChannels(root, A);
  assert.equal(await status(B), 502);
  assert.deepEqual(await running(), [A, F]);
});

test("after a restart, nodes with channels come back even when idle ones are listed first", async (context) => {
  const { root, env } = await workspace(context);
  Object.assign(process.env, env);
  const host = await import("../managed-host/index.mjs");
  context.after(() => host.shutdown());
  await withChannels(root, F);
  for (const user of [A, B, C]) await mkdir(join(root, "users", user), { recursive: true });

  await host.startKnownNodes([A, B, C, F]);
  assert.deepEqual(host.runningUsers().sort(), [C, F]);
});
