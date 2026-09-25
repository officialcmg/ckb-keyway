import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { spawn } from "node:child_process";
import { cp, mkdir, readdir, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { createServer as createTcpServer } from "node:net";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const USER_ID = /^[0-9a-f]{64}$/;
const SNAPSHOT = /^snap-\d+$/;
const nodes = new Map();
const starting = new Map();
let shuttingDown = false;

export function managedUserId(userId) {
  return createHash("sha256").update(userId).digest("hex");
}

export function authorizationMatches(header, token) {
  if (!header?.startsWith("Bearer ") || !token) return false;
  const supplied = Buffer.from(header.slice(7));
  const expected = Buffer.from(token);
  return supplied.length === expected.length && timingSafeEqual(supplied, expected);
}

async function main() {
  required("FIBER_SECRET_KEY_PASSWORD");
  required("KEYWAY_MANAGED_HOST_TOKEN");
  const server = createServer(handleRequest);
  server.listen(Number(process.env.PORT ?? 8080), "0.0.0.0", () => {
    console.log(`[managed-host] listening on ${process.env.PORT ?? 8080}`);
  });
  for (const userId of await existingUsers()) void ensureNode(userId).catch(logError);
  const stop = () => {
    shuttingDown = true;
    server.close();
    for (const node of nodes.values()) node.child.kill("SIGTERM");
  };
  process.on("SIGTERM", stop);
  process.on("SIGINT", stop);
}

async function handleRequest(request, response) {
  try {
    if (!authorizationMatches(request.headers.authorization, required("KEYWAY_MANAGED_HOST_TOKEN"))) {
      return send(response, 401, { error: "Unauthorized" });
    }
    if (request.method === "GET" && request.url === "/readyz") {
      return send(response, 200, { status: "ready", nodes: nodes.size, maxNodes: maxNodes() });
    }
    const backups = /^\/users\/([0-9a-f]{64})\/backups$/.exec(request.url ?? "");
    if (backups && request.method === "GET") {
      return send(response, 200, { snapshots: await listSnapshots({ userId: backups[1] }) });
    }
    if (backups && request.method === "POST") {
      return send(response, 200, await snapshotUser(backups[1]));
    }
    const restore = request.method === "POST" && /^\/users\/([0-9a-f]{64})\/restore$/.exec(request.url ?? "");
    if (restore) {
      const { name } = await readJsonBody(request);
      return send(response, 200, await restoreUser(restore[1], name));
    }
    const match = request.method === "POST" && /^\/users\/([0-9a-f]{64})$/.exec(request.url ?? "");
    if (!match) return send(response, 404, { error: "Not found" });
    const body = await readBody(request, 1_048_576);
    const node = await ensureNode(match[1]);
    const upstream = await fetch(`http://127.0.0.1:${node.port}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
      signal: AbortSignal.timeout(120_000),
    });
    response.writeHead(upstream.status, { "content-type": upstream.headers.get("content-type") ?? "application/json" });
    response.end(Buffer.from(await upstream.arrayBuffer()));
  } catch (error) {
    logError(error);
    send(response, 502, { error: error instanceof Error ? error.message : "Managed node failed" });
  }
}

async function ensureNode(userId) {
  if (!USER_ID.test(userId)) throw new Error("Managed user ID is invalid");
  const running = nodes.get(userId);
  if (running) return running;
  const pending = starting.get(userId);
  if (pending) return pending;
  if (new Set([...nodes.keys(), ...starting.keys()]).size >= maxNodes()) {
    throw new Error("Managed node capacity is full");
  }
  const promise = startNode(userId).finally(() => starting.delete(userId));
  starting.set(userId, promise);
  return promise;
}

async function startNode(userId) {
  const port = await availablePort();
  const baseDir = managedDataDir(userId);
  const ckbDir = join(baseDir, "ckb");
  await mkdir(ckbDir, { recursive: true });
  await createCkbKey(join(ckbDir, "key"));
  const child = spawn(required("FNN_PATH", "/usr/local/bin/fnn"), [
    "-d", baseDir,
    "-c", required("FIBER_CONFIG_TEMPLATE", "/usr/local/share/fiber/config/testnet/config.yml"),
    "--fiber-listening-addr=/ip4/0.0.0.0/tcp/0",
    "--fiber-announce-listening-addr=false",
    `--rpc-listening-addr=127.0.0.1:${port}`,
    `--ckb-node-rpc-url=${process.env.CKB_NODE_RPC_URL ?? "https://testnet.ckbapp.dev/"}`,
  ], { env: process.env, stdio: ["ignore", "pipe", "pipe"] });
  child.stdout.on("data", (chunk) => process.stdout.write(`[fnn:${userId.slice(0, 8)}] ${chunk}`));
  child.stderr.on("data", (chunk) => process.stderr.write(`[fnn:${userId.slice(0, 8)}] ${chunk}`));
  const node = { child, port };
  child.once("exit", (code, signal) => {
    const wasRunning = nodes.get(userId)?.child === child;
    if (wasRunning) nodes.delete(userId);
    console.error(`[managed-host] fnn ${userId.slice(0, 8)} exited code=${code} signal=${signal}`);
    if (wasRunning && !shuttingDown) setTimeout(() => void ensureNode(userId).catch(logError), 1_000);
  });
  await waitForRpc(port, child);
  nodes.set(userId, node);
  return node;
}

export async function createCkbKey(path) {
  try {
    await writeFile(path, randomBytes(32).toString("hex"), { flag: "wx", mode: 0o600 });
  } catch (error) {
    if (error?.code !== "EEXIST") throw error;
  }
}

async function waitForRpc(port, child) {
  const deadline = Date.now() + 60_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`Fiber node exited during startup (${child.exitCode})`);
    try {
      const response = await fetch(`http://127.0.0.1:${port}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "node_info", params: [] }),
        signal: AbortSignal.timeout(2_000),
      });
      if (response.ok) return;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  child.kill("SIGTERM");
  throw new Error("Fiber node startup timed out");
}

async function snapshotUser(userId) {
  const wasRunning = await stopNode(userId);
  try {
    return await createSnapshot({ userId });
  } finally {
    if (wasRunning) await ensureNode(userId).catch(logError);
  }
}

async function restoreUser(userId, name) {
  const wasRunning = await stopNode(userId);
  try {
    return await restoreSnapshot({ userId, name });
  } finally {
    if (wasRunning) await ensureNode(userId).catch(logError);
  }
}

async function stopNode(userId) {
  const pending = starting.get(userId);
  const node = nodes.get(userId) ?? (pending ? await pending.catch(() => undefined) : undefined);
  if (!node) return false;
  nodes.delete(userId);
  await waitForExit(node.child);
  return true;
}

function waitForExit(child, timeout = 15_000) {
  return new Promise((resolve) => {
    if (child.exitCode !== null || child.signalCode !== null) return resolve();
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      resolve();
    }, timeout);
    child.once("exit", () => {
      clearTimeout(timer);
      resolve();
    });
    child.kill("SIGTERM");
  });
}

export function managedDataDir(userId) {
  return join(required("KEYWAY_MANAGED_DATA_DIR", "/fiber/users"), userId);
}

export function managedBackupDir(userId) {
  return join(required("KEYWAY_MANAGED_BACKUP_DIR", "/fiber/backups"), userId);
}

export async function listSnapshots({ userId, root = managedBackupDir(userId) }) {
  let entries;
  try {
    entries = await readdir(root, { withFileTypes: true });
  } catch (error) {
    if (error?.code === "ENOENT") return [];
    throw error;
  }
  const snapshots = [];
  for (const entry of entries.filter((candidate) => candidate.isDirectory() && SNAPSHOT.test(candidate.name))) {
    const path = join(root, entry.name);
    const record = await readSnapshotRecord(root, entry.name);
    snapshots.push({
      name: entry.name,
      createdAt: record?.createdAt ?? (await stat(path)).mtime.toISOString(),
      bytes: record?.bytes ?? await directoryBytes(path),
      digest: record?.digest ?? await snapshotDigest(path),
    });
  }
  return snapshots.sort((left, right) => left.name.localeCompare(right.name));
}

export async function createSnapshot({
  userId,
  dataDir = managedDataDir(userId),
  root = managedBackupDir(userId),
  limitBytes = Number(process.env.KEYWAY_MANAGED_MAX_BACKUP_BYTES ?? 512 * 1024 * 1024),
  keep = Number(process.env.KEYWAY_MANAGED_BACKUP_GENERATIONS ?? 3),
}) {
  const bytes = await directoryBytes(dataDir);
  if (bytes > limitBytes) throw new Error("Managed Fiber data directory exceeds the backup size limit");
  const expected = await snapshotDigest(dataDir);
  const name = `snap-${Date.now()}`;
  await mkdir(root, { recursive: true });
  const target = join(root, name);
  await cp(dataDir, target, { recursive: true });
  if (await snapshotDigest(target) !== expected) {
    await rm(target, { recursive: true, force: true });
    throw new Error("Managed Fiber snapshot verification failed");
  }
  const createdAt = new Date().toISOString();
  await writeFile(join(root, `${name}.json`), JSON.stringify({ digest: expected, bytes, createdAt }));
  for (const stale of (await listSnapshots({ userId, root })).slice(0, -keep)) {
    await rm(join(root, stale.name), { recursive: true, force: true });
    await rm(join(root, `${stale.name}.json`), { force: true });
  }
  return { name, createdAt, bytes, digest: expected };
}

export async function restoreSnapshot({
  userId,
  dataDir = managedDataDir(userId),
  root = managedBackupDir(userId),
  name,
}) {
  if (typeof name !== "string" || !SNAPSHOT.test(name)) throw new Error("A valid managed Fiber snapshot name is required");
  const source = join(root, name);
  const record = await readSnapshotRecord(root, name);
  if (!record) throw new Error("Managed Fiber snapshot metadata is missing");
  const expected = record.digest;
  const staging = `${dataDir}.restore`;
  await rm(staging, { recursive: true, force: true });
  await cp(source, staging, { recursive: true });
  if (await snapshotDigest(staging) !== expected) {
    await rm(staging, { recursive: true, force: true });
    throw new Error("Managed Fiber snapshot is corrupted");
  }
  await rm(dataDir, { recursive: true, force: true });
  await rename(staging, dataDir);
  return { restored: true, name, digest: expected };
}

async function readSnapshotRecord(root, name) {
  try {
    const record = JSON.parse(await readFile(join(root, `${name}.json`), "utf8"));
    return /^[0-9a-f]{64}$/.test(record?.digest) && typeof record?.bytes === "number" && typeof record?.createdAt === "string"
      ? record
      : undefined;
  } catch (error) {
    if (error?.code === "ENOENT") return undefined;
    throw error;
  }
}

export async function snapshotDigest(directory) {
  const hash = createHash("sha256");
  for (const relative of await filesIn(directory)) {
    hash.update(relative);
    hash.update("\0");
    hash.update(await readFile(join(directory, relative)));
  }
  return hash.digest("hex");
}

async function directoryBytes(directory) {
  let bytes = 0;
  for (const relative of await filesIn(directory)) bytes += (await stat(join(directory, relative))).size;
  return bytes;
}

async function filesIn(directory, prefix = "") {
  const files = [];
  const entries = await readdir(directory, { withFileTypes: true });
  for (const entry of [...entries].sort((left, right) => left.name.localeCompare(right.name))) {
    const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) files.push(...await filesIn(join(directory, entry.name), relative));
    else if (entry.isFile()) files.push(relative);
  }
  return files;
}

function maxNodes() {
  return Number(process.env.KEYWAY_MANAGED_MAX_NODES ?? 16);
}

async function readJsonBody(request, limit = 65_536) {
  const body = await readBody(request, limit);
  try {
    const parsed = JSON.parse(body.toString("utf8"));
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    throw new Error("Request body must be valid JSON");
  }
}

async function existingUsers() {
  try {
    return (await readdir(required("KEYWAY_MANAGED_DATA_DIR", "/fiber/users"), { withFileTypes: true }))
      .filter((entry) => entry.isDirectory() && USER_ID.test(entry.name))
      .map((entry) => entry.name);
  } catch (error) {
    if (error?.code === "ENOENT") return [];
    throw error;
  }
}

function availablePort() {
  return new Promise((resolve, reject) => {
    const server = createTcpServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      server.close(() => typeof address === "object" && address ? resolve(address.port) : reject(new Error("No port assigned")));
    });
  });
}

function readBody(request, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    request.on("data", (chunk) => {
      size += chunk.length;
      if (size > limit) {
        request.destroy();
        reject(new Error("Request is too large"));
      } else chunks.push(chunk);
    });
    request.on("end", () => resolve(Buffer.concat(chunks)));
    request.on("error", reject);
  });
}

function send(response, status, body) {
  if (response.headersSent) return;
  response.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" });
  response.end(JSON.stringify(body));
}

function required(name, fallback) {
  const value = process.env[name] ?? fallback;
  if (!value) throw new Error(`Missing managed-host configuration: ${name}`);
  return value;
}

function logError(error) {
  console.error("[managed-host]", error);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) void main().catch((error) => {
  logError(error);
  process.exitCode = 1;
});
