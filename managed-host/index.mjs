import { createCipheriv, createDecipheriv, createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { spawn } from "node:child_process";
import { createReadStream, createWriteStream } from "node:fs";
import { cp, mkdir, mkdtemp, readdir, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { createServer as createTcpServer } from "node:net";
import { join } from "node:path";
import { pipeline } from "node:stream/promises";
import { pathToFileURL } from "node:url";

const USER_ID = /^[0-9a-f]{64}$/;
const SNAPSHOT = /^snap-\d+$/;
const nodes = new Map();
const starting = new Map();
const operations = new Map();
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
  backupKey();
  const server = createServer(handleRequest);
  server.listen(Number(process.env.PORT ?? 8080), "0.0.0.0", () => {
    console.log(`[managed-host] listening on ${process.env.PORT ?? 8080}`);
  });
  for (const userId of await existingUsers()) void withUserOperation(userId, () => ensureNode(userId)).catch(logError);
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
    if (request.method === "GET" && request.url === "/inventory") {
      return send(response, 200, { users: await existingUsers(), running: [...nodes.keys()] });
    }
    const retirement = request.method === "POST" && /^\/users\/([0-9a-f]{64})\/retire$/.exec(request.url ?? "");
    if (retirement) {
      return send(response, 200, await withUserOperation(retirement[1], () => retireUser(retirement[1])));
    }
    const purge = request.method === "POST" && /^\/users\/([0-9a-f]{64})\/purge-retired$/.exec(request.url ?? "");
    if (purge) {
      const { confirmUserId } = await readJsonBody(request);
      if (confirmUserId !== purge[1]) throw new Error("Explicit retired-user confirmation is required");
      return send(response, 200, await withUserOperation(purge[1], () => purgeRetiredUser(purge[1])));
    }
    const backups = /^\/users\/([0-9a-f]{64})\/backups$/.exec(request.url ?? "");
    if (backups && request.method === "GET") {
      return send(response, 200, { snapshots: await withUserOperation(backups[1], () => listSnapshots({ userId: backups[1] })) });
    }
    if (backups && request.method === "POST") {
      return send(response, 200, await withUserOperation(backups[1], () => snapshotUser(backups[1])));
    }
    const restore = request.method === "POST" && /^\/users\/([0-9a-f]{64})\/restore$/.exec(request.url ?? "");
    if (restore) {
      const { name } = await readJsonBody(request);
      return send(response, 200, await withUserOperation(restore[1], () => restoreUser(restore[1], name)));
    }
    const match = request.method === "POST" && /^\/users\/([0-9a-f]{64})$/.exec(request.url ?? "");
    if (!match) return send(response, 404, { error: "Not found" });
    const body = await readBody(request, 1_048_576);
    await withUserOperation(match[1], async () => {
      const node = await ensureNode(match[1]);
      const upstream = await fetch(`http://127.0.0.1:${node.port}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body,
        signal: AbortSignal.timeout(120_000),
      });
      response.writeHead(upstream.status, { "content-type": upstream.headers.get("content-type") ?? "application/json" });
      response.end(Buffer.from(await upstream.arrayBuffer()));
    });
  } catch (error) {
    logError(error);
    send(response, 502, { error: error instanceof Error ? error.message : "Managed node failed" });
  }
}

export async function withUserOperation(userId, operation) {
  const previous = operations.get(userId) ?? Promise.resolve();
  const current = previous.catch(() => {}).then(operation);
  operations.set(userId, current);
  try {
    return await current;
  } finally {
    if (operations.get(userId) === current) operations.delete(userId);
  }
}

async function ensureNode(userId) {
  if (!USER_ID.test(userId)) throw new Error("Managed user ID is invalid");
  if (shuttingDown) throw new Error("Managed host is shutting down");
  if (await isRetired(userId)) throw new Error("Legacy Fiber node has been retired");
  const running = nodes.get(userId);
  if (running?.stopping) throw new Error("Fiber process is still stopping");
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
  await requireCleanRestore(baseDir);
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
    if (wasRunning && !node.stopping && !shuttingDown) setTimeout(() => void withUserOperation(userId, () => ensureNode(userId)).catch(logError), 1_000);
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
  return completeDatabaseOperation(
    () => createSnapshot({ userId }),
    async () => { if (wasRunning) await ensureNode(userId); },
  );
}

async function restoreUser(userId, name) {
  const wasRunning = await stopNode(userId);
  return completeDatabaseOperation(
    () => restoreSnapshot({ userId, name }),
    async () => { if (wasRunning) await ensureNode(userId); },
  );
}

export async function completeDatabaseOperation(operation, resume) {
  try {
    return await operation();
  } finally {
    await resume();
  }
}

async function stopNode(userId) {
  const pending = starting.get(userId);
  const node = nodes.get(userId) ?? (pending ? await pending.catch(() => undefined) : undefined);
  if (!node) return false;
  node.stopping = true;
  await waitForExit(node.child);
  if (nodes.get(userId) === node) nodes.delete(userId);
  return true;
}

export function waitForExit(child, timeout = 15_000) {
  return new Promise((resolve, reject) => {
    if (child.exitCode !== null || child.signalCode !== null) return resolve();
    let deadline;
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      deadline = setTimeout(() => reject(new Error("Fiber process did not stop; database operation aborted")), 5_000);
    }, timeout);
    child.once("exit", () => {
      clearTimeout(timer);
      clearTimeout(deadline);
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

function retiredPath(userId) {
  if (!USER_ID.test(userId)) throw new Error("Managed user ID is invalid");
  return join(required("KEYWAY_MANAGED_RETIRED_DIR", "/fiber/retired"), userId);
}

async function isRetired(userId) {
  try { await stat(retiredPath(userId)); return true; }
  catch (error) { if (error?.code === "ENOENT") return false; throw error; }
}

export function requireClosedChannels(channels) {
  if (!Array.isArray(channels) || channels.some((channel) => String(channel?.state?.state_name).replaceAll("_", "").toLowerCase() !== "closed" || channel?.state?.state_flags !== "COOPERATIVE")) {
    throw new Error("Channel closure is incomplete; preserve the node database");
  }
}

async function retireUser(userId) {
  if (await isRetired(userId)) return { retired: true, databasePreserved: true };
  await stat(managedDataDir(userId)); // Never provision a new identity for cleanup.
  const node = await ensureNode(userId);
  const response = await fetch(`http://127.0.0.1:${node.port}`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "list_channels", params: [{ include_closed: true }] }),
    signal: AbortSignal.timeout(15_000),
  });
  const result = await response.json();
  if (!response.ok || result.error) throw new Error("Could not verify channel closure");
  requireClosedChannels(result.result?.channels);
  await mkdir(required("KEYWAY_MANAGED_RETIRED_DIR", "/fiber/retired"), { recursive: true });
  await writeFile(retiredPath(userId), JSON.stringify({ retiredAt: new Date().toISOString() }), { flag: "wx", mode: 0o600 });
  await stopNode(userId);
  return { retired: true, databasePreserved: true };
}

export async function purgeRetiredUser(userId, roots = {}) {
  if (!USER_ID.test(userId)) throw new Error("Managed user ID is invalid");
  const marker = join(roots.retiredRoot ?? required("KEYWAY_MANAGED_RETIRED_DIR", "/fiber/retired"), userId);
  await stat(marker).catch(() => { throw new Error("Only a retired node may be purged"); });
  if (nodes.has(userId) || starting.has(userId)) throw new Error("Node is still running");
  await rm(roots.dataRoot ? join(roots.dataRoot, userId) : managedDataDir(userId), { recursive: true, force: true });
  await rm(roots.backupRoot ? join(roots.backupRoot, userId) : managedBackupDir(userId), { recursive: true, force: true });
  // Keep the tombstone so stale callers cannot recreate the obsolete identity.
  return { purged: true, userId };
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
  for (const entry of entries.filter((candidate) => candidate.isFile() && /^snap-\d+\.json$/.test(candidate.name))) {
    const name = entry.name.slice(0, -5);
    const record = await readSnapshotRecord(root, name);
    if (!record) continue;
    snapshots.push({
      name,
      createdAt: record.createdAt,
      bytes: record.bytes,
      digest: record.digest,
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
  encryptionKey,
}) {
  const key = backupKey(encryptionKey);
  const bytes = await directoryBytes(dataDir);
  if (bytes > limitBytes) throw new Error("Managed Fiber data directory exceeds the backup size limit");
  const expected = await snapshotDigest(dataDir);
  const name = `snap-${Date.now()}`;
  await mkdir(root, { recursive: true });
  const target = join(root, `${name}.enc`);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const tar = spawn("tar", ["-C", dataDir, "-cf", "-", "."], { stdio: ["ignore", "pipe", "pipe"] });
  try {
    await Promise.all([pipeline(tar.stdout, cipher, createWriteStream(target, { mode: 0o600 })), tarResult(tar)]);
  } catch (error) {
    tar.kill();
    await rm(target, { force: true });
    throw error;
  }
  const createdAt = new Date().toISOString();
  await writeFile(join(root, `${name}.json`), JSON.stringify({ digest: expected, bytes, createdAt, format: 2, iv: iv.toString("hex"), tag: cipher.getAuthTag().toString("hex") }), { mode: 0o600 });
  for (const stale of (await listSnapshots({ userId, root })).slice(0, -keep)) {
    await rm(join(root, stale.name), { recursive: true, force: true });
    await rm(join(root, `${stale.name}.enc`), { force: true });
    await rm(join(root, `${stale.name}.json`), { force: true });
  }
  return { name, createdAt, bytes, digest: expected };
}

export async function restoreSnapshot({
  userId,
  dataDir = managedDataDir(userId),
  root = managedBackupDir(userId),
  name,
  encryptionKey,
}) {
  if (typeof name !== "string" || !SNAPSHOT.test(name)) throw new Error("A valid managed Fiber snapshot name is required");
  await requireCleanRestore(dataDir);
  const record = await readSnapshotRecord(root, name);
  if (!record) throw new Error("Managed Fiber snapshot metadata is missing");
  const expected = record.digest;
  const staging = `${dataDir}.restore`;
  await rm(staging, { recursive: true, force: true });
  await mkdir(staging, { recursive: true });
  try {
    if (record.format === 2) {
      const decipher = createDecipheriv("aes-256-gcm", backupKey(encryptionKey), Buffer.from(record.iv, "hex"));
      decipher.setAuthTag(Buffer.from(record.tag, "hex"));
      const scratch = await mkdtemp(`${dataDir}.archive-`);
      try {
        const archive = join(scratch, "snapshot.tar");
        // GCM authenticates at EOF; never feed unauthenticated plaintext to tar.
        await pipeline(createReadStream(join(root, `${name}.enc`)), decipher, createWriteStream(archive, { flags: "wx", mode: 0o600 }));
        const tar = spawn("tar", ["-C", staging, "-xf", archive], { stdio: ["ignore", "ignore", "pipe"] });
        await tarResult(tar);
      } finally {
        await rm(scratch, { recursive: true, force: true });
      }
    } else {
      await cp(join(root, name), staging, { recursive: true });
    }
    if (await snapshotDigest(staging) !== expected) throw new Error("Managed Fiber snapshot is corrupted");
  } catch (error) {
    await rm(staging, { recursive: true, force: true });
    throw error;
  }
  const previous = `${dataDir}.previous`;
  let hadPrevious = false;
  try {
    await rename(dataDir, previous);
    hadPrevious = true;
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  try {
    await rename(staging, dataDir);
  } catch (error) {
    if (hadPrevious) await rename(previous, dataDir);
    throw error;
  }
  if (hadPrevious) await rm(previous, { recursive: true });
  return { restored: true, name, digest: expected };
}

export async function requireCleanRestore(dataDir) {
  try {
    await stat(`${dataDir}.previous`);
  } catch (error) {
    if (error?.code === "ENOENT") return;
    throw error;
  }
  // Do not start with stale channel state or create a new key after an interrupted swap.
  throw new Error("Managed Fiber restore was interrupted; operator recovery is required before startup");
}

async function readSnapshotRecord(root, name) {
  try {
    const record = JSON.parse(await readFile(join(root, `${name}.json`), "utf8"));
    return /^[0-9a-f]{64}$/.test(record?.digest) && typeof record?.bytes === "number" && typeof record?.createdAt === "string" && (record.format === undefined || record.format === 2 && /^[0-9a-f]{24}$/.test(record.iv) && /^[0-9a-f]{32}$/.test(record.tag))
      ? record
      : undefined;
  } catch (error) {
    if (error?.code === "ENOENT") return undefined;
    throw error;
  }
}

function backupKey(override) {
  const configured = override ? undefined : required("KEYWAY_MANAGED_BACKUP_KEY");
  if (configured && !/^[0-9a-fA-F]{64}$/.test(configured)) throw new Error("KEYWAY_MANAGED_BACKUP_KEY must be 32 bytes (64 hex characters)");
  const key = override ?? Buffer.from(configured, "hex");
  if (!Buffer.isBuffer(key) || key.length !== 32) throw new Error("KEYWAY_MANAGED_BACKUP_KEY must be 32 bytes (64 hex characters)");
  return key;
}

function tarResult(child) {
  return new Promise((resolve, reject) => {
    let stderr = "";
    child.stderr.on("data", (chunk) => { stderr += chunk.toString(); });
    child.once("error", reject);
    child.once("close", (code) => code === 0 ? resolve() : reject(new Error(`tar failed: ${stderr.trim()}`)));
  });
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
    const users = (await readdir(required("KEYWAY_MANAGED_DATA_DIR", "/fiber/users"), { withFileTypes: true }))
      .filter((entry) => entry.isDirectory() && USER_ID.test(entry.name))
      .map((entry) => entry.name);
    const retired = await Promise.all(users.map((userId) => isRetired(userId)));
    return users.filter((_, index) => !retired[index]);
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
