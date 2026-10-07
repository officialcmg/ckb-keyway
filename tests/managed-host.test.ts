import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdir, mkdtemp, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  authorizationMatches,
  completeDatabaseOperation,
  createCkbKey,
  createSnapshot,
  listSnapshots,
  managedUserId,
  restoreSnapshot,
  requireCleanRestore,
  snapshotDigest,
  waitForExit,
  withUserOperation,
  requireClosedChannels,
} from "../managed-host/index.mjs";

const USER = "a".repeat(64);
const ENCRYPTION_KEY = randomBytes(32);

test("node retirement rejects active, settling, or unknown channel states", () => {
  requireClosedChannels([]);
  requireClosedChannels([{ state: { state_name: "Closed", state_flags: "COOPERATIVE" } }]);
  assert.throws(() => requireClosedChannels([{ state: { state_name: "Closed", state_flags: "FORCE" } }]), /preserve/);
  for (const state_name of ["ChannelReady", "ShuttingDown", "AwaitingTxSignatures", "Unknown"]) {
    assert.throws(() => requireClosedChannels([{ state: { state_name } }]), /preserve/);
  }
  assert.throws(() => requireClosedChannels(undefined), /preserve/);
});

test("managed database operations report success only after the node resumes", async () => {
  const events: string[] = [];
  const result = await completeDatabaseOperation(
    async () => { events.push("database"); return { restored: true }; },
    async () => { events.push("resume"); },
  );
  assert.deepEqual(result, { restored: true });
  assert.deepEqual(events, ["database", "resume"]);
  await assert.rejects(completeDatabaseOperation(
    async () => ({ restored: true }),
    async () => { throw new Error("node startup failed"); },
  ), /node startup failed/);
  let resumed = false;
  await assert.rejects(completeDatabaseOperation(
    async () => { throw new Error("snapshot failed"); },
    async () => { resumed = true; },
  ), /snapshot failed/);
  assert.equal(resumed, true);
});

test("managed database operations serialize per user without blocking other users", async () => {
  const events: string[] = [];
  let release!: () => void;
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const first = withUserOperation(USER, async () => {
    events.push("snapshot");
    await gate;
    throw new Error("snapshot failed");
  });
  const failure = assert.rejects(first, /snapshot failed/);
  const next = withUserOperation(USER, async () => { events.push("rpc"); });
  await withUserOperation("b".repeat(64), async () => { events.push("other user"); });
  assert.deepEqual(events, ["snapshot", "other user"]);
  release();
  await failure;
  await next;
  assert.deepEqual(events, ["snapshot", "other user", "rpc"]);
});

test("managed shutdown waits for actual exit after forced termination", async (context) => {
  const child = spawn(process.execPath, ["-e", "process.on('SIGTERM',()=>{}); process.send('ready'); setInterval(()=>{},1000)"], { stdio: ["ignore", "ignore", "ignore", "ipc"] });
  context.after(() => { child.kill("SIGKILL"); });
  await once(child, "message");
  await waitForExit(child, 10);
  assert.equal(child.signalCode, "SIGKILL");
});

async function fixture(context: { after: (fn: () => Promise<void>) => void }) {
  const workspace = await mkdtemp(join(tmpdir(), "keyway-managed-backup-"));
  context.after(() => rm(workspace, { recursive: true, force: true }));
  const dataDir = join(workspace, "users", USER);
  const root = join(workspace, "backups", USER);
  await mkdir(join(dataDir, "ckb"), { recursive: true });
  return { workspace, dataDir, root };
}

test("managed host uses stable opaque user directories", () => {
  const id = managedUserId("user-test-123");
  assert.match(id, /^[0-9a-f]{64}$/);
  assert.equal(id, managedUserId("user-test-123"));
  assert.notEqual(id, managedUserId("user-test-456"));
});

test("managed host requires an exact bearer token", () => {
  assert.equal(authorizationMatches("Bearer secret", "secret"), true);
  assert.equal(authorizationMatches("Bearer wrong", "secret"), false);
  assert.equal(authorizationMatches(undefined, "secret"), false);
});

test("managed host creates one private persistent CKB key", async (context) => {
  const directory = await mkdtemp(join(tmpdir(), "keyway-managed-host-"));
  context.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, "key");
  await createCkbKey(path);
  const first = await readFile(path, "utf8");
  await createCkbKey(path);
  assert.match(first, /^[0-9a-f]{64}$/);
  assert.equal(await readFile(path, "utf8"), first);
  assert.equal((await stat(path)).mode & 0o777, 0o600);
});

test("managed host snapshots and restores durable node state", async (context) => {
  const { dataDir, root } = await fixture(context);
  const keyPath = join(dataDir, "ckb", "key");
  await createCkbKey(keyPath);
  await writeFile(join(dataDir, "fiber.db"), "channel-state");

  const snapshot = await createSnapshot({ userId: USER, dataDir, root, encryptionKey: ENCRYPTION_KEY });
  assert.match(snapshot.name, /^snap-\d+$/);
  assert.equal(snapshot.digest.length, 64);
  assert.equal(snapshot.bytes, (await stat(keyPath)).size + "channel-state".length);
  assert.equal((await listSnapshots({ userId: USER, root })).length, 1);
  assert.equal((await readFile(join(root, `${snapshot.name}.enc`))).includes(await readFile(keyPath)), false);

  await writeFile(join(dataDir, "fiber.db"), "overwritten");
  await rm(keyPath);
  await restoreSnapshot({ userId: USER, dataDir, root, name: snapshot.name, encryptionKey: ENCRYPTION_KEY });
  assert.equal(await readFile(join(dataDir, "fiber.db"), "utf8"), "channel-state");
  assert.equal((await stat(keyPath)).mode & 0o777, 0o600);
});

test("managed host rejects a tampered snapshot before overwriting live state", async (context) => {
  const { dataDir, root } = await fixture(context);
  await writeFile(join(dataDir, "fiber.db"), "channel-state");
  const snapshot = await createSnapshot({ userId: USER, dataDir, root, encryptionKey: ENCRYPTION_KEY });

  await assert.rejects(
    restoreSnapshot({ userId: USER, dataDir, root, name: snapshot.name, encryptionKey: randomBytes(32) }),
    /authenticate/,
  );
  assert.equal(await readFile(join(dataDir, "fiber.db"), "utf8"), "channel-state");
  await writeFile(join(root, `${snapshot.name}.enc`), "tampered");
  await assert.rejects(
    restoreSnapshot({ userId: USER, dataDir, root, name: snapshot.name, encryptionKey: ENCRYPTION_KEY }),
  );
  assert.equal(await readFile(join(dataDir, "fiber.db"), "utf8"), "channel-state");
  await assert.rejects(
    restoreSnapshot({ userId: USER, dataDir, root, name: "../escape", encryptionKey: ENCRYPTION_KEY }),
    /valid managed Fiber snapshot name/,
  );
});

test("an interrupted restore preserves old state and blocks startup or another restore", async (context) => {
  const { dataDir, root } = await fixture(context);
  await writeFile(join(dataDir, "fiber.db"), "current-state");
  const snapshot = await createSnapshot({ userId: USER, dataDir, root, encryptionKey: ENCRYPTION_KEY });
  await rename(dataDir, `${dataDir}.previous`);
  await assert.rejects(requireCleanRestore(dataDir), /operator recovery/);
  await assert.rejects(
    restoreSnapshot({ userId: USER, dataDir, root, name: snapshot.name, encryptionKey: ENCRYPTION_KEY }),
    /operator recovery/,
  );
  assert.equal(await readFile(join(`${dataDir}.previous`, "fiber.db"), "utf8"), "current-state");
  await assert.rejects(stat(dataDir), { code: "ENOENT" });
});

test("managed host can restore a pre-encryption snapshot", async (context) => {
  const { dataDir, root } = await fixture(context);
  const name = "snap-1";
  await mkdir(join(root, name), { recursive: true });
  await writeFile(join(root, name, "fiber.db"), "legacy-state");
  await writeFile(join(root, `${name}.json`), JSON.stringify({
    digest: await snapshotDigest(join(root, name)),
    bytes: "legacy-state".length,
    createdAt: new Date().toISOString(),
  }));
  await restoreSnapshot({ userId: USER, dataDir, root, name, encryptionKey: ENCRYPTION_KEY });
  assert.equal(await readFile(join(dataDir, "fiber.db"), "utf8"), "legacy-state");
});

test("managed host keeps bounded backup generations and enforces a size limit", async (context) => {
  const { dataDir, root } = await fixture(context);
  await writeFile(join(dataDir, "fiber.db"), "state");
  for (let generation = 0; generation < 4; generation += 1) {
    await createSnapshot({ userId: USER, dataDir, root, keep: 2, limitBytes: 64, encryptionKey: ENCRYPTION_KEY });
    await new Promise((resolve) => setTimeout(resolve, 2));
  }
  assert.equal((await listSnapshots({ userId: USER, root })).length, 2);
  await assert.rejects(
    createSnapshot({ userId: USER, dataDir, root, limitBytes: 1, encryptionKey: ENCRYPTION_KEY }),
    /backup size limit/,
  );
});
