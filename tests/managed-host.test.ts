import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  authorizationMatches,
  createCkbKey,
  createSnapshot,
  listSnapshots,
  managedUserId,
  restoreSnapshot,
} from "../managed-host/index.mjs";

const USER = "a".repeat(64);

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

  const snapshot = await createSnapshot({ userId: USER, dataDir, root });
  assert.match(snapshot.name, /^snap-\d+$/);
  assert.equal(snapshot.digest.length, 64);
  assert.equal(snapshot.bytes, (await stat(keyPath)).size + "channel-state".length);
  assert.equal((await listSnapshots({ userId: USER, root })).length, 1);

  await writeFile(join(dataDir, "fiber.db"), "overwritten");
  await rm(keyPath);
  await restoreSnapshot({ userId: USER, dataDir, root, name: snapshot.name });
  assert.equal(await readFile(join(dataDir, "fiber.db"), "utf8"), "channel-state");
  assert.equal((await stat(keyPath)).mode & 0o777, 0o600);
});

test("managed host rejects a tampered snapshot before overwriting live state", async (context) => {
  const { dataDir, root } = await fixture(context);
  await writeFile(join(dataDir, "fiber.db"), "channel-state");
  const snapshot = await createSnapshot({ userId: USER, dataDir, root });

  await writeFile(join(root, snapshot.name, "fiber.db"), "tampered");
  await assert.rejects(
    restoreSnapshot({ userId: USER, dataDir, root, name: snapshot.name }),
    /corrupted/,
  );
  assert.equal(await readFile(join(dataDir, "fiber.db"), "utf8"), "channel-state");
  await assert.rejects(
    restoreSnapshot({ userId: USER, dataDir, root, name: "../escape" }),
    /valid managed Fiber snapshot name/,
  );
});

test("managed host keeps bounded backup generations and enforces a size limit", async (context) => {
  const { dataDir, root } = await fixture(context);
  await writeFile(join(dataDir, "fiber.db"), "state");
  for (let generation = 0; generation < 4; generation += 1) {
    await createSnapshot({ userId: USER, dataDir, root, keep: 2, limitBytes: 64 });
    await new Promise((resolve) => setTimeout(resolve, 2));
  }
  assert.equal((await listSnapshots({ userId: USER, root })).length, 2);
  await assert.rejects(
    createSnapshot({ userId: USER, dataDir, root, limitBytes: 1 }),
    /backup size limit/,
  );
});
