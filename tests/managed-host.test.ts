import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { authorizationMatches, createCkbKey, managedUserId } from "../managed-host/index.mjs";

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
