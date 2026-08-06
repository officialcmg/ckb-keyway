import assert from "node:assert/strict";
import test from "node:test";
import { backUpBeforeLogout, restoreBeforeStart } from "../src/sdk/browser/node-migration.ts";

const payload = {
  formatVersion: 1 as const,
  databasePrefix: "/wasm-wallet",
  salt: "salt",
  iv: "iv",
  ciphertext: "ciphertext",
  digest: "ab".repeat(32),
};

test("backs up before releasing ownership and clears temporary key bytes", async () => {
  const order: string[] = [];
  const key = new Uint8Array(32).fill(7);
  await backUpBeforeLogout({
    loadFiberKey: async () => key,
    stopNode: async () => { order.push("stop"); },
    createBackup: async () => { order.push("encrypt"); return payload; },
    saveBackup: async () => { order.push("upload"); return { digest: payload.digest }; },
    releaseOwnership: async () => { order.push("release"); },
  });
  assert.deepEqual(order, ["stop", "encrypt", "upload", "release"]);
  assert.deepEqual(key, new Uint8Array(32));
});

test("does not release ownership when backup upload fails", async () => {
  let released = false;
  const key = new Uint8Array(32).fill(7);
  await assert.rejects(backUpBeforeLogout({
    loadFiberKey: async () => key,
    stopNode: async () => undefined,
    createBackup: async () => payload,
    saveBackup: async () => { throw new Error("upload failed"); },
    releaseOwnership: async () => { released = true; },
  }), /upload failed/);
  assert.equal(released, false);
  assert.deepEqual(key, new Uint8Array(32));
});

test("confirms a restore only after import succeeds", async () => {
  const order: string[] = [];
  const key = new Uint8Array(32).fill(9);
  await restoreBeforeStart({
    loadFiberKey: async () => key,
    loadBackup: async () => ({ ...payload, generation: 3 }),
    restoreBackup: async () => { order.push("restore"); },
    confirmRestore: async (generation) => { order.push(`confirm-${generation}`); },
  });
  assert.deepEqual(order, ["restore", "confirm-3"]);
  assert.deepEqual(key, new Uint8Array(32));
});

test("does not consume a backup when IndexedDB restore fails", async () => {
  let confirmed = false;
  await assert.rejects(restoreBeforeStart({
    loadFiberKey: async () => new Uint8Array(32),
    loadBackup: async () => ({ ...payload, generation: 3 }),
    restoreBackup: async () => { throw new Error("restore failed"); },
    confirmRestore: async () => { confirmed = true; },
  }), /restore failed/);
  assert.equal(confirmed, false);
});
