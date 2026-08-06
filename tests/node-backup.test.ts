import "fake-indexeddb/auto";
import assert from "node:assert/strict";
import test from "node:test";
import {
  createEncryptedNodeBackup,
  exportNodeDatabases,
  restoreEncryptedNodeBackup,
} from "../src/sdk/browser/node-backup.ts";

const PREFIX = "/wasm-wallet-test";
const FIBER_KEY = new Uint8Array(32).fill(17);

test("exports, encrypts, and restores wallet-scoped IndexedDB state", async () => {
  await cleanup();
  const walletDatabase = await openDatabase(`${PREFIX}-fiber`, 3, (database) => {
    const records = database.createObjectStore("records", { keyPath: "id" });
    records.createIndex("by-kind", "kind", { unique: false });
    database.createObjectStore("binary");
  });
  const unrelated = await openDatabase("/wasm-another-wallet-fiber", 1, (database) => {
    database.createObjectStore("records", { keyPath: "id" });
  });
  const date = new Date("2026-08-07T12:00:00.000Z");
  const write = walletDatabase.transaction(["records", "binary"], "readwrite");
  write.objectStore("records").put({
    id: ["channel", 1],
    kind: "channel",
    amount: 901n,
    openedAt: date,
    metadata: new Map([["peer", "02abc"]]),
    tags: new Set(["ready", "public"]),
  });
  write.objectStore("binary").put(new Uint8Array([1, 2, 3, 4]), ["payment", 7]);
  await transactionDone(write);
  const unrelatedWrite = unrelated.transaction("records", "readwrite");
  unrelatedWrite.objectStore("records").put({ id: "untouched", value: 42 });
  await transactionDone(unrelatedWrite);
  walletDatabase.close();
  unrelated.close();

  const archive = await exportNodeDatabases(PREFIX);
  assert.deepEqual(archive.databases.map(({ name }) => name), [`${PREFIX}-fiber`]);
  const backup = await createEncryptedNodeBackup(PREFIX, FIBER_KEY);
  await deleteDatabase(`${PREFIX}-fiber`);
  await restoreEncryptedNodeBackup(backup, PREFIX, FIBER_KEY);

  const restored = await request(indexedDB.open(`${PREFIX}-fiber`));
  assert.equal(restored.version, 3);
  const read = restored.transaction(["records", "binary"], "readonly");
  const record = await request(read.objectStore("records").get(["channel", 1]));
  const binary = await request(read.objectStore("binary").get(["payment", 7]));
  assert.equal(record.amount, 901n);
  assert.equal(record.openedAt.toISOString(), date.toISOString());
  assert.deepEqual(record.metadata, new Map([["peer", "02abc"]]));
  assert.deepEqual(record.tags, new Set(["ready", "public"]));
  assert.deepEqual(binary, new Uint8Array([1, 2, 3, 4]));
  assert.equal(read.objectStore("records").index("by-kind").unique, false);
  await transactionDone(read);
  restored.close();

  const untouched = await request(indexedDB.open("/wasm-another-wallet-fiber"));
  assert.deepEqual(await request(untouched.transaction("records").objectStore("records").get("untouched")), {
    id: "untouched",
    value: 42,
  });
  untouched.close();
  await cleanup();
});

test("rejects corrupted ciphertext and the wrong wallet prefix", async () => {
  await cleanup();
  const database = await openDatabase(`${PREFIX}-empty`, 1, (target) => target.createObjectStore("records"));
  database.close();
  const backup = await createEncryptedNodeBackup(PREFIX, FIBER_KEY);
  const corrupted = { ...backup, ciphertext: `${backup.ciphertext.slice(0, -4)}AAAA` };
  await assert.rejects(restoreEncryptedNodeBackup(corrupted, PREFIX, FIBER_KEY), /corrupted/);
  await assert.rejects(restoreEncryptedNodeBackup(backup, "/wasm-other", FIBER_KEY), /does not belong/);
  await cleanup();
});

async function cleanup() {
  for (const database of await indexedDB.databases()) {
    if (database.name?.startsWith(PREFIX) || database.name === "/wasm-another-wallet-fiber") {
      await deleteDatabase(database.name);
    }
  }
}

function openDatabase(name: string, version: number, upgrade: (database: IDBDatabase) => void): Promise<IDBDatabase> {
  const opened = indexedDB.open(name, version);
  opened.onupgradeneeded = () => upgrade(opened.result);
  return request(opened);
}

function deleteDatabase(name: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const deletion = indexedDB.deleteDatabase(name);
    deletion.onsuccess = () => resolve();
    deletion.onerror = () => reject(deletion.error);
  });
}

function request<T>(value: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    value.onsuccess = () => resolve(value.result);
    value.onerror = () => reject(value.error);
  });
}

function transactionDone(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
    transaction.onabort = () => reject(transaction.error);
  });
}
