import assert from "node:assert/strict";
import test from "node:test";
import { IDBFactory } from "fake-indexeddb";
import { cleanupLegacyDatabases } from "../src/sdk/browser/legacy-cleanup.ts";

test("cleanup removes only exact approved wallet namespaces", async () => {
  const factory = new IDBFactory();
  const prefix = `/wasm-0x${"a".repeat(40)}`;
  const names = [`${prefix}/store`, `${prefix}other/store`, `/wasm-0x${"b".repeat(40)}/store`, "unrelated"];
  for (const name of names) await new Promise<void>((resolve) => { const request = factory.open(name); request.onsuccess = () => { request.result.close(); resolve(); }; });
  await cleanupLegacyDatabases({ epoch: "reset-1", prefixes: [prefix] }, factory);
  assert.deepEqual((await factory.databases()).map((row) => row.name).sort(), names.slice(1).sort());
  await assert.rejects(cleanupLegacyDatabases({ epoch: "reset-1", prefixes: ["/wasm-"] }, factory), /Invalid/);
});
