import assert from "node:assert/strict";
import test from "node:test";
import type { User } from "stytch";
import { createHash } from "node:crypto";
import { database } from "../src/server/database.ts";
import {
  confirmNodeBackupRestored,
  prepareBackupForDevice,
  readClaimedNodeBackup,
  saveNodeBackup,
} from "../src/server/node-backup.ts";

test("moves an encrypted backup through available, claimed, and consumed states", { skip: !process.env.DATABASE_URL }, async () => {
  const user = { user_id: `backup-test-${crypto.randomUUID()}` } as User;
  const source = "a".repeat(64);
  const destination = "b".repeat(64);
  const ciphertext = Buffer.from("ciphertext");
  const saved = await saveNodeBackup(user, source, {
    formatVersion: 1,
    databasePrefix: "/wasm-wallet",
    salt: Buffer.alloc(32).toString("base64"),
    iv: Buffer.alloc(12).toString("base64"),
    ciphertext: ciphertext.toString("base64"),
    digest: createHash("sha256").update(ciphertext).digest("hex"),
  });
  const sql = await database();
  assert.deepEqual(await prepareBackupForDevice(user, source, destination, undefined, sql), {
    restoreRequired: true,
    canRebind: true,
  });
  const claimed = await readClaimedNodeBackup(user, destination);
  assert.equal(claimed.generation, saved.generation);
  assert.equal(claimed.status, "claimed");
  await confirmNodeBackupRestored(user, destination, saved.generation);
  await assert.rejects(readClaimedNodeBackup(user, destination), /No Fiber node backup/);
});

test("rejects an encrypted backup with a false digest", { skip: !process.env.DATABASE_URL }, async () => {
  const user = { user_id: `backup-digest-test-${crypto.randomUUID()}` } as User;
  await assert.rejects(saveNodeBackup(user, "a".repeat(64), {
    formatVersion: 1,
    databasePrefix: "/wasm-wallet",
    salt: Buffer.alloc(32).toString("base64"),
    iv: Buffer.alloc(12).toString("base64"),
    ciphertext: Buffer.from("ciphertext").toString("base64"),
    digest: "ab".repeat(32),
  }), /digest does not match/);
});
