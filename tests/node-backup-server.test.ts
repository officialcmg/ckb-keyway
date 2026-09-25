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

test("keeps older encrypted backups and claims only the newest generation", { skip: !process.env.DATABASE_URL }, async () => {
  const user = { user_id: `backup-generations-${crypto.randomUUID()}` } as User;
  const source = "a".repeat(64);
  const destination = "b".repeat(64);
  const first = await saveNodeBackup(user, source, payload("first"));
  const second = await saveNodeBackup(user, source, payload("second"));
  assert.equal(first.generation, 1);
  assert.equal(second.generation, 2);
  const sql = await database();
  assert.deepEqual(await generations(user.user_id), [1, 2]);

  assert.deepEqual(await prepareBackupForDevice(user, source, destination, undefined, sql), {
    restoreRequired: true,
    canRebind: true,
  });
  assert.equal((await readClaimedNodeBackup(user, destination)).generation, 2);
  await confirmNodeBackupRestored(user, destination, 2);

  // The consumed generation and every older one stay on disk for rollback.
  assert.deepEqual(await generations(user.user_id), [1, 2]);
  assert.equal((await saveNodeBackup(user, source, payload("third"))).generation, 3);

  process.env.KEYWAY_BACKUP_GENERATIONS = "2";
  try {
    assert.equal((await saveNodeBackup(user, source, payload("fourth"))).generation, 4);
    assert.deepEqual(await generations(user.user_id), [3, 4]);
  } finally {
    delete process.env.KEYWAY_BACKUP_GENERATIONS;
  }
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

function payload(label: string) {
  const ciphertext = Buffer.from(label);
  return {
    formatVersion: 1 as const,
    databasePrefix: "/wasm-wallet",
    salt: Buffer.alloc(32).toString("base64"),
    iv: Buffer.alloc(12).toString("base64"),
    ciphertext: ciphertext.toString("base64"),
    digest: createHash("sha256").update(ciphertext).digest("hex"),
  };
}

async function generations(userId: string): Promise<number[]> {
  const sql = await database();
  const rows = await sql<{ generation: string | number }[]>`
    select generation from keyway_node_backups where stytch_user_id = ${userId} order by generation
  `;
  return rows.map((row) => Number(row.generation));
}
