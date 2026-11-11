import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { database } from "../src/server/database.ts";
import { acquireLease } from "../src/server/device-lease.ts";
import { fiberKeyAccess as access } from "../src/server/http.ts";
import { prepareBackupForDevice, readClaimedNodeBackup, saveNodeBackup } from "../src/server/node-backup.ts";
import { saveWallet, type ReadyWallet } from "../src/server/user-wallet.ts";

const enabled = Boolean(process.env.KEYWAY_AUTH_TEST_DATABASE_URL);
/** The Fiber-key request, with Lit's wrapping of the key replaced. */
const fiberKeyAccess = (user: { id: string }, device: string, leaseId: string) => access(user, device, leaseId, async () => "wrapped key");
const A = "a".repeat(64);
const B = "b".repeat(64);

function payload(text: string) {
  const ciphertext = Buffer.from(text);
  return {
    formatVersion: 1,
    databasePrefix: "/wasm-wallet",
    salt: Buffer.alloc(32).toString("base64"),
    iv: Buffer.alloc(12).toString("base64"),
    ciphertext: ciphertext.toString("base64"),
    digest: createHash("sha256").update(ciphertext).digest("hex"),
  };
}

test("a node that runs again after its logout saved a backup retires that backup", { skip: !enabled }, async (t) => {
  process.env.DATABASE_URL = process.env.KEYWAY_AUTH_TEST_DATABASE_URL;
  const sql = await database();
  async function device() {
    const user = { id: crypto.randomUUID() };
    const wallet: ReadyWallet = {
      version: 1, status: "ready", litPkpId: `0x${"11".repeat(20)}`, litPublicKey: `0x02${"22".repeat(32)}`, ckbAddress: "ckt1",
      encryptedFiberKey: "ciphertext", primaryDeviceIdHash: A, hasOpenedChannel: true,
      createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
    };
    await saveWallet(user, wallet);
    return { user, lease: await acquireLease(user, A) };
  }
  const lapse = (userId: string) => sql`update keyway_v2_device_leases set expires_at = now() - interval '1 second' where user_id = ${userId}`;

  await t.test("another device can't restore it once the node has its key again", async () => {
    const { user, lease } = await device();
    // The logout loaded the key, saved the backup, then failed to release the device: the node resumes.
    await fiberKeyAccess(user, A, lease.leaseId);
    await saveNodeBackup(user, A, payload("state at logout"));
    await fiberKeyAccess(user, A, lease.leaseId);
    // The tab later closes without a logout and the lease runs out: another device signs in.
    await lapse(user.id);
    assert.deepEqual(await prepareBackupForDevice(user, A, B, undefined, sql), { restoreRequired: false, canRebind: false });
  });

  await t.test("a claim made before the node got its key back is no longer valid", async () => {
    const { user } = await device();
    await saveNodeBackup(user, A, payload("state at logout"));
    await lapse(user.id);
    assert.equal((await prepareBackupForDevice(user, A, B, undefined, sql)).restoreRequired, true);
    // The first device takes the lease back before the other one restores, and runs its node again.
    const again = await acquireLease(user, A);
    await fiberKeyAccess(user, A, again.leaseId);
    await assert.rejects(readClaimedNodeBackup(user, B), /No Fiber node backup is claimed/);
  });

  await t.test("a backup saved after the key was loaded, by a logout that completes, stays restorable", async () => {
    const { user, lease } = await device();
    await fiberKeyAccess(user, A, lease.leaseId);
    await saveNodeBackup(user, A, payload("state at logout"));
    await lapse(user.id);
    assert.deepEqual(await prepareBackupForDevice(user, A, B, undefined, sql), { restoreRequired: true, canRebind: true });
  });

  await t.test("a key that couldn't be wrapped retires nothing", async () => {
    const { user, lease } = await device();
    await saveNodeBackup(user, A, payload("state at logout"));
    await assert.rejects(access(user, A, lease.leaseId, async () => { throw new Error("Lit unavailable"); }), /Lit unavailable/);
    await lapse(user.id);
    assert.equal((await prepareBackupForDevice(user, A, B, undefined, sql)).restoreRequired, true);
  });

  await t.test("the device's own claim of its backup survives the key it loads to restore it", async () => {
    const { user } = await device();
    await saveNodeBackup(user, A, payload("state at logout"));
    await lapse(user.id);
    // Another device claimed it and was rebound, then gave up; the first device signs in again and claims it back.
    assert.equal((await prepareBackupForDevice(user, A, B, undefined, sql)).restoreRequired, true);
    await sql`update keyway_v2_node_backups set claim_expires_at = now() - interval '1 second' where user_id = ${user.id}`;
    assert.equal((await prepareBackupForDevice(user, B, A, undefined, sql)).restoreRequired, true);
    // The restore loads the key first, then reads the claimed backup.
    const again = await acquireLease(user, A);
    await fiberKeyAccess(user, A, again.leaseId);
    assert.equal((await readClaimedNodeBackup(user, A)).status, "claimed");
  });

  await t.test("a device that lost the wallet while its key was being wrapped gets no key and retires nothing", async () => {
    const { user, lease } = await device();
    await saveNodeBackup(user, A, payload("state at logout"));
    // While Lit wraps the key, the lease runs out, and another device signs in, claims the backup and is bound.
    await assert.rejects(access(user, A, lease.leaseId, async (wallet) => {
      await lapse(user.id);
      assert.equal((await prepareBackupForDevice(user, A, B, undefined, sql)).restoreRequired, true);
      await saveWallet(user, { ...wallet, primaryDeviceIdHash: B });
      return "wrapped key";
    }), /bound to another device/);
    assert.equal((await readClaimedNodeBackup(user, B)).status, "claimed", "the other device can still restore it");
  });

  await t.test("a lease that ran out while the key was being wrapped retires nothing", async () => {
    const { user, lease } = await device();
    await saveNodeBackup(user, A, payload("state at logout"));
    await assert.rejects(access(user, A, lease.leaseId, async () => {
      await lapse(user.id);
      return "wrapped key";
    }), /active device lease/);
    assert.equal((await prepareBackupForDevice(user, A, B, undefined, sql)).restoreRequired, true);
  });

  await t.test("only a device holding the lease gets its key, and nothing is retired otherwise", async () => {
    const { user, lease } = await device();
    await saveNodeBackup(user, A, payload("state at logout"));
    await lapse(user.id);
    await assert.rejects(fiberKeyAccess(user, A, lease.leaseId), /active device lease/);
    assert.equal((await prepareBackupForDevice(user, A, B, undefined, sql)).restoreRequired, true);
  });
});
