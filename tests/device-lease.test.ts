import assert from "node:assert/strict";
import test from "node:test";
import type { User } from "stytch";
import { acquireLease, heartbeatLease, releaseLease, requireLease } from "../src/server/device-lease.ts";

test("enforces one active device lease atomically", { skip: !process.env.DATABASE_URL }, async () => {
  const user = { user_id: `lease-test-${crypto.randomUUID()}` } as User;
  const lease = await acquireLease(user, "device-a");
  assert.equal((await requireLease(user, "device-a", lease.leaseId)).leaseId, lease.leaseId);
  await assert.rejects(acquireLease(user, "device-b"), /another device/);
  assert.equal((await heartbeatLease(user, "device-a", lease.leaseId)).deviceIdHash, "device-a");
  await releaseLease(user, "device-a", lease.leaseId);
  await assert.rejects(requireLease(user, "device-a", lease.leaseId), /active device lease/);
});
