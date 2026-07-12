import assert from "node:assert/strict";
import test from "node:test";
import type { User } from "stytch";
import { readActiveLease, requireLease, type StoredDeviceLease } from "../src/server/device-lease.ts";

function userWithLease(lease: Partial<StoredDeviceLease>): User {
  return {
    user_id: "user-test",
    trusted_metadata: { keywayDeviceLease: lease },
  } as unknown as User;
}

test("accepts only the active lease for the authenticated user and device", () => {
  const user = userWithLease({
    stytchUserId: "user-test",
    deviceIdHash: "device-a",
    leaseId: "lease-a",
    expiresAt: new Date(Date.now() + 30_000).toISOString(),
  });

  assert.equal(requireLease(user, "device-a", "lease-a").leaseId, "lease-a");
  assert.throws(() => requireLease(user, "device-b", "lease-a"), /active device lease/);
  assert.throws(() => requireLease(user, "device-a", "lease-b"), /active device lease/);
});

test("rejects expired and cross-user lease records", () => {
  const expired = userWithLease({
    stytchUserId: "user-test",
    deviceIdHash: "device-a",
    leaseId: "lease-a",
    expiresAt: new Date(Date.now() - 1).toISOString(),
  });
  const crossUser = userWithLease({
    stytchUserId: "another-user",
    deviceIdHash: "device-a",
    leaseId: "lease-a",
    expiresAt: new Date(Date.now() + 30_000).toISOString(),
  });

  assert.equal(readActiveLease(expired), undefined);
  assert.equal(readActiveLease(crossUser), undefined);
});
