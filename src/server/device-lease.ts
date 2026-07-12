import type { User } from "stytch";
import { updateTrustedMetadata } from "./stytch.ts";

const LEASE_TTL_MS = 45_000;
const METADATA_KEY = "keywayDeviceLease";

export type StoredDeviceLease = {
  stytchUserId: string;
  deviceIdHash: string;
  leaseId: string;
  expiresAt: string;
};

export async function acquireLease(user: User, deviceIdHash: string): Promise<StoredDeviceLease> {
  const current = readActiveLease(user);
  if (current && current.deviceIdHash !== deviceIdHash) {
    throw new Error("Fiber identity is active on another device");
  }
  return saveLease(user, {
    stytchUserId: user.user_id,
    deviceIdHash,
    leaseId: current?.leaseId ?? crypto.randomUUID(),
    expiresAt: expiry(),
  });
}

export async function heartbeatLease(
  user: User,
  deviceIdHash: string,
  leaseId: string,
): Promise<StoredDeviceLease> {
  const lease = requireLease(user, deviceIdHash, leaseId);
  return saveLease(user, { ...lease, expiresAt: expiry() });
}

export async function releaseLease(user: User, deviceIdHash: string, leaseId: string): Promise<void> {
  requireLease(user, deviceIdHash, leaseId);
  const metadata = { ...(user.trusted_metadata ?? {}) };
  delete metadata[METADATA_KEY];
  await updateTrustedMetadata(user.user_id, metadata);
}

export function requireLease(user: User, deviceIdHash: string, leaseId: string): StoredDeviceLease {
  const lease = readActiveLease(user);
  if (!lease || lease.leaseId !== leaseId || lease.deviceIdHash !== deviceIdHash) {
    throw new Error("An active device lease is required");
  }
  return lease;
}

export function readActiveLease(user: User): StoredDeviceLease | undefined {
  const value = user.trusted_metadata?.[METADATA_KEY];
  if (!value || typeof value !== "object") return undefined;
  const lease = value as Partial<StoredDeviceLease>;
  if (
    lease.stytchUserId !== user.user_id ||
    typeof lease.deviceIdHash !== "string" ||
    typeof lease.leaseId !== "string" ||
    typeof lease.expiresAt !== "string" ||
    Date.parse(lease.expiresAt) <= Date.now()
  ) return undefined;
  return lease as StoredDeviceLease;
}

async function saveLease(user: User, lease: StoredDeviceLease): Promise<StoredDeviceLease> {
  await updateTrustedMetadata(user.user_id, { ...(user.trusted_metadata ?? {}), [METADATA_KEY]: lease });
  return lease;
}

function expiry(): string {
  return new Date(Date.now() + LEASE_TTL_MS).toISOString();
}
