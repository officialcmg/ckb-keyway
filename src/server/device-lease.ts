import type { User } from "stytch";
import { database, type DatabaseSql } from "./database.ts";

const LEASE_TTL_MS = 45_000;

export type StoredDeviceLease = {
  stytchUserId: string;
  deviceIdHash: string;
  leaseId: string;
  expiresAt: string;
};

type LeaseRow = {
  stytch_user_id: string;
  device_id_hash: string;
  lease_id: string;
  expires_at: Date;
};

export async function acquireLease(user: User, deviceIdHash: string): Promise<StoredDeviceLease> {
  const sql = await database();
  const rows = await sql<LeaseRow[]>`
    insert into keyway_device_leases (stytch_user_id, device_id_hash, lease_id, expires_at)
    values (${user.user_id}, ${deviceIdHash}, ${crypto.randomUUID()}, ${expiry()})
    on conflict (stytch_user_id) do update set
      device_id_hash = excluded.device_id_hash,
      lease_id = excluded.lease_id,
      expires_at = excluded.expires_at
    where keyway_device_leases.expires_at <= now()
       or keyway_device_leases.device_id_hash = excluded.device_id_hash
    returning stytch_user_id, device_id_hash, lease_id::text, expires_at
  `;
  if (!rows[0]) throw new Error("Fiber identity is active on another device");
  return publicLease(rows[0]);
}

export async function heartbeatLease(
  user: User,
  deviceIdHash: string,
  leaseId: string,
): Promise<StoredDeviceLease> {
  const sql = await database();
  const rows = await sql<LeaseRow[]>`
    update keyway_device_leases set expires_at = ${expiry()}
    where stytch_user_id = ${user.user_id}
      and device_id_hash = ${deviceIdHash}
      and lease_id = ${leaseId}
      and expires_at > now()
    returning stytch_user_id, device_id_hash, lease_id::text, expires_at
  `;
  if (!rows[0]) throw new Error("An active device lease is required");
  return publicLease(rows[0]);
}

export async function releaseLease(user: User, deviceIdHash: string, leaseId: string): Promise<void> {
  const sql = await database();
  await sql`
    delete from keyway_device_leases
    where stytch_user_id = ${user.user_id}
      and device_id_hash = ${deviceIdHash}
      and lease_id = ${leaseId}
  `;
}

export async function requireLease(user: User, deviceIdHash: string, leaseId: string): Promise<StoredDeviceLease> {
  const sql = await database();
  const rows = await sql<LeaseRow[]>`
    select stytch_user_id, device_id_hash, lease_id::text, expires_at
    from keyway_device_leases
    where stytch_user_id = ${user.user_id}
      and device_id_hash = ${deviceIdHash}
      and lease_id = ${leaseId}
      and expires_at > now()
  `;
  if (!rows[0]) throw new Error("An active device lease is required");
  return publicLease(rows[0]);
}

export async function readActiveLease(user: User, connection?: DatabaseSql): Promise<StoredDeviceLease | undefined> {
  const sql = connection ?? await database();
  const rows = await sql<LeaseRow[]>`
    select stytch_user_id, device_id_hash, lease_id::text, expires_at
    from keyway_device_leases
    where stytch_user_id = ${user.user_id} and expires_at > now()
  `;
  return rows[0] ? publicLease(rows[0]) : undefined;
}

function publicLease(row: LeaseRow): StoredDeviceLease {
  return {
    stytchUserId: row.stytch_user_id,
    deviceIdHash: row.device_id_hash,
    leaseId: row.lease_id,
    expiresAt: row.expires_at.toISOString(),
  };
}

function expiry(): string {
  return new Date(Date.now() + LEASE_TTL_MS).toISOString();
}
