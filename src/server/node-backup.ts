import type { User } from "stytch";
import { createHash } from "node:crypto";
import { database, type DatabaseSql } from "./database.ts";

export type StoredNodeBackup = {
  generation: number;
  formatVersion: number;
  databasePrefix: string;
  salt: string;
  iv: string;
  ciphertext: string;
  digest: string;
  sourceDeviceIdHash: string;
  status: "available" | "claimed" | "consumed";
  claimedDeviceIdHash?: string;
};

type BackupRow = {
  generation: string | number;
  format_version: number;
  database_prefix: string;
  salt: string;
  iv: string;
  ciphertext: Buffer;
  digest: string;
  source_device_id_hash: string;
  status: StoredNodeBackup["status"];
  claimed_device_id_hash: string | null;
};

export async function saveNodeBackup(
  user: User,
  deviceIdHash: string,
  backup: Omit<StoredNodeBackup, "generation" | "sourceDeviceIdHash" | "status" | "claimedDeviceIdHash">,
): Promise<{ generation: number; digest: string }> {
  const sql = await database();
  const ciphertext = Buffer.from(backup.ciphertext, "base64");
  const digest = createHash("sha256").update(ciphertext).digest("hex");
  if (digest !== backup.digest) throw new Error("Encrypted Fiber node backup digest does not match its ciphertext");
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const rows = await sql<{ generation: string | number; digest: string }[]>`
      insert into keyway_node_backups (
        stytch_user_id, generation, format_version, database_prefix, salt, iv,
        ciphertext, digest, source_device_id_hash, status, claimed_device_id_hash,
        claim_expires_at, created_at, updated_at
      )
      select
        ${user.user_id}, coalesce(max(generation), 0) + 1,
        ${backup.formatVersion}, ${backup.databasePrefix}, ${backup.salt}, ${backup.iv},
        ${ciphertext}, ${digest}, ${deviceIdHash}, 'available', null, null, now(), now()
      from keyway_node_backups where stytch_user_id = ${user.user_id}
      on conflict (stytch_user_id, generation) do nothing
      returning generation, digest
    `;
    if (rows[0]) {
      await pruneNodeBackups(sql, user.user_id);
      return { generation: Number(rows[0].generation), digest: rows[0].digest };
    }
  }
  throw new Error("Fiber node backup generation could not be assigned");
}

export async function prepareBackupForDevice(
  user: User,
  currentDeviceIdHash: string,
  requestedDeviceIdHash: string,
  activeLeaseDeviceIdHash: string | undefined,
  sql: DatabaseSql,
): Promise<{ restoreRequired: boolean; canRebind: boolean }> {
  const backup = await readBackup(user, sql);
  if (currentDeviceIdHash === requestedDeviceIdHash) {
    if (backup?.status === "available" && backup.sourceDeviceIdHash === requestedDeviceIdHash) {
      await consumeBackup(user, sql);
    }
    return { restoreRequired: backup?.status === "claimed" && backup.claimedDeviceIdHash === requestedDeviceIdHash, canRebind: true };
  }
  if (activeLeaseDeviceIdHash && activeLeaseDeviceIdHash !== requestedDeviceIdHash) {
    throw new Error("Fiber identity is currently running on another device");
  }
  if (!backup || backup.status === "consumed") return { restoreRequired: false, canRebind: false };
  const rows = await sql<{ generation: string | number }[]>`
    update keyway_node_backups set
      status = 'claimed', claimed_device_id_hash = ${requestedDeviceIdHash},
      claim_expires_at = now() + interval '2 minutes', updated_at = now()
    where stytch_user_id = ${user.user_id}
      and generation = (
        select max(generation) from keyway_node_backups where stytch_user_id = ${user.user_id}
      )
      and (status = 'available' or (status = 'claimed' and claim_expires_at <= now()))
    returning generation
  `;
  if (!rows[0]) throw new Error("Fiber state migration is currently claimed by another device");
  return { restoreRequired: true, canRebind: true };
}

export async function readClaimedNodeBackup(user: User, deviceIdHash: string): Promise<StoredNodeBackup> {
  const backup = await readBackup(user);
  if (!backup || backup.status !== "claimed" || backup.claimedDeviceIdHash !== deviceIdHash) {
    throw new Error("No Fiber node backup is claimed by this device");
  }
  return backup;
}

export async function confirmNodeBackupRestored(user: User, deviceIdHash: string, generation: number): Promise<void> {
  const sql = await database();
  const rows = await sql<{ generation: string | number }[]>`
    update keyway_node_backups set status = 'consumed', claim_expires_at = null, updated_at = now()
    where stytch_user_id = ${user.user_id}
      and generation = ${generation}
      and status = 'claimed'
      and claimed_device_id_hash = ${deviceIdHash}
    returning generation
  `;
  if (!rows[0]) throw new Error("Fiber node backup claim is no longer valid");
}

async function consumeBackup(user: User, sql: DatabaseSql): Promise<void> {
  await sql`
    update keyway_node_backups set status = 'consumed', claim_expires_at = null, updated_at = now()
    where stytch_user_id = ${user.user_id}
      and generation = (
        select max(generation) from keyway_node_backups where stytch_user_id = ${user.user_id}
      )
  `;
}

// ponytail: newest N rows per user, by delete; move to partitioned storage if backups outgrow Postgres.
async function pruneNodeBackups(sql: DatabaseSql, userId: string): Promise<void> {
  const keep = Number(process.env.KEYWAY_BACKUP_GENERATIONS ?? 3);
  if (!Number.isInteger(keep) || keep < 1) return;
  await sql`
    delete from keyway_node_backups
    where stytch_user_id = ${userId}
      and status <> 'claimed'
      and generation not in (
        select generation from keyway_node_backups
        where stytch_user_id = ${userId}
        order by generation desc
        limit ${keep}
      )
  `;
}

async function readBackup(user: User, connection?: DatabaseSql): Promise<StoredNodeBackup | undefined> {
  const sql = connection ?? await database();
  const rows = await sql<BackupRow[]>`
    select generation, format_version, database_prefix, salt, iv, ciphertext, digest,
      source_device_id_hash, status, claimed_device_id_hash
    from keyway_node_backups where stytch_user_id = ${user.user_id}
    order by generation desc
    limit 1
  `;
  const row = rows[0];
  if (!row) return undefined;
  return {
    generation: Number(row.generation),
    formatVersion: row.format_version,
    databasePrefix: row.database_prefix,
    salt: row.salt,
    iv: row.iv,
    ciphertext: row.ciphertext.toString("base64"),
    digest: row.digest,
    sourceDeviceIdHash: row.source_device_id_hash,
    status: row.status,
    claimedDeviceIdHash: row.claimed_device_id_hash ?? undefined,
  };
}
