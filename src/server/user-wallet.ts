import type { User } from "stytch";
import { database, withUserLock, type DatabaseSql } from "./database.ts";

export type ProvisioningWallet = {
  version: 1;
  status: "provisioning";
  litPkpId: string;
  primaryDeviceIdHash: string;
  createdAt: string;
};

export type ReadyWallet = Omit<ProvisioningWallet, "status"> & {
  status: "ready";
  litPublicKey: string;
  ckbAddress: string;
  encryptedFiberKey: string;
  hasOpenedChannel: boolean;
  updatedAt: string;
};

export type KeyWayWallet = ProvisioningWallet | ReadyWallet;

export function parseWallet(value: unknown): KeyWayWallet | undefined {
  if (!value || typeof value !== "object") return undefined;
  const candidate = value as Partial<KeyWayWallet>;
  if (candidate.version !== 1 || (candidate.status !== "provisioning" && candidate.status !== "ready")) return undefined;
  if (typeof candidate.litPkpId !== "string" || typeof candidate.primaryDeviceIdHash !== "string") return undefined;
  if (candidate.status === "ready" && (
    typeof candidate.litPublicKey !== "string" ||
    typeof candidate.ckbAddress !== "string" ||
    typeof candidate.encryptedFiberKey !== "string"
  )) return undefined;
  return candidate as KeyWayWallet;
}

export async function readWallet(user: User, connection?: DatabaseSql): Promise<KeyWayWallet | undefined> {
  const sql = connection ?? await database();
  const [row] = await sql<{ wallet: unknown }[]>`
    select wallet from keyway_wallets where stytch_user_id = ${user.user_id}
  `;
  const stored = parseWallet(row?.wallet);
  if (stored) return stored;

  // Import wallets created before Postgres became the authoritative store.
  const legacy = parseWallet(user.trusted_metadata?.keyway);
  if (legacy) await saveWallet(user, legacy, sql);
  return legacy;
}

export async function saveWallet(user: User, wallet: KeyWayWallet, connection?: DatabaseSql): Promise<void> {
  const sql = connection ?? await database();
  await sql`
    insert into keyway_wallets (stytch_user_id, wallet)
    values (${user.user_id}, ${sql.json(wallet)})
    on conflict (stytch_user_id) do update
      set wallet = excluded.wallet, updated_at = now()
  `;
}

export function rebindReadyWallet(
  wallet: ReadyWallet,
  deviceIdHash: string,
  activeLeaseDeviceIdHash?: string,
): ReadyWallet {
  if (wallet.primaryDeviceIdHash === deviceIdHash) return wallet;
  if (wallet.hasOpenedChannel) {
    throw new Error("CHANNEL_STATE_DEVICE_BOUND: transfer the Fiber channel database before using another device");
  }
  if (activeLeaseDeviceIdHash && activeLeaseDeviceIdHash !== deviceIdHash) {
    throw new Error("Fiber identity is currently running on another device");
  }
  return { ...wallet, primaryDeviceIdHash: deviceIdHash, updatedAt: new Date().toISOString() };
}

export function rebindProvisioningWallet(
  wallet: ProvisioningWallet,
  deviceIdHash: string,
  activeLeaseDeviceIdHash?: string,
): ProvisioningWallet {
  if (wallet.primaryDeviceIdHash === deviceIdHash) return wallet;
  if (activeLeaseDeviceIdHash && activeLeaseDeviceIdHash !== deviceIdHash) {
    throw new Error("Fiber identity is currently running on another device");
  }
  return { ...wallet, primaryDeviceIdHash: deviceIdHash };
}

export async function markChannelOpened(user: User, deviceIdHash: string): Promise<ReadyWallet> {
  return withUserLock(user.user_id, async (sql) => {
    const wallet = await readWallet(user, sql);
    if (!wallet || wallet.status !== "ready") throw new Error("KeyWay wallet is not provisioned");
    if (wallet.primaryDeviceIdHash !== deviceIdHash) throw new Error("Fiber wallet is bound to another device");
    const updated = { ...wallet, hasOpenedChannel: true, updatedAt: new Date().toISOString() };
    await saveWallet(user, updated, sql);
    return updated;
  });
}
