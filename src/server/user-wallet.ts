import { parseRecovery, type KeyWayRecovery } from "../sdk/browser/account-lock.ts";
import type { User } from "./auth-user.ts";
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
  /** The account's current address: the Omnilock one once recovery is on, else the secp256k1 one. */
  ckbAddress: string;
  encryptedFiberKey: string;
  hasOpenedChannel: boolean;
  updatedAt: string;
  /** Set once the user turns account recovery on; `legacyAddress` then holds the old secp256k1 address. */
  recovery?: KeyWayRecovery;
  /** A recovery change that was sent and isn't committed yet; it takes effect once it is. */
  recoveryPending?: PendingRecoveryChange;
};

export type PendingRecoveryChange = {
  kind: "enable" | "add" | "remove";
  transactionHash: string;
  /** The settings once the transaction commits. */
  recovery: KeyWayRecovery;
  /** The account's address once the transaction commits. */
  ckbAddress: string;
  sentAt: string;
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
  // Malformed recovery settings throw rather than read as no wallet, which would provision a new one.
  if (candidate.status === "ready") {
    parseRecovery(candidate.recovery, candidate.litPublicKey as string);
    const pending = candidate.recoveryPending;
    if (pending !== undefined && (
      !pending || !["enable", "add", "remove"].includes(pending.kind) || typeof pending.transactionHash !== "string" ||
      typeof pending.ckbAddress !== "string" || typeof pending.sentAt !== "string" || !parseRecovery(pending.recovery, candidate.litPublicKey as string)
    )) throw new Error("KeyWay account recovery settings are invalid");
  }
  return candidate as KeyWayWallet;
}

export async function readWallet(user: User, connection?: DatabaseSql): Promise<KeyWayWallet | undefined> {
  const sql = connection ?? await database();
  const [row] = await sql<{ wallet: unknown }[]>`
    select wallet from keyway_v2_wallets where user_id = ${user.id}
  `;
  return parseWallet(row?.wallet);
}

export async function saveWallet(user: User, wallet: KeyWayWallet, connection?: DatabaseSql): Promise<void> {
  const sql = connection ?? await database();
  await sql`
    insert into keyway_v2_wallets (user_id, wallet)
    values (${user.id}, ${sql.json(wallet)})
    on conflict (user_id) do update
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
  return withUserLock(user.id, async (sql) => {
    const wallet = await readWallet(user, sql);
    if (!wallet || wallet.status !== "ready") throw new Error("KeyWay wallet is not provisioned");
    if (wallet.primaryDeviceIdHash !== deviceIdHash) throw new Error("Fiber wallet is bound to another device");
    const updated = { ...wallet, hasOpenedChannel: true, updatedAt: new Date().toISOString() };
    await saveWallet(user, updated, sql);
    return updated;
  });
}
