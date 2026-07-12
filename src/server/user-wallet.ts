import type { User } from "stytch";
import { updateTrustedMetadata } from "./stytch.ts";

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

export function readWallet(user: User): KeyWayWallet | undefined {
  const value = user.trusted_metadata?.keyway;
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

export async function saveWallet(user: User, wallet: KeyWayWallet): Promise<void> {
  await updateTrustedMetadata(user.user_id, { ...(user.trusted_metadata ?? {}), keyway: wallet });
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
  const wallet = readWallet(user);
  if (!wallet || wallet.status !== "ready") throw new Error("KeyWay wallet is not provisioned");
  if (wallet.primaryDeviceIdHash !== deviceIdHash) throw new Error("Fiber wallet is bound to another device");
  const updated = { ...wallet, hasOpenedChannel: true, updatedAt: new Date().toISOString() };
  await saveWallet(user, updated);
  return updated;
}
