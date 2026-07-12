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
