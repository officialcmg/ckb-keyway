import type { User } from "stytch";
import { addPkpToGroup, createPkp, findGroupId } from "./chipotle";
import { loadLitAction } from "./lit-actions";
import { encryptFiberKey } from "./lit";
import { derivePkpIdentity } from "./pkp-identity";
import { readWallet, saveWallet, type KeyWayWallet, type ReadyWallet } from "./user-wallet";

const BASE64_KEY = /^[A-Za-z0-9+/]{43}=$/;
const DEVICE_ID_HASH = /^[0-9a-f]{64}$/;

export type BootstrapResult =
  | { needsFiberKey: true }
  | { needsFiberKey: false; provisioned: boolean; wallet: Omit<ReadyWallet, "encryptedFiberKey"> };

export async function bootstrap(user: User, deviceIdHash: string, encodedFiberKey?: string): Promise<BootstrapResult> {
  if (!DEVICE_ID_HASH.test(deviceIdHash)) throw new Error("Device ID hash must be 32-byte lowercase hex");
  let wallet = readWallet(user);
  if (wallet?.status === "ready") return publicResult(wallet, false);
  if (!wallet && !encodedFiberKey) return { needsFiberKey: true };
  if (encodedFiberKey && !BASE64_KEY.test(encodedFiberKey)) throw new Error("Fiber key must be base64-encoded 32 bytes");

  const apiKey = requiredEnv("LIT_USAGE_API_KEY");
  if (!wallet) {
    wallet = {
      version: 1,
      status: "provisioning",
      litPkpId: await createPkp(apiKey),
      primaryDeviceIdHash: deviceIdHash,
      createdAt: new Date().toISOString(),
    };
    await saveWallet(user, wallet);
  }

  if (wallet.primaryDeviceIdHash !== deviceIdHash) throw new Error("Fiber wallet is bound to another device");
  if (!encodedFiberKey) return { needsFiberKey: true };

  await addPkpToGroup(apiKey, await findGroupId(apiKey, "CKB Keyway"), wallet.litPkpId);
  const signing = { apiKey, actionCid: requiredEnv("LIT_SIGN_ACTION_CID") };
  const identity = await derivePkpIdentity(wallet.litPkpId, signing);
  const fiberKey = new Uint8Array(Buffer.from(encodedFiberKey, "base64"));
  try {
    const encryptedFiberKey = await encryptFiberKey(fiberKey, wallet.litPkpId, {
      apiKey,
      actionCid: requiredEnv("LIT_ENCRYPT_ACTION_CID"),
      actionCode: await loadLitAction("encrypt-fiber-key"),
    });
    const now = new Date().toISOString();
    const ready: ReadyWallet = {
      ...wallet,
      status: "ready",
      litPublicKey: identity.publicKey,
      ckbAddress: identity.ckbAddress,
      encryptedFiberKey,
      hasOpenedChannel: false,
      updatedAt: now,
    };
    await saveWallet(user, ready);
    return publicResult(ready, true);
  } finally {
    fiberKey.fill(0);
  }
}

function publicResult(wallet: ReadyWallet, provisioned: boolean): BootstrapResult {
  const { encryptedFiberKey: _encrypted, ...publicWallet } = wallet;
  return { needsFiberKey: false, provisioned, wallet: publicWallet };
}

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Missing server configuration: ${name}`);
  return value;
}
