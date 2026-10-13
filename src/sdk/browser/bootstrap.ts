import { KeyWayApiClient } from "./api-client";
import { createFiberKeyRecipient } from "./fiber-key-wrap";

export type PublicWallet = {
  version: 1;
  status: "ready";
  litPkpId: string;
  litPublicKey: string;
  ckbAddress: string;
  primaryDeviceIdHash: string;
  hasOpenedChannel: boolean;
  createdAt: string;
  updatedAt: string;
};

type BootstrapResponse =
  | { needsFiberKey: true }
  | { needsFiberKey: false; provisioned: boolean; restoreRequired: boolean; wallet: PublicWallet };

const DEVICE_STORAGE_KEY = "ckb-keyway:device-id";

export async function bootstrapKeyWay(
  authToken: string,
  api = new KeyWayApiClient(),
  nodeMode: "browser" | "managed" = "browser",
): Promise<{ provisioned: boolean; restoreRequired: boolean; wallet: PublicWallet }> {
  if (!authToken) throw new Error("Authenticated KeyWay session is required");
  return navigator.locks.request("ckb-keyway:bootstrap", async () => {
    const deviceIdHash = await getDeviceIdHash();
    // Lit creates the Fiber key inside its secure enclave; neither this browser nor KeyWay's server sends one.
    const result = await requestBootstrap(api, authToken, { deviceIdHash, nodeMode, keyCustody: "lit" });
    if (result.needsFiberKey) throw new Error("KeyWay couldn't create this account's Fiber key");
    return result;
  });
}

export async function getDeviceIdHash(): Promise<string> {
  let deviceId = localStorage.getItem(DEVICE_STORAGE_KEY);
  if (!deviceId) {
    deviceId = bytesToBase64(crypto.getRandomValues(new Uint8Array(32)));
    localStorage.setItem(DEVICE_STORAGE_KEY, deviceId);
  }
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(deviceId));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/**
 * Unlocks the Fiber key for this device's lease. Lit seals it to a one-time key made here, so KeyWay's
 * server only relays ciphertext; the bundle opens only for this wallet, this device and this request.
 */
export async function loadFiberKey(
  authToken: string,
  leaseId: string,
  pkpId: string,
  api = new KeyWayApiClient(),
): Promise<Uint8Array> {
  if (!authToken) throw new Error("Authenticated KeyWay session is required");
  const deviceIdHash = await getDeviceIdHash();
  const recipient = await createFiberKeyRecipient();
  const bundle = await api.loadFiberKey(authToken, { deviceIdHash, leaseId, recipientPublicKey: recipient.publicKey });
  return recipient.unwrap(bundle, { pkpId, deviceIdHash });
}

export async function markChannelOpened(authToken: string, api = new KeyWayApiClient()): Promise<void> {
  await api.markChannelOpened(authToken, { deviceIdHash: await getDeviceIdHash() });
}

async function requestBootstrap(
  api: KeyWayApiClient,
  authToken: string,
  body: { deviceIdHash: string; nodeMode?: "browser" | "managed"; keyCustody: "lit" },
): Promise<BootstrapResponse> {
  return await api.bootstrap(authToken, body) as BootstrapResponse;
}

function bytesToBase64(value: Uint8Array): string {
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary);
}
