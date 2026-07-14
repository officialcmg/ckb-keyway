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
  | { needsFiberKey: false; provisioned: boolean; wallet: PublicWallet };

const DEVICE_STORAGE_KEY = "ckb-keyway:device-id";

export async function bootstrapKeyWay(
  authToken: string,
  api = new KeyWayApiClient(),
): Promise<{ provisioned: boolean; wallet: PublicWallet }> {
  if (!authToken) throw new Error("Authenticated KeyWay session is required");
  return navigator.locks.request("ckb-keyway:bootstrap", async () => {
    const deviceIdHash = await getDeviceIdHash();
    const existing = await requestBootstrap(api, authToken, { deviceIdHash });
    if (!existing.needsFiberKey) return existing;

    const fiberKey = crypto.getRandomValues(new Uint8Array(32));
    let encodedFiberKey = bytesToBase64(fiberKey);
    try {
      const provisioned = await requestBootstrap(api, authToken, { deviceIdHash, fiberKey: encodedFiberKey });
      if (provisioned.needsFiberKey) throw new Error("Fiber key provisioning did not complete");
      return provisioned;
    } finally {
      fiberKey.fill(0);
      encodedFiberKey = "";
    }
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

export async function loadFiberKey(
  authToken: string,
  leaseId: string,
  api = new KeyWayApiClient(),
): Promise<Uint8Array> {
  if (!authToken) throw new Error("Authenticated KeyWay session is required");
  const fiberKey = await api.loadFiberKey(authToken, { deviceIdHash: await getDeviceIdHash(), leaseId });
  if (fiberKey.length !== 32) {
    fiberKey.fill(0);
    throw new Error("Backend returned an invalid Fiber key");
  }
  return fiberKey;
}

export async function markChannelOpened(authToken: string, api = new KeyWayApiClient()): Promise<void> {
  await api.markChannelOpened(authToken, { deviceIdHash: await getDeviceIdHash() });
}

async function requestBootstrap(
  api: KeyWayApiClient,
  authToken: string,
  body: { deviceIdHash: string; fiberKey?: string },
): Promise<BootstrapResponse> {
  return await api.bootstrap(authToken, body) as BootstrapResponse;
}

function bytesToBase64(value: Uint8Array): string {
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary);
}
import { KeyWayApiClient } from "./api-client";
