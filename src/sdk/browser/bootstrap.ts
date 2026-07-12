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

export async function bootstrapKeyWay(sessionJwt: string): Promise<{ provisioned: boolean; wallet: PublicWallet }> {
  if (!sessionJwt) throw new Error("Authenticated Stytch session is required");
  return navigator.locks.request("ckb-keyway:bootstrap", async () => {
    const deviceIdHash = await getDeviceIdHash();
    const existing = await requestBootstrap(sessionJwt, { deviceIdHash });
    if (!existing.needsFiberKey) return existing;

    const fiberKey = crypto.getRandomValues(new Uint8Array(32));
    let encodedFiberKey = bytesToBase64(fiberKey);
    try {
      const provisioned = await requestBootstrap(sessionJwt, { deviceIdHash, fiberKey: encodedFiberKey });
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

export async function loadFiberKey(sessionJwt: string, leaseId: string): Promise<Uint8Array> {
  if (!sessionJwt) throw new Error("Authenticated Stytch session is required");
  const response = await fetch("/api/keyway/fiber-key", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${sessionJwt}` },
    body: JSON.stringify({ deviceIdHash: await getDeviceIdHash(), leaseId }),
  });
  if (!response.ok) {
    const result = await response.json().catch(() => ({}));
    throw new Error(result.error ?? "Could not unlock Fiber credentials");
  }
  const fiberKey = new Uint8Array(await response.arrayBuffer());
  if (fiberKey.length !== 32) {
    fiberKey.fill(0);
    throw new Error("Backend returned an invalid Fiber key");
  }
  return fiberKey;
}

async function requestBootstrap(
  sessionJwt: string,
  body: { deviceIdHash: string; fiberKey?: string },
): Promise<BootstrapResponse> {
  const response = await fetch("/api/keyway/bootstrap", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${sessionJwt}` },
    body: JSON.stringify(body),
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error ?? "KeyWay bootstrap failed");
  return result as BootstrapResponse;
}

function bytesToBase64(value: Uint8Array): string {
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary);
}
