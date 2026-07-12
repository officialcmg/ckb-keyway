import { getDeviceIdHash } from "./bootstrap";

export type DeviceLease = { leaseId: string; release: () => Promise<void> };

export async function acquireDeviceLease(sessionJwt: string): Promise<DeviceLease> {
  const deviceIdHash = await getDeviceIdHash();
  const lease = await requestLease(sessionJwt, { operation: "acquire", deviceIdHash });
  const heartbeat = window.setInterval(() => {
    void requestLease(sessionJwt, {
      operation: "heartbeat",
      deviceIdHash,
      leaseId: lease.leaseId,
    }).catch(() => undefined);
  }, 20_000);
  let released = false;

  return {
    leaseId: lease.leaseId,
    release: async () => {
      if (released) return;
      released = true;
      window.clearInterval(heartbeat);
      await requestLease(sessionJwt, { operation: "release", deviceIdHash, leaseId: lease.leaseId });
    },
  };
}

async function requestLease(
  sessionJwt: string,
  body: { operation: string; deviceIdHash: string; leaseId?: string },
): Promise<{ leaseId: string; expiresAt: string }> {
  const response = await fetch("/api/keyway/device-lease", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${sessionJwt}` },
    body: JSON.stringify(body),
  });
  if (response.status === 204) return { leaseId: body.leaseId ?? "", expiresAt: "" };
  const result = await response.json();
  if (!response.ok) throw new Error(result.error ?? "Device lease failed");
  return result;
}
