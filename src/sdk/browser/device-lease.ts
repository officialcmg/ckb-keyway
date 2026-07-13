import { getDeviceIdHash } from "./bootstrap";
import { KeyWayApiClient } from "./api-client";

export type DeviceLease = { leaseId: string; release: () => Promise<void> };

export async function acquireDeviceLease(sessionJwt: string, api = new KeyWayApiClient()): Promise<DeviceLease> {
  const deviceIdHash = await getDeviceIdHash();
  const lease = await api.requestLease(sessionJwt, { operation: "acquire", deviceIdHash });
  const heartbeat = window.setInterval(() => {
    void api.requestLease(sessionJwt, {
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
      await api.requestLease(sessionJwt, { operation: "release", deviceIdHash, leaseId: lease.leaseId });
    },
  };
}
