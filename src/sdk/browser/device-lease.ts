import { getDeviceIdHash } from "./bootstrap";
import { KeyWayApiClient } from "./api-client";

export type DeviceLease = { leaseId: string; release: () => Promise<void> };

export async function acquireDeviceLease(
  authToken: string,
  api = new KeyWayApiClient(),
  onLost?: (error: unknown) => void,
): Promise<DeviceLease> {
  const deviceIdHash = await getDeviceIdHash();
  const lease = await api.requestLease(authToken, { operation: "acquire", deviceIdHash });
  let released = false;
  const heartbeat = window.setInterval(() => {
    void api.requestLease(authToken, {
      operation: "heartbeat",
      deviceIdHash,
      leaseId: lease.leaseId,
    }).catch((error) => {
      if (released) return;
      released = true;
      window.clearInterval(heartbeat);
      onLost?.(error);
    });
  }, 20_000);

  return {
    leaseId: lease.leaseId,
    release: async () => {
      if (released) return;
      released = true;
      window.clearInterval(heartbeat);
      await api.requestLease(authToken, { operation: "release", deviceIdHash, leaseId: lease.leaseId });
    },
  };
}
