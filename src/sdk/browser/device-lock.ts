export type DeviceLock = { release: () => Promise<void> };

export async function acquireDeviceLock(identifier: string): Promise<DeviceLock> {
  if (!identifier) throw new Error("Fiber identity is required for device locking");
  let releaseHold: (() => void) | undefined;
  let resolveAcquired: ((acquired: boolean) => void) | undefined;
  const acquired = new Promise<boolean>((resolve) => { resolveAcquired = resolve; });
  const hold = new Promise<void>((resolve) => { releaseHold = resolve; });
  const name = `ckb-keyway:fiber:${identifier}`;
  const channel = new BroadcastChannel(name);

  const lockRequest = navigator.locks.request(name, { ifAvailable: true }, async (lock) => {
    resolveAcquired?.(Boolean(lock));
    if (!lock) return;
    channel.postMessage({ state: "running" });
    await hold;
  });

  if (!await acquired) {
    channel.close();
    await lockRequest;
    throw new Error("This Fiber identity is already running in another tab");
  }

  let released = false;
  return {
    release: async () => {
      if (released) return;
      released = true;
      channel.postMessage({ state: "stopped" });
      releaseHold?.();
      await lockRequest;
      channel.close();
    },
  };
}
