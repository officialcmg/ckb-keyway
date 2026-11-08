import type { ClaimedNodeBackup, NodeBackupPayload } from "./api-client";

export async function backUpBeforeLogout(options: {
  loadFiberKey: () => Promise<Uint8Array>;
  stopNode: () => Promise<void>;
  /** Fails while KeyWay's watchtower is still missing a channel update: the logout then stops, keeping the device. */
  flushWatchtower?: () => Promise<void>;
  createBackup: (fiberKey: Uint8Array) => Promise<NodeBackupPayload>;
  saveBackup: (backup: NodeBackupPayload) => Promise<{ digest: string }>;
  releaseOwnership: () => Promise<void>;
}): Promise<void> {
  const fiberKey = await options.loadFiberKey();
  try {
    await options.stopNode();
    await options.flushWatchtower?.();
    const backup = await options.createBackup(fiberKey);
    const saved = await options.saveBackup(backup);
    if (saved.digest !== backup.digest) throw new Error("Backend did not verify the Fiber node backup");
    await options.releaseOwnership();
  } finally {
    fiberKey.fill(0);
  }
}

/**
 * A logout with nothing to back up: no node holds the device here. A stop before it may have left channel updates
 * queued for KeyWay's watchtower, still being retried from this page; they must reach it before the session ends,
 * so until they do the logout fails.
 */
export async function stopBeforeLogout(options: {
  stop: () => Promise<void>;
  flushWatchtower: () => Promise<void>;
}): Promise<void> {
  await options.stop();
  await options.flushWatchtower();
}

/**
 * The nodes stopped during a session (Stop Fiber, a lost device lease, a restart). Each one's page keeps retrying
 * the channel updates KeyWay's watchtower is missing; a logout delivers them through it first and fails while any
 * is still missing, as it does for a running node.
 */
export function createStoppedNodes<T extends { stopForLogout(): Promise<void> }>() {
  const nodes = new Set<T>();
  return {
    add(node: T) {
      nodes.add(node);
    },
    async logout() {
      for (const node of [...nodes]) {
        await node.stopForLogout();
        nodes.delete(node);
      }
    },
  };
}

/**
 * Brings Fiber back after a failed logout; the user is still signed in. A node whose logout failed before it let go
 * of the device starts again on the same claim, and stays the connection even when it can't start, so the next
 * logout retries its delivery to KeyWay's watchtower and its backup before anything is released. A node that had
 * already let go (or a hosted one) is replaced by a fresh connection, as before.
 */
export async function recoverFailedLogout(
  node: { start(): Promise<unknown>; holdsDevice?: () => boolean },
  reconnect: () => Promise<unknown>,
  /** Runs before a node that held on to the device starts again (the provider lets its callbacks answer again). */
  onResume?: () => void,
): Promise<"resumed" | "reconnected"> {
  if (node.holdsDevice?.()) {
    onResume?.();
    await node.start().catch(() => undefined);
    return "resumed";
  }
  await reconnect().catch(() => undefined);
  return "reconnected";
}

export async function restoreBeforeStart(options: {
  loadFiberKey: () => Promise<Uint8Array>;
  loadBackup: () => Promise<ClaimedNodeBackup>;
  restoreBackup: (backup: ClaimedNodeBackup, fiberKey: Uint8Array) => Promise<void>;
  confirmRestore: (generation: number) => Promise<void>;
}): Promise<void> {
  const fiberKey = await options.loadFiberKey();
  try {
    const backup = await options.loadBackup();
    await options.restoreBackup(backup, fiberKey);
    await options.confirmRestore(backup.generation);
  } finally {
    fiberKey.fill(0);
  }
}
