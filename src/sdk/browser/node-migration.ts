import type { ClaimedNodeBackup, NodeBackupPayload } from "./api-client";

export async function backUpBeforeLogout(options: {
  loadFiberKey: () => Promise<Uint8Array>;
  stopNode: () => Promise<void>;
  createBackup: (fiberKey: Uint8Array) => Promise<NodeBackupPayload>;
  saveBackup: (backup: NodeBackupPayload) => Promise<{ digest: string }>;
  releaseOwnership: () => Promise<void>;
}): Promise<void> {
  const fiberKey = await options.loadFiberKey();
  try {
    await options.stopNode();
    const backup = await options.createBackup(fiberKey);
    const saved = await options.saveBackup(backup);
    if (saved.digest !== backup.digest) throw new Error("Backend did not verify the Fiber node backup");
    await options.releaseOwnership();
  } finally {
    fiberKey.fill(0);
  }
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
