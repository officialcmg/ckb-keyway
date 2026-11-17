import { restoreEncryptedNodeBackup, type EncryptedNodeBackup } from "./node-backup";

/**
 * A returning device still has its old channel databases. Restore a claimed backup into fresh databases and
 * switch the local pointer only after the whole import succeeds. Never overwrite or delete the old state.
 * Call only while holding the wallet's device lock and server lease, before starting Fiber or its watchtower.
 */
export function createNodeStorage(canonicalPrefix: string, storage: Pick<Storage, "getItem" | "setItem">) {
  const key = `ckb-keyway:node-storage:${canonicalPrefix}`;
  // Outside the canonical prefix, so exporting the original databases never includes retained restores.
  const restoredPrefix = `/keyway-restored-${encodeURIComponent(canonicalPrefix)}-`;
  function current(): string {
    const value = storage.getItem(key);
    if (value === null) return canonicalPrefix;
    if (!value.startsWith(restoredPrefix) || !/^[0-9a-f-]{36}$/.test(value.slice(restoredPrefix.length))) {
      throw new Error("The local Fiber storage pointer is invalid; refusing to start stale state");
    }
    return value;
  }
  return {
    current,
    async restore(backup: EncryptedNodeBackup, fiberKey: Uint8Array): Promise<string> {
      const target = `${restoredPrefix}${crypto.randomUUID()}`;
      await restoreEncryptedNodeBackup(backup, canonicalPrefix, fiberKey, target);
      // Persist before the server consumes the backup. A lost confirmation response can then safely retry;
      // an interrupted import leaves the previous pointer and all previous databases intact.
      storage.setItem(key, target);
      return target;
    },
  };
}
