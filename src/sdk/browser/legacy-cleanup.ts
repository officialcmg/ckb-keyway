export type LegacyCleanupManifest = { epoch: string; prefixes: string[] };

/** Only server-published, settlement-approved legacy prefixes are eligible. */
export async function cleanupLegacyDatabases(manifest: LegacyCleanupManifest, factory: IDBFactory = indexedDB): Promise<void> {
  if (!manifest.epoch || !Array.isArray(manifest.prefixes) || manifest.prefixes.some((prefix) => !/^\/wasm-0x[0-9a-f]{40}$/.test(prefix))) {
    throw new Error("Invalid legacy cleanup manifest");
  }
  if (typeof factory.databases !== "function") return;
  const databases = await factory.databases();
  for (const database of databases) {
    const name = database.name;
    if (!name || !manifest.prefixes.some((prefix) => name === prefix || name.startsWith(`${prefix}/`))) continue;
    await new Promise<void>((resolve, reject) => {
      const request = factory.deleteDatabase(name);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(new Error("Could not remove obsolete wallet database"));
      request.onblocked = () => reject(new Error("Close other KeyWay tabs to finish legacy cleanup"));
    });
  }
}
