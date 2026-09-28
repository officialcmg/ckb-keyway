import { decode, encode } from "cbor-x";

const BACKUP_FORMAT_VERSION = 1 as const;
const HKDF_INFO = new TextEncoder().encode("ckb-keyway:fiber-node-backup:v1");

type ArchiveIndex = {
  name: string;
  keyPath: string | string[] | null;
  unique: boolean;
  multiEntry: boolean;
};

type ArchiveStore = {
  name: string;
  keyPath: string | string[] | null;
  autoIncrement: boolean;
  indexes: ArchiveIndex[];
  records: Array<{ key: IDBValidKey; value: unknown }>;
};

type ArchiveDatabase = { name: string; version: number; stores: ArchiveStore[] };
type NodeArchive = { version: typeof BACKUP_FORMAT_VERSION; databases: ArchiveDatabase[] };

export type EncryptedNodeBackup = {
  formatVersion: typeof BACKUP_FORMAT_VERSION;
  databasePrefix: string;
  salt: string;
  iv: string;
  ciphertext: string;
  digest: string;
};

export async function createEncryptedNodeBackup(
  databasePrefix: string,
  fiberKey: Uint8Array,
): Promise<EncryptedNodeBackup> {
  const archive = await exportNodeDatabases(databasePrefix);
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveBackupKey(fiberKey, salt);
  const plaintext = encode(archive);
  try {
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: exactBuffer(iv) },
      key,
      exactBuffer(plaintext),
    ));
    return {
      formatVersion: BACKUP_FORMAT_VERSION,
      databasePrefix,
      salt: bytesToBase64(salt),
      iv: bytesToBase64(iv),
      ciphertext: bytesToBase64(ciphertext),
      digest: await sha256Hex(ciphertext),
    };
  } finally {
    plaintext.fill(0);
    salt.fill(0);
    iv.fill(0);
  }
}

export async function restoreEncryptedNodeBackup(
  backup: EncryptedNodeBackup,
  expectedPrefix: string,
  fiberKey: Uint8Array,
): Promise<void> {
  if (backup.formatVersion !== BACKUP_FORMAT_VERSION || backup.databasePrefix !== expectedPrefix) {
    throw new Error("Fiber node backup does not belong to this wallet");
  }
  const ciphertext = base64ToBytes(backup.ciphertext);
  if (await sha256Hex(ciphertext) !== backup.digest) throw new Error("Fiber node backup is corrupted");
  if ((await existingNodeDatabases(expectedPrefix)).length > 0) {
    throw new Error("This device already holds local Fiber state; refusing to overwrite it");
  }
  const salt = base64ToBytes(backup.salt);
  const iv = base64ToBytes(backup.iv);
  const key = await deriveBackupKey(fiberKey, salt);
  let plaintext: Uint8Array | undefined;
  try {
    plaintext = new Uint8Array(await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: exactBuffer(iv) },
      key,
      exactBuffer(ciphertext),
    ));
    const archive = decode(plaintext) as NodeArchive;
    validateArchive(archive, expectedPrefix);
    await importNodeDatabases(archive);
  } catch (error) {
    throw new Error("Could not decrypt or restore the Fiber node backup", { cause: error });
  } finally {
    ciphertext.fill(0);
    salt.fill(0);
    iv.fill(0);
    plaintext?.fill(0);
  }
}

export async function exportNodeDatabases(databasePrefix: string): Promise<NodeArchive> {
  if (!databasePrefix) throw new Error("Fiber database prefix is required");
  if (!indexedDB.databases) throw new Error("This browser cannot enumerate Fiber databases for backup");
  const databases = (await indexedDB.databases())
    .filter((database): database is IDBDatabaseInfo & { name: string } => Boolean(database.name?.startsWith(databasePrefix)));
  return {
    version: BACKUP_FORMAT_VERSION,
    databases: await Promise.all(databases.map(({ name }) => exportDatabase(name))),
  };
}

async function existingNodeDatabases(databasePrefix: string): Promise<string[]> {
  if (!indexedDB.databases) return [];
  return (await indexedDB.databases())
    .map(({ name }) => name)
    .filter((name): name is string => Boolean(name?.startsWith(databasePrefix)));
}

export async function importNodeDatabases(archive: NodeArchive): Promise<void> {
  validateArchive(archive, "");
  const existing = new Set((await indexedDB.databases()).map(({ name }) => name));
  if (archive.databases.some(({ name }) => existing.has(name))) {
    throw new Error("This device already holds local Fiber state; refusing to overwrite it");
  }
  const created: string[] = [];
  try {
    for (const database of archive.databases) {
      const opened = indexedDB.open(database.name, database.version);
      opened.onupgradeneeded = (event) => {
        if (event.oldVersion !== 0) {
          opened.transaction?.abort();
          return;
        }
        created.push(database.name);
        const target = opened.result;
        for (const store of database.stores) {
          const destination = target.createObjectStore(store.name, {
            keyPath: store.keyPath ?? undefined,
            autoIncrement: store.autoIncrement,
          });
          for (const index of store.indexes) {
            destination.createIndex(index.name, index.keyPath ?? "", {
              unique: index.unique,
              multiEntry: index.multiEntry,
            });
          }
        }
      };
      const target = await request(opened);
      try {
        if (!created.includes(database.name)) throw new Error("Fiber database appeared during restoration");
        for (const store of database.stores) {
          if (!store.records.length) continue;
          const transaction = target.transaction(store.name, "readwrite");
          const completed = transactionDone(transaction);
          const destination = transaction.objectStore(store.name);
          for (const record of store.records) {
            if (store.keyPath === null) destination.put(record.value, record.key);
            else destination.put(record.value);
          }
          await completed;
        }
      } finally {
        target.close();
      }
    }
  } catch (error) {
    // Only remove this attempt's new databases, never pre-existing wallet state.
    await Promise.all(created.map(deleteDatabase));
    throw error;
  }
}

async function exportDatabase(name: string): Promise<ArchiveDatabase> {
  const database = await request(indexedDB.open(name));
  try {
    const stores: ArchiveStore[] = [];
    for (const storeName of Array.from(database.objectStoreNames)) {
      const transaction = database.transaction(storeName, "readonly");
      const completed = transactionDone(transaction);
      const store = transaction.objectStore(storeName);
      const records = await readRecords(store);
      const indexes = Array.from(store.indexNames, (indexName) => {
        const index = store.index(indexName);
        return {
          name: index.name,
          keyPath: index.keyPath,
          unique: index.unique,
          multiEntry: index.multiEntry,
        };
      });
      await completed;
      stores.push({
        name: store.name,
        keyPath: store.keyPath,
        autoIncrement: store.autoIncrement,
        indexes,
        records,
      });
    }
    return { name, version: database.version, stores };
  } finally {
    database.close();
  }
}

function readRecords(store: IDBObjectStore): Promise<ArchiveStore["records"]> {
  return new Promise((resolve, reject) => {
    const records: ArchiveStore["records"] = [];
    const cursor = store.openCursor();
    cursor.onerror = () => reject(cursor.error ?? new Error("Could not read Fiber database"));
    cursor.onsuccess = () => {
      if (!cursor.result) return resolve(records);
      records.push({ key: cursor.result.key, value: cursor.result.value });
      cursor.result.continue();
    };
  });
}

function validateArchive(archive: NodeArchive, expectedPrefix: string): void {
  if (archive?.version !== BACKUP_FORMAT_VERSION || !Array.isArray(archive.databases)) {
    throw new Error("Fiber node backup format is invalid");
  }
  const uniqueNames = (items: Array<{ name: string }>) => {
    if (items.some((item) => !item || typeof item.name !== "string") ||
      new Set(items.map(({ name }) => name)).size !== items.length) {
      throw new Error("Fiber node backup contains invalid or duplicate names");
    }
  };
  const keyPathValid = (value: unknown) => value === null || typeof value === "string" ||
    (Array.isArray(value) && value.length > 0 && value.every((part) => typeof part === "string"));
  uniqueNames(archive.databases);
  for (const database of archive.databases) {
    if (!database.name.startsWith(expectedPrefix)) {
      throw new Error("Fiber node backup contains another wallet's database");
    }
    if (!database.name || !Number.isSafeInteger(database.version) || database.version < 1 ||
      !Array.isArray(database.stores)) throw new Error("Fiber node backup database schema is invalid");
    uniqueNames(database.stores);
    for (const store of database.stores) {
      if (!keyPathValid(store.keyPath) || typeof store.autoIncrement !== "boolean" ||
        !Array.isArray(store.indexes) || !Array.isArray(store.records) ||
        (store.autoIncrement && (store.keyPath === "" || Array.isArray(store.keyPath)))) {
        throw new Error("Fiber node backup store schema is invalid");
      }
      uniqueNames(store.indexes);
      for (const index of store.indexes) {
        if (index.keyPath === null || !keyPathValid(index.keyPath) ||
          typeof index.unique !== "boolean" || typeof index.multiEntry !== "boolean" ||
          (index.multiEntry && Array.isArray(index.keyPath))) {
          throw new Error("Fiber node backup index schema is invalid");
        }
      }
      for (const record of store.records) {
        if (!record || !Object.hasOwn(record, "value")) throw new Error("Fiber node backup record is invalid");
        indexedDB.cmp(record.key, record.key);
      }
    }
  }
}

async function deriveBackupKey(fiberKey: Uint8Array, salt: Uint8Array): Promise<CryptoKey> {
  if (fiberKey.length !== 32) throw new Error("Fiber key must be exactly 32 bytes");
  const material = await crypto.subtle.importKey("raw", exactBuffer(fiberKey), "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: exactBuffer(salt), info: exactBuffer(HKDF_INFO) },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

function deleteDatabase(name: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const deletion = indexedDB.deleteDatabase(name);
    deletion.onsuccess = () => resolve();
    deletion.onerror = () => reject(deletion.error ?? new Error("Could not replace Fiber database"));
    deletion.onblocked = () => reject(new Error("Fiber database is still open"));
  });
}

function request<T>(value: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    value.onsuccess = () => resolve(value.result);
    value.onerror = () => reject(value.error ?? new Error("IndexedDB request failed"));
  });
}

function transactionDone(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error ?? new Error("IndexedDB transaction failed"));
    transaction.onabort = () => reject(transaction.error ?? new Error("IndexedDB transaction was aborted"));
  });
}

async function sha256Hex(value: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", exactBuffer(value));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function bytesToBase64(value: Uint8Array): string {
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function exactBuffer(value: Uint8Array): ArrayBuffer {
  return value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength) as ArrayBuffer;
}
