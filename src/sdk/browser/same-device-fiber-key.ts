const DATABASE = "ckb-keyway";
const STORE = "fiber-credentials";

type StoredCredential = {
  wrappingKey: CryptoKey;
  iv: Uint8Array<ArrayBuffer>;
  ciphertext: ArrayBuffer;
};

export async function loadSameDeviceFiberKey(identifier: string): Promise<Uint8Array> {
  if (!identifier) throw new Error("Credential identifier is required");
  const database = await openDatabase();

  try {
    const stored = await readCredential(database, identifier);
    if (stored) return decryptFiberKey(stored);

    const fiberKey = crypto.getRandomValues(new Uint8Array(32));
    const credential = await encryptFiberKey(fiberKey);
    await writeCredential(database, identifier, credential);
    return fiberKey;
  } finally {
    database.close();
  }
}

export async function encryptFiberKey(fiberKey: Uint8Array): Promise<StoredCredential> {
  if (fiberKey.length !== 32) throw new Error("Fiber key must be exactly 32 bytes");
  const wrappingKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);
  const plaintext = new Uint8Array(32);
  plaintext.set(fiberKey);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, wrappingKey, plaintext);
  return { wrappingKey, iv, ciphertext };
}

export async function decryptFiberKey(credential: StoredCredential): Promise<Uint8Array> {
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: credential.iv },
    credential.wrappingKey,
    credential.ciphertext,
  );
  const fiberKey = new Uint8Array(plaintext);
  if (fiberKey.length !== 32) throw new Error("Stored Fiber key is invalid");
  return fiberKey;
}

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(STORE);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("Could not open credential storage"));
  });
}

function readCredential(database: IDBDatabase, identifier: string): Promise<StoredCredential | undefined> {
  return new Promise((resolve, reject) => {
    const request = database.transaction(STORE).objectStore(STORE).get(identifier);
    request.onsuccess = () => resolve(request.result as StoredCredential | undefined);
    request.onerror = () => reject(request.error ?? new Error("Could not read Fiber credential"));
  });
}

function writeCredential(database: IDBDatabase, identifier: string, credential: StoredCredential): Promise<void> {
  return new Promise((resolve, reject) => {
    const transaction = database.transaction(STORE, "readwrite");
    transaction.objectStore(STORE).add(credential, identifier);
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error ?? new Error("Could not store Fiber credential"));
  });
}
