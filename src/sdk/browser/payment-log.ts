/**
 * Fiber's browser build has no `list_payments`, so the SDK remembers the payments it sends. The log sits
 * next to the node's own databases (same name prefix), so encrypted node backups carry it between devices.
 */
const STORE = "payments";

type Entry = { payment_hash: string; sent_at: number };

export function createPaymentLog(databasePrefix: string) {
  const name = `${databasePrefix}-keyway-payments`;

  function open(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(name, 1);
      request.onupgradeneeded = () => request.result.createObjectStore(STORE, { keyPath: "payment_hash" });
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error ?? new Error("Could not open the payment log"));
    });
  }

  async function record(paymentHash: string): Promise<void> {
    const database = await open();
    try {
      await new Promise<void>((resolve, reject) => {
        const transaction = database.transaction(STORE, "readwrite");
        const store = transaction.objectStore(STORE);
        const existing = store.get(paymentHash);
        existing.onsuccess = () => {
          if (!existing.result) store.put({ payment_hash: paymentHash, sent_at: Date.now() } satisfies Entry);
        };
        transaction.oncomplete = () => resolve();
        transaction.onerror = () => reject(transaction.error ?? new Error("Could not record the payment"));
      });
    } finally {
      database.close();
    }
  }

  /** Payment hashes, newest first. */
  async function hashes(): Promise<string[]> {
    const database = await open();
    try {
      const entries = await new Promise<Entry[]>((resolve, reject) => {
        const request = database.transaction(STORE, "readonly").objectStore(STORE).getAll();
        request.onsuccess = () => resolve(request.result as Entry[]);
        request.onerror = () => reject(request.error ?? new Error("Could not read the payment log"));
      });
      return entries.sort((a, b) => b.sent_at - a.sent_at).map((entry) => entry.payment_hash);
    } finally {
      database.close();
    }
  }

  return { record, hashes };
}

export type PaymentLog = ReturnType<typeof createPaymentLog>;
