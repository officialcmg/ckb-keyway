import type { WatchtowerCall } from "./watchtower-bridge";

/** Fiber's settlement data in its JSON-RPC form (fiber-json-types watchtower.rs): amounts are hex u128. */
export type SettlementTlcJson = {
  tlc_id: { Offered: string } | { Received: string };
  hash_algorithm: string;
  payment_amount: string;
  payment_hash: string;
  expiry: string;
  local_key: string;
  remote_key: string;
};
export type SettlementDataJson = { local_amount: string; remote_amount: string; tlcs: SettlementTlcJson[] };

/** What the in-page watchtower knows about one channel. */
export type WatchedChannel = {
  channelId: string;
  /** Absent in snapshots from legacy channels; V2 uses full 32-byte payment hashes. */
  channelFeatures?: 0 | 1;
  fundingUdtTypeScript: unknown | null;
  /** The channel's settlement private key from Fiber; it signs the claim of the user's share. */
  localSettlementKey: string;
  remoteSettlementKey: string;
  localFundingPubkey: string;
  remoteFundingPubkey: string;
  /** Settlement data for the node's own latest commitment (what a force close by this node puts on-chain). */
  localSettlement: SettlementDataJson;
  /** Settlement data for the peer's commitments: the latest acknowledged one and the one awaiting it. */
  remoteSettlement?: SettlementDataJson;
  pendingRemoteSettlement?: SettlementDataJson;
  revocation?: unknown;
  createdAt: number;
  updatedAt: number;
};

export type WatchtowerStore = {
  apply(call: WatchtowerCall): Promise<void>;
  list(): Promise<WatchedChannel[]>;
  get(channelId: string): Promise<WatchedChannel | undefined>;
  remove(channelId: string): Promise<void>;
  /**
   * Puts back a record that was removed when its channel was found finished (channel-closures.ts keeps a copy),
   * unless the node has handed the channel over again meanwhile: a record already there is left as it is.
   */
  restore(channel: WatchedChannel): Promise<void>;
  /** The preimage the node handed over for a payment hash (`create_preimage`), if it still has one. */
  preimage(paymentHash: string): Promise<string | undefined>;
  close(): void;
};

const STORE = "channels";
const PREIMAGES = "preimages";

function request<T>(req: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

/** Fiber sends hashes with a 0x prefix and keys without one; both are stored 0x-prefixed. */
function hexBytes(value: unknown, length: number, name: string): string {
  const text = typeof value === "string" ? value.replace(/^0x/i, "") : "";
  if (!new RegExp(`^[0-9a-fA-F]{${length * 2}}$`).test(text)) throw new Error(`Invalid ${name} in watchtower data`);
  return `0x${text.toLowerCase()}`;
}
const hex32 = (value: unknown, name: string) => hexBytes(value, 32, name);
const pubkey = (value: unknown, name: string) => hexBytes(value, 33, name);
function settlement(value: unknown): SettlementDataJson {
  const data = value as SettlementDataJson | undefined;
  if (!data || typeof data.local_amount !== "string" || typeof data.remote_amount !== "string" || !Array.isArray(data.tlcs)) {
    throw new Error("Invalid settlement data in watchtower data");
  }
  return { local_amount: data.local_amount, remote_amount: data.remote_amount, tlcs: data.tlcs };
}

/** Applies one watchtower call to a channel record, as fiber-lib's watchtower store does. Pure, for testing. */
export function applyWatchtowerCall(existing: WatchedChannel | undefined, call: WatchtowerCall, now = Date.now()): WatchedChannel | undefined | "remove" {
  const p = call.params;
  switch (call.method) {
    case "create_watch_channel":
      return {
        ...existing,
        channelId: hex32(p.channel_id, "channel id"),
        // A repeated create that leaves the features out must not turn a stored V2 channel back into a legacy one.
        channelFeatures: p.channel_features === undefined ? (existing?.channelFeatures ?? 0) : parseChannelFeatures(p.channel_features),
        fundingUdtTypeScript: p.funding_udt_type_script ?? null,
        localSettlementKey: hex32(p.local_settlement_key, "settlement key"),
        remoteSettlementKey: pubkey(p.remote_settlement_key, "remote settlement key"),
        localFundingPubkey: pubkey(p.local_funding_pubkey, "local funding key"),
        remoteFundingPubkey: pubkey(p.remote_funding_pubkey, "remote funding key"),
        // Fiber registers a channel again at every start, with the settlement it was funded with. As in Fiber's
        // own store (insert_watch_channel_with_features: "never reset an already monitored channel's usable
        // settlement/revocation snapshots"), that must not put the first settlement back in place of the latest:
        // a pass that read it would not recognise the payments in flight on the commitment as the user's.
        // What a repeated create carries is still checked, and refused if malformed.
        localSettlement: ((fresh) => existing?.localSettlement ?? fresh)(settlement(p.settlement_data)),
        createdAt: existing?.createdAt ?? now,
        updatedAt: now,
      };
    case "remove_watch_channel":
      return "remove";
    case "update_local_settlement":
      return existing && { ...existing, localSettlement: settlement(p.settlement_data), updatedAt: now };
    case "update_revocation":
      return existing && { ...existing, revocation: p.revocation_data, remoteSettlement: settlement(p.settlement_data), updatedAt: now };
    case "update_pending_remote_settlement":
      return existing && { ...existing, pendingRemoteSettlement: settlement(p.settlement_data), updatedAt: now };
    default:
      return existing;
  }
}

function parseChannelFeatures(value: unknown): 0 | 1 {
  if (value === undefined || value === "0x0") return 0;
  if (value === "0x1") return 1;
  throw new Error("Unsupported channel features in watchtower data");
}

/**
 * The in-page watchtower's data, in an IndexedDB database next to the node's own (its name starts with the
 * node's database prefix, so the encrypted node backup carries it to a new device with the channels).
 */
export function openWatchtowerStore(databasePrefix: string): WatchtowerStore {
  let opened: Promise<IDBDatabase> | undefined;
  const db = () => {
    if (opened) return opened;
    const opening: Promise<IDBDatabase> = new Promise((resolve, reject) => {
      const req = indexedDB.open(`${databasePrefix}-keyway-watchtower`, 1);
      req.onupgradeneeded = () => {
        req.result.createObjectStore(STORE, { keyPath: "channelId" });
        req.result.createObjectStore(PREIMAGES, { keyPath: "paymentHash" });
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    // A failed open is retried by the next call (unless a newer open has replaced it).
    opening.catch(() => { if (opened === opening) opened = undefined; });
    return opened = opening;
  };
  async function get(channelId: string) {
    const tx = (await db()).transaction(STORE, "readonly");
    return await request(tx.objectStore(STORE).get(channelId.toLowerCase())) as WatchedChannel | undefined;
  }
  return {
    async apply(call) {
      if (call.method === "create_preimage" || call.method === "remove_preimage") {
        const paymentHash = hex32(call.params.payment_hash, "payment hash");
        const tx = (await db()).transaction(PREIMAGES, "readwrite");
        const store = tx.objectStore(PREIMAGES);
        if (call.method === "create_preimage") store.put({ paymentHash, preimage: hex32(call.params.preimage, "preimage") });
        else store.delete(paymentHash);
        await new Promise<void>((resolve, reject) => { tx.oncomplete = () => resolve(); tx.onerror = () => reject(tx.error); });
        return;
      }
      const channelId = hex32(call.params.channel_id, "channel id");
      const existing = await get(channelId);
      const next = applyWatchtowerCall(existing, call);
      const tx = (await db()).transaction(STORE, "readwrite");
      if (next === "remove") tx.objectStore(STORE).delete(channelId);
      else if (next) tx.objectStore(STORE).put(next);
      else console.warn(`[keyway] watchtower ${call.method} for unknown channel ${channelId}`);
      await new Promise<void>((resolve, reject) => { tx.oncomplete = () => resolve(); tx.onerror = () => reject(tx.error); });
    },
    async list() {
      const tx = (await db()).transaction(STORE, "readonly");
      return await request(tx.objectStore(STORE).getAll()) as WatchedChannel[];
    },
    get,
    async remove(channelId) {
      const tx = (await db()).transaction(STORE, "readwrite");
      tx.objectStore(STORE).delete(channelId.toLowerCase());
      await new Promise<void>((resolve, reject) => { tx.oncomplete = () => resolve(); tx.onerror = () => reject(tx.error); });
    },
    async restore(channel) {
      const tx = (await db()).transaction(STORE, "readwrite");
      // `add`, not `put`: it fails for a key that is already there, and that failure is the answer wanted.
      const adding = tx.objectStore(STORE).add({ ...channel, channelId: channel.channelId.toLowerCase() });
      adding.onerror = (event) => { event.preventDefault(); event.stopPropagation(); };
      await new Promise<void>((resolve, reject) => { tx.oncomplete = () => resolve(); tx.onerror = () => reject(tx.error); tx.onabort = () => reject(tx.error); });
    },
    async preimage(paymentHash) {
      const tx = (await db()).transaction(PREIMAGES, "readonly");
      const found = await request(tx.objectStore(PREIMAGES).get(hex32(paymentHash, "payment hash"))) as { preimage: string } | undefined;
      return found?.preimage;
    },
    close() {
      void opened?.then((database) => database.close(), () => undefined);
      opened = undefined;
    },
  };
}
