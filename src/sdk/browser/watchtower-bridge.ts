/**
 * Fiber 0.9.1's browser build has no watchtower of its own: `fiber-wasm` compiles fiber-lib without its
 * `watchtower` feature and never starts a WatchtowerActor (crates/fiber-wasm/src/lib.rs), so nothing claims a
 * force-closed channel's funds. What the browser build does do is send every watchtower event (new channel,
 * revocation, latest settlement data) to a standalone watchtower over JSON-RPC, when its config names one with
 * `standalone_watchtower_rpc_url`.
 *
 * KeyWay keeps those events in the browser instead of sending them anywhere: the node's config names an address
 * that never leaves the page, and a small shim inside Fiber's worker answers the WebSocket for that address and
 * hands each call to the page over a BroadcastChannel. The page stores the data (see watchtower-store.ts) and
 * claims the user's share itself once the commitment's delay has passed (see watchtower-settle.ts).
 */

/** The watchtower address the node is given. `.invalid` can never resolve, so nothing is sent off the device. */
export const WATCHTOWER_URL = "ws://keyway-watchtower.invalid/";

/** The JSON-RPC methods Fiber's event handler calls on a standalone watchtower (fiber-lib event_handler.rs). */
export const WATCHTOWER_METHODS = [
  "create_watch_channel",
  "remove_watch_channel",
  "update_revocation",
  "update_pending_remote_settlement",
  "update_local_settlement",
  "create_preimage",
  "remove_preimage",
] as const;
export type WatchtowerMethod = typeof WATCHTOWER_METHODS[number];
export type WatchtowerCall = { method: WatchtowerMethod; params: Record<string, unknown> };

/** Adds the in-page watchtower to the node's YAML config (under `fiber:`). */
export function withWatchtower(config: string, url = WATCHTOWER_URL): string {
  if (/^\s+standalone_watchtower_rpc_url:/m.test(config)) return config;
  if (!/^fiber:\s*$/m.test(config)) throw new Error("The Fiber config has no fiber section");
  return config.replace(/^fiber:\s*$/m, `fiber:\n  standalone_watchtower_rpc_url: ${JSON.stringify(url)}`);
}

/**
 * The script that runs in Fiber's workers before Fiber itself. It replaces WebSocket for the watchtower address
 * only; every other address still gets the browser's own WebSocket.
 */
export function workerShimSource(channelName: string, url = WATCHTOWER_URL): string {
  return `(() => {
  const target = ${JSON.stringify(url)};
  const NativeWebSocket = self.WebSocket;
  let bridge;
  let sequence = 0;
  const pending = new Map();
  function channel() {
    if (bridge) return bridge;
    bridge = new BroadcastChannel(${JSON.stringify(channelName)});
    bridge.onmessage = (event) => {
      const reply = event.data;
      if (!reply || reply.kind !== "reply" || !pending.has(reply.id)) return;
      const settle = pending.get(reply.id);
      pending.delete(reply.id);
      settle(reply);
    };
    return bridge;
  }
  function call(method, params) {
    const id = ++sequence;
    return new Promise((resolve) => {
      const timer = setTimeout(() => { pending.delete(id); resolve({ ok: false, error: "the page did not store the watchtower data" }); }, 30000);
      pending.set(id, (reply) => { clearTimeout(timer); resolve(reply); });
      channel().postMessage({ kind: "call", id, method, params });
    });
  }
  class WatchtowerSocket extends EventTarget {
    constructor(address, protocols) {
      if (String(address) !== target) return new NativeWebSocket(address, protocols);
      super();
      this.url = String(address);
      this.readyState = 0;
      this.binaryType = "blob";
      this.protocol = "";
      this.extensions = "";
      this.bufferedAmount = 0;
      this.onopen = null;
      this.onmessage = null;
      this.onerror = null;
      this.onclose = null;
      setTimeout(() => { if (this.readyState === 0) { this.readyState = 1; this.emit(new Event("open")); } }, 0);
    }
    emit(event) {
      this.dispatchEvent(event);
      const handler = this["on" + event.type];
      if (typeof handler === "function") handler.call(this, event);
    }
    send(data) {
      if (this.readyState !== 1) throw new DOMException("The watchtower socket is not open", "InvalidStateError");
      const text = typeof data === "string" ? data : new TextDecoder().decode(data);
      let request;
      try { request = JSON.parse(text); } catch { return; }
      const requests = Array.isArray(request) ? request : [request];
      Promise.all(requests.map(async (item) => {
        const params = Array.isArray(item.params) ? item.params[0] : item.params;
        const reply = await call(item.method, params ?? {});
        if (item.id === undefined || item.id === null) return undefined;
        return reply.ok
          ? { jsonrpc: "2.0", id: item.id, result: null }
          : { jsonrpc: "2.0", id: item.id, error: { code: -32000, message: String(reply.error) } };
      })).then((responses) => {
        const answered = responses.filter(Boolean);
        if (!answered.length || this.readyState !== 1) return;
        const body = JSON.stringify(Array.isArray(request) ? answered : answered[0]);
        this.emit(new MessageEvent("message", { data: body }));
      });
    }
    close(code = 1000, reason = "") {
      if (this.readyState >= 2) return;
      this.readyState = 3;
      if (bridge && pending.size === 0) { bridge.close(); bridge = undefined; }
      setTimeout(() => this.emit(new CloseEvent("close", { code, reason, wasClean: true })), 0);
    }
  }
  for (const [name, value] of [["CONNECTING", 0], ["OPEN", 1], ["CLOSING", 2], ["CLOSED", 3]]) {
    Object.defineProperty(WatchtowerSocket, name, { value });
    Object.defineProperty(WatchtowerSocket.prototype, name, { value });
  }
  self.WebSocket = WatchtowerSocket;
})();
`;
}

type WorkerConstructor = new (url: string | URL, options?: WorkerOptions) => Worker;

/**
 * Runs `construct` (which creates Fiber's workers) with each new worker first loading the shim. fiber-js builds
 * its workers from blob URLs and revokes them straight away, so those revocations wait until `release` is called,
 * after the workers have loaded their scripts.
 */
export function withWorkerShim<T>(shim: string, construct: () => T): { value: T; release: () => void } {
  const scope = globalThis as unknown as { Worker: WorkerConstructor; URL: typeof URL };
  const NativeWorker = scope.Worker;
  const nativeRevoke = scope.URL.revokeObjectURL;
  const held: string[] = [];
  const created: string[] = [];
  scope.URL.revokeObjectURL = (url: string) => { held.push(url); };
  scope.Worker = function ShimmedWorker(url: string | URL, options?: WorkerOptions) {
    if (options?.type === "module") return new NativeWorker(url, options);
    const source = `${shim}\nimportScripts(${JSON.stringify(String(url))});\n`;
    const wrapped = URL.createObjectURL(new Blob([source], { type: "text/javascript" }));
    created.push(wrapped);
    return new NativeWorker(wrapped, options);
  } as unknown as WorkerConstructor;
  let value: T;
  try {
    value = construct();
  } finally {
    scope.Worker = NativeWorker;
    scope.URL.revokeObjectURL = nativeRevoke;
  }
  return {
    value,
    release() {
      for (const url of held.splice(0)) nativeRevoke.call(scope.URL, url);
      for (const url of created.splice(0)) nativeRevoke.call(scope.URL, url);
    },
  };
}

/**
 * Listens for the shim's calls and answers each once `handle` has finished (so Fiber logs an error if the data
 * couldn't be stored). Returns a function that stops listening.
 */
export function listenForWatchtowerCalls(channelName: string, handle: (call: WatchtowerCall) => Promise<void>): () => void {
  const channel = new BroadcastChannel(channelName);
  // Fiber sends its events one after another and waits for each answer, so they are stored in order.
  let queue = Promise.resolve();
  channel.onmessage = (event: MessageEvent) => {
    const message = event.data as { kind?: string; id?: number; method?: string; params?: Record<string, unknown> };
    if (message?.kind !== "call" || typeof message.id !== "number") return;
    const { id } = message;
    queue = queue.then(async () => {
      try {
        if (!(WATCHTOWER_METHODS as readonly string[]).includes(String(message.method))) throw new Error(`Unknown watchtower method ${message.method}`);
        await handle({ method: message.method as WatchtowerMethod, params: message.params ?? {} });
        channel.postMessage({ kind: "reply", id, ok: true });
      } catch (error) {
        console.error("[keyway] could not store the node's watchtower data", error);
        channel.postMessage({ kind: "reply", id, ok: false, error: error instanceof Error ? error.message : String(error) });
      }
    });
  };
  return () => channel.close();
}
