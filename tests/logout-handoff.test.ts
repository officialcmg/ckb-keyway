import assert from "node:assert/strict";
import test from "node:test";
import {
  handOffLogout,
  LOGGING_OUT_ERROR,
  logsOutBrowserNode,
  refuseWhileFiberRuns,
  serveLogoutHandoff,
  startUnlessLoggingOut,
  UNFINISHED_HANDOFF_ERROR,
  whileLoggingOut,
  type LockManagerLike,
  type LockOptions,
} from "../src/sdk/browser/logout-handoff.ts";

type LockCallback = (lock: unknown) => Promise<unknown>;
type LockMode = "shared" | "exclusive";

/** One origin's lock manager, shared by every "tab" in the test: exclusive or shared locks, granted in turn. */
function originLocks() {
  const held = new Map<string, { mode: LockMode; count: number }>();
  const queued = new Map<string, Array<{ mode: LockMode; grant: () => void }>>();
  const grantable = (name: string, mode: LockMode) => {
    const lock = held.get(name);
    return !lock || (mode === "shared" && lock.mode === "shared");
  };
  const take = (name: string, mode: LockMode) => held.set(name, { mode, count: (held.get(name)?.count ?? 0) + 1 });
  const drop = (name: string) => {
    const lock = held.get(name)!;
    if (lock.count > 1) lock.count -= 1; else held.delete(name);
    const queue = queued.get(name) ?? [];
    while (queue.length > 0 && grantable(name, queue[0].mode)) {
      const next = queue.shift()!;
      take(name, next.mode);
      next.grant();
    }
  };
  const locks: LockManagerLike & { held: typeof held } = {
    held,
    async request(name: string, optionsOrCallback: LockOptions | LockCallback, maybeCallback?: LockCallback) {
      const options = typeof optionsOrCallback === "function" ? {} : optionsOrCallback;
      const callback = typeof optionsOrCallback === "function" ? optionsOrCallback : maybeCallback!;
      const mode = options.mode ?? "exclusive";
      const queue = queued.get(name) ?? [];
      queued.set(name, queue);
      if (grantable(name, mode) && queue.length === 0) take(name, mode);
      else if (options.ifAvailable) return callback(null);
      else await new Promise<void>((grant) => queue.push({ mode, grant }));
      try {
        return await callback({ name, mode });
      } finally {
        drop(name);
      }
    },
    async query() {
      return { held: [...held.keys()].map((name) => ({ name })) };
    },
  };
  return locks;
}
const scope = `app:${crypto.randomUUID()}`;

/** One origin's localStorage, shared by every "tab" in the test. */
function originStorage() {
  const items = new Map<string, string>();
  return { getItem: (key: string) => items.get(key) ?? null, setItem: (key: string, value: string) => void items.set(key, value), removeItem: (key: string) => void items.delete(key) };
}

test("a logout in a tab without the node waits for the node's tab to log out before the session ends", async () => {
  const locks = originLocks();
  const events: string[] = [];
  let finishBackup!: () => void;
  const backedUp = new Promise<void>((resolve) => { finishBackup = resolve; });
  const nodeTab = serveLogoutHandoff({
    scope, tabId: "node-tab", locks,
    handle: async () => {
      events.push("node tab: stop, deliver revocations, back up");
      await backedUp;
      events.push("node tab: released the device");
      return { nodeLoggedOut: true };
    },
  });
  const loggingOut = handOffLogout({ scope, tabId: "other-tab", locks }).then(() => events.push("other tab: session ends"));
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.deepEqual(events, ["node tab: stop, deliver revocations, back up"], "the session doesn't end while the node tab is still delivering");
  finishBackup();
  await loggingOut;
  assert.deepEqual(events, ["node tab: stop, deliver revocations, back up", "node tab: released the device", "other tab: session ends"]);
  assert.equal(locks.held.size, 0, "the node tab has nothing left to hand off");
  nodeTab.release();
});

test("the logout fails when the node's tab can't log out, and the tab keeps answering", async () => {
  const locks = originLocks();
  let fail = true;
  const nodeTab = serveLogoutHandoff({
    scope, tabId: "node-tab", locks,
    handle: async () => {
      if (fail) throw new Error("KeyWay's watchtower is unreachable");
      return { nodeLoggedOut: true };
    },
  });
  await assert.rejects(handOffLogout({ scope, tabId: "other-tab", locks }), /another tab: KeyWay's watchtower is unreachable/);
  fail = false;
  await handOffLogout({ scope, tabId: "other-tab", locks });
  nodeTab.release();
});

test("the logout fails when the node's tab doesn't answer, or closes without answering", async () => {
  const locks = originLocks();
  const storage = originStorage();
  // A tab that holds its lock but never answers (e.g. frozen).
  let closeTab!: () => void;
  void locks.request(`ckb-keyway:logout-handoff:${scope}:silent-tab`, () => new Promise<void>((resolve) => { closeTab = resolve; }));
  await assert.rejects(handOffLogout({ scope, tabId: "other-tab", locks, storage, timeoutMs: 50 }), /didn't finish logging out/);
  // Closing it proves its node stopped, not that it delivered or backed up.
  const waiting = handOffLogout({ scope, tabId: "other-tab", locks, storage, timeoutMs: 5_000 });
  setTimeout(() => closeTab(), 20);
  await assert.rejects(waiting, /closed before it finished logging out/);
});

test("a tab that closes before it answers fails the logout, and every logout after it, until a node logs out here", async () => {
  const locks = originLocks();
  const storage = originStorage();
  // The node's tab gets the request, starts its logout steps, and is closed (or crashes) before it delivers its
  // newest revocation and backs up: its locks go with it, but nothing says it finished.
  let crash!: () => void;
  let started!: () => void;
  const handling = new Promise<void>((resolve) => { started = resolve; });
  void locks.request(`ckb-keyway:logout-handoff:${scope}:node-tab`, () => new Promise<void>((resolve) => { crash = resolve; }));
  const channel = new BroadcastChannel(`ckb-keyway:logout-handoff:${scope}`);
  channel.onmessage = (event) => { if ((event.data as { type?: string }).type === "logout") started(); };
  try {
    const loggingOut = handOffLogout({ scope, tabId: "other-tab", locks, storage, timeoutMs: 5_000 });
    await handling;
    crash();
    await assert.rejects(loggingOut, /closed before it finished logging out/);
  } finally {
    channel.close();
  }
  // The tab is gone, so no lock says anything is missing; the logout still fails until a node has logged out here,
  // whose start sends KeyWay's watchtower every stored channel update again and whose logout backs it up.
  await assert.rejects(handOffLogout({ scope, tabId: "other-tab", locks, storage }), /closed before it finished logging out/);
  await handOffLogout({ scope, tabId: "other-tab", locks, storage, nodeLoggedOutHere: true });
  await handOffLogout({ scope, tabId: "other-tab", locks, storage });
});

test("a tab that times out and is then closed doesn't let the next logout through", async () => {
  const locks = originLocks();
  const storage = originStorage();
  // Frozen: it holds its lock but never answers, so the logout times out; then the user closes it, as told.
  let closeTab!: () => void;
  void locks.request(`ckb-keyway:logout-handoff:${scope}:frozen-tab`, () => new Promise<void>((resolve) => { closeTab = resolve; }));
  await assert.rejects(handOffLogout({ scope, tabId: "other-tab", locks, storage, timeoutMs: 50 }), /didn't finish logging out/);
  closeTab();
  await new Promise((resolve) => setTimeout(resolve, 0));
  await assert.rejects(handOffLogout({ scope, tabId: "other-tab", locks, storage }), /closed before it finished logging out/);
  // A node that logs out in a tab the logout is handed to settles it too.
  const node = serveLogoutHandoff({ scope, tabId: "node-tab", locks, storage, handle: async () => ({ nodeLoggedOut: true }) });
  await handOffLogout({ scope, tabId: "other-tab", locks, storage });
  node.release();
  await handOffLogout({ scope, tabId: "other-tab", locks, storage });
});

test("a tab that fails its logout and then closes doesn't let the next logout through", async () => {
  const locks = originLocks();
  const storage = originStorage();
  // Its watchtower delivery fails, so it keeps its node and answers with the error; then it is closed.
  const failing = serveLogoutHandoff({ scope, tabId: "node-tab", locks, storage, handle: async () => { throw new Error("KeyWay's watchtower is unreachable"); } });
  await assert.rejects(handOffLogout({ scope, tabId: "other-tab", locks, storage }), /unreachable/);
  failing.release();
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(locks.held.size, 0, "the tab is gone");
  await assert.rejects(handOffLogout({ scope, tabId: "other-tab", locks, storage }), /closed before it finished logging out/);
  await handOffLogout({ scope, tabId: "other-tab", locks, storage, nodeLoggedOutHere: true });
});

test("an idle tab that finishes doesn't settle what a closed tab owes", async () => {
  const locks = originLocks();
  const storage = originStorage();
  storage.setItem(`ckb-keyway:logout-handoff:${scope}:unfinished`, JSON.stringify(["gone-tab"]));
  const idle = serveLogoutHandoff({ scope, tabId: "idle-tab", locks, storage, handle: async () => ({ nodeLoggedOut: false }) });
  await assert.rejects(handOffLogout({ scope, tabId: "other-tab", locks, storage }), /closed before it finished logging out/);
  idle.release();
  assert.deepEqual(JSON.parse(storage.getItem(`ckb-keyway:logout-handoff:${scope}:unfinished`)!), ["gone-tab"]);
});

test("a tab that answers it finished clears the note even if the tab that asked has gone", async () => {
  const locks = originLocks();
  const storage = originStorage();
  storage.setItem(`ckb-keyway:logout-handoff:${scope}:unfinished`, "1");
  const node = serveLogoutHandoff({ scope, tabId: "node-tab", locks, storage, handle: async () => ({ nodeLoggedOut: true }) });
  const channel = new BroadcastChannel(`ckb-keyway:logout-handoff:${scope}`);
  try {
    // The logging-out tab sent its request and was closed; the node's tab still finishes.
    const answered = new Promise<void>((resolve) => { channel.onmessage = (event) => { if ((event.data as { type?: string }).type === "logout-done") resolve(); }; });
    channel.postMessage({ type: "logout", id: "gone", to: "node-tab" });
    await answered;
  } finally {
    channel.close();
    node.release();
  }
  await handOffLogout({ scope, tabId: "other-tab", locks, storage });
});

test("a node that logs out in the tab a logout was handed to also clears an earlier unfinished handoff", async () => {
  const locks = originLocks();
  const storage = originStorage();
  storage.setItem(`ckb-keyway:logout-handoff:${scope}:unfinished`, "1");
  const idle = serveLogoutHandoff({ scope, tabId: "idle-tab", locks, storage, handle: async () => ({ nodeLoggedOut: false }) });
  await assert.rejects(handOffLogout({ scope, tabId: "other-tab", locks, storage }), /closed before it finished logging out/);
  idle.release();
  const node = serveLogoutHandoff({ scope, tabId: "node-tab", locks, storage, handle: async () => ({ nodeLoggedOut: true }) });
  await handOffLogout({ scope, tabId: "other-tab", locks, storage });
  node.release();
});

test("an answer that arrives just after the tab let go of its lock still counts", async () => {
  const locks = originLocks();
  const storage = originStorage();
  // The tab answers and releases its lock at once; the logging-out tab may see the lock gone before the message.
  const nodeTab = serveLogoutHandoff({ scope, tabId: "node-tab", locks, storage, handle: async () => ({ nodeLoggedOut: true }) });
  await handOffLogout({ scope, tabId: "other-tab", locks, storage });
  nodeTab.release();
  await handOffLogout({ scope, tabId: "other-tab", locks, storage });
});

test("a tab doesn't hand its own logout to itself, and other sessions' tabs aren't asked", async () => {
  const locks = originLocks();
  let asked = 0;
  const own = serveLogoutHandoff({ scope, tabId: "this-tab", locks, handle: async () => { asked++; return { nodeLoggedOut: false }; } });
  const elsewhere = serveLogoutHandoff({ scope: `app:${crypto.randomUUID()}`, tabId: "another-user", locks, handle: async () => { asked++; return { nodeLoggedOut: false }; } });
  await handOffLogout({ scope, tabId: "this-tab", locks, timeoutMs: 50 });
  assert.equal(asked, 0);
  own.release();
  elsewhere.release();
});

test("a node still running anywhere fails the logout", async () => {
  const locks = originLocks();
  let stop!: () => void;
  void locks.request("ckb-keyway:fiber:0xabc", () => new Promise<void>((resolve) => { stop = resolve; }));
  await assert.rejects(refuseWhileFiberRuns("0xabc", { locks }), /still running in another tab/);
  await refuseWhileFiberRuns("0xother", { locks });
  stop();
  await new Promise((resolve) => setTimeout(resolve, 0));
  await refuseWhileFiberRuns("0xabc", { locks });
});

test("the provider hands a logout to the session's other tabs, and checks no node still runs, before it ends the session", async () => {
  const { readFile } = await import("node:fs/promises");
  const source = await readFile(new URL("../src/sdk/react/keyway-provider.tsx", import.meta.url), "utf8");
  const logout = source.slice(source.indexOf("  async function logout() {"), source.indexOf("handoffHandlerRef.current = async"));
  const end = logout.indexOf("await api.logout(token)");
  assert.ok(end > 0);
  assert.ok(logout.indexOf("await handOffLogout(") > 0 && logout.indexOf("await handOffLogout(") < end);
  assert.ok(logout.indexOf("await refuseWhileFiberRuns(") > 0 && logout.indexOf("await refuseWhileFiberRuns(") < end);
  // A logout whose own node just stopped, delivered and backed up clears a note left by a tab that closed mid-handoff,
  // and a tab answering a handoff says whether a node logged out there.
  // Only a browser node counts, asked before its logout: a KeyWay-hosted connection delivers and backs up nothing here.
  assert.match(logout, /const nodeLoggedOutHere = logsOutBrowserNode\(current\);\s*if \(current\) await current\.keyway\.stopForLogout\(\);/);
  assert.match(logout, /handOffLogout\(\{[^}]*nodeLoggedOutHere \}/);
  const handler = source.slice(source.indexOf("  async function logOutNodesHere()"));
  assert.match(handler, /^[^]*?const nodeLoggedOut = logsOutBrowserNode\(current\);[^]*?return \{ nodeLoggedOut \};/);
  assert.doesNotMatch(source, /Boolean\(current\)/);
  // A node whose start a logout overtook becomes the connection that logout stops, delivers and backs up; one
  // overtaken otherwise is stopped as one of the stopped nodes.
  assert.match(source, /if \(loggingOutRef\.current > 0 && !connectionRef\.current\) \{[^}]*connectionRef\.current = next;/);
  assert.match(source, /stoppedNodes\.add\(next\.keyway\);\s*await next\.keyway\.stop\(\);\s*throw new Error\("KeyWay connection was superseded"\)/);
  for (const handler of ["async function logout() {", "handoffHandlerRef.current = async () => {"]) {
    assert.match(source.slice(source.indexOf(handler)), /^[^]{0,80}loggingOutRef\.current \+= 1;/);
  }
  // A tab that ever ran a node answers other tabs' logouts.
  assert.match(source.slice(source.indexOf("  async function connect() {")), /^[^]*?serveLogoutHandoff\(/);
});

test("only a browser node that still holds the device counts as logging out here, never a KeyWay-hosted connection", async () => {
  const browser = (holds: boolean) => ({ mode: "browser" as const, keyway: { holdsDevice: () => holds } });
  assert.equal(logsOutBrowserNode(browser(true)), true);
  assert.equal(logsOutBrowserNode(browser(false)), false, "a node that already let go has nothing left to back up");
  assert.equal(logsOutBrowserNode({ mode: "hosted" }), false, "a hosted node runs on KeyWay's servers: nothing here delivers or backs up");
  assert.equal(logsOutBrowserNode(undefined), false);
  // So a hosted connection's logout doesn't clear what a tab that closed mid-handoff left owing.
  const locks = originLocks();
  const storage = originStorage();
  storage.setItem(`ckb-keyway:logout-handoff:${scope}:unfinished`, JSON.stringify(["gone-tab"]));
  const hostedTab = serveLogoutHandoff({ scope, tabId: "hosted-tab", locks, storage, handle: async () => ({ nodeLoggedOut: logsOutBrowserNode({ mode: "hosted" }) }) });
  await assert.rejects(handOffLogout({ scope, tabId: "other-tab", locks, storage, nodeLoggedOutHere: logsOutBrowserNode({ mode: "hosted" }) }), /closed before it finished logging out/);
  hostedTab.release();
  await handOffLogout({ scope, tabId: "other-tab", locks, storage, nodeLoggedOutHere: logsOutBrowserNode(browser(true)) });
});

test("a note that can't be read counts as owed, so the logout fails rather than pass", async () => {
  const locks = originLocks();
  const unreadable = { getItem: () => { throw new Error("SecurityError"); }, setItem: () => undefined, removeItem: () => undefined };
  await assert.rejects(handOffLogout({ scope, tabId: "other-tab", locks, storage: unreadable }), (error: Error) => error.message === UNFINISHED_HANDOFF_ERROR);
  // Storage blocked outright (reading localStorage itself throws) is not the same as a browser without storage.
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, "localStorage");
  Object.defineProperty(globalThis, "localStorage", { configurable: true, get() { throw new Error("SecurityError"); } });
  try {
    await assert.rejects(handOffLogout({ scope, tabId: "other-tab", locks }), (error: Error) => error.message === UNFINISHED_HANDOFF_ERROR);
  } finally {
    if (descriptor) Object.defineProperty(globalThis, "localStorage", descriptor);
    else delete (globalThis as { localStorage?: unknown }).localStorage;
  }
  // Without any storage there is no note to read, as before.
  await handOffLogout({ scope, tabId: "other-tab", locks });
});

test("a logout that can't note the tabs it hands off to fails before it asks them", async () => {
  const locks = originLocks();
  const full = { ...originStorage(), setItem: () => { throw new Error("QuotaExceededError"); } };
  let asked = 0;
  const nodeTab = serveLogoutHandoff({ scope, tabId: "node-tab", locks, storage: full, handle: async () => { asked++; return { nodeLoggedOut: true }; } });
  await assert.rejects(handOffLogout({ scope, tabId: "other-tab", locks, storage: full }), /Could not note the Fiber logout handed to another tab[^]*QuotaExceededError/);
  assert.equal(asked, 0, "unnoted, a tab that closed mid-handoff would leave nothing to fail the next logout");
  nodeTab.release();
});

test("no node starts while a logout ends the session, from before its handoff until after", async () => {
  const locks = originLocks();
  let signedIn = true;
  let claims = 0;
  const claimDevice = async () => { claims++; return "device lock"; };
  // Another tab answered the handoff, so the last check finds no node: it then tries to start one before the
  // session has ended.
  const answered = serveLogoutHandoff({ scope, tabId: "answered-tab", locks, handle: async () => ({ nodeLoggedOut: true }) });
  await whileLoggingOut(scope, async () => {
    await handOffLogout({ scope, tabId: "other-tab", locks });
    await refuseWhileFiberRuns("0xabc", { locks });
    await assert.rejects(startUnlessLoggingOut(scope, claimDevice, () => signedIn, { locks }), (error: Error) => error.message === LOGGING_OUT_ERROR);
    signedIn = false; // the session ends (revoked, and cleared from storage)
  }, { locks });
  answered.release();
  // Once the logout lets go, the session has ended: a start that waited out the logout is refused too.
  await assert.rejects(startUnlessLoggingOut(scope, claimDevice, () => signedIn, { locks }), (error: Error) => error.message === LOGGING_OUT_ERROR);
  assert.equal(claims, 0, "no node took the device");
  // Signed in, with no logout in progress, a node starts; and another session's logout doesn't hold this one's.
  signedIn = true;
  await whileLoggingOut(`app:${crypto.randomUUID()}`, async () => {
    assert.equal(await startUnlessLoggingOut(scope, claimDevice, () => signedIn, { locks }), "device lock");
  }, { locks });
  assert.equal(claims, 1);
  assert.equal(locks.held.size, 0);
});

test("a logout waits for a node that is taking the device, then finds it running", async () => {
  const locks = originLocks();
  let finishClaim!: () => void;
  let stopNode!: () => void;
  const claiming = startUnlessLoggingOut(scope, async () => {
    await new Promise<void>((resolve) => { finishClaim = resolve; });
    // The node's device lock: held until the node stops.
    void locks.request("ckb-keyway:fiber:0xabc", () => new Promise<void>((resolve) => { stopNode = resolve; }));
  }, () => true, { locks });
  let ended = false;
  const loggingOut = whileLoggingOut(scope, async () => {
    await refuseWhileFiberRuns("0xabc", { locks });
    ended = true;
  }, { locks });
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal(ended, false, "the logout's checks wait for the start taking the device");
  finishClaim();
  await claiming;
  await assert.rejects(loggingOut, /still running in another tab/);
  stopNode();
});

test("a browser node takes the device only through the provider's logout guard", async () => {
  const { readFile } = await import("node:fs/promises");
  const createKeyWay = await readFile(new URL("../src/sdk/browser/create-keyway.ts", import.meta.url), "utf8");
  assert.match(createKeyWay, /const lockDevice = \(\) => acquireDeviceLock\(options\.identifier\);\s*deviceLock = await \(options\.guardClaim \? options\.guardClaim\(lockDevice\) : lockDevice\(\)\);/);
  const connectKeyWay = await readFile(new URL("../src/sdk/browser/connect-keyway.ts", import.meta.url), "utf8");
  assert.match(connectKeyWay, /guardClaim: options\.guardClaim,/);
  const source = await readFile(new URL("../src/sdk/react/keyway-provider.tsx", import.meta.url), "utf8");
  const connect = source.slice(source.indexOf("  async function connect() {"), source.indexOf("  async function disconnect() {"));
  assert.match(connect, /guardClaim: <T,>\(claim: \(\) => Promise<T>\) => startUnlessLoggingOut\(handoffScope\(appId, user\.id\), claim, \(\) => readStoredSession\(appId\)\?\.user\.id === user\.id\)/);
  // The logout holds the session's logout lock from before the handoff until the session has ended here too.
  const logout = source.slice(source.indexOf("  async function logoutNow() {"), source.indexOf("handoffHandlerRef.current = async"));
  const endSession = logout.slice(logout.indexOf("const endSession = async () => {"), logout.indexOf("await whileLoggingOut(handoffScope(appId, user.id), endSession);"));
  assert.ok(endSession.length > 0);
  for (const step of ["await handOffLogout(", "await refuseWhileFiberRuns(", "await api.logout(token)", "clearStoredSession(appId)"]) {
    assert.ok(endSession.includes(step), step);
  }
  assert.equal(logout.match(/clearStoredSession\(/g)?.length, 1);
});
