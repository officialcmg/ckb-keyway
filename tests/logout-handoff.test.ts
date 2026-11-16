import assert from "node:assert/strict";
import test from "node:test";
import { handOffLogout, refuseWhileFiberRuns, serveLogoutHandoff, type LockManagerLike } from "../src/sdk/browser/logout-handoff.ts";

/** One origin's lock manager, shared by every "tab" in the test. */
function originLocks() {
  const held = new Map<string, number>();
  const locks: LockManagerLike & { held: Map<string, number> } = {
    held,
    async request(name, callback) {
      held.set(name, (held.get(name) ?? 0) + 1);
      try {
        return await callback({ name });
      } finally {
        const count = (held.get(name) ?? 1) - 1;
        if (count) held.set(name, count); else held.delete(name);
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
  assert.match(logout, /handOffLogout\(\{[^}]*nodeLoggedOutHere: Boolean\(current\)/);
  assert.match(source, /return \{ nodeLoggedOut: Boolean\(current\) \};/);
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
