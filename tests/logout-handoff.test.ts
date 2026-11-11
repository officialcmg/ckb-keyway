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
    handle: async () => { if (fail) throw new Error("KeyWay's watchtower is unreachable"); },
  });
  await assert.rejects(handOffLogout({ scope, tabId: "other-tab", locks }), /another tab: KeyWay's watchtower is unreachable/);
  fail = false;
  await handOffLogout({ scope, tabId: "other-tab", locks });
  nodeTab.release();
});

test("the logout fails when the node's tab doesn't answer, but not when it closes", async () => {
  const locks = originLocks();
  // A tab that holds its lock but never answers (e.g. frozen).
  let closeTab!: () => void;
  void locks.request(`ckb-keyway:logout-handoff:${scope}:silent-tab`, () => new Promise<void>((resolve) => { closeTab = resolve; }));
  await assert.rejects(handOffLogout({ scope, tabId: "other-tab", locks, timeoutMs: 50 }), /didn't finish logging out/);
  const waiting = handOffLogout({ scope, tabId: "other-tab", locks, timeoutMs: 5_000 });
  setTimeout(() => closeTab(), 20);
  await waiting;
});

test("a tab doesn't hand its own logout to itself, and other sessions' tabs aren't asked", async () => {
  const locks = originLocks();
  let asked = 0;
  const own = serveLogoutHandoff({ scope, tabId: "this-tab", locks, handle: async () => { asked++; } });
  const elsewhere = serveLogoutHandoff({ scope: `app:${crypto.randomUUID()}`, tabId: "another-user", locks, handle: async () => { asked++; } });
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
  // A node whose start a logout overtook is stopped as one of the stopped nodes, so the logout delivers and backs it up.
  assert.match(source, /stoppedNodes\.add\(next\.keyway\);\s*await next\.keyway\.stop\(\);\s*throw new Error\("KeyWay connection was superseded"\)/);
  // A tab that ever ran a node answers other tabs' logouts.
  assert.match(source.slice(source.indexOf("  async function connect() {")), /^[^]*?serveLogoutHandoff\(/);
});
