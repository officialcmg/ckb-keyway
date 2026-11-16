/**
 * A logout from one tab ends the session every tab of the app shares. Another tab may be running the Fiber node, or
 * hold a stopped one still retrying channel updates to KeyWay's watchtower: once the session ends, nothing more from
 * that tab reaches the watchtower, and its node isn't backed up for the next device. So before the session ends, the
 * logging-out tab hands the logout to every such tab, and fails the logout unless each one says it has finished.
 *
 * A tab with node work holds a Web Lock named for the app's session and the tab (`serveLogoutHandoff`); the lock
 * manager lists held locks for every tab of the origin, and a closed tab's locks go with it. The logging-out tab
 * asks each holder over a BroadcastChannel to run its logout steps (stop the node, deliver to KeyWay's watchtower,
 * back up, release the device) and waits for its answer (`handOffLogout`).
 *
 * A tab whose lock goes away without an answer was closed or crashed: that proves its node stopped, not that it
 * delivered its newest revocation or backed up. So a note in the origin's storage lists the tabs that owe a
 * handoff: each is added before it is asked and removed only once it answers that it finished. A tab that fails,
 * times out or closes stays listed; while the note lists a tab that is gone, logouts fail until a node has logged
 * out in this browser again (which clears the note): starting one sends KeyWay's watchtower every channel update the
 * node stored, and its logout backs it up. A listed tab that is still open is simply asked again. Storage that can't
 * be read counts as owing, and a logout that can't write the note fails before it asks anyone.
 *
 * From before the handoff until the session has ended, the logging-out tab holds a second lock for the session on its
 * own (`whileLoggingOut`). A node's start takes it shared while it claims the device (`startUnlessLoggingOut`), so no
 * node can start after the last check that none runs and then run on once the session has ended.
 */

const PREFIX = "ckb-keyway:logout-handoff:";
/** Long enough for a node to stop, deliver its channel updates (10 s at most), and upload its backup. */
const ANSWER_TIMEOUT_MS = 90_000;
/** How long an answer may trail its tab's lock release (the message and the release race). */
const LATE_ANSWER_MS = 2_000;
export const UNFINISHED_HANDOFF_ERROR = "Fiber in another tab closed before it finished logging out, so its newest channel state may not have reached KeyWay. Connect Fiber in this tab, then log out again";

export type LockOptions = { mode?: "shared" | "exclusive"; ifAvailable?: boolean };
export type LockManagerLike = {
  request(name: string, callback: (lock: unknown) => Promise<unknown>): Promise<unknown>;
  request(name: string, options: LockOptions, callback: (lock: unknown) => Promise<unknown>): Promise<unknown>;
  query(): Promise<{ held?: Array<{ name?: string }> }>;
};
export type BroadcastChannelLike = {
  postMessage(message: unknown): void;
  addEventListener(type: "message", listener: (event: { data: unknown }) => void): void;
  removeEventListener(type: "message", listener: (event: { data: unknown }) => void): void;
  close(): void;
};
export type StorageLike = Pick<Storage, "getItem" | "setItem" | "removeItem">;
export type HandoffEnvironment = {
  locks?: LockManagerLike;
  channel?: (name: string) => BroadcastChannelLike;
  /** The origin's storage (localStorage), for the note that a handed-off logout never finished. */
  storage?: StorageLike;
};

type Request = { type: "logout"; id: string; to: string };
type Answer = { type: "logout-done"; id: string; from: string; error?: string; nodeLoggedOut?: boolean };
/** What a tab's logout steps report: whether a node of this session stopped, delivered and backed up there. */
export type HandledLogout = { nodeLoggedOut: boolean };

/**
 * Whether logging out `connection` stops a browser node that delivers to KeyWay's watchtower and backs up: asked
 * before its logout, while the node still holds the device. Only that settles a handoff a closed tab left
 * unfinished. A KeyWay-hosted connection never does: its node runs on KeyWay's servers, so its logout here
 * delivers and backs up nothing from this browser.
 */
export function logsOutBrowserNode(connection: { mode: "browser"; keyway: { holdsDevice(): boolean } } | { mode: "hosted" } | undefined): boolean {
  return connection?.mode === "browser" && connection.keyway.holdsDevice();
}

/** The tabs that owe a handed-off logout (see above), kept in the origin's storage for every tab of the session. */
function owedHandoffs(scope: string, env: HandoffEnvironment) {
  // Storage that is blocked (reading `localStorage` throws) is treated as failing, not as missing: the note could
  // hold a debt this tab can't see. Only a browser with no storage at all goes without the note.
  let storage: StorageLike | "unusable" | undefined;
  try {
    storage = env.storage ?? (typeof localStorage !== "undefined" ? localStorage : undefined);
  } catch {
    storage = "unusable";
  }
  const key = `${PREFIX}${scope}:unfinished`;
  const read = (): string[] => {
    if (storage === undefined) return [];
    let value: string | null;
    // A note that can't be read may list a tab that is gone: it counts as owed, so the logout fails rather than pass.
    try {
      if (storage === "unusable") return ["unknown"];
      value = storage.getItem(key);
    } catch {
      return ["unknown"];
    }
    if (value == null) return [];
    try {
      const tabs = JSON.parse(value);
      if (Array.isArray(tabs) && tabs.every((tab) => typeof tab === "string")) return tabs;
    } catch { /* unreadable: owed by a tab no one can name */ }
    return ["unknown"];
  };
  const write = (tabs: string[]) => {
    if (storage === undefined) return;
    if (storage === "unusable") throw new Error("storage is blocked");
    if (tabs.length === 0) storage.removeItem(key);
    else storage.setItem(key, JSON.stringify(tabs));
  };
  return {
    tabs: read,
    owe(tabs: string[]) {
      // Unrecorded, a tab that closed mid-handoff would leave nothing to fail the next logout: so this one fails now,
      // before it asks any tab (e.g. storage full or blocked).
      try {
        write([...new Set([...read(), ...tabs])]);
      } catch (error) {
        throw new Error(`Could not note the Fiber logout handed to another tab, so it was not handed off; free up this site's storage and try again (${error instanceof Error ? error.message : String(error)})`);
      }
    },
    // A failed write leaves the note listing the tab, so the next logout fails rather than pass.
    settle(tab: string) { try { write(read().filter((owed) => owed !== tab)); } catch { /* still owed */ } },
    clear() { try { write([]); } catch { /* still owed */ } },
  };
}

function lockManager(env: HandoffEnvironment = {}): LockManagerLike | undefined {
  return env.locks ?? (typeof navigator !== "undefined" ? (navigator as { locks?: LockManagerLike }).locks : undefined);
}

function environment(env: HandoffEnvironment = {}): Required<Pick<HandoffEnvironment, "locks" | "channel">> | undefined {
  const locks = lockManager(env);
  const channel = env.channel ?? (typeof BroadcastChannel !== "undefined" ? (name: string) => new BroadcastChannel(name) as BroadcastChannelLike : undefined);
  return locks && channel ? { locks, channel } : undefined;
}

/** A tab's own ID for the handoff. */
export function newTabId(): string {
  return crypto.randomUUID();
}

/**
 * Makes this tab answer logouts started in other tabs of the same session (`scope`): `handle` runs this tab's
 * logout steps and throws if they fail. Holds the tab's lock until `release()` or a handled logout succeeds.
 */
export function serveLogoutHandoff(options: { scope: string; tabId: string; handle: () => Promise<HandledLogout> } & HandoffEnvironment): { release(): void } {
  const env = environment(options);
  if (!env) return { release() {} };
  const channel = env.channel(`${PREFIX}${options.scope}`);
  const owed = owedHandoffs(options.scope, options);
  let releaseLock!: () => void;
  const held = new Promise<void>((resolve) => { releaseLock = resolve; });
  void env.locks.request(`${PREFIX}${options.scope}:${options.tabId}`, () => held).catch(() => undefined);
  let released = false;
  let handling: Promise<void> = Promise.resolve();
  const release = () => {
    if (released) return;
    released = true;
    releaseLock();
    channel.removeEventListener("message", listener);
    channel.close();
  };
  function listener(event: { data: unknown }) {
    const request = event.data as Partial<Request> | null;
    if (!request || request.type !== "logout" || request.to !== options.tabId || typeof request.id !== "string") return;
    const id = request.id;
    // One at a time: a second request waits for the first and then finds nothing left to do.
    handling = handling.then(async () => {
      if (released) return channel.postMessage({ type: "logout-done", id, from: options.tabId } satisfies Answer);
      let handled: HandledLogout;
      try {
        handled = await options.handle();
      } catch (error) {
        channel.postMessage({ type: "logout-done", id, from: options.tabId, error: error instanceof Error ? error.message : String(error) } satisfies Answer);
        return;
      }
      // Even if the tab that asked has gone meanwhile. A node of this session has logged out in this browser:
      // nothing a closed tab left owing remains.
      if (handled.nodeLoggedOut) owed.clear();
      else owed.settle(options.tabId);
      channel.postMessage({ type: "logout-done", id, from: options.tabId, nodeLoggedOut: handled.nodeLoggedOut } satisfies Answer);
      release();
    });
  }
  channel.addEventListener("message", listener);
  return { release };
}

/**
 * Before this tab ends the session: asks every other tab of it that has node work to run its logout, and throws
 * unless each answers that it has finished. A tab that closes without finishing fails this logout and every later
 * one until a node logs out in this browser: here (`nodeLoggedOutHere`, this logout's own node stopped, delivered
 * and backed up) or in a tab this logout is handed to.
 */
export async function handOffLogout(options: { scope: string; tabId: string; timeoutMs?: number; nodeLoggedOutHere?: boolean } & HandoffEnvironment): Promise<void> {
  const owed = owedHandoffs(options.scope, options);
  if (options.nodeLoggedOutHere) owed.clear();
  const env = environment(options);
  if (!env) return;
  await askOtherTabs(options, env, owed);
  // Every open tab that owed one has just answered; any still listed has gone without finishing.
  if (owed.tabs().length > 0) throw new Error(UNFINISHED_HANDOFF_ERROR);
}

async function askOtherTabs(
  options: { scope: string; tabId: string; timeoutMs?: number },
  env: Required<Pick<HandoffEnvironment, "locks" | "channel">>,
  owed: ReturnType<typeof owedHandoffs>,
): Promise<void> {
  const others = async () => {
    const { held = [] } = await env.locks.query();
    const prefix = `${PREFIX}${options.scope}:`;
    return [...new Set(held.map((lock) => lock.name ?? "").filter((name) => name.startsWith(prefix)).map((name) => name.slice(prefix.length)))]
      .filter((tab) => tab !== options.tabId);
  };
  const tabs = await others();
  if (tabs.length === 0) return;
  // Listed before it is asked, and kept until it answers that it finished: a tab that fails, or closes, or freezes
  // past the deadline and is then closed, stays listed, so a later logout can't take its silence for success.
  owed.owe(tabs);
  const channel = env.channel(`${PREFIX}${options.scope}`);
  const id = newTabId();
  const answers = new Map<string, Answer>();
  let notify: (() => void) | undefined;
  const listener = (event: { data: unknown }) => {
    const answer = event.data as Partial<Answer> | null;
    if (!answer || answer.type !== "logout-done" || answer.id !== id || typeof answer.from !== "string") return;
    answers.set(answer.from, answer as Answer);
    if (!answer.error) {
      if (answer.nodeLoggedOut) owed.clear();
      else owed.settle(answer.from);
    }
    notify?.();
  };
  channel.addEventListener("message", listener);
  try {
    for (const tab of tabs) channel.postMessage({ type: "logout", id, to: tab } satisfies Request);
    const deadline = Date.now() + (options.timeoutMs ?? ANSWER_TIMEOUT_MS);
    /** When the first tab still waited for was found closed (its lock gone with it) without an answer. */
    let closedAt: number | undefined;
    for (;;) {
      const failed = [...answers.values()].find((answer) => answer.error);
      // That tab keeps its node, and stays listed: the next logout asks it again if it is still open.
      if (failed) throw new Error(`Fiber could not be logged out in another tab: ${failed.error}`);
      const waiting = tabs.filter((tab) => !answers.has(tab));
      if (waiting.length === 0) return;
      const stillOpen = new Set(await others());
      if (waiting.some((tab) => !stillOpen.has(tab))) {
        // Its answer may still be on its way: a tab answers, then lets its lock go.
        closedAt ??= Date.now();
        if (Date.now() - closedAt >= LATE_ANSWER_MS) throw new Error(UNFINISHED_HANDOFF_ERROR);
      }
      const left = deadline - Date.now();
      if (left <= 0) throw new Error("Fiber is running in another tab that didn't finish logging out; close that tab or try again");
      await new Promise<void>((resolve) => {
        const timer = setTimeout(resolve, Math.min(left, closedAt === undefined ? 1_000 : 100));
        notify = () => { clearTimeout(timer); resolve(); };
      });
      notify = undefined;
    }
  } finally {
    channel.removeEventListener("message", listener);
    channel.close();
  }
}

/**
 * Throws while any tab still runs the Fiber node for `identifier` (it holds that node's device lock, see
 * device-lock.ts): checked after the handoff, so a node no handoff reached still fails the logout.
 */
export async function refuseWhileFiberRuns(identifier: string, env: HandoffEnvironment = {}): Promise<void> {
  const locks = environment(env)?.locks;
  if (!locks) return;
  const { held = [] } = await locks.query();
  if (held.some((lock) => lock.name === `ckb-keyway:fiber:${identifier}`)) {
    throw new Error("Fiber is still running in another tab; log out there, or close that tab, first");
  }
}

/** Outside `${PREFIX}${scope}:`, where every lock names a tab to hand the logout to. */
const sessionLock = (scope: string) => `ckb-keyway:logout:${scope}`;
export const LOGGING_OUT_ERROR = "Fiber can't start while this account is logging out in another tab, or once it has logged out";

/**
 * Runs `end` (the handoff, the last check that no node runs, and ending the session) holding the session's logout
 * lock on its own, so no node of the session starts meanwhile (`startUnlessLoggingOut`). Without Web Locks it just
 * runs `end`, as before.
 */
export async function whileLoggingOut<T>(scope: string, end: () => Promise<T>, env: HandoffEnvironment = {}): Promise<T> {
  const locks = lockManager(env);
  if (!locks) return end();
  return await locks.request(sessionLock(scope), { mode: "exclusive" }, () => end()) as T;
}

/**
 * Runs `claim` (taking the node's device lock) holding the session's logout lock shared, and only while no logout of
 * the session holds it and the session is still signed in (`signedIn`, asked once no logout can end it meanwhile).
 * Otherwise a node could start after a logout's last check that none runs and run on once the session ended, with
 * nothing more reaching KeyWay's watchtower. It fails rather than waits: the logout may itself be waiting for this
 * tab's start to settle before it can finish. Without Web Locks it just runs `claim`, as before.
 */
export async function startUnlessLoggingOut<T>(scope: string, claim: () => Promise<T>, signedIn: () => boolean, env: HandoffEnvironment = {}): Promise<T> {
  const locks = lockManager(env);
  if (!locks) return claim();
  return await locks.request(sessionLock(scope), { mode: "shared", ifAvailable: true }, async (lock) => {
    if (!lock || !signedIn()) throw new Error(LOGGING_OUT_ERROR);
    return claim();
  }) as T;
}
