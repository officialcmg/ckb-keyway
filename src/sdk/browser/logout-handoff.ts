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
 */

const PREFIX = "ckb-keyway:logout-handoff:";
/** Long enough for a node to stop, deliver its channel updates (10 s at most), and upload its backup. */
const ANSWER_TIMEOUT_MS = 90_000;

export type LockManagerLike = {
  request(name: string, callback: (lock: unknown) => Promise<unknown>): Promise<unknown>;
  query(): Promise<{ held?: Array<{ name?: string }> }>;
};
export type BroadcastChannelLike = {
  postMessage(message: unknown): void;
  addEventListener(type: "message", listener: (event: { data: unknown }) => void): void;
  removeEventListener(type: "message", listener: (event: { data: unknown }) => void): void;
  close(): void;
};
export type HandoffEnvironment = {
  locks?: LockManagerLike;
  channel?: (name: string) => BroadcastChannelLike;
};

type Request = { type: "logout"; id: string; to: string };
type Answer = { type: "logout-done"; id: string; from: string; error?: string };

function environment(env: HandoffEnvironment = {}): Required<HandoffEnvironment> | undefined {
  const locks = env.locks ?? (typeof navigator !== "undefined" ? (navigator as { locks?: LockManagerLike }).locks : undefined);
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
export function serveLogoutHandoff(options: { scope: string; tabId: string; handle: () => Promise<void> } & HandoffEnvironment): { release(): void } {
  const env = environment(options);
  if (!env) return { release() {} };
  const channel = env.channel(`${PREFIX}${options.scope}`);
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
      try {
        await options.handle();
      } catch (error) {
        channel.postMessage({ type: "logout-done", id, from: options.tabId, error: error instanceof Error ? error.message : String(error) } satisfies Answer);
        return;
      }
      channel.postMessage({ type: "logout-done", id, from: options.tabId } satisfies Answer);
      release();
    });
  }
  channel.addEventListener("message", listener);
  return { release };
}

/**
 * Before this tab ends the session: asks every other tab of it that has node work to run its logout, and throws
 * unless each answers that it has finished (or has closed meanwhile).
 */
export async function handOffLogout(options: { scope: string; tabId: string; timeoutMs?: number } & HandoffEnvironment): Promise<void> {
  const env = environment(options);
  if (!env) return;
  const others = async () => {
    const { held = [] } = await env.locks.query();
    const prefix = `${PREFIX}${options.scope}:`;
    return [...new Set(held.map((lock) => lock.name ?? "").filter((name) => name.startsWith(prefix)).map((name) => name.slice(prefix.length)))]
      .filter((tab) => tab !== options.tabId);
  };
  const tabs = await others();
  if (tabs.length === 0) return;
  const channel = env.channel(`${PREFIX}${options.scope}`);
  const id = newTabId();
  const answers = new Map<string, Answer>();
  let notify: (() => void) | undefined;
  const listener = (event: { data: unknown }) => {
    const answer = event.data as Partial<Answer> | null;
    if (!answer || answer.type !== "logout-done" || answer.id !== id || typeof answer.from !== "string") return;
    answers.set(answer.from, answer as Answer);
    notify?.();
  };
  channel.addEventListener("message", listener);
  try {
    for (const tab of tabs) channel.postMessage({ type: "logout", id, to: tab } satisfies Request);
    const deadline = Date.now() + (options.timeoutMs ?? ANSWER_TIMEOUT_MS);
    for (;;) {
      const failed = [...answers.values()].find((answer) => answer.error);
      if (failed) throw new Error(`Fiber could not be logged out in another tab: ${failed.error}`);
      // A tab that hasn't answered may have closed (its lock is gone with it).
      const waiting = tabs.filter((tab) => !answers.has(tab));
      if (waiting.length === 0) return;
      const stillOpen = new Set(await others());
      if (!waiting.some((tab) => stillOpen.has(tab))) return;
      const left = deadline - Date.now();
      if (left <= 0) throw new Error("Fiber is running in another tab that didn't finish logging out; close that tab or try again");
      await new Promise<void>((resolve) => {
        const timer = setTimeout(resolve, Math.min(left, 1_000));
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
