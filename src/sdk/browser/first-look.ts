import type { KeyWayChannel } from "./create-keyway";
import { presentChannels, type ChannelClosure } from "./channel-closures";

/**
 * Which of the node's channels the in-page watchtower has yet to look at on-chain since the node last started.
 *
 * When a wallet is reopened, what its node says about a channel is as old as the last time the wallet was open:
 * the peer may have closed the channel on-chain since, and Fiber's own check for that first runs minutes after a
 * start (channel-closures.ts). The watchtower's first pass reads the chain at once, and channel lists wait for it,
 * but only so long (`wait` from the start), so that an RPC that doesn't answer can't hold a list up. A pass slower
 * than that, or one that failed, used to leave the list with the node's word: a channel shown as ready, with its
 * balance, whose funding cell was already spent.
 *
 * So the list goes by what has actually been looked at. Until a pass of this run has read a channel's funding cell
 * and found no force close on it (`seenOpen`), a channel the node calls ready is held back (`awaited`): listed, but
 * as pending with nothing to send or receive (channel-closures.ts `presentChannels`). A pass that finds a force
 * close records it, and the channel is closing from then on. Held back are the channels the node already had when
 * this run's first pass listed them (`listed`), and every channel before that; a channel opened later in the run
 * can't have been closed behind the wallet's back.
 *
 * The wait stays bounded and nothing here can hang a list. What an RPC that doesn't answer costs is that channels
 * read as pending, not ready, until it does: the SDK doesn't vouch for a channel it could not check.
 */
export function createFirstLooks(options: { /** How long after a start a list waits for the first pass, at most (ms). */ wait: number; now?: () => number }) {
  const now = options.now ?? Date.now;
  let run: { pass: Promise<unknown>; until: number; known?: Set<string>; open: Set<string> } | undefined;
  return {
    /** A start of the node: `pass` is the watchtower's first pass of this run. Everything seen before is forgotten. */
    begin(pass: Promise<unknown>) {
      run = { pass: pass.catch(() => undefined), until: now() + options.wait, open: new Set() };
    },
    /** A pass has the node's channel list. The first one of a run fixes which channels were there before it. */
    listed(channelIds: Iterable<string>) {
      if (run && !run.known) run.known = new Set(channelIds);
    },
    /** A pass read this channel's funding cell and found no force close on it. */
    seenOpen(channelId: string) {
      run?.open.add(channelId);
    },
    /** Waits for the first pass of this run, but not past `wait` from the start, however often it is asked. */
    async settled(): Promise<void> {
      const current = run;
      const left = current ? current.until - now() : 0;
      if (!current || left <= 0) return;
      let timer: ReturnType<typeof setTimeout> | undefined;
      await Promise.race([current.pass, new Promise((resolve) => { timer = setTimeout(resolve, left); })]);
      clearTimeout(timer);
    },
    /** Whether a channel (by its ID, lower-case) is still waiting for its first look of this run. */
    awaited(channelId: string): boolean {
      if (!run || run.open.has(channelId)) return false;
      return run.known === undefined || run.known.has(channelId);
    },
  };
}

export type FirstLooks = ReturnType<typeof createFirstLooks>;

/**
 * What a list does about the channels it holds back (`listPresented`'s `lookNow`): asks for a pass now. If one is
 * already running, it may have listed the node's channels before one of these could be looked at, and asking for a
 * pass would only join it. So one more pass is queued behind it, and runs if any channel a list has asked about is
 * still waiting when the running pass ends: such a channel doesn't wait for the next minute's pass. However many
 * lists ask meanwhile, one pass is queued. `pass` starts a pass, or returns the one running, and does nothing once
 * the node has stopped (create-keyway.ts `watchNow`), so nothing queued here outlives a stop.
 */
export function lookAgain(deps: { looks: FirstLooks; /** The pass in progress, if any. */ running(): Promise<unknown> | undefined; pass(): Promise<unknown> }): (held: string[]) => void {
  let wanted: Set<string> | undefined;
  return (held) => {
    const active = deps.running();
    if (!active) {
      void deps.pass().catch(() => undefined);
      return;
    }
    if (wanted) {
      for (const id of held) wanted.add(id.toLowerCase());
      return;
    }
    const mine = wanted = new Set(held.map((id) => id.toLowerCase()));
    void active.catch(() => undefined).then(() => {
      wanted = undefined;
      if ([...mine].some((id) => deps.looks.awaited(id))) return deps.pass();
    }).catch(() => undefined);
  };
}

/**
 * The channel list as the wallet gives it out (create-keyway.ts `getChannels`): waits for the first pass of this
 * run as long as `looks` allows, then lists the node's channels corrected by what the watchtower has recorded, with
 * those still waiting for their first look held back. When one is held back, a pass is asked for now (`lookNow`,
 * in the wallet `lookAgain` below), so it doesn't wait for the next minute's.
 */
export async function listPresented(deps: {
  looks: FirstLooks;
  /** The node's channels, closed ones included, as the SDK shapes them. */
  channels(): Promise<KeyWayChannel[]>;
  closures(): Promise<ChannelClosure[]>;
  includeClosed: boolean;
  /** Told which channels were held back. */
  lookNow?(held: string[]): void;
}): Promise<KeyWayChannel[]> {
  await deps.looks.settled();
  const channels = await deps.channels();
  const seen = await deps.closures();
  const presented = presentChannels(channels, seen, deps.includeClosed, deps.looks.awaited);
  // Held back: ready by the node's word, pending as listed.
  const ready = new Set(channels.filter((channel) => channel.status === "ready").map((channel) => channel.id));
  const held = presented.filter((channel) => channel.status === "pending" && ready.has(channel.id)).map((channel) => channel.id);
  if (held.length > 0) deps.lookNow?.(held);
  return presented;
}
