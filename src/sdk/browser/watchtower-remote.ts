import type { WatchtowerCall } from "./watchtower-bridge";
import type { WatchedChannel } from "./watchtower-store";

/**
 * Sends KeyWay's watchtower what it needs to punish a peer that publishes a revoked commitment while the tab is
 * closed, and nothing more. Fiber hands the page a channel's settlement key, TLC keys, preimages and settlement
 * data too; none of that leaves the device. Only these are sent:
 *
 * - `watch`: the channel ID and the two funding public keys (the watchtower finds the channel on-chain from them),
 *   plus the token script for a token channel;
 * - `revoke`: the newest revocation data (commitment number, the two parties' aggregated signature over the
 *   revocation output, and that output, which pays the whole channel to the user's own address);
 * - `unwatch`: the channel ID, when Fiber reports the channel closed.
 *
 * Updates are coalesced per channel (only the newest revocation matters: it covers every older commitment) and
 * retried until KeyWay has them. `pending()` says whether something is still unsent, so the page can warn before
 * the tab closes. A channel KeyWay won't register because the account is at its watched-channel limit keeps its
 * updates; they are tried again on each `flush()`, and `deliver()` fails while the channel is unwatched.
 */

export type RemoteWatchUpdate =
  | { operation: "watch"; channelId: string; localFundingPubkey: string; remoteFundingPubkey: string; fundingUdtTypeScript: { code_hash: string; hash_type: string; args: string } | null }
  | { operation: "revoke"; channelId: string; revocation: { commitment_number: string; aggregated_signature: string; output: string; output_data: string } }
  | { operation: "unwatch"; channelId: string };

const text = (value: unknown) => (typeof value === "string" ? value : "");
const prefixed = (value: unknown) => {
  const hex = text(value).replace(/^0x/i, "").toLowerCase();
  return hex ? `0x${hex}` : "";
};

/** Picks the fields the remote watchtower may see out of one of Fiber's watchtower calls. Pure, for testing. */
export function remoteWatchUpdate(call: WatchtowerCall): RemoteWatchUpdate | undefined {
  const p = call.params;
  const channelId = prefixed(p.channel_id);
  switch (call.method) {
    case "create_watch_channel": {
      const udt = p.funding_udt_type_script as { code_hash?: unknown; hash_type?: unknown; args?: unknown } | null | undefined;
      return {
        operation: "watch",
        channelId,
        localFundingPubkey: prefixed(p.local_funding_pubkey),
        remoteFundingPubkey: prefixed(p.remote_funding_pubkey),
        fundingUdtTypeScript: udt ? { code_hash: text(udt.code_hash), hash_type: text(udt.hash_type), args: text(udt.args) } : null,
      };
    }
    case "update_revocation": {
      const r = (p.revocation_data ?? {}) as Record<string, unknown>;
      return {
        operation: "revoke",
        channelId,
        revocation: {
          commitment_number: text(r.commitment_number),
          aggregated_signature: text(r.aggregated_signature),
          output: text(r.output),
          output_data: text(r.output_data),
        },
      };
    }
    case "remove_watch_channel":
      return { operation: "unwatch", channelId };
    default:
      // Settlement data (which carries TLC private keys) and preimages stay in the page.
      return undefined;
  }
}

/** The updates that bring the remote watchtower up to date with one channel in the in-page store. */
export function updatesForStoredChannel(channel: WatchedChannel): RemoteWatchUpdate[] {
  const updates: RemoteWatchUpdate[] = [];
  const watch = remoteWatchUpdate({
    method: "create_watch_channel",
    params: {
      channel_id: channel.channelId,
      local_funding_pubkey: channel.localFundingPubkey,
      remote_funding_pubkey: channel.remoteFundingPubkey,
      funding_udt_type_script: channel.fundingUdtTypeScript,
    },
  });
  if (watch) updates.push(watch);
  if (channel.revocation) {
    const revoke = remoteWatchUpdate({ method: "update_revocation", params: { channel_id: channel.channelId, revocation_data: channel.revocation } });
    if (revoke) updates.push(revoke);
  }
  return updates;
}

type ChannelQueue = { watch?: RemoteWatchUpdate; revoke?: RemoteWatchUpdate; unwatch?: RemoteWatchUpdate; reregistered?: boolean };

const commitmentNumber = (update?: RemoteWatchUpdate) => {
  if (update?.operation !== "revoke") return -1n;
  try {
    return BigInt(update.revocation.commitment_number);
  } catch {
    return -1n;
  }
};

export type RemoteWatchtower = {
  enqueue(update: RemoteWatchUpdate | undefined): void;
  /** Sends everything queued; resolves when the queue is empty or a send failed (it is then retried later). */
  flush(): Promise<void>;
  /**
   * Sends everything queued, and fails unless KeyWay has all of it within `timeoutMs` (e.g. before a logout), or while
   * KeyWay refuses to watch a channel because the account is at its limit.
   */
  deliver(timeoutMs: number): Promise<void>;
  /** Channels with an update KeyWay doesn't have yet, including one it won't watch while the account is at its limit. */
  pending(): number;
  stop(): void;
};

export function createRemoteWatchtower(options: {
  send: (update: RemoteWatchUpdate) => Promise<unknown>;
  /** The channel's registration, from the in-page store, for when KeyWay reports it doesn't know the channel. */
  registration?: (channelId: string) => Promise<RemoteWatchUpdate | undefined>;
  retryMs?: number;
  /** A send that takes longer than this counts as failed and is retried, so a stuck request can't hold the queue. */
  sendTimeoutMs?: number;
  log?: Pick<Console, "info" | "warn">;
}): RemoteWatchtower {
  const queues = new Map<string, ChannelQueue>();
  const log = options.log ?? console;
  let flushing: Promise<void> | undefined;
  let retry: ReturnType<typeof setTimeout> | undefined;
  let stopped = false;
  let attempt = 0;
  /** How long KeyWay asked us to wait when it last turned a send away for its rate limit. */
  let retryAfterMs: number | undefined;

  function enqueue(update: RemoteWatchUpdate | undefined) {
    if (!update || !/^0x[0-9a-f]{64}$/.test(update.channelId) || rejectedChannels.has(update.channelId)) return;
    if (update.operation === "unwatch" && atLimit.has(update.channelId)) {
      // Closed before KeyWay could watch it: there is nothing left to register.
      atLimit.delete(update.channelId);
      queues.delete(update.channelId);
      return;
    }
    const queue = queues.get(update.channelId) ?? {};
    if (update.operation === "revoke") {
      // Only the newest revocation is worth sending.
      if (commitmentNumber(update) > commitmentNumber(queue.revoke)) queue.revoke = update;
    } else {
      queue[update.operation] = update;
    }
    queues.set(update.channelId, queue);
    void run(false);
  }

  /**
   * A request KeyWay refused for good: resending it can't succeed. Only the API's own refusals count; any other
   * failure (network, 5xx, 429, a database error the API reports as 400) is retried, so a revocation is never dropped
   * because of a passing fault.
   */
  const PERMANENT = /Token channels are not watched|Invalid watchtower|Unsupported watchtower operation|already watched with other funding keys|does not match the channel's asset/i;
  /** KeyWay won't register another channel until one of the account's watched channels is closed. */
  const LIMIT = /already watches \d+ open channels/i;
  const refused = (error: unknown, message: string) => {
    const status = (error as { status?: unknown })?.status;
    return status === 400 && PERMANENT.test(message);
  };
  /** Channels KeyWay won't watch (e.g. token channels): their later updates are dropped too. */
  const rejectedChannels = new Set<string>();
  /**
   * CKB channels KeyWay refused to register at the account's watched-channel limit. Nothing watches them while the
   * tab is closed, so their updates are kept (the newest revocation still replaces older ones) and tried again on a
   * `flush()` rather than on every retry, and `deliver()` reports them until KeyWay takes them or they close.
   */
  const atLimit = new Set<string>();

  async function flushOnce(retryAtLimit: boolean) {
    let failed = false;
    for (const [channelId, queue] of [...queues]) {
      if (stopped) return;
      if (rejectedChannels.has(channelId)) {
        queues.delete(channelId);
        continue;
      }
      if (atLimit.has(channelId) && !retryAtLimit) continue;
      // In order: the watchtower needs the channel before its revocations, and the close comes last. A channel
      // whose update fails waits for the retry; the other channels still go now.
      for (const kind of ["watch", "revoke", "unwatch"] as const) {
        const update = queue[kind];
        if (!update || stopped) continue;
        try {
          await withTimeout(options.send(update), options.sendTimeoutMs ?? 30_000, "KeyWay's watchtower did not answer in time");
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          const notWatched = kind === "revoke" && /not watched/i.test(message);
          if (notWatched && !queue.watch && !queue.reregistered) {
            // KeyWay doesn't know this channel (e.g. it was opened before this SDK version): register it first. A
            // lookup that fails is tried again; one that finds nothing ends the attempts.
            try {
              const registration = await options.registration?.(channelId);
              queue.reregistered = true;
              if (registration?.operation === "watch") queue.watch = registration;
            } catch {
              // Retried with the update.
            }
          } else if (kind === "watch" && (error as { status?: unknown })?.status === 400 && LIMIT.test(message)) {
            if (queue.unwatch) {
              // Already closed: there is nothing left to register.
              queues.delete(channelId);
              atLimit.delete(channelId);
            } else {
              if (!atLimit.has(channelId)) log.warn(`[keyway] watchtower: KeyWay is at this account's channel limit and won't watch channel ${channelId} yet`, message);
              atLimit.add(channelId);
            }
            break;
          } else if (refused(error, message) || (notWatched && queue.reregistered && !queue.watch)) {
            log.warn(`[keyway] watchtower: KeyWay refused ${kind} for channel ${channelId}`, message);
            if (kind === "watch") rejectedChannels.add(channelId);
            if (queue[kind] === update) delete queue[kind];
            if (kind === "watch") break;
            continue;
          }
          log.warn(`[keyway] watchtower: could not update KeyWay's watchtower for channel ${channelId}; retrying`, message);
          const wait = (error as { status?: unknown })?.status === 429 ? /Try again in (\d+) seconds/i.exec(message) : null;
          if (wait) retryAfterMs = Math.max(retryAfterMs ?? 0, 1000, Number(wait[1]) * 1000);
          failed = true;
          break;
        }
        // A send got through, so a failure after it starts the backoff over: a peer that keeps the updates coming
        // can't push the wait to its longest.
        attempt = 0;
        if (kind === "watch") atLimit.delete(channelId);
        // A newer update may have replaced this one while it was being sent.
        if (queue[kind] === update) delete queue[kind];
      }
      if (rejectedChannels.has(channelId) || (!queue.watch && !queue.revoke && !queue.unwatch && queues.get(channelId) === queue)) {
        queues.delete(channelId);
        atLimit.delete(channelId);
      }
    }
    if (failed) scheduleRetry();
  }

  function scheduleRetry() {
    if (retry || stopped) return;
    attempt += 1;
    // A rate-limited send is tried again when KeyWay says it can be, not after a growing wait.
    const delay = retryAfterMs ?? Math.min(5 * 60_000, (options.retryMs ?? 15_000) * 2 ** Math.min(attempt - 1, 5));
    retryAfterMs = undefined;
    retry = setTimeout(() => {
      retry = undefined;
      void run(false);
    }, delay);
  }

  /**
   * Sends what is queued. New updates (`force` false) go out at once unless a retry is waiting; `flush()` (e.g. when
   * the node stops) also cancels a waiting retry and runs after a pass already in progress.
   */
  function run(force: boolean): Promise<void> {
    if (stopped) return Promise.resolve();
    if (flushing) return force ? flushing.then(() => run(true)) : flushing;
    if (retry) {
      if (!force) return Promise.resolve();
      clearTimeout(retry);
      retry = undefined;
    }
    const pass = (async () => {
      // Each pass sends something, drops a refused update, sets a channel aside at the limit or schedules a retry,
      // so this ends. A flush starts with one pass that also tries the channels set aside.
      let retryAtLimit = force;
      while (!retry && !stopped && (retryAtLimit ? pending() : sendable()) > 0) {
        await flushOnce(retryAtLimit);
        retryAtLimit = false;
      }
      if (!retry) attempt = 0;
    })();
    // Cleared once the pass settles, never before it is set: a pass with nothing to send finishes at once.
    flushing = pass;
    const clear = () => { if (flushing === pass) flushing = undefined; };
    void pass.then(clear, clear);
    return pass;
  }
  const flush = () => run(true);

  async function deliver(timeoutMs: number) {
    await withTimeout(flush(), timeoutMs, "").catch(() => undefined);
    if (sendable() > 0) throw new Error("Fiber channel updates have not reached KeyWay's watchtower yet. Try again in a moment.");
    if (atLimit.size > 0) {
      throw new Error(`KeyWay's watchtower is already watching as many channels as it can for this account, so ${atLimit.size === 1 ? "a channel on this device isn't" : `${atLimit.size} channels on this device aren't`} watched. Close a channel, then try again.`);
    }
  }

  const waiting = (queue: ChannelQueue) => Boolean(queue.watch || queue.revoke || queue.unwatch);
  /** Channels with an update to send now: not those set aside at the limit. */
  function sendable() {
    return [...queues].filter(([channelId, queue]) => !atLimit.has(channelId) && waiting(queue)).length;
  }
  function pending() {
    return [...queues.values()].filter(waiting).length;
  }

  return {
    enqueue,
    flush,
    deliver,
    pending,
    stop() {
      stopped = true;
      if (retry) clearTimeout(retry);
      retry = undefined;
    },
  };
}

function withTimeout<T>(promise: Promise<T>, ms: number, message: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  return Promise.race([promise, new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error(message)), ms); })])
    .finally(() => clearTimeout(timer));
}
