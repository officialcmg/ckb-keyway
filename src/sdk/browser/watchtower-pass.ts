import { closureOf, recordSettleResult, type ChannelClosure, type ClosureStore } from "./channel-closures";
import { closedBy } from "./settlement-sweep";
import type { SettleFailure, SettleResult } from "./watchtower-settle";
import type { WatchedChannel } from "./watchtower-store";

/** A channel as the node lists it, as far as a pass reads it. */
type NodeChannel = { channel_id?: unknown; channel_outpoint?: unknown; shutdown_transaction_hash?: unknown; state: { state_name: string; state_flags?: unknown } };

/**
 * One pass of the in-page watchtower over every channel it holds a record of: what create-keyway.ts runs each
 * minute, kept apart from the node so it can be run against a chain alone.
 *
 * A channel whose verdict stands and which the node reports closed by the same transaction is dropped again (Fiber
 * hands a force-closed Channel V2 channel over at every start); every other one is looked at on-chain (`settle`), a
 * claim is sent if one is due, and what was seen is recorded (`recordSettleResult`).
 *
 * Returns whether this pass finished a channel, which is when the fee reserve may have become returnable.
 */
export async function watchChannels(deps: {
  watchtower: { list(): Promise<WatchedChannel[]>; remove(channelId: string): Promise<void> };
  closures: ClosureStore;
  /** Every channel the node knows, closed ones included. */
  channels: NodeChannel[];
  gate: { settledForGood(closure: ChannelClosure | undefined, channel: NodeChannel): Promise<boolean> };
  /** One look at a watched channel on-chain, sending the claim that is due (watchtower-settle.ts `settleChannel`). */
  settle(channel: WatchedChannel, fundingOutPoint: string): Promise<SettleResult>;
  isBuried(txHash: string): Promise<boolean>;
  /** True once the node is stopping: the pass ends at the next channel. */
  stopped?(): boolean;
  /** A claim was sent. */
  onClaim?(txHash: NonNullable<SettleResult["txHash"]>): void;
  /** The status last logged for each channel, so a pass says only what changed. */
  statuses?: Map<string, string>;
}): Promise<{ finished: boolean }> {
  const { watchtower, closures, channels } = deps;
  const stopped = deps.stopped ?? (() => false);
  const statuses = deps.statuses ?? new Map<string, string>();
  const say = (channelId: string, status: string, log: () => void) => {
    if (statuses.get(channelId) === status) return;
    statuses.set(channelId, status);
    log();
  };
  let finished = false;

  const watched = await watchtower.list();
  if (stopped()) return { finished };
  const seen: ChannelClosure[] = watched.length > 0 ? await closures.list().catch(() => []) : [];

  /** Records what was seen of a channel on-chain (channel-closures.ts); true when that finished the channel. */
  const note = async (channelId: string, result: SettleResult, fundingOutPoint: string, raw: NodeChannel | undefined): Promise<boolean> => {
    try {
      const done = await recordSettleResult({ result, fundingOutPoint, closures, watchtower, nodeClosedBy: raw ? closedBy(raw) : undefined, isBuried: deps.isBuried });
      if (done) console.info(`[keyway] watchtower: channel ${channelId} is finished on-chain (${result.status}); nothing is left to claim`);
      return done;
    } catch (error) {
      console.warn(`[keyway] watchtower: could not record what channel ${channelId} looks like on-chain; the next pass tries again`, error);
      return false;
    }
  };

  for (const channel of watched) {
    if (stopped()) return { finished };
    const raw = channels.find((item) => String(item.channel_id).toLowerCase() === channel.channelId);
    const outpoint = raw?.channel_outpoint ? String(raw.channel_outpoint) : undefined;
    // Fiber hands a force-closed channel over again at every start; one finished for good needs no second look.
    if (raw && await deps.gate.settledForGood(closureOf(seen, raw), raw)) {
      await watchtower.remove(channel.channelId).catch(() => undefined);
      continue;
    }
    if (!outpoint) {
      say(channel.channelId, "missing", () => console.warn(`[keyway] watchtower: channel ${channel.channelId} is not in the node's channel list; it can't be checked until it is`));
      continue;
    }
    try {
      const result = await deps.settle(channel, outpoint);
      say(channel.channelId, result.status, () => console.info(`[keyway] watchtower: channel ${channel.channelId}: ${result.status}${result.txHash ? ` ${result.txHash}` : ""}`));
      if (result.txHash) deps.onClaim?.(result.txHash);
      // Remembers a force close seen on-chain and, once the channel is finished for good, ends its watch.
      if (await note(channel.channelId, result, outpoint, raw)) finished = true;
    } catch (error) {
      console.warn(`[keyway] watchtower: channel ${channel.channelId} could not be settled yet`, error);
      // A claim that couldn't be built or sent (no fee cell, an RPC error) doesn't unsee the close.
      // And a claim that was due contradicts any verdict that nothing is left.
      const failure = error as SettleFailure | undefined;
      if (failure?.closingTx) {
        await note(channel.channelId, { channelId: channel.channelId, status: "could not be settled yet", closingTx: failure.closingTx, ...(failure.unsettled ? { unsettled: true as const } : {}) }, outpoint, raw);
      }
    }
  }
  return { finished };
}
