import {
  closureOf, endWatch, recordChainVerdict, recordSettleResult, restoreWatch,
  type ChannelClosure, type ClosureStore, type WatchRecords,
} from "./channel-closures";
import { channelFinished, channelKey, closedBy } from "./settlement-sweep";
import type { ForceCloseOnChain, SettleFailure, SettleResult } from "./watchtower-settle";
import type { WatchedChannel } from "./watchtower-store";

/** A channel as the node lists it, as far as a pass reads it. */
type NodeChannel = { channel_id?: unknown; channel_outpoint?: unknown; shutdown_transaction_hash?: unknown; state: { state_name: string; state_flags?: unknown } };

/**
 * One pass of the in-page watchtower over every channel: what create-keyway.ts runs each minute, kept apart from
 * the node so it can be run against a chain alone.
 *
 * - Channels the watchtower holds a record of: one whose verdict stands and which the node reports closed by the
 *   same transaction is dropped again (Fiber hands a force-closed Channel V2 channel over at every start); every
 *   other one is looked at on-chain (`settle`), a claim is sent if one is due, and what was seen is recorded
 *   (`recordSettleResult`).
 * - Before that, records that were removed on a verdict since taken back are put back (`restoreWatch`).
 * - After it, channels of which there is no record at all (an earlier SDK removed it) are followed on-chain
 *   without one (`recordChainVerdict`): shown as closing once a commitment has spent their funding cell, and
 *   finished only when the node reports the close and nothing is left under the commitment lock.
 *
 * Returns whether this pass finished a channel, which is when the fee reserve may have become returnable.
 */
export async function watchChannels(deps: {
  watchtower: WatchRecords & { list(): Promise<WatchedChannel[]> };
  closures: ClosureStore;
  /** Every channel the node knows, closed ones included. */
  channels: NodeChannel[];
  gate: {
    settledForGood(closure: ChannelClosure | undefined, channel: NodeChannel): Promise<boolean>;
    holds(closure: ChannelClosure): Promise<boolean>;
  };
  /** One look at a watched channel on-chain, sending the claim that is due (watchtower-settle.ts `settleChannel`). */
  settle(channel: WatchedChannel, fundingOutPoint: string): Promise<SettleResult>;
  /** What the chain alone shows of a channel's close (watchtower-settle.ts `forceCloseSettled`). */
  follow(fundingOutPoint: string): Promise<ForceCloseOnChain>;
  isBuried(txHash: string): Promise<boolean>;
  /** True once the node is stopping: the pass ends at the next channel. */
  stopped?(): boolean;
  /** A claim was sent. */
  onClaim?(txHash: NonNullable<SettleResult["txHash"]>): void;
  /** The status last logged for each channel, so a pass says only what changed. */
  statuses?: Map<string, string>;
  /**
   * Told which channels the node lists, and each one whose funding cell this pass read and found no force close
   * on (live, or spent by a cooperative close): until then the channel list holds a ready channel back (first-look.ts).
   */
  looks?: { listed(channelIds: string[]): void; seenOpen(channelId: string): void };
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
  deps.looks?.listed(channels.map((channel) => channelKey(channel.channel_id)).filter((id): id is string => id !== undefined));
  const NOT_FORCE_CLOSED: ReadonlySet<string> = new Set(["open", "closed cooperatively"]);

  const seen: ChannelClosure[] = await closures.list().catch(() => []);
  // A verdict that was taken back after the watchtower's record had been removed: the watch starts again.
  await restoreWatch({ closures: seen, watchtower }).catch((error) => console.warn("[keyway] watchtower: could not put back a channel whose verdict was taken back; the next pass tries again", error));
  if (stopped()) return { finished };
  const watched = await watchtower.list();
  const recorded = new Set(watched.map((channel) => channel.channelId));

  /** Records what was seen of a channel on-chain (channel-closures.ts); true when that finished the channel. */
  const note = async (channelId: string, result: SettleResult, fundingOutPoint: string, raw: NodeChannel): Promise<boolean> => {
    try {
      const done = await recordSettleResult({ result, fundingOutPoint, closures, watchtower, nodeClosedBy: closedBy(raw), isBuried: deps.isBuried });
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
    const closure = raw ? closureOf(seen, raw) : undefined;
    if (raw && closure && await deps.gate.settledForGood(closure, raw)) {
      await endWatch({ closure, closures, watchtower }).catch(() => undefined);
      continue;
    }
    if (!raw || !outpoint) {
      say(channel.channelId, "missing", () => console.warn(`[keyway] watchtower: channel ${channel.channelId} is not in the node's channel list; it can't be checked until it is`));
      continue;
    }
    try {
      const result = await deps.settle(channel, outpoint);
      say(channel.channelId, result.status, () => console.info(`[keyway] watchtower: channel ${channel.channelId}: ${result.status}${result.txHash ? ` ${result.txHash}` : ""}`));
      if (result.txHash) deps.onClaim?.(result.txHash);
      if (result.closingTx === undefined && NOT_FORCE_CLOSED.has(result.status)) deps.looks?.seenOpen(channel.channelId);
      // Remembers a force close seen on-chain and, once the channel is finished for good, ends its watch.
      if (await note(channel.channelId, result, outpoint, raw)) finished = true;
    } catch (error) {
      const failure = error as SettleFailure | undefined;
      // No cell on the node's key to pay the fee with is not a passing failure: said once, in so many words.
      if (failure?.noFeeCell) {
        console.warn(`[keyway] watchtower: channel ${channel.channelId} has funds to claim on-chain, but the claim can't be sent: the node's key (${failure.noFeeCell.address}) holds no CKB cell to pay its fee with. The claim is tried again every minute and goes through once the node's key holds a fee cell; opening a channel sends one (the 62 CKB fee reserve).`);
      } else console.warn(`[keyway] watchtower: channel ${channel.channelId} could not be settled yet`, error);
      // A claim that couldn't be built or sent (no fee cell, an RPC error) doesn't unsee the close.
      // And a claim that was due contradicts any verdict that nothing is left.
      if (failure?.closingTx) {
        await note(channel.channelId, { channelId: channel.channelId, status: "could not be settled yet", closingTx: failure.closingTx, ...(failure.unsettled ? { unsettled: true as const } : {}) }, outpoint, raw);
      }
    }
  }
  if (stopped()) return { finished };

  // Channels the watchtower has no record of (an earlier SDK removed it, or the channel predates the in-page
  // watchtower): followed on the chain alone. A commitment that spent the funding cell is recorded, so the channel
  // stops showing as ready; finished only when the node reports the close and nothing is left under the commitment lock.
  const now = await closures.list().catch(() => undefined);
  if (!now) return { finished };
  for (const raw of channels) {
    if (stopped()) return { finished };
    const channelId = channelKey(raw.channel_id);
    if (channelId === undefined || recorded.has(channelId) || channelFinished(raw) || !raw.channel_outpoint) continue;
    const closure = closureOf(now, raw);
    // Its record is kept and on its way back to the watchtower, which can do more than follow.
    if (closure?.record && !closure.finished) continue;
    if (closure?.finished && closure.closingTx === closedBy(raw) && await deps.gate.holds(closure)) continue;
    try {
      const follow = async (fundingOutPoint: string) => {
        const found = await deps.follow(fundingOutPoint);
        if (found.notForceClosed) deps.looks?.seenOpen(channelId);
        return found;
      };
      if (await recordChainVerdict({ channel: raw, follow, closures, watchtower, isBuried: deps.isBuried })) {
        finished = true;
        console.info(`[keyway] watchtower: channel ${channelId}, of which no record is left, has nothing under its commitment lock any more; it is finished on-chain`);
      }
    } catch (error) {
      console.warn(`[keyway] watchtower: channel ${channelId} could not be followed on-chain yet`, error);
    }
  }
  return { finished };
}
