import assert from "node:assert/strict";
import test from "node:test";
import { FEE_RESERVE, needsFeeReserve, planSweep } from "../src/sdk/browser/settlement-sweep.ts";

const CKB = 100_000_000n;
const channel = (state_name: string, state_flags?: string) => ({ state: { state_name, state_flags } });

test("the reserve stays while any channel is open, closing or waiting to settle on-chain", () => {
  assert.equal(needsFeeReserve([]), false);
  assert.equal(needsFeeReserve([channel("CHANNEL_READY")]), true);
  assert.equal(needsFeeReserve([channel("SHUTTING_DOWN", "WAITING_COMMITMENT_CONFIRMATION")]), true);
  assert.equal(needsFeeReserve([channel("CLOSED", "UNCOOPERATIVE_LOCAL | WAITING_ONCHAIN_SETTLEMENT")]), true);
  assert.equal(needsFeeReserve([channel("CLOSED", "COOPERATIVE")]), false);
  // Fiber keeps WAITING_ONCHAIN_SETTLEMENT while its settlement still has work to do, whatever else is set.
  assert.equal(needsFeeReserve([channel("CLOSED", "UNCOOPERATIVE_LOCAL | WAITING_ONCHAIN_SETTLEMENT | ONCHAIN_SETTLEMENT_CONFIRMED")]), true);
  assert.equal(needsFeeReserve([channel("CLOSED", "COOPERATIVE"), channel("CHANNEL_READY")]), true);
  // As Fiber 0.9.1 reports a force close once it has settled: the reserve comes back.
  assert.equal(needsFeeReserve([channel("CLOSED", "UNCOOPERATIVE_LOCAL|WAITING_ONCHAIN_SETTLEMENT")]), true);
  assert.equal(needsFeeReserve([channel("CLOSED", "UNCOOPERATIVE_LOCAL")]), false);
  assert.equal(needsFeeReserve([channel("CLOSED", "UNCOOPERATIVE_REMOTE")]), false);
});

test("a sweep keeps the reserve and sends the rest of a settlement to the user", () => {
  assert.deepEqual(planSweep(FEE_RESERVE + 500n * CKB, 0, FEE_RESERVE), { toUser: 500n * CKB, reserve: FEE_RESERVE });
});

test("a sweep leaves the reserve alone when nothing else has arrived", () => {
  assert.equal(planSweep(FEE_RESERVE, 0, FEE_RESERVE), undefined);
  // Dust that can't be a cell of its own stays with the reserve.
  assert.equal(planSweep(FEE_RESERVE + 10n * CKB, 0, FEE_RESERVE), undefined);
});

test("a sweep still moves tokens while keeping the reserve", () => {
  assert.deepEqual(planSweep(FEE_RESERVE, 1, FEE_RESERVE), { toUser: 0n, reserve: FEE_RESERVE });
});

test("once every channel is closed, the reserve goes back to the user too", () => {
  assert.deepEqual(planSweep(FEE_RESERVE, 0, 0n), { toUser: FEE_RESERVE, reserve: 0n });
});

// Fiber 0.10.1's browser node never drops WAITING_ONCHAIN_SETTLEMENT from a force-closed channel, so the in-page
// watchtower's verdict that a channel is finished on-chain stands in for it (channel-closures.ts).
const ID = `0x${"0a".repeat(32)}`;
const OUTPOINT = `0x${"0b".repeat(32)}00000000`;
const listed = (state_name: string, state_flags?: string, id = ID, outPoint = OUTPOINT) => ({ channel_id: id, channel_outpoint: outPoint, state: { state_name, state_flags } });
const verdict = (finished: boolean, id = ID, outPoint = OUTPOINT) => ({ channelId: id, fundingOutPoint: outPoint, ...(finished ? { finished: { status: "settled", evidence: `0x${"0c".repeat(32)}` } } : {}) });
const WAITING = "UNCOOPERATIVE_REMOTE|WAITING_ONCHAIN_SETTLEMENT";

test("a force-closed channel the node keeps waiting on, which the watchtower found finished on-chain, releases the reserve", () => {
  assert.equal(needsFeeReserve([listed("CLOSED", WAITING)], [verdict(true)]), false);
  assert.equal(needsFeeReserve([listed("CLOSED", "UNCOOPERATIVE_LOCAL|WAITING_ONCHAIN_SETTLEMENT")], [verdict(true)]), false);
  assert.equal(needsFeeReserve([listed("CLOSED", WAITING), listed("CLOSED", "COOPERATIVE", `0x${"1a".repeat(32)}`)], [verdict(true)]), false);
});

test("the reserve stays unless every channel is finished, each on positive evidence about that channel", () => {
  // No verdict, or a force close the watchtower has seen but not found finished (the user's share is unclaimed).
  assert.equal(needsFeeReserve([listed("CLOSED", WAITING)]), true);
  assert.equal(needsFeeReserve([listed("CLOSED", WAITING)], []), true);
  assert.equal(needsFeeReserve([listed("CLOSED", WAITING)], [verdict(false)]), true);
  // A verdict about another channel, or about this channel ID on another funding cell.
  assert.equal(needsFeeReserve([listed("CLOSED", WAITING)], [verdict(true, `0x${"1a".repeat(32)}`)]), true);
  assert.equal(needsFeeReserve([listed("CLOSED", WAITING)], [verdict(true, ID, `0x${"1b".repeat(32)}00000000`)]), true);
  // One finished channel doesn't release the reserve another still needs.
  assert.equal(needsFeeReserve([listed("CLOSED", WAITING), listed("CLOSED", WAITING, `0x${"1a".repeat(32)}`)], [verdict(true)]), true);
  assert.equal(needsFeeReserve([listed("CLOSED", WAITING), listed("CHANNEL_READY", undefined, `0x${"1a".repeat(32)}`)], [verdict(true)]), true);
  // The node must itself report the channel closed: a verdict alone doesn't release it.
  assert.equal(needsFeeReserve([listed("CHANNEL_READY")], [verdict(true)]), true);
  assert.equal(needsFeeReserve([listed("SHUTTING_DOWN", "WAITING_COMMITMENT_CONFIRMATION")], [verdict(true)]), true);
  // A channel the node lists without an ID or funding cell can't be matched to any verdict.
  assert.equal(needsFeeReserve([{ state: { state_name: "CLOSED", state_flags: WAITING } }], [verdict(true, "", "")]), true);
});
