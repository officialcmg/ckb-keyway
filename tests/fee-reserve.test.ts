import assert from "node:assert/strict";
import test from "node:test";
import { FEE_RESERVE, needsFeeReserve, needsFeeReserveOnChain, planSweep } from "../src/sdk/browser/settlement-sweep.ts";

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

test("a force close the chain shows as fully settled gives the reserve back, though the browser node still says waiting", async () => {
  // What Fiber 0.10.1's browser node reported on testnet (2026-11-18) for a force-closed channel, from the claim of
  // the user's share on: it never drops WAITING_ONCHAIN_SETTLEMENT.
  const waiting = { ...channel("CLOSED", "UNCOOPERATIVE_LOCAL|WAITING_ONCHAIN_SETTLEMENT"), channel_outpoint: "0xaa" };
  const asked: string[] = [];
  const chain = (settled: boolean) => async (outpoint: string) => { asked.push(outpoint); return settled; };
  assert.equal(await needsFeeReserveOnChain([waiting], chain(true)), false);
  assert.deepEqual(asked, ["0xaa"]);
  // Something is still locked under the channel's commitment: the reserve may have to pay for a claim.
  assert.equal(await needsFeeReserveOnChain([waiting], chain(false)), true);
  // The chain couldn't be asked, or the node gave no funding cell to follow: the reserve stays.
  assert.equal(await needsFeeReserveOnChain([waiting], async () => { throw new Error("offline"); }), true);
  assert.equal(await needsFeeReserveOnChain([channel("CLOSED", "UNCOOPERATIVE_LOCAL|WAITING_ONCHAIN_SETTLEMENT")], chain(true)), true);
  // Only a channel closed by force and waiting is ever judged by the chain: any other unfinished channel keeps it.
  asked.length = 0;
  assert.equal(await needsFeeReserveOnChain([{ ...channel("CHANNEL_READY"), channel_outpoint: "0xbb" }], chain(true)), true);
  assert.equal(await needsFeeReserveOnChain([{ ...channel("SHUTTING_DOWN", "WAITING_COMMITMENT_CONFIRMATION"), channel_outpoint: "0xcc" }], chain(true)), true);
  assert.deepEqual(asked, []);
  assert.equal(await needsFeeReserveOnChain([waiting, { ...channel("CHANNEL_READY"), channel_outpoint: "0xbb" }], chain(true)), true);
  assert.equal(await needsFeeReserveOnChain([waiting, channel("CLOSED", "COOPERATIVE"), channel("CLOSED", "UNCOOPERATIVE_REMOTE")], chain(true)), false);
  assert.equal(await needsFeeReserveOnChain([], chain(true)), false);
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
