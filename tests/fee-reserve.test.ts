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
  assert.equal(needsFeeReserve([channel("CLOSED", "UNCOOPERATIVE_LOCAL | WAITING_ONCHAIN_SETTLEMENT | ONCHAIN_SETTLEMENT_CONFIRMED")]), false);
  assert.equal(needsFeeReserve([channel("CLOSED", "COOPERATIVE"), channel("CHANNEL_READY")]), true);
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
