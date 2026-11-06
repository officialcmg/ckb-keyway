import assert from "node:assert/strict";
import test from "node:test";
import { forAccount, forChannel, loadSettlementState } from "../research/e2e/settlement-state.mjs";

const finishedRun = {
  email: "st-old@example.test", password: "x", address: "ckt1old", channelId: "0xold",
  funding: { txHash: "0xfunding", index: 0 }, feeReserveTxHash: null, forceCloseAt: "2026-11-01 10:00:00",
  commitment: "0xoldcommitment", userScript: { code_hash: "0xold", args: "0xold" }, finished: true,
};

test("a fresh settlement run never inherits a finished run's commitment", () => {
  const state = loadSettlementState(JSON.stringify(finishedRun));
  assert.deepEqual(state, {});
  // Even if the old run never got as far as finishing, a new account and channel drop what it found.
  const unfinished = loadSettlementState(JSON.stringify({ ...finishedRun, finished: undefined }));
  forAccount(unfinished, "ckt1new");
  forChannel(unfinished, "0xnew");
  assert.equal(unfinished.commitment, undefined);
  assert.equal(unfinished.userScript, undefined);
  assert.equal(unfinished.forceCloseAt, undefined);
  assert.equal(unfinished.address, "ckt1new");
  assert.equal(unfinished.channelId, "0xnew");
});

test("a run restarted on the same account and channel keeps what it found", () => {
  const state = loadSettlementState(JSON.stringify({ ...finishedRun, finished: undefined }));
  forAccount(state, "ckt1old");
  forChannel(state, "0xold");
  assert.equal(state.commitment, "0xoldcommitment");
  assert.deepEqual(state.funding, { txHash: "0xfunding", index: 0 });
  assert.deepEqual(state.userScript, { code_hash: "0xold", args: "0xold" });
  // The same account with a new channel keeps the account but not the old channel's commitment.
  forChannel(state, "0xsecond");
  assert.equal(state.commitment, undefined);
  assert.deepEqual(state.userScript, { code_hash: "0xold", args: "0xold" });
});

test("a missing or unreadable state file starts from nothing", () => {
  assert.deepEqual(loadSettlementState(undefined), {});
  assert.deepEqual(loadSettlementState("{not json"), {});
  assert.deepEqual(loadSettlementState("[]"), {});
});
