import assert from "node:assert/strict";
import test from "node:test";
import { forAccount, forChannel, loadSettlementState, resumableRun, startupPlan } from "../research/e2e/settlement-state.mjs";

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
  for (const scalar of ["null", "42", '"state"', "true"]) assert.deepEqual(loadSettlementState(scalar), {}, scalar);
});

test("a restart resumes an unfinished run that reached its force close, on the same account and channel", () => {
  const saved = { ...finishedRun, finished: undefined };
  const state = loadSettlementState(JSON.stringify(saved));
  assert.equal(resumableRun(state), true);
  // Signing in again to the saved account keeps the channel, its funding and the commitment found so far.
  forAccount(state, saved.address);
  assert.equal(state.channelId, saved.channelId);
  assert.equal(state.commitment, saved.commitment);
  assert.deepEqual(state.funding, saved.funding);
  // A finished run, or one that never opened its channel, starts fresh.
  assert.equal(resumableRun(loadSettlementState(JSON.stringify(finishedRun))), false);
  assert.equal(resumableRun(loadSettlementState(JSON.stringify({ ...saved, channelId: undefined, funding: undefined }))), false);
  assert.equal(resumableRun(loadSettlementState(JSON.stringify({ ...saved, password: undefined }))), false);
});

test("the script's startup plan: resume on the kept profile once a channel is saved, and force-close only if that hadn't happened", () => {
  const saved = { ...finishedRun, finished: undefined };
  const plan = (state: Record<string, unknown>) => startupPlan(loadSettlementState(JSON.stringify(state)));
  // No state, a finished run, or one stopped before its channel opened: a fresh account, channel and profile.
  const fresh = { resume: false, keepProfile: false, setUp: true, forceClose: true };
  assert.deepEqual(plan({}), fresh);
  assert.deepEqual(plan(finishedRun), fresh);
  assert.deepEqual(plan({ email: saved.email, password: saved.password, address: saved.address }), fresh);
  // Stopped after the channel opened but before the force close was recorded: same account, channel and profile,
  // and the force close still to do.
  assert.deepEqual(plan({ ...saved, forceCloseAt: undefined, commitment: undefined }), { resume: true, keepProfile: true, setUp: false, forceClose: true });
  // Stopped after the force close: only following remains.
  assert.deepEqual(plan(saved), { resume: true, keepProfile: true, setUp: false, forceClose: false });
});
