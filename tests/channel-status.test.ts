import assert from "node:assert/strict";
import test from "node:test";
import { normalizeChannel } from "../src/sdk/browser/create-keyway.ts";

function channel(state_name: string) {
  return {
    channel_id: `0x${"aa".repeat(32)}`, is_public: true, is_acceptor: false, is_one_way: false, channel_outpoint: null,
    pubkey: `0x02${"bb".repeat(32)}`, funding_udt_type_script: null, state: { state_name },
    local_balance: "0x0", offered_tlc_balance: "0x0", remote_balance: "0x0", received_tlc_balance: "0x0", pending_tlcs: [],
    latest_commitment_transaction_hash: null, created_at: "0x0", enabled: true, tlc_expiry_delta: "0x0",
    tlc_fee_proportional_millionths: "0x0", shutdown_transaction_hash: null,
  } as unknown as Parameters<typeof normalizeChannel>[0];
}

test("reports a cooperatively closing channel as closing", () => {
  assert.equal(normalizeChannel(channel("SHUTTING_DOWN")).status, "closing");
});

test("keeps the other channel states", () => {
  assert.equal(normalizeChannel(channel("CHANNEL_READY")).status, "ready");
  assert.equal(normalizeChannel(channel("CLOSED")).status, "closed");
  assert.equal(normalizeChannel(channel("AWAITING_CHANNEL_READY")).status, "pending");
  assert.equal(normalizeChannel(channel("NEGOTIATING_FUNDING")).status, "pending");
});

// What the in-page watchtower has seen on-chain corrects what the node says (channel-closures.ts).
function funded(state_name: string) {
  // Fiber's `channel_outpoint` is the serialized out point (36 bytes of hex), whatever the SDK's types call it.
  return { ...channel(state_name), channel_outpoint: `0x${"cc".repeat(32)}00000000`, local_balance: "0x861c46800", remote_balance: "0x342770c00" } as unknown as Parameters<typeof normalizeChannel>[0];
}

test("a channel the node calls ready is closing, with nothing to send, once a force close has spent its funding cell", async () => {
  const { closureOf, withClosure } = await import("../src/sdk/browser/channel-closures.ts");
  const raw = funded("CHANNEL_READY");
  const seen = [{ channelId: `0x${"aa".repeat(32)}`, fundingOutPoint: `0x${"cc".repeat(32)}00000000`, closingTx: `0x${"dd".repeat(32)}`, seenAt: 0 }];
  const shown = withClosure(normalizeChannel(raw), closureOf(seen, raw));
  assert.equal(shown.status, "closing");
  assert.equal(shown.canSend, 0n);
  assert.equal(shown.canReceive, 0n);
  assert.equal(shown.capacity, 500n * 100_000_000n);
  assert.equal(shown.raw, raw, "Fiber's own channel object is untouched");
  // Finished on-chain: closed.
  const finished = [{ ...seen[0], finished: { status: "settled", evidence: `0x${"ee".repeat(32)}` } }];
  assert.equal(withClosure(normalizeChannel(raw), closureOf(finished, raw)).status, "closed");
  // The same holds while the node is still opening or cooperatively closing the channel.
  assert.equal(withClosure(normalizeChannel(funded("SHUTTING_DOWN")), closureOf(seen, raw)).canSend, 0n);
});

test("a closure applies only to its own channel and funding cell, and never changes a channel the node reports closed", async () => {
  const { closureOf, withClosure } = await import("../src/sdk/browser/channel-closures.ts");
  const raw = funded("CHANNEL_READY");
  const elsewhere = [
    { channelId: `0x${"ab".repeat(32)}`, fundingOutPoint: `0x${"cc".repeat(32)}00000000`, closingTx: "0x", seenAt: 0 },
    { channelId: `0x${"aa".repeat(32)}`, fundingOutPoint: `0x${"cd".repeat(32)}00000000`, closingTx: "0x", seenAt: 0 },
  ];
  assert.equal(closureOf(elsewhere, raw), undefined);
  const untouched = withClosure(normalizeChannel(raw), closureOf(elsewhere, raw));
  assert.equal(untouched.status, "ready");
  assert.equal(untouched.canSend, 360n * 100_000_000n);
  // A channel without a funding cell yet (still opening) matches nothing.
  assert.equal(closureOf([{ channelId: `0x${"aa".repeat(32)}`, fundingOutPoint: "", closingTx: "0x", seenAt: 0 }], channel("NEGOTIATING_FUNDING")), undefined);
  // Nor does a funding cell that isn't a serialized out point: no two channels may ever compare equal by accident.
  const odd = { ...raw, channel_outpoint: { tx_hash: `0x${"cc".repeat(32)}`, index: "0x0" } } as unknown as typeof raw;
  assert.equal(closureOf([{ channelId: `0x${"aa".repeat(32)}`, fundingOutPoint: "[object object]", closingTx: "0x", seenAt: 0 }], odd), undefined);
  const closed = normalizeChannel(funded("CLOSED"));
  assert.deepEqual(withClosure(closed, { finished: undefined }), closed);
});

test("normalizeChannel still maps over a channel list", () => {
  // Array.map passes the index as a second argument; it must not be read as anything.
  assert.deepEqual([funded("CHANNEL_READY"), funded("CHANNEL_READY")].map(normalizeChannel).map(({ status, canSend }) => [status, canSend]), [["ready", 360n * 100_000_000n], ["ready", 360n * 100_000_000n]]);
});
