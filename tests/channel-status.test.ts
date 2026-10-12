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
