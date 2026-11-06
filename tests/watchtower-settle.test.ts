import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import * as ccc from "@ckb-ccc/core";
import { JsonRpcTransformers } from "@ckb-ccc/core/advanced";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import {
  applyUnlocks, blake160, encodeSettlementWitness, encodeWitnessState, parseCommitmentArgs, parseSettlementWitness,
  planClaim, settlementMessage, signSettlement, XUDT_COMPATIBLE_WITNESS,
} from "../src/sdk/browser/watchtower-settle.ts";
import type { WatchedChannel } from "../src/sdk/browser/watchtower-store.ts";

// The commitment and the peer's settlement from the 2026-10-28 browser force close on CKB testnet.
const run2 = JSON.parse(readFileSync(new URL("./fixtures/fiber-settlement-run2.json", import.meta.url), "utf8"));
const commitment = JsonRpcTransformers.transactionTo(run2.commitment.transaction);
const peerSettlement = JsonRpcTransformers.transactionTo(run2.peerSettlement.transaction);
const hex = (bytes: Uint8Array) => ccc.hexFrom(bytes);
const CKB = 100_000_000n;

test("the fixture transactions are the real ones", () => {
  assert.equal(commitment.hash(), run2.commitment.hash);
  assert.equal(peerSettlement.hash(), run2.peerSettlement.hash);
});

test("reads the commitment lock args Fiber wrote on-chain", () => {
  const args = parseCommitmentArgs(commitment.outputs[0].lock.args);
  assert.equal(args.delaySince, 0xa000010000000001n);
  assert.equal(args.commitmentNumber, 1n);
  assert.equal(hex(args.witnessHash), "0x8c180a2fdadeb82536e365d5b41e0e4930361b03");
});

test("decodes the peer's settlement witness and reproduces the successor commitment's args", () => {
  const witness = ccc.bytesFrom(peerSettlement.witnesses[0]);
  assert.equal(hex(witness.slice(0, 16)), hex(XUDT_COMPATIBLE_WITNESS));
  const parsed = parseSettlementWitness(witness.slice(16))!;
  assert.equal(parsed.pendingTlcs.length, 0);
  assert.equal(hex(parsed.first.pubkeyHash), "0x2c06cf190af53acc02d62e609383c7a0f4d9edd0");
  assert.equal(parsed.first.amount, 500n * CKB);
  assert.equal(hex(parsed.second.pubkeyHash), "0xef7bbbb41e5a46011792e9569035a3f706359186");
  assert.equal(parsed.second.amount, 250n * CKB);
  assert.deepEqual(parsed.unlocks, [{ type: 0xff, withPreimage: false }]);
  // Before the unlock, the witness hashes to the commitment's own lock args.
  assert.equal(hex(blake160(encodeWitnessState(parsed))), "0x8c180a2fdadeb82536e365d5b41e0e4930361b03");
  // After it, to the successor cell's args, which then end in 0x01.
  const next = applyUnlocks(parsed)!;
  const successorArgs = ccc.bytesFrom(peerSettlement.outputs[0].lock.args);
  assert.equal(hex(blake160(encodeWitnessState(next))), hex(successorArgs.slice(36, 56)));
  assert.equal(hex(successorArgs.slice(0, 36)), hex(ccc.bytesFrom(commitment.outputs[0].lock.args).slice(0, 36)));
  assert.equal(successorArgs[56], 1);
});

test("the settlement signature signs the transaction without cell deps, as r || s || recovery id", () => {
  const witness = ccc.bytesFrom(peerSettlement.witnesses[0]);
  const signature = witness.slice(witness.length - 65);
  const message = ccc.bytesFrom(settlementMessage(peerSettlement));
  const recovered = secp256k1.Signature.fromBytes(signature.slice(0, 64), "compact").addRecoveryBit(signature[64]).recoverPublicKey(message).toBytes(true);
  // The peer signed with the key behind the slot it claimed.
  assert.equal(hex(blake160(recovered)), "0xef7bbbb41e5a46011792e9569035a3f706359186");
});

/** A channel like a KeyWay browser channel: the user funded 500 CKB, the peer 250 CKB. */
function channelFixture() {
  const localSettlementKey = hex(secp256k1.utils.randomSecretKey());
  const remoteKey = secp256k1.utils.randomSecretKey();
  const localSettlement = { local_amount: "0xba43b7400", remote_amount: "0x5d21dba00", tlcs: [] };
  const remoteSettlement = { local_amount: "0xba43b7400", remote_amount: "0x5d21dba00", tlcs: [] };
  const channel: Pick<WatchedChannel, "localSettlementKey" | "remoteSettlementKey" | "localSettlement" | "remoteSettlement" | "pendingRemoteSettlement"> = {
    localSettlementKey, remoteSettlementKey: hex(secp256k1.getPublicKey(remoteKey, true)), localSettlement, remoteSettlement,
  };
  const prefix = ccc.bytesFrom(commitment.outputs[0].lock.args).slice(0, 36);
  const argsFor = (witness: Uint8Array) => hex(ccc.bytesConcat(prefix, blake160(witness), new Uint8Array([0])));
  return { channel, remoteKey, argsFor };
}

test("after the delay, the node's own commitment is claimed first: the user's share out, the peer's stays locked", () => {
  const { channel, argsFor } = channelFixture();
  const ours = encodeSettlementWitness(channel.localSettlement, false, channel.localSettlementKey, channel.remoteSettlementKey);
  const capacity = 75_000_000_000n - 456n;
  const decision = planClaim({ channel, cell: { capacity, args: argsFor(ours) } });
  assert.ok("claim" in decision);
  const { claim } = decision;
  assert.equal(claim.unlockType, 0xfe);
  assert.equal(claim.since, 0xa000010000000001n);
  assert.deepEqual(claim.witnessState, ours);
  // The peer's 250 CKB (less the commitment fee) stays under the commitment lock with the user's slot emptied.
  assert.equal(claim.successor?.capacity, capacity - 500n * CKB);
  const emptied = applyUnlocks({ ...parseSettlementWitness(ours, false)!, unlocks: [{ type: 0xfe, withPreimage: false }] })!;
  assert.equal(ccc.bytesFrom(claim.successor!.args).slice(36, 56).join(), blake160(encodeWitnessState(emptied)).join());
});

test("when the peer settled first, the node claims the rest of the cell without waiting", () => {
  const { channel, argsFor } = channelFixture();
  const ours = encodeSettlementWitness(channel.localSettlement, false, channel.localSettlementKey, channel.remoteSettlementKey);
  assert.ok(argsFor(ours));
  // The peer's settlement witness: unlock count, our witness, then its 0xFF unlock.
  const previous = ccc.bytesConcat(new Uint8Array([1]), ours, new Uint8Array([0xff, 0]), new Uint8Array(65));
  const decision = planClaim({ channel, cell: { capacity: 49_999_999_544n, args: "0x" + "00".repeat(57) }, previousWitness: previous });
  assert.ok("claim" in decision);
  assert.equal(decision.claim.unlockType, 0xfe);
  assert.equal(decision.claim.since, 0n);
  assert.equal(decision.claim.successor, undefined);
});

test("the peer's commitment is matched with the peer's settlement data", () => {
  const { channel, argsFor } = channelFixture();
  const theirs = encodeSettlementWitness(channel.remoteSettlement!, true, channel.localSettlementKey, channel.remoteSettlementKey);
  const decision = planClaim({ channel, cell: { capacity: 75_000_000_000n, args: argsFor(theirs) } });
  assert.ok("claim" in decision);
  assert.equal(decision.claim.unlockType, 0xff);
});

test("an unknown or revoked commitment, pending TLCs, or an already claimed share is left alone", () => {
  const { channel, argsFor } = channelFixture();
  assert.ok("skip" in planClaim({ channel, cell: { capacity: 1n, args: argsFor(new Uint8Array([0])) } }));
  const withTlc = {
    ...channel,
    localSettlement: {
      ...channel.localSettlement,
      tlcs: [{
        tlc_id: { Offered: "0x0" }, hash_algorithm: "CkbHash", payment_amount: "0x1", payment_hash: hex(new Uint8Array(32).fill(7)), expiry: "0x19a5d6b6000",
        local_key: hex(secp256k1.utils.randomSecretKey()).slice(2), remote_key: channel.remoteSettlementKey.slice(2),
      }],
    },
  };
  const tlcWitness = encodeSettlementWitness(withTlc.localSettlement, false, withTlc.localSettlementKey, withTlc.remoteSettlementKey);
  const pending = planClaim({ channel: withTlc, cell: { capacity: 75_000_000_000n, args: argsFor(tlcWitness) } });
  assert.ok("skip" in pending && /TLC/.test(pending.skip));
  const ours = encodeSettlementWitness(channel.localSettlement, false, channel.localSettlementKey, channel.remoteSettlementKey);
  const claimed = ccc.bytesConcat(new Uint8Array([1]), ours, new Uint8Array([0xfe, 0]), new Uint8Array(65));
  assert.ok("skip" in planClaim({ channel, cell: { capacity: 25_000_000_000n, args: "0x" + "00".repeat(57) }, previousWitness: claimed }));
});

test("signs the commitment input with the channel's settlement key", () => {
  const key = secp256k1.utils.randomSecretKey();
  const tx = ccc.Transaction.from({
    cellDeps: [{ outPoint: { txHash: "0x" + "11".repeat(32), index: 0 }, depType: "code" }],
    inputs: [{ previousOutput: { txHash: commitment.hash(), index: 0 } }],
    outputs: [{ capacity: 100n, lock: commitment.outputs[0].lock }],
    outputsData: ["0x"],
    witnesses: [hex(ccc.bytesConcat(XUDT_COMPATIBLE_WITNESS, new Uint8Array([1, 0xfe, 0]), new Uint8Array(65)))],
  });
  signSettlement(tx, key);
  const witness = ccc.bytesFrom(tx.witnesses[0]);
  const signature = witness.slice(witness.length - 65);
  const recovered = secp256k1.Signature.fromBytes(signature.slice(0, 64), "compact").addRecoveryBit(signature[64]).recoverPublicKey(ccc.bytesFrom(settlementMessage(tx))).toBytes(true);
  assert.deepEqual(recovered, secp256k1.getPublicKey(key, true));
  // Cell deps aren't signed, so they can be filled in later.
  const moved = tx.clone();
  moved.cellDeps = [];
  assert.equal(settlementMessage(moved), settlementMessage(tx));
});
