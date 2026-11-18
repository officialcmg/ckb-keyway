import "fake-indexeddb/auto";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import * as ccc from "@ckb-ccc/core";
import { JsonRpcTransformers } from "@ckb-ccc/core/advanced";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import {
  applyUnlocks, blake160, delayFraction, encodeSettlementWitness, encodeWitnessState, epochDelayPassed, parseCommitmentArgs, parseSettlementWitness,
  planClaim, settleChannel, settlementMessage, signSettlement, trackNodeKeySends, XUDT_COMPATIBLE_WITNESS,
} from "../src/sdk/browser/watchtower-settle.ts";
import { normalizeChannel } from "../src/sdk/browser/create-keyway.ts";
import { needsFeeReserve } from "../src/sdk/browser/settlement-sweep.ts";
import { openWatchtowerStore, type WatchedChannel } from "../src/sdk/browser/watchtower-store.ts";
import { COMMITMENT_LOCK } from "../src/sdk/browser/watchtower-settle.ts";

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
  // The peer's settlement witness: unlock count, our witness, then its 0xFF unlock.
  const previous = ccc.bytesConcat(new Uint8Array([1]), ours, new Uint8Array([0xff, 0]), new Uint8Array(65));
  // The cell's args name the state after the peer's unlock, not the commitment's own: without the previous witness
  // the node can't tell what the cell holds, and leaves it alone.
  const successorArgs = ccc.hexFrom(ccc.bytesConcat(ccc.bytesFrom(argsFor(ours)).slice(0, 36), blake160(encodeWitnessState(applyUnlocks(parseSettlementWitness(previous)!)!)), new Uint8Array([1])));
  assert.notEqual(successorArgs, argsFor(ours));
  assert.ok("skip" in planClaim({ channel, cell: { capacity: 49_999_999_544n, args: successorArgs } }));
  const decision = planClaim({ channel, cell: { capacity: 49_999_999_544n, args: successorArgs }, previousWitness: previous });
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

test("an unknown or revoked commitment, or an already claimed share, is left alone", () => {
  const { channel, argsFor } = channelFixture();
  assert.ok("skip" in planClaim({ channel, cell: { capacity: 1n, args: argsFor(new Uint8Array([0])) } }));
  const ours = encodeSettlementWitness(channel.localSettlement, false, channel.localSettlementKey, channel.remoteSettlementKey);
  const claimed = ccc.bytesConcat(new Uint8Array([1]), ours, new Uint8Array([0xfe, 0]), new Uint8Array(65));
  assert.ok("skip" in planClaim({ channel, cell: { capacity: 25_000_000_000n, args: "0x" + "00".repeat(57) }, previousWitness: claimed }));
});

// A force close with payments still in flight. The user's node had offered one TLC (an outgoing payment) and
// received another (an incoming one) when the peer's commitment went on-chain.
const HOUR = 3_600_000;
const NOW = Date.parse("2026-11-11T12:00:00Z");
function tlcFixture(options: { offeredExpiry?: number; receivedExpiry?: number } = {}) {
  const { channel, remoteKey, argsFor } = channelFixture();
  const tlcKey = () => hex(secp256k1.utils.randomSecretKey()).slice(2);
  const peerTlcKey = () => hex(secp256k1.getPublicKey(secp256k1.utils.randomSecretKey(), true)).slice(2);
  const incomingPreimage = hex(new Uint8Array(32).fill(0x42));
  const outgoing = {
    tlc_id: { Offered: "0x0" }, hash_algorithm: "CkbHash", payment_amount: `0x${(180n * CKB).toString(16)}`, payment_hash: hex(new Uint8Array(32).fill(7)),
    expiry: `0x${(options.offeredExpiry ?? NOW - HOUR).toString(16)}`, local_key: tlcKey(), remote_key: peerTlcKey(),
  };
  const incoming = {
    tlc_id: { Received: "0x0" }, hash_algorithm: "CkbHash", payment_amount: `0x${(170n * CKB).toString(16)}`, payment_hash: ccc.hashCkb(incomingPreimage),
    expiry: `0x${(options.receivedExpiry ?? NOW + HOUR).toString(16)}`, local_key: tlcKey(), remote_key: peerTlcKey(),
  };
  const remoteSettlement = { ...channel.remoteSettlement!, tlcs: [outgoing, incoming] };
  const withTlcs = { ...channel, remoteSettlement };
  const theirs = encodeSettlementWitness(remoteSettlement, true, channel.localSettlementKey, channel.remoteSettlementKey);
  // 500 CKB of the user's, 250 of the peer's, and the two payments.
  const capacity = 1100n * CKB;
  return { channel: withTlcs, remoteKey, argsFor, theirs, capacity, outgoing, incoming, incomingPreimage, cell: { capacity, args: argsFor(theirs) } };
}

test("V2 settlements preserve all 32 hash bytes and the feature flag through a TLC claim", () => {
  const f = tlcFixture();
  const channel = { ...f.channel, channelFeatures: 1 as const };
  const witness = encodeSettlementWitness(channel.remoteSettlement, true, channel.localSettlementKey, channel.remoteSettlementKey, 1);
  assert.equal(witness.length, 1 + 2 * 97 + 72);
  assert.equal(hex(witness.slice(18, 50)), f.outgoing.payment_hash);
  const parsed = parseSettlementWitness(witness, false, 1)!;
  assert.equal(parsed.pendingTlcs[1].length, 97);
  assert.equal(hex(parsed.pendingTlcs[1].slice(17, 49)), f.incoming.payment_hash);
  const args = hex(ccc.bytesConcat(ccc.bytesFrom(f.argsFor(witness)), new Uint8Array([1])));
  assert.equal(parseCommitmentArgs(args).channelFeatures, 1);
  const decision = planClaim({ channel, cell: { capacity: f.capacity, args }, preimages: new Map([[f.incoming.payment_hash, f.incomingPreimage]]), now: NOW, delayPassed: () => true });
  assert.ok("claim" in decision);
  assert.equal(decision.claim.unlockType, 1);
  assert.equal(decision.claim.preimage, f.incomingPreimage);
  assert.equal(decision.claim.successor?.capacity, f.capacity - 170n * CKB);
  assert.equal(decision.claim.successor!.args.slice(-4), "0101");
  const after = applyUnlocks({ ...parsed, unlocks: [{ type: 1, withPreimage: true }] })!;
  assert.equal(hex(parseCommitmentArgs(decision.claim.successor!.args).witnessHash), hex(blake160(encodeWitnessState(after))));
  assert.ok("skip" in planClaim({ channel: f.channel, cell: { capacity: f.capacity, args }, now: NOW }));
  assert.throws(() => parseCommitmentArgs(args.slice(0, -2) + "02"), /Unsupported/);
});

test("an incoming payment in flight is claimed with its preimage once a third of the delay has passed", () => {
  const f = tlcFixture();
  const preimages = new Map([[f.incoming.payment_hash, f.incomingPreimage]]);
  const third = 0xa000030001000000n; // a third of the one-epoch delay, as the lock works it out
  const passed = new Set<bigint>();
  const plan = (now = NOW) => planClaim({ channel: f.channel, cell: f.cell, preimages, now, delayPassed: (since) => passed.has(since) });
  assert.deepEqual(plan(), { skip: "waiting for a pending payment to resolve" });
  passed.add(third);
  const decision = plan();
  assert.ok("claim" in decision);
  const { claim } = decision;
  assert.equal(claim.unlockType, 1, "the received TLC, the second pending one");
  assert.equal(claim.preimage, f.incomingPreimage);
  assert.equal(claim.since, third);
  assert.equal(claim.feeSince, undefined, "a preimage unlock carries no timestamp");
  assert.equal(claim.signingKey, `0x${f.incoming.local_key}`, "signed by the TLC's own key");
  // Everything else stays in a successor whose args name the state without that TLC.
  assert.equal(claim.successor?.capacity, f.capacity - 170n * CKB);
  const after = applyUnlocks({ ...parseSettlementWitness(f.theirs, false)!, unlocks: [{ type: 1, withPreimage: true }] })!;
  assert.equal(after.pendingTlcs.length, 1);
  assert.equal(hex(ccc.bytesFrom(claim.successor!.args).slice(36, 56)), hex(blake160(encodeWitnessState(after))));
  // Still claimed after it expires (the peer may not have taken it back yet), and a preimage that doesn't hash to the
  // payment hash is never used.
  assert.equal((planClaim({ channel: f.channel, cell: f.cell, preimages, now: NOW + 2 * HOUR }) as { claim: { unlockType: number } }).claim.unlockType, 1);
  const wrong = planClaim({ channel: f.channel, cell: f.cell, preimages: new Map([[f.incoming.payment_hash, hex(new Uint8Array(32).fill(1))]]), now: NOW });
  assert.ok("claim" in wrong && wrong.claim.unlockType !== 1);
});

test("an outgoing payment in flight is taken back once it expires, with its expiry on the fee inputs", () => {
  const f = tlcFixture({ offeredExpiry: NOW + HOUR });
  const twoThirds = 0xa000030002000000n;
  const passed = new Set<bigint>([twoThirds]);
  const plan = (now: number) => planClaim({ channel: f.channel, cell: f.cell, now, delayPassed: (since) => passed.has(since) });
  // Not expired yet: nothing can go, and the user's share waits for its payments.
  assert.deepEqual(plan(NOW), { skip: "waiting for a pending payment to resolve" });
  const decision = plan(NOW + 2 * HOUR);
  assert.ok("claim" in decision);
  assert.equal(decision.claim.unlockType, 0);
  assert.equal(decision.claim.preimage, undefined);
  assert.equal(decision.claim.since, twoThirds);
  assert.equal(decision.claim.signingKey, `0x${f.outgoing.local_key}`);
  const expiry = BigInt(Math.floor((NOW + HOUR) / 1000));
  assert.equal(decision.claim.feeSince, (0x40n << 56n) | expiry, "an absolute timestamp: the TLC's own expiry");
});

test("the most urgent payment goes first: one claimable with a preimage before one taken back after expiry", () => {
  const f = tlcFixture({ offeredExpiry: NOW - HOUR });
  const decision = planClaim({ channel: f.channel, cell: f.cell, preimages: new Map([[f.incoming.payment_hash, f.incomingPreimage]]), now: NOW });
  assert.ok("claim" in decision);
  assert.equal(decision.claim.unlockType, 1);
});

test("the user's share waits while a payment may still be the user's, since whoever settles second may take the cell", () => {
  // Neither payment is the node's to claim yet: no preimage, and the outgoing one hasn't expired.
  const f = tlcFixture({ offeredExpiry: NOW + HOUR });
  // With the user's slot emptied first, the peer (settling second) could sweep the cell, payments and all.
  assert.deepEqual(planClaim({ channel: f.channel, cell: f.cell, now: NOW }), { skip: "waiting for a pending payment to resolve" });
  // Once nothing remains that can become the user's (the outgoing one taken back, the incoming one expired without
  // its preimage), the share goes, and a successor keeps what is the peer's to take back.
  const resolved = tlcFixture({ receivedExpiry: NOW - HOUR, offeredExpiry: NOW + HOUR });
  const outgoingBack = ccc.bytesConcat(new Uint8Array([1]), resolved.theirs, new Uint8Array([0, 0]), new Uint8Array(65));
  const decision = planClaim({ channel: resolved.channel, cell: { capacity: resolved.capacity - 180n * CKB, args: "0x" + "00".repeat(57) }, previousWitness: outgoingBack, now: NOW });
  assert.ok("claim" in decision);
  assert.equal(decision.claim.unlockType, 0xff, "the user's slot on the peer's commitment");
  assert.equal(decision.claim.since, 0n);
  assert.equal(decision.claim.successor?.capacity, resolved.capacity - 180n * CKB - 500n * CKB);
  const after = applyUnlocks({ ...parseSettlementWitness(outgoingBack)!, unlocks: [{ type: 0, withPreimage: false }, { type: 0xff, withPreimage: false }] })!;
  assert.equal(after.pendingTlcs.length, 1);
  assert.equal(hex(ccc.bytesFrom(decision.claim.successor!.args).slice(36, 56)), hex(blake160(encodeWitnessState(after))));

  // The peer settles its share first: settling second, the user's claim takes the whole cell at once, payments
  // and all, as Fiber's does.
  const peerSettled = ccc.bytesConcat(new Uint8Array([1]), f.theirs, new Uint8Array([0xfe, 0]), new Uint8Array(65));
  const afterPeer = { capacity: f.capacity - 250n * CKB, args: "0x" + "00".repeat(57) };
  const whole = planClaim({ channel: f.channel, cell: afterPeer, previousWitness: peerSettled, now: NOW });
  assert.ok("claim" in whole && whole.claim.unlockType === 0xff && whole.claim.since === 0n);
  assert.equal(whole.claim.successor, undefined);
});

test("the delay's shares are worked out as the commitment lock does", () => {
  // fiber-scripts commitment-lock `mul` vectors: 7.6 epochs, 7 1/3 epochs, 10.5 epochs.
  const since = (number: bigint, index: bigint, length: bigint) => (0xa0n << 56n) | number | (index << 24n) | (length << 40n);
  assert.equal(delayFraction(since(7n, 60n, 100n), 1n, 3n), since(2n, 160n, 300n));
  assert.equal(delayFraction(since(7n, 60n, 100n), 2n, 3n), since(5n, 20n, 300n));
  assert.equal(delayFraction(since(7n, 700n, 2100n), 1n, 3n), since(2n, 700n, 1575n));
  assert.equal(delayFraction(since(7n, 700n, 2100n), 2n, 3n), since(4n, 1400n, 1575n));
  assert.equal(delayFraction(since(10n, 1n, 2n), 2n, 3n), since(7n, 0n, 6n));
  assert.equal(epochDelayPassed([100, 0, 1], since(0n, 1n, 3n), [100, 1, 3]), true);
  assert.equal(epochDelayPassed([100, 0, 1], since(0n, 1n, 3n), [100, 332, 1000]), false);
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

test("a peer remainder too small for its own commitment cell is not claimed (the transaction would be invalid)", () => {
  const { channel, argsFor } = channelFixture();
  const ours = encodeSettlementWitness(channel.localSettlement, false, channel.localSettlementKey, channel.remoteSettlementKey);
  const decision = planClaim({ channel, cell: { capacity: 500n * CKB + 50n * CKB, args: argsFor(ours) } });
  assert.ok("skip" in decision && /too small/.test(decision.skip));
});

/**
 * A chain for settleChannel: the funding transaction, the commitment that spent it, any settlements after it, and
 * the node's fee reserve, served by a fake client so the chain following, the delay and the claim are checked
 * without a network.
 */
function fakeChain(options: {
  peerSettledFirst?: boolean; settlementWitness?: (ours: Uint8Array) => Uint8Array; peerTookEverything?: boolean;
  /** The peer's commitment with payments in flight (tlcFixture) instead of the node's own. */
  tlcs?: ReturnType<typeof tlcFixture>; preimages?: Map<string, string>; now?: number;
  /** The chain's median block time (ms), answered to `get_block_median_time`. */
  medianTime?: () => number;
  /**
   * After the peer's settlement, a second one empties the cell (both slots settled, so the lock checks no output) and
   * also creates an unrelated cell under a lookalike commitment lock at output 1.
   */
  bothSettledWithDecoy?: boolean;
  /**
   * Sends go through ccc's own `sendTransaction` (and its cache); the node then never mines them unless `mined`
   * says so, and reports them as `pool` says (unknown, by default: dropped).
   */
  cachedSends?: { pool?: (hash: ccc.Hex) => "pending" | undefined };
  /** The commitment on-chain is the peer's latest one (an honest force close by the peer) instead of the node's own. */
  byPeer?: boolean;
  /** The commitment on-chain is one the peer had revoked: it matches none of the node's settlement data. */
  revoked?: boolean;
  /** After a revoked commitment: the penalty has spent it, paying the whole channel to the user's own lock. */
  penalized?: boolean;
  /** A token channel. */
  token?: boolean;
} = {}) {
  const { channel, argsFor } = options.tlcs ?? channelFixture();
  const ours = options.tlcs?.theirs
    ?? (options.revoked ? new Uint8Array([0, 9, 9, 9]) : undefined)
    ?? encodeSettlementWitness(options.byPeer ? channel.remoteSettlement! : channel.localSettlement, Boolean(options.byPeer), channel.localSettlementKey, channel.remoteSettlementKey);
  const nodeKey = hex(secp256k1.utils.randomSecretKey());
  const plainLock = { codeHash: "0x" + "00".repeat(32), hashType: "data" as const, args: "0x01" };
  const commitmentLock = (args: ccc.HexLike) => ({ codeHash: COMMITMENT_LOCK.testnet.codeHash, hashType: "type" as const, args });
  const txs = new Map<string, { tx: ccc.Transaction; blockHash: ccc.Hex; epoch: ccc.EpochLike; blockNumber: bigint }>();
  const live = new Set<string>();
  const key = (outPoint: ccc.OutPointLike) => `${ccc.hexFrom(ccc.OutPoint.from(outPoint).txHash)}:${Number(ccc.OutPoint.from(outPoint).index)}`;
  // Each transaction lands in a block of its own, at the chain's tip.
  let height = 0n;
  const add = (tx: ccc.Transaction, epoch: ccc.EpochLike = [90, 0, 1], blockNumber = ++height) => {
    txs.set(tx.hash(), { tx, blockHash: ccc.hexFrom(ccc.hashCkb(tx.hash())), epoch, blockNumber });
    for (const input of tx.inputs) live.delete(key(input.previousOutput));
    tx.outputs.forEach((_output, index) => live.add(key({ txHash: tx.hash(), index })));
    return tx;
  };
  const funding = add(ccc.Transaction.from({ outputs: [{ capacity: 751n * CKB, lock: plainLock }], outputsData: ["0x"] }));
  const commitmentTx = add(ccc.Transaction.from({
    inputs: [{ previousOutput: { txHash: funding.hash(), index: 0 } }],
    outputs: [{ capacity: options.tlcs?.capacity ?? 750n * CKB, lock: commitmentLock(argsFor(ours)) }],
    outputsData: ["0x"],
    witnesses: ["0x"],
  }), [100, 0, 1]);
  let liveCell = { txHash: commitmentTx.hash(), index: 0 };
  // The penalty: Fiber's revocation unlock (unlock count 0, commitment number, a key and the aggregated signature).
  const penaltyTx = options.penalized ? add(ccc.Transaction.from({
    inputs: [{ previousOutput: liveCell }],
    outputs: [{ capacity: 750n * CKB, lock: plainLock }],
    outputsData: ["0x"],
    witnesses: [ccc.hexFrom(ccc.bytesConcat(XUDT_COMPATIBLE_WITNESS, new Uint8Array([0]), new Uint8Array(8 + 32 + 64).fill(7)))],
  }), [100, 1, 2]) : undefined;
  if (options.peerSettledFirst || options.settlementWitness || options.peerTookEverything) {
    const previous = ccc.bytesConcat(new Uint8Array([1]), ours, new Uint8Array([0xff, 0]), new Uint8Array(65));
    const witness = options.settlementWitness ? options.settlementWitness(ours) : ccc.bytesConcat(XUDT_COMPATIBLE_WITNESS, previous);
    const after = blake160(encodeWitnessState(applyUnlocks(parseSettlementWitness(previous)!)!));
    const successorArgs = ccc.bytesConcat(ccc.bytesFrom(argsFor(ours)).slice(0, 36), after, new Uint8Array([1]));
    const settlement = add(ccc.Transaction.from({
      inputs: [{ previousOutput: liveCell }],
      outputs: options.peerTookEverything
        ? [{ capacity: 750n * CKB, lock: plainLock }]
        : [{ capacity: 500n * CKB, lock: commitmentLock(successorArgs) }, { capacity: 250n * CKB, lock: plainLock }],
      outputsData: options.peerTookEverything ? ["0x"] : ["0x", "0x"],
      witnesses: [ccc.hexFrom(witness)],
    }), [101, 0, 1]);
    liveCell = { txHash: settlement.hash(), index: 0 };
    if (options.bothSettledWithDecoy) {
      const afterPeer = applyUnlocks(parseSettlementWitness(previous)!)!;
      const last = add(ccc.Transaction.from({
        inputs: [{ previousOutput: liveCell }],
        outputs: [
          { capacity: 500n * CKB, lock: plainLock },
          { capacity: 100n * CKB, lock: commitmentLock(ccc.bytesConcat(ccc.bytesFrom(argsFor(ours)).slice(0, 36), new Uint8Array(20).fill(9), new Uint8Array([1]))) },
        ],
        outputsData: ["0x", "0x"],
        witnesses: [ccc.hexFrom(ccc.bytesConcat(XUDT_COMPATIBLE_WITNESS, new Uint8Array([1]), encodeWitnessState(afterPeer), new Uint8Array([0xfe, 0]), new Uint8Array(65)))],
      }), [102, 0, 1]);
      liveCell = { txHash: last.hash(), index: 1 };
    }
  }
  let tip: ccc.EpochLike = [100, 0, 1];
  const sent: ccc.Transaction[] = [];
  const base = new ccc.ClientPublicTestnet({ url: "http://127.0.0.1:9/" });
  const signer = new ccc.SignerCkbPrivateKey(base, nodeKey);
  const ready = (async () => {
    const nodeLock = (await signer.getRecommendedAddressObj()).script;
    // The node's fee reserve, from before the channel's funding.
    add(ccc.Transaction.from({ outputs: [{ capacity: 200n * CKB, lock: nodeLock }], outputsData: ["0x"] }), undefined, 0n);
    return nodeLock;
  })();
  const overrides: Record<string, unknown> = {
    async getTransaction(hash: ccc.HexLike) {
      const found = txs.get(ccc.hexFrom(hash));
      return found && { transaction: found.tx, status: "committed", blockHash: found.blockHash, blockNumber: found.blockNumber };
    },
    async getTip() {
      return height;
    },
    async getCellLive(outPoint: ccc.OutPointLike) {
      return live.has(key(outPoint)) ? {} : undefined;
    },
    async *findTransactions() {
      for (const [txHash, { tx }] of txs) if (tx.inputs.length) yield { txHash, isInput: true, blockNumber: 1n, txIndex: 0n, cellIndex: 0n };
    },
    async getHeaderByHash(hash: ccc.HexLike) {
      const found = [...txs.values()].find((item) => item.blockHash === ccc.hexFrom(hash));
      return found && { epoch: ccc.epochFrom(found.epoch) };
    },
    async getTipHeader() {
      return { epoch: ccc.epochFrom(tip) };
    },
    async findSingletonCellByType() {
      return { outPoint: ccc.OutPoint.from({ txHash: "0x" + "33".repeat(32), index: 0 }) };
    },
    async *findCellsOnChain() {
      const nodeLock = await ready;
      for (const [txHash, { tx }] of txs) {
        for (let index = 0; index < tx.outputs.length; index++) {
          if (!tx.outputs[index].lock.eq(nodeLock) || !live.has(key({ txHash, index }))) continue;
          yield ccc.Cell.from({ outPoint: { txHash, index }, cellOutput: tx.outputs[index], outputData: "0x" });
        }
      }
    },
    requestor: {
      async request(method: string) {
        if (method !== "get_block_median_time" || !options.medianTime) throw new Error(`unexpected ${method}`);
        return `0x${options.medianTime().toString(16)}`;
      },
    },
    ...(options.cachedSends ? {
      async sendTransactionNoCache(tx: ccc.TransactionLike) {
        const signed = ccc.Transaction.from(tx);
        sent.push(signed);
        return signed.hash();
      },
      async getTransactionNoCache(hash: ccc.HexLike) {
        const found = txs.get(ccc.hexFrom(hash));
        if (found) return { transaction: found.tx, status: "committed", blockHash: found.blockHash, blockNumber: found.blockNumber };
        const pending = sent.find((tx) => tx.hash() === ccc.hexFrom(hash));
        return pending && options.cachedSends?.pool?.(pending.hash()) ? { transaction: pending, status: "pending" } : undefined;
      },
    } : {
      async sendTransaction(tx: ccc.TransactionLike) {
        const signed = ccc.Transaction.from(tx);
        sent.push(signed);
        return signed.hash();
      },
      async getTransactionNoCache(hash: ccc.HexLike) {
        const found = txs.get(ccc.hexFrom(hash));
        if (found) return { transaction: found.tx, status: "committed", blockHash: found.blockHash, blockNumber: found.blockNumber };
        return sent.some((tx) => tx.hash() === ccc.hexFrom(hash)) ? { transaction: sent.find((tx) => tx.hash() === ccc.hexFrom(hash))!, status: "pending" } : undefined;
      },
    }),
  };
  const client = new Proxy(base, {
    get: (target, property, receiver) => property in overrides ? overrides[property as string] : Reflect.get(target, property, receiver),
  }) as ccc.Client;
  const watched = {
    ...channel, channelId: "0x" + "01".repeat(32), localFundingPubkey: "", remoteFundingPubkey: "", createdAt: 0, updatedAt: 0,
    ...(options.token ? { fundingUdtTypeScript: { code_hash: "0x00", hash_type: "type", args: "0x" } } : {}),
  } as WatchedChannel;
  const settle = (dryRun?: { submit: (tx: ccc.Transaction) => Promise<ccc.Hex> }) => settleChannel({
    client, network: "testnet", nodeKey, channel: watched,
    ref: { channelId: watched.channelId, fundingOutPoint: { txHash: funding.hash(), index: 0 } }, ...(dryRun ? { dryRun } : {}),
    preimage: async (hash) => options.preimages?.get(hash), now: options.now,
  });
  return {
    channel, settle, sent, liveCell, ready, funding, commitmentTx, penaltyTx, client, watched,
    setTip: (epoch: ccc.EpochLike) => { tip = epoch; },
    reopen: () => live.add(key({ txHash: funding.hash(), index: 0 })),
    /** A transaction the node sent is mined, at the tip. */
    mine: (tx: ccc.Transaction) => add(tx, tip),
    /** `count` more blocks are mined on top. */
    bury: (count: bigint) => { height += count; },
    /** A reorganization drops a transaction: its outputs are gone, the cells it spent are live again. */
    drop: (tx: ccc.Transaction) => {
      txs.delete(tx.hash());
      tx.outputs.forEach((_output, index) => live.delete(key({ txHash: tx.hash(), index })));
      for (const input of tx.inputs) live.add(key(input.previousOutput));
    },
    /** The node's key loses its fee cell (so a claim can't be built). */
    emptyNodeKey: async () => { const nodeLock = await ready; for (const [txHash, { tx }] of txs) tx.outputs.forEach((output, index) => { if (output.lock.eq(nodeLock)) live.delete(key({ txHash, index })); }); },
    /** The channel as the node lists it, on this chain's funding cell, in the state the node reports. */
    listed: (state_name: string, state_flags?: string, shutdownTx: string | null = state_name === "CLOSED" ? commitmentTx.hash() : null) => ({
      channel_id: watched.channelId, is_public: false, pubkey: `0x02${"bb".repeat(32)}`, funding_udt_type_script: null,
      channel_outpoint: ccc.hexFrom(ccc.OutPoint.from({ txHash: funding.hash(), index: 0 }).toBytes()),
      // Once the node has seen the close, it names the transaction that closed the channel.
      shutdown_transaction_hash: shutdownTx,
      state: { state_name, ...(state_flags ? { state_flags } : {}) },
      // 360 CKB the user's, 140 CKB the peer's, as the node last knew them.
      local_balance: `0x${(360n * CKB).toString(16)}`, remote_balance: `0x${(140n * CKB).toString(16)}`,
    }) as unknown as Parameters<typeof normalizeChannel>[0],
  };
}

test("settleChannel waits out the commitment delay to the epoch, then claims", async () => {
  const chain = fakeChain();
  // The commitment confirmed in epoch 100 with a one-epoch delay: not before epoch 101.
  chain.setTip([100, 999, 1000]);
  assert.equal((await chain.settle()).status, "waiting for the commitment delay");
  assert.equal(chain.sent.length, 0);
  chain.setTip([101, 0, 1000]);
  const claimed = await chain.settle();
  assert.equal(claimed.status, "claimed");
  assert.equal(chain.sent.length, 1);
  assert.equal(claimed.txHash, chain.sent[0].hash());
  assert.equal(chain.sent[0].inputs[0].since, 0xa000010000000001n);
});

test("settleChannel builds the claim fully, then signs the commitment input over the final transaction", async () => {
  const chain = fakeChain();
  let built: ccc.Transaction | undefined;
  // A dry run builds the claim before the delay has passed and hands it over instead of sending it.
  const result = await chain.settle({ submit: async (tx) => { built = tx; return tx.hash(); } });
  assert.equal(result.status, "claimed");
  assert.equal(chain.sent.length, 0);
  const tx = built!;
  assert.ok(tx.inputs[0].previousOutput.eq(chain.liveCell));
  // The peer's 250 CKB stays under the commitment lock; the user's share goes to the node, which pays the fee
  // from its reserve (the second input) and keeps the change.
  assert.equal(tx.outputs[0].lock.codeHash, COMMITMENT_LOCK.testnet.codeHash);
  assert.equal(tx.outputs[0].capacity, 250n * CKB);
  const nodeLock = await chain.ready;
  assert.ok(tx.outputs[1].lock.eq(nodeLock));
  assert.equal(tx.inputs.length, 2);
  assert.ok(tx.outputs[1].capacity > 500n * CKB && tx.outputs[1].capacity < 700n * CKB);
  // Witness 0: the xUDT-compatible prefix, one unlock of the user's slot, and a signature by the settlement key over
  // the transaction as sent (so the fee and change were in place before it signed).
  const witness = ccc.bytesFrom(tx.witnesses[0]);
  assert.equal(hex(witness.slice(0, 16)), hex(XUDT_COMPATIBLE_WITNESS));
  assert.equal(witness[16], 1);
  const signature = witness.slice(witness.length - 65);
  const recovered = secp256k1.Signature.fromBytes(signature.slice(0, 64), "compact").addRecoveryBit(signature[64]).recoverPublicKey(ccc.bytesFrom(settlementMessage(tx))).toBytes(true);
  assert.deepEqual(recovered, secp256k1.getPublicKey(ccc.bytesFrom(chain.channel.localSettlementKey), true));
  assert.notEqual(tx.witnesses[1] ?? "0x", "0x", "the node did not sign its fee input");
});

test("settleChannel follows the peer's settlement to the live cell and claims it without waiting", async () => {
  const chain = fakeChain({ peerSettledFirst: true });
  chain.setTip([90, 0, 1]);
  const result = await chain.settle();
  assert.equal(result.status, "claimed");
  const tx = chain.sent[0];
  assert.ok(tx.inputs[0].previousOutput.eq(chain.liveCell));
  assert.equal(tx.inputs[0].since, 0n);
  // The peer's slot is already empty, so the claim empties the cell: no successor.
  assert.notEqual(tx.outputs[0].lock.codeHash, COMMITMENT_LOCK.testnet.codeHash);
});

test("settleChannel reports an open channel, a settled one and a settlement it can't read", async () => {
  const open = fakeChain();
  open.reopen();
  assert.equal((await open.settle()).status, "open");
  assert.equal((await fakeChain({ peerTookEverything: true }).settle()).status, "settled");
  const odd = fakeChain({ settlementWitness: (ours) => ccc.bytesConcat(new Uint8Array(16).fill(9), ours) });
  assert.equal((await odd.settle()).status, "unexpected settlement witness");
});

test("settleChannel claims an incoming payment with its preimage, signed by the payment's key", async () => {
  const tlcs = tlcFixture();
  const chain = fakeChain({ tlcs, preimages: new Map([[tlcs.incoming.payment_hash, tlcs.incomingPreimage]]), now: NOW });
  // A third of the one-epoch delay after the commitment's epoch 100.
  chain.setTip([100, 1, 3]);
  const result = await chain.settle();
  assert.equal(result.status, "claimed");
  const tx = chain.sent[0];
  assert.equal(tx.inputs[0].since, 0xa000030001000000n);
  assert.ok(tx.inputs.slice(1).every((input) => input.since === 0n), "no timestamp anywhere: the lock reads that as an expiry claim");
  assert.equal(tx.outputs[0].capacity, tlcs.capacity - 170n * CKB);
  const witness = ccc.bytesFrom(tx.witnesses[0]);
  const unlock = witness.slice(witness.length - 99);
  assert.deepEqual([unlock[0], unlock[1]], [1, 1], "the received TLC, with a preimage");
  assert.equal(hex(unlock.slice(67)), tlcs.incomingPreimage);
  const signature = unlock.slice(2, 67);
  const recovered = secp256k1.Signature.fromBytes(signature.slice(0, 64), "compact").addRecoveryBit(signature[64]).recoverPublicKey(ccc.bytesFrom(settlementMessage(tx))).toBytes(true);
  assert.deepEqual(recovered, secp256k1.getPublicKey(ccc.bytesFrom(`0x${tlcs.incoming.local_key}`), true));
});

test("settleChannel takes back an expired outgoing payment with its expiry on the node's fee input", async () => {
  const tlcs = tlcFixture({ offeredExpiry: NOW - HOUR });
  const chain = fakeChain({ tlcs, now: NOW });
  chain.setTip([100, 2, 3]);
  const result = await chain.settle();
  assert.equal(result.status, "claimed");
  const tx = chain.sent[0];
  assert.equal(tx.inputs[0].since, 0xa000030002000000n);
  const expiry = (0x40n << 56n) | BigInt(Math.floor((NOW - HOUR) / 1000));
  assert.ok(tx.inputs.length > 1 && tx.inputs.slice(1).every((input) => input.since === expiry));
  const witness = ccc.bytesFrom(tx.witnesses[0]);
  const unlock = witness.slice(witness.length - 67);
  assert.deepEqual([unlock[0], unlock[1]], [0, 0]);
  const recovered = secp256k1.Signature.fromBytes(unlock.slice(2, 66), "compact").addRecoveryBit(unlock[66]).recoverPublicKey(ccc.bytesFrom(settlementMessage(tx))).toBytes(true);
  assert.deepEqual(recovered, secp256k1.getPublicKey(ccc.bytesFrom(`0x${tlcs.outgoing.local_key}`), true), "signed over the transaction with the timestamps in place");
});

test("the in-page store hands back a preimage the node gave it, until the node removes it", async () => {
  const store = openWatchtowerStore(`/wasm-test-${crypto.randomUUID()}`);
  const paymentHash = `0x${"AB".repeat(32)}`;
  const preimage = `0x${"cd".repeat(32)}`;
  assert.equal(await store.preimage(paymentHash), undefined);
  await store.apply({ method: "create_preimage", params: { payment_hash: paymentHash, preimage } } as never);
  assert.equal(await store.preimage(paymentHash.toLowerCase()), preimage);
  await store.apply({ method: "remove_preimage", params: { payment_hash: paymentHash } } as never);
  assert.equal(await store.preimage(paymentHash), undefined);
  store.close();
});

test("payment expiries are judged by the chain's median time, not the browser's clock", async () => {
  // Expired an hour ago by this machine's clock, but the chain's median time hasn't reached it yet.
  const expiry = Date.now() - HOUR;
  let median = expiry - HOUR;
  const tlcs = tlcFixture({ offeredExpiry: expiry });
  const chain = fakeChain({ tlcs, medianTime: () => median });
  chain.setTip([101, 0, 1]);
  assert.equal((await chain.settle()).status, "waiting for a pending payment to resolve");
  assert.equal(chain.sent.length, 0, "a claim the chain would refuse as immature isn't sent");
  median = expiry + 1_000;
  assert.equal((await chain.settle()).status, "claimed");
  assert.equal(chain.sent[0].inputs[1].since, (0x40n << 56n) | BigInt(Math.floor(expiry / 1000)));
});

test("once the peer has settled its share, the next claim takes the whole cell at once, payments and all", () => {
  // The peer's commitment with two incoming payments the user holds preimages for, both close to expiry, and an
  // outgoing one that hasn't expired yet. The peer then settled its own share first.
  const f = tlcFixture({ offeredExpiry: NOW + HOUR, receivedExpiry: NOW + 60_000 });
  const secondPreimage = hex(new Uint8Array(32).fill(0x43));
  const secondIncoming = { ...f.incoming, tlc_id: { Received: "0x1" }, payment_hash: ccc.hashCkb(secondPreimage), payment_amount: `0x${(90n * CKB).toString(16)}` };
  const remoteSettlement = { ...f.channel.remoteSettlement!, tlcs: [...f.channel.remoteSettlement!.tlcs, secondIncoming] };
  const channel = { ...f.channel, remoteSettlement };
  const theirs = encodeSettlementWitness(remoteSettlement, true, channel.localSettlementKey, channel.remoteSettlementKey);
  const peerSettled = ccc.bytesConcat(new Uint8Array([1]), theirs, new Uint8Array([0xfe, 0]), new Uint8Array(65));
  const cell = { capacity: f.capacity + 90n * CKB - 250n * CKB, args: "0x" + "00".repeat(57) };
  const preimages = new Map([[f.incoming.payment_hash, f.incomingPreimage], [secondIncoming.payment_hash, secondPreimage]]);
  // Settling second, the user's claim may take the whole cell (the lock checks no output once both slots are empty),
  // as Fiber 0.9.1's watchtower does: one transaction secures both incoming payments and the user's share, instead of
  // one payment per pass while the peer can take the others back once they expire.
  for (const decision of [
    planClaim({ channel, cell, previousWitness: peerSettled, preimages, now: NOW }),
    // Without preimages, the unexpired outgoing payment doesn't hold the user's share back either.
    planClaim({ channel, cell, previousWitness: peerSettled, now: NOW }),
  ]) {
    assert.ok("claim" in decision, "skip" in decision ? decision.skip : "");
    assert.equal(decision.claim.unlockType, 0xff, "the user's own slot");
    assert.equal(decision.claim.since, 0n);
    assert.equal(decision.claim.successor, undefined, "nothing is left behind");
    assert.equal(decision.claim.preimage, undefined);
    assert.equal(decision.claim.signingKey, channel.localSettlementKey);
  }
});

test("only the settlement's output 0, the one the commitment lock checks, is followed as the successor", async () => {
  // Both parties have settled, so the last settlement emptied the cell; an unrelated cell under a lookalike
  // commitment lock (same prefix) sits at its output 1.
  const chain = fakeChain({ peerSettledFirst: true, bothSettledWithDecoy: true });
  chain.setTip([90, 0, 1]);
  assert.equal((await chain.settle()).status, "settled");
  assert.equal(chain.sent.length, 0);
});

test("a claim the chain dropped leaves no phantom fee cell: the next pass pays the fee from the real reserve again", async () => {
  const chain = fakeChain({ peerSettledFirst: true, cachedSends: {} });
  chain.setTip([90, 0, 1]);
  const sends = trackNodeKeySends(chain.client);
  const first = await chain.settle();
  assert.equal(first.status, "claimed");
  sends.record(first.txHash!);
  const reserve = chain.sent[0].inputs[1].previousOutput;
  // The chain drops the claim: the commitment cell is still live, and the reserve still unspent.
  await sends.refresh();
  assert.equal((await chain.settle()).status, "claimed");
  assert.deepEqual(chain.sent[1].inputs.slice(1).map((input) => input.previousOutput.toHex()), [reserve.toHex()], "not the dropped claim's output");
});

test("a claim still in the mempool keeps its reserve spent and its output usable across passes", async () => {
  let inPool = true;
  const chain = fakeChain({ peerSettledFirst: true, cachedSends: { pool: () => (inPool ? "pending" : undefined) } });
  chain.setTip([90, 0, 1]);
  const sends = trackNodeKeySends(chain.client);
  const first = await chain.settle();
  sends.record(first.txHash!);
  const reserve = chain.sent[0].inputs[1].previousOutput;
  const output = ccc.OutPoint.from({ txHash: first.txHash!, index: 0 });
  await sends.refresh();
  assert.equal(await chain.client.cache.isUnusable(reserve), true);
  assert.ok(await chain.client.cache.getCell(output));
  inPool = false;
  await sends.refresh();
  assert.equal(await chain.client.cache.isUnusable(reserve), false, "dropped: the reserve is usable again");
});

test("a sweep that lands while a pass rebuilds the cache keeps its spent marks", async () => {
  // A claim P is pending; a sweep then spends P's payout. The pass's refresh is slow to ask the node about P.
  let inPoolRead!: () => void;
  const reading = new Promise<void>((resolve) => { inPoolRead = resolve; });
  let answer!: () => void;
  const answered = new Promise<void>((resolve) => { answer = resolve; });
  const client = new ccc.ClientPublicTestnet({ url: "http://127.0.0.1:9/" });
  const lock = { codeHash: "0x" + "00".repeat(32), hashType: "data" as const, args: "0x01" };
  const claim = ccc.Transaction.from({ inputs: [{ previousOutput: { txHash: "0x" + "aa".repeat(32), index: 0 } }], outputs: [{ capacity: 500n * CKB, lock }], outputsData: ["0x"] });
  Object.assign(client, {
    async getTransactionNoCache() {
      inPoolRead();
      await answered;
      return { transaction: claim, status: "pending" };
    },
  });
  const sends = trackNodeKeySends(client);
  sends.record(claim.hash());
  const payout = ccc.OutPoint.from({ txHash: claim.hash(), index: 0 });
  const pass = sends.exclusive(() => sends.refresh());
  await reading;
  // The sweep is sent now; ccc marks the payout it spends.
  const sweep = sends.exclusive(async () => { await client.cache.markUnusable(payout); });
  answer();
  await Promise.all([pass, sweep]);
  assert.equal(await client.cache.isUnusable(payout), true, "the next claim must not pick the swept payout");
});

test("a token channel's force close is seen and keeps the reserve, but no claim is built for it in the page", async () => {
  const open = fakeChain({ token: true });
  open.reopen();
  assert.equal((await open.settle()).status, "open");
  const closed = fakeChain({ token: true });
  closed.setTip([200, 0, 1]);
  const result = await closed.settle();
  assert.match(result.status, /token channels/);
  assert.equal(result.closingTx, closed.commitmentTx.hash(), "the commitment that spent the funding cell is reported");
  assert.equal(closed.sent.length, 0, "no claim is built for a token channel");
  const wallet = walletOver(closed);
  closed.bury(100n);
  await wallet.pass("CHANNEL_READY");
  assert.equal((await wallet.shown("CHANNEL_READY"))[0].status, "closing");
  // The page never reaches a verdict for it, so it holds the reserve, as before.
  assert.equal(await wallet.reserveHeld("CLOSED", WAITING), true);
});

// What the in-page watchtower has seen of a channel's close, kept apart from what the node says (channel-closures.ts).
const closureModule = () => import("../src/sdk/browser/channel-closures.ts");
const FINAL_DEPTH = 24n;
const WAITING = "UNCOOPERATIVE_REMOTE|WAITING_ONCHAIN_SETTLEMENT";

/**
 * The wallet's side of a channel on the fake chain, through the functions create-keyway.ts itself runs: a
 * watchtower pass (settle, then record what was seen, with what the node reports about the channel), the channel
 * list as `getChannels` builds it, and the reserve gate the sweep asks. Each `walletOver` is one page load: the
 * closures are read from storage every time, the gate's memory is the session's.
 */
function walletOver(chain: ReturnType<typeof fakeChain>, prefix = `/wasm-test-${crypto.randomUUID()}`) {
  const removed: string[] = [];
  let opening = false;
  let gate: Awaited<ReturnType<typeof makeGate>> | undefined;
  let node: ReturnType<typeof chain.listed>[] = [];
  let closuresFail = false;
  async function makeGate() {
    const { createReserveGate, openClosureStore } = await closureModule();
    const { isBuried } = await import("../src/sdk/browser/watchtower-settle.ts");
    return createReserveGate({
      listChannels: async () => node,
      listClosures: async () => { if (closuresFail) throw new Error("IndexedDB is unavailable"); return openClosureStore(prefix).list(); },
      isBuried: (txHash) => isBuried(chain.client, txHash),
      opening: () => opening,
    });
  }
  return {
    prefix, removed,
    setOpening: (value: boolean) => { opening = value; },
    failClosures: (value: boolean) => { closuresFail = value; },
    /** One pass, with the node reporting the channel in this state. A failed settle is recorded as create-keyway.ts does. */
    async pass(state_name: string, state_flags?: string, shutdownTx?: string | null) {
      const { openClosureStore, recordSettleResult } = await closureModule();
      const { closedBy } = await import("../src/sdk/browser/settlement-sweep.ts");
      const { isBuried } = await import("../src/sdk/browser/watchtower-settle.ts");
      const raw = chain.listed(state_name, state_flags, shutdownTx);
      const record = (result: Awaited<ReturnType<typeof chain.settle>>) => recordSettleResult({
        result, closures: openClosureStore(prefix), fundingOutPoint: String(raw.channel_outpoint), nodeClosedBy: closedBy(raw as never),
        watchtower: { remove: async (channelId) => { removed.push(channelId); } },
        isBuried: (txHash) => isBuried(chain.client, txHash),
      });
      // As the pass does: a channel finished for good is dropped without another look at the chain.
      gate ??= await makeGate();
      if (await gate.settledForGood((await closureModule()).closureOf(await openClosureStore(prefix).list(), raw), raw as never)) {
        removed.push(chain.watched.channelId);
        return { channelId: chain.watched.channelId, status: "finished for good: not looked at again", finishedNow: false } as Awaited<ReturnType<typeof chain.settle>> & { finishedNow: boolean };
      }
      try {
        const result = await chain.settle();
        return { ...result, finishedNow: await record(result) };
      } catch (error) {
        const failure = error as { closingTx?: ccc.Hex; unsettled?: true };
        if (failure.closingTx) await record({ channelId: chain.watched.channelId, status: "could not be settled yet", closingTx: failure.closingTx, ...(failure.unsettled ? { unsettled: true as const } : {}) });
        return { channelId: chain.watched.channelId, status: `failed: ${(error as Error).message}`, finishedNow: false } as Awaited<ReturnType<typeof chain.settle>> & { finishedNow: boolean };
      }
    },
    /** The channel list, default (closed channels left out) or with them. */
    async shown(state_name: string, state_flags?: string, includeClosed = false) {
      const { openClosureStore, presentChannels } = await closureModule();
      return presentChannels([normalizeChannel(chain.listed(state_name, state_flags))], await openClosureStore(prefix).list(), includeClosed);
    },
    /** Whether the sweep would keep the fee reserve, the node listing these channels (this chain's one by default). */
    async reserveHeld(state_name: string, state_flags?: string, others: unknown[] = [], shutdownTx?: string | null) {
      node = [chain.listed(state_name, state_flags, shutdownTx), ...(others as typeof node)];
      gate ??= await makeGate();
      // As the sweep asks: every verdict the answer rests on is put to the chain again.
      return gate.needed({ fresh: true });
    },
    async stored() {
      return (await (await closureModule()).openClosureStore(prefix).list());
    },
  };
}

test("a channel the node still calls ready, whose funding the peer's revoked commitment has spent, is shown as closing with nothing to send", async () => {
  const chain = fakeChain({ revoked: true });
  const result = await chain.settle();
  assert.match(result.status, /needs revocation/);
  assert.equal(result.closingTx, chain.commitmentTx.hash(), "the watchtower reports that a commitment spent the funding cell");
  const wallet = walletOver(chain);
  await wallet.pass("CHANNEL_READY");
  // Fiber's own check hasn't run yet: the node still lists the channel as ready with 360 CKB to send.
  const [channel] = await wallet.shown("CHANNEL_READY");
  assert.equal(channel.status, "closing");
  assert.equal(channel.canSend, 0n);
  assert.equal(channel.canReceive, 0n);
  assert.equal(channel.capacity, 500n * CKB);
  assert.equal(await wallet.reserveHeld("CHANNEL_READY"), true, "nothing is finished yet: the reserve stays");
});

test("a force-closed channel reads the same before and after the node notices, and stays listed until nothing is left to claim", async () => {
  const chain = fakeChain({ byPeer: true });
  const wallet = walletOver(chain);
  chain.setTip([100, 500, 1000]);
  await wallet.pass("CHANNEL_READY");
  const before = (await wallet.shown("CHANNEL_READY"))[0];
  // The node's own check has run: it now calls the channel closed, with its old balance, hours before the claim.
  const after = (await wallet.shown("CLOSED", WAITING))[0];
  assert.ok(after, "still in the default list: the user's share is unclaimed");
  assert.deepEqual([after.status, after.canSend, after.canReceive], [before.status, before.canSend, before.canReceive]);
  assert.deepEqual([after.status, after.canSend], ["closing", 0n]);
  // Without a closure the node's own closed channel is listed as before: closed, and only when asked for.
  const { presentChannels } = await closureModule();
  const plain = normalizeChannel(chain.listed("CLOSED", WAITING));
  assert.deepEqual(presentChannels([plain], [], false), []);
  assert.deepEqual(presentChannels([plain], [], true), [plain]);
});

test("a penalized channel the node keeps in WAITING_ONCHAIN_SETTLEMENT releases the fee reserve once the penalty is buried, and not before", async () => {
  const chain = fakeChain({ revoked: true, penalized: true });
  const wallet = walletOver(chain);
  const first = await wallet.pass("CHANNEL_READY");
  assert.equal(first.status, "settled");
  assert.equal(first.evidence, chain.penaltyTx!.hash(), "the verdict rests on the penalty transaction");
  // The penalty is only a block deep: a reorganization could still undo it, so nothing is final yet.
  assert.equal(await wallet.reserveHeld("CLOSED", WAITING), true);
  assert.equal((await wallet.shown("CHANNEL_READY"))[0].status, "closing");

  chain.bury(FINAL_DEPTH - 1n);
  await wallet.pass("CHANNEL_READY");
  assert.equal(await wallet.reserveHeld("CLOSED", WAITING), true, "23 blocks on top is not enough");
  chain.bury(1n);
  assert.equal((await wallet.pass("CHANNEL_READY")).finishedNow, true);
  // While the node still calls it ready: shown as closed (so out of the default list), but the watch goes on and
  // the reserve waits for the node to agree.
  assert.deepEqual(await wallet.shown("CHANNEL_READY"), []);
  assert.deepEqual((await wallet.shown("CHANNEL_READY", undefined, true)).map(({ status, canSend }) => [status, canSend]), [["closed", 0n]]);
  assert.equal(await wallet.reserveHeld("CHANNEL_READY"), true);
  assert.deepEqual(wallet.removed, [], "the watchtower keeps its record until the node agrees the channel is closed");
  // The node's check runs. Fiber 0.10.1's browser node never drops the flag; the verdict stands in for it.
  await wallet.pass("CLOSED", WAITING);
  assert.deepEqual(wallet.removed, [chain.watched.channelId], "both agree: the watch ends");
  assert.equal(await wallet.reserveHeld("CLOSED", WAITING), false);
});

test("an honest force close keeps the fee reserve until the user's share is claimed and the claim is buried", async () => {
  const chain = fakeChain({ byPeer: true });
  const wallet = walletOver(chain);
  // The peer's commitment is on-chain; its delay hasn't passed, so the user's share can't be claimed yet.
  chain.setTip([100, 500, 1000]);
  assert.equal((await wallet.pass("CHANNEL_READY")).status, "waiting for the commitment delay");
  assert.equal((await wallet.shown("CHANNEL_READY"))[0].status, "closing", "seen on-chain before the node notices");
  assert.equal(await wallet.reserveHeld("CLOSED", WAITING), true, "the claim will need the reserve for its fee");
  // The delay passes; the claim is sent, paying its fee from the reserve.
  chain.setTip([101, 0, 1000]);
  assert.equal((await wallet.pass("CLOSED", WAITING)).status, "claimed");
  assert.equal(await wallet.reserveHeld("CLOSED", WAITING), true, "a claim only sent proves nothing yet");
  // Still in the mempool on the next pass: the commitment cell is live, the claim is built again.
  assert.equal((await wallet.pass("CLOSED", WAITING)).status, "claimed");
  assert.equal(await wallet.reserveHeld("CLOSED", WAITING), true);
  // The claim is mined: the user's slot is empty in the cell it left for the peer.
  chain.mine(chain.sent[0]);
  const after = await wallet.pass("CLOSED", WAITING);
  assert.equal(after.status, "the user's share is already claimed");
  assert.equal(after.evidence, chain.sent[0].hash());
  assert.equal(await wallet.reserveHeld("CLOSED", WAITING), true, "mined, but not yet buried");
  assert.equal((await wallet.shown("CLOSED", WAITING))[0].status, "closing");
  assert.deepEqual(wallet.removed, []);
  chain.bury(FINAL_DEPTH);
  await wallet.pass("CLOSED", WAITING);
  assert.deepEqual(wallet.removed, [chain.watched.channelId]);
  assert.equal(await wallet.reserveHeld("CLOSED", WAITING), false);
  assert.deepEqual(await wallet.shown("CLOSED", WAITING), [], "closed now: out of the default list");
});

test("the verdict survives a reload, and speaks only for its channel, funding cell and closing transaction", async () => {
  const chain = fakeChain({ revoked: true, penalized: true });
  chain.bury(FINAL_DEPTH);
  const first = walletOver(chain);
  await first.pass("CLOSED", WAITING);
  assert.deepEqual(first.removed, [chain.watched.channelId], "a finished channel's watchtower record is removed");
  // A reload: nothing in memory, the watchtower record gone. Only the stored verdict is left.
  const wallet = walletOver(chain, first.prefix);
  const stored = await wallet.stored();
  assert.equal(stored.length, 1);
  assert.deepEqual(stored[0].finished, { status: "settled", evidence: chain.penaltyTx!.hash() });
  assert.equal(stored[0].closingTx, chain.commitmentTx.hash());
  const waiting = chain.listed("CLOSED", WAITING);
  assert.equal(needsFeeReserve([waiting]), true, "by the node's own state the reserve would stay forever");
  assert.equal(await wallet.reserveHeld("CLOSED", WAITING), false);
  // Another channel still waiting to settle keeps the reserve, as does the same channel ID on another funding cell,
  // one the node saw closed by another transaction than the verdict followed, and one it doesn't name a transaction for.
  assert.equal(await wallet.reserveHeld("CLOSED", WAITING, [{ ...waiting, channel_id: "0x" + "02".repeat(32) }]), true);
  assert.equal(needsFeeReserve([{ ...waiting, channel_outpoint: "0x" + "aa".repeat(36) }], stored), true);
  assert.equal(await wallet.reserveHeld("CLOSED", WAITING, [], "0x" + "cc".repeat(32)), true);
  assert.equal(await wallet.reserveHeld("CLOSED", WAITING, [], null), true);
  // Fiber hands the channel over again at the next start: the pass that follows drops it again without reading
  // the chain, the verdict untouched.
  assert.match((await wallet.pass("CLOSED", WAITING)).status, /not looked at again/);
  assert.deepEqual(wallet.removed, [chain.watched.channelId]);
  assert.deepEqual((await wallet.stored())[0].finished, stored[0].finished);
});

test("a verdict is taken back when the chain no longer bears it out", async () => {
  // The funding cell is live again (a deep reorganization, or the verdict was written on a wrong answer).
  const reopened = fakeChain({ revoked: true, penalized: true });
  reopened.bury(FINAL_DEPTH);
  let wallet = walletOver(reopened);
  await wallet.pass("CHANNEL_READY");
  assert.ok((await wallet.stored())[0].finished);
  assert.deepEqual(wallet.removed, [], "the node hasn't agreed, so the watchtower still holds the channel's data");
  reopened.reopen();
  assert.equal((await wallet.pass("CHANNEL_READY")).status, "open");
  assert.deepEqual(await wallet.stored(), []);
  const back = (await wallet.shown("CHANNEL_READY"))[0];
  assert.deepEqual([back.status, back.canSend], ["ready", 360n * CKB]);

  // The claim that emptied the user's slot is dropped by a reorganization: the commitment cell is live again.
  const unclaimed = fakeChain({ byPeer: true });
  wallet = walletOver(unclaimed);
  unclaimed.setTip([101, 0, 1000]);
  await wallet.pass("CHANNEL_READY");
  unclaimed.mine(unclaimed.sent[0]);
  unclaimed.bury(FINAL_DEPTH);
  assert.equal((await wallet.pass("CHANNEL_READY")).finishedNow, true);
  unclaimed.drop(unclaimed.sent[0]);
  const again = await wallet.pass("CHANNEL_READY");
  assert.equal(again.status, "claimed", "the watchtower still had the data and claims again");
  assert.equal((await wallet.stored())[0].finished, undefined);
  assert.equal(await wallet.reserveHeld("CLOSED", WAITING), true);
  assert.equal((await wallet.shown("CLOSED", WAITING))[0].status, "closing");

  // After both agreed and the record is gone, the verdict's transaction is asked about once more before the
  // reserve goes: one that is no longer on-chain doesn't release it.
  const gone = fakeChain({ revoked: true, penalized: true });
  gone.bury(FINAL_DEPTH);
  const before = walletOver(gone);
  await before.pass("CLOSED", WAITING);
  assert.deepEqual(before.removed, [gone.watched.channelId]);
  gone.drop(gone.penaltyTx!);
  const reloaded = walletOver(gone, before.prefix);
  assert.equal(await reloaded.reserveHeld("CLOSED", WAITING), true);
  // And the channel Fiber hands over again at that start is looked at afresh, not dropped on the stale verdict.
  assert.match((await reloaded.pass("CLOSED", WAITING)).status, /needs revocation/);
  assert.deepEqual(reloaded.removed, []);
  assert.equal((await reloaded.stored())[0].finished, undefined);
});

test("a verdict whose transaction a reorganization replaced gives way to the new one, at its own depth", async () => {
  const chain = fakeChain({ byPeer: true });
  const wallet = walletOver(chain);
  chain.setTip([101, 0, 1000]);
  await wallet.pass("CHANNEL_READY");
  chain.mine(chain.sent[0]);
  chain.bury(FINAL_DEPTH);
  assert.equal((await wallet.pass("CHANNEL_READY")).finishedNow, true);
  // The claim is dropped and another transaction makes the same claim instead (here: the same one, a shannon apart).
  chain.drop(chain.sent[0]);
  const replacement = chain.sent[0].clone();
  replacement.outputs[replacement.outputs.length - 1].capacity -= 1n;
  chain.mine(replacement);
  assert.notEqual(replacement.hash(), chain.sent[0].hash());
  // The node has noticed the close meanwhile. The status is the same, the transaction under it is not.
  const after = await wallet.pass("CLOSED", WAITING);
  assert.equal(after.status, "the user's share is already claimed");
  assert.equal(after.evidence, replacement.hash());
  assert.equal((await wallet.stored())[0].finished, undefined, "the old verdict is void; the new transaction is one block deep");
  assert.deepEqual(wallet.removed, [], "the watchtower keeps its record until the new one is buried");
  assert.equal(await wallet.reserveHeld("CLOSED", WAITING), true);
  chain.bury(FINAL_DEPTH);
  assert.equal((await wallet.pass("CLOSED", WAITING)).finishedNow, true);
  assert.deepEqual((await wallet.stored())[0].finished, { status: "the user's share is already claimed", evidence: replacement.hash() });
  assert.deepEqual(wallet.removed, [chain.watched.channelId]);
  assert.equal(await wallet.reserveHeld("CLOSED", WAITING), false);
});

test("the sweep puts a verdict to the chain every time; a restart forgets every earlier answer", async () => {
  const { createReserveGate } = await closureModule();
  const id = "0x" + "0a".repeat(32);
  const outPoint = "0x" + "0b".repeat(32) + "00000000";
  const closingTx = "0x" + "0d".repeat(32);
  const closure = { channelId: id, fundingOutPoint: outPoint, closingTx, seenAt: 0, finished: { status: "settled", evidence: "0x" + "0c".repeat(32) } };
  const listed = { channel_id: id, channel_outpoint: outPoint, shutdown_transaction_hash: closingTx, state: { state_name: "CLOSED", state_flags: WAITING } };
  let buried = true;
  let asked = 0;
  const gate = createReserveGate({
    listChannels: async () => [listed], listClosures: async () => [closure], opening: () => false,
    isBuried: async () => { asked++; return buried; },
  });
  // A channel Fiber hands over again is dropped on one answer, and noticing that the reserve may be due reuses it.
  assert.equal(await gate.settledForGood(closure, listed), true);
  assert.equal(await gate.needed(), false);
  assert.equal(asked, 1);
  // A reorganization then drops the verdict's transaction. The answer already had would still say "buried"...
  buried = false;
  assert.equal(await gate.needed(), false);
  // ...so the sweep, which is what moves the reserve, never goes by it.
  assert.equal(await gate.needed({ fresh: true }), true);
  assert.equal(asked, 2);
  assert.equal(await gate.needed(), true, "and the stale answer is gone with it");
  // The node is stopped and started again: nothing is taken from before.
  buried = true;
  assert.equal(await gate.needed({ fresh: true }), false);
  buried = false;
  gate.reset();
  assert.equal(await gate.settledForGood(closure, listed), false, "the channel handed over again is looked at afresh");
  assert.equal(await gate.needed(), true);
  // An RPC failure is not an answer.
  const failing = createReserveGate({ listChannels: async () => [listed], listClosures: async () => [closure], opening: () => false, isBuried: async () => { throw new Error("unreachable"); } });
  assert.equal(await failing.needed({ fresh: true }), true);
});

test("a close that a reorganization undid before it was final is forgotten", async () => {
  const chain = fakeChain({ byPeer: true });
  const wallet = walletOver(chain);
  chain.setTip([100, 500, 1000]);
  await wallet.pass("CHANNEL_READY");
  assert.equal((await wallet.shown("CHANNEL_READY"))[0].status, "closing");
  chain.reopen();
  assert.equal((await wallet.pass("CHANNEL_READY")).status, "open");
  const back = (await wallet.shown("CHANNEL_READY"))[0];
  assert.equal(back.status, "ready");
  assert.equal(back.canSend, 360n * CKB);
});

test("a claim that can't be built doesn't unsee the close", async () => {
  const chain = fakeChain({ byPeer: true });
  chain.setTip([101, 0, 1000]);
  await chain.emptyNodeKey();
  // No fee cell on the node's key: the claim can't be built, and settleChannel rejects.
  const failure = await chain.settle().then(() => undefined, (error: Error & { closingTx?: string; unsettled?: true }) => error);
  assert.ok(failure, "the claim was expected to fail without a fee cell");
  assert.equal(failure.closingTx, chain.commitmentTx.hash(), "the failure still says the channel is force-closed");
  assert.equal(failure.unsettled, true, "and that something in it was the user's to claim");
  const wallet = walletOver(chain);
  assert.match((await wallet.pass("CHANNEL_READY")).status, /^failed/);
  assert.equal((await wallet.shown("CHANNEL_READY"))[0].status, "closing");
  assert.equal(await wallet.reserveHeld("CLOSED", WAITING), true);

  // Nor does it leave a verdict standing: the claim was mined and buried, the channel called finished, then a
  // reorganization dropped the claim and the fee cell with it. The pass that now fails to claim takes the verdict
  // back and keeps the watchtower's record, although the node reports the channel closed.
  const undone = fakeChain({ byPeer: true });
  const after = walletOver(undone);
  undone.setTip([101, 0, 1000]);
  await after.pass("CHANNEL_READY");
  undone.mine(undone.sent[0]);
  undone.bury(FINAL_DEPTH);
  assert.equal((await after.pass("CHANNEL_READY")).finishedNow, true);
  undone.drop(undone.sent[0]);
  await undone.emptyNodeKey();
  assert.match((await after.pass("CLOSED", WAITING)).status, /^failed/);
  assert.equal((await after.stored())[0].finished, undefined);
  assert.deepEqual(after.removed, []);
  assert.equal(await after.reserveHeld("CLOSED", WAITING), true);
});

test("the close is recorded before the chain is asked whether a verdict is final", async () => {
  const chain = fakeChain({ revoked: true, penalized: true });
  const { openClosureStore, recordSettleResult } = await closureModule();
  const prefix = `/wasm-test-${crypto.randomUUID()}`;
  const result = await chain.settle();
  await assert.rejects(recordSettleResult({
    result, closures: openClosureStore(prefix), fundingOutPoint: String(chain.listed("CHANNEL_READY").channel_outpoint),
    watchtower: { remove: async () => assert.fail("nothing may end the watch here") },
    isBuried: async () => { throw new Error("the RPC is unreachable"); },
  }), /unreachable/);
  const stored = await openClosureStore(prefix).list();
  assert.equal(stored.length, 1);
  assert.equal(stored[0].finished, undefined);
  assert.equal(stored[0].closingTx, chain.commitmentTx.hash());
});

test("the reserve stays while a channel is being opened, and while the closures can't be read", async () => {
  const chain = fakeChain({ revoked: true, penalized: true });
  chain.bury(FINAL_DEPTH);
  const wallet = walletOver(chain);
  await wallet.pass("CLOSED", WAITING);
  assert.equal(await wallet.reserveHeld("CLOSED", WAITING), false);
  // The node lists a channel being opened only once the peer has answered; the open itself holds the reserve.
  wallet.setOpening(true);
  assert.equal(await wallet.reserveHeld("CLOSED", WAITING), true);
  wallet.setOpening(false);
  wallet.failClosures(true);
  assert.equal(await wallet.reserveHeld("CLOSED", WAITING), true);
  wallet.failClosures(false);
  assert.equal(await wallet.reserveHeld("CLOSED", WAITING), false);
});

test("a pending payment the node's data doesn't know keeps a channel from being called finished", () => {
  // The peer's commitment with two payments in flight; the user's share is already claimed. The node's data for
  // the channel is incomplete: it knows neither payment.
  const f = tlcFixture({ offeredExpiry: NOW - HOUR, receivedExpiry: NOW - HOUR });
  const claimed = ccc.bytesConcat(new Uint8Array([1]), f.theirs, new Uint8Array([0xff, 0]), new Uint8Array(65));
  const cell = { capacity: f.capacity - 500n * CKB, args: "0x" + "00".repeat(57) };
  const blind = { ...f.channel, remoteSettlement: { ...f.channel.remoteSettlement!, tlcs: [] } };
  const decision = planClaim({ channel: blind, cell, previousWitness: claimed, now: NOW });
  assert.ok("skip" in decision);
  assert.match(decision.skip, /already claimed, but a pending payment in the cell matches none of the node's data/);
  // With the payments known, the expired outgoing one is the user's to take back: there is something to claim.
  assert.ok("claim" in planClaim({ channel: f.channel, cell, previousWitness: claimed, now: NOW }));
});

test("a transaction counts as buried only when committed with 24 blocks on top", async () => {
  const { isBuried } = await import("../src/sdk/browser/watchtower-settle.ts");
  const chain = fakeChain({ revoked: true, penalized: true });
  const penalty = chain.penaltyTx!.hash();
  chain.bury(FINAL_DEPTH - 1n);
  assert.equal(await isBuried(chain.client, penalty), false);
  chain.bury(1n);
  assert.equal(await isBuried(chain.client, penalty), true);
  assert.equal(await isBuried(chain.client, "0x" + "ee".repeat(32)), false, "unknown to the chain");
  // A claim sent but not mined is not evidence of anything.
  const claiming = fakeChain({ byPeer: true });
  claiming.setTip([101, 0, 1000]);
  const claimed = await claiming.settle();
  claiming.bury(100n);
  assert.equal(await isBuried(claiming.client, claimed.txHash!), false);
});
