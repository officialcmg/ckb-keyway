import "fake-indexeddb/auto";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import * as ccc from "@ckb-ccc/core";
import { JsonRpcTransformers } from "@ckb-ccc/core/advanced";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import {
  applyUnlocks, blake160, delayFraction, encodeSettlementWitness, encodeWitnessState, epochDelayPassed, parseCommitmentArgs, parseSettlementWitness,
  planClaim, settleChannel, settlementMessage, signSettlement, XUDT_COMPATIBLE_WITNESS,
} from "../src/sdk/browser/watchtower-settle.ts";
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

test("an incoming payment in flight is claimed with its preimage once a third of the delay has passed", () => {
  const f = tlcFixture();
  const preimages = new Map([[f.incoming.payment_hash, f.incomingPreimage]]);
  const third = 0xa000030001000000n; // a third of the one-epoch delay, as the lock works it out
  const passed = new Set<bigint>();
  const plan = (now = NOW) => planClaim({ channel: f.channel, cell: f.cell, preimages, now, delayPassed: (since) => passed.has(since) });
  assert.deepEqual(plan(), { skip: "waiting for the commitment delay" });
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
  // Not expired yet: nothing of the user's can go, the share waits for the full delay.
  assert.deepEqual(plan(NOW), { skip: "waiting for the commitment delay" });
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

test("the user's share isn't held back by payments in flight, and a successor keeps them", () => {
  // Neither payment is the node's to claim yet: no preimage, and the outgoing one hasn't expired.
  const f = tlcFixture({ offeredExpiry: NOW + HOUR });
  const decision = planClaim({ channel: f.channel, cell: f.cell, now: NOW });
  assert.ok("claim" in decision);
  assert.equal(decision.claim.unlockType, 0xff, "the user's slot on the peer's commitment");
  assert.equal(decision.claim.since, 0xa000010000000001n);
  assert.equal(decision.claim.successor?.capacity, f.capacity - 500n * CKB);
  const after = applyUnlocks({ ...parseSettlementWitness(f.theirs, false)!, unlocks: [{ type: 0xff, withPreimage: false }] })!;
  assert.equal(after.pendingTlcs.length, 2);
  assert.equal(hex(ccc.bytesFrom(decision.claim.successor!.args).slice(36, 56)), hex(blake160(encodeWitnessState(after))));

  // Once the peer has settled its share too, the TLCs' amounts still stay locked for them rather than going to the
  // user with the rest of the cell, and the node keeps the channel until its own payment can be taken back.
  const peerSettled = ccc.bytesConcat(new Uint8Array([1]), f.theirs, new Uint8Array([0xfe, 0]), new Uint8Array(65));
  const remaining = f.capacity - 250n * CKB;
  const next = planClaim({ channel: f.channel, cell: { capacity: remaining, args: "0x" + "00".repeat(57) }, previousWitness: peerSettled, now: NOW });
  assert.ok("claim" in next);
  assert.equal(next.claim.since, 0n);
  assert.equal(next.claim.successor?.capacity, remaining - 500n * CKB);
  const userSettled = ccc.bytesConcat(new Uint8Array([1]), encodeWitnessState(applyUnlocks(parseSettlementWitness(peerSettled)!)!), new Uint8Array([0xff, 0]), new Uint8Array(65));
  assert.deepEqual(
    planClaim({ channel: f.channel, cell: { capacity: 350n * CKB, args: "0x" + "00".repeat(57) }, previousWitness: userSettled, now: NOW }),
    { skip: "waiting for a pending payment to resolve" },
  );
  // After expiry the outgoing payment comes back on that last cell, and nothing then remains for the user.
  const back = planClaim({ channel: f.channel, cell: { capacity: 350n * CKB, args: "0x" + "00".repeat(57) }, previousWitness: userSettled, now: NOW + 2 * HOUR });
  assert.ok("claim" in back && back.claim.unlockType === 0 && back.claim.since === 0n);
  assert.equal(back.claim.successor?.capacity, 170n * CKB);
  // The incoming payment, without its preimage and past its expiry, is the peer's to take back.
  const lost = tlcFixture({ receivedExpiry: NOW - HOUR, offeredExpiry: NOW + HOUR });
  const lostAfter = ccc.bytesConcat(new Uint8Array([1]), encodeWitnessState(applyUnlocks({ ...parseSettlementWitness(lost.theirs, false)!, unlocks: [{ type: 0, withPreimage: false }, { type: 0xff, withPreimage: false }] })!), new Uint8Array([0xfe, 0]), new Uint8Array(65));
  assert.deepEqual(planClaim({ channel: lost.channel, cell: { capacity: 170n * CKB, args: "0x" + "00".repeat(57) }, previousWitness: lostAfter, now: NOW }), { skip: "the user's share is already claimed" });
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

test("token channels are left to Fiber's native watchtower", async () => {
  const { channel } = channelFixture();
  const untouched = new Proxy({}, { get: () => { throw new Error("no chain access expected"); } }) as ccc.Client;
  const result = await settleChannel({
    client: untouched, network: "testnet", nodeKey: hex(secp256k1.utils.randomSecretKey()),
    channel: { ...channel, channelId: "0x" + "01".repeat(32), fundingUdtTypeScript: { code_hash: "0x00", hash_type: "type", args: "0x" }, localFundingPubkey: "", remoteFundingPubkey: "", createdAt: 0, updatedAt: 0 } as WatchedChannel,
    ref: { channelId: "0x" + "01".repeat(32), fundingOutPoint: { txHash: "0x" + "02".repeat(32), index: 0 } },
  });
  assert.match(result.status, /token channels/);
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
} = {}) {
  const { channel, argsFor } = options.tlcs ?? channelFixture();
  const ours = options.tlcs?.theirs ?? encodeSettlementWitness(channel.localSettlement, false, channel.localSettlementKey, channel.remoteSettlementKey);
  const nodeKey = hex(secp256k1.utils.randomSecretKey());
  const plainLock = { codeHash: "0x" + "00".repeat(32), hashType: "data" as const, args: "0x01" };
  const commitmentLock = (args: ccc.HexLike) => ({ codeHash: COMMITMENT_LOCK.testnet.codeHash, hashType: "type" as const, args });
  const txs = new Map<string, { tx: ccc.Transaction; blockHash: ccc.Hex; epoch: ccc.EpochLike }>();
  const live = new Set<string>();
  const key = (outPoint: ccc.OutPointLike) => `${ccc.hexFrom(ccc.OutPoint.from(outPoint).txHash)}:${Number(ccc.OutPoint.from(outPoint).index)}`;
  const add = (tx: ccc.Transaction, epoch: ccc.EpochLike = [90, 0, 1]) => {
    txs.set(tx.hash(), { tx, blockHash: ccc.hexFrom(ccc.hashCkb(tx.hash())), epoch });
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
  if (options.peerSettledFirst || options.settlementWitness || options.peerTookEverything) {
    const previous = ccc.bytesConcat(new Uint8Array([1]), ours, new Uint8Array([0xff, 0]), new Uint8Array(65));
    const witness = options.settlementWitness ? options.settlementWitness(ours) : ccc.bytesConcat(XUDT_COMPATIBLE_WITNESS, previous);
    const after = blake160(encodeWitnessState(applyUnlocks(parseSettlementWitness(previous)!)!));
    const successorArgs = ccc.bytesConcat(ccc.bytesFrom(argsFor(ours)).slice(0, 36), after, new Uint8Array([1]));
    const settlement = add(ccc.Transaction.from({
      inputs: [{ previousOutput: liveCell }],
      outputs: options.peerTookEverything
        ? [{ capacity: 750n * CKB, lock: plainLock }]
        : [{ capacity: 250n * CKB, lock: plainLock }, { capacity: 500n * CKB, lock: commitmentLock(successorArgs) }],
      outputsData: options.peerTookEverything ? ["0x"] : ["0x", "0x"],
      witnesses: [ccc.hexFrom(witness)],
    }), [101, 0, 1]);
    liveCell = { txHash: settlement.hash(), index: 1 };
  }
  let tip: ccc.EpochLike = [100, 0, 1];
  const sent: ccc.Transaction[] = [];
  const base = new ccc.ClientPublicTestnet({ url: "http://127.0.0.1:9/" });
  const signer = new ccc.SignerCkbPrivateKey(base, nodeKey);
  const ready = (async () => {
    const nodeLock = (await signer.getRecommendedAddressObj()).script;
    add(ccc.Transaction.from({ outputs: [{ capacity: 200n * CKB, lock: nodeLock }], outputsData: ["0x"] }));
    return nodeLock;
  })();
  const overrides: Record<string, unknown> = {
    async getTransaction(hash: ccc.HexLike) {
      const found = txs.get(ccc.hexFrom(hash));
      return found && { transaction: found.tx, status: "committed", blockHash: found.blockHash, blockNumber: 1n };
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
    async sendTransaction(tx: ccc.TransactionLike) {
      const signed = ccc.Transaction.from(tx);
      sent.push(signed);
      return signed.hash();
    },
  };
  const client = new Proxy(base, {
    get: (target, property, receiver) => property in overrides ? overrides[property as string] : Reflect.get(target, property, receiver),
  }) as ccc.Client;
  const watched = { ...channel, channelId: "0x" + "01".repeat(32), localFundingPubkey: "", remoteFundingPubkey: "", createdAt: 0, updatedAt: 0 } as WatchedChannel;
  const settle = (dryRun?: { submit: (tx: ccc.Transaction) => Promise<ccc.Hex> }) => settleChannel({
    client, network: "testnet", nodeKey, channel: watched,
    ref: { channelId: watched.channelId, fundingOutPoint: { txHash: funding.hash(), index: 0 } }, ...(dryRun ? { dryRun } : {}),
    preimage: async (hash) => options.preimages?.get(hash), now: options.now,
  });
  return {
    channel, settle, sent, liveCell, ready, funding, commitmentTx,
    setTip: (epoch: ccc.EpochLike) => { tip = epoch; },
    reopen: () => live.add(key({ txHash: funding.hash(), index: 0 })),
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
