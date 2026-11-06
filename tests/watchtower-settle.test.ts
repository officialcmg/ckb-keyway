import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import * as ccc from "@ckb-ccc/core";
import { JsonRpcTransformers } from "@ckb-ccc/core/advanced";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import {
  applyUnlocks, blake160, encodeSettlementWitness, encodeWitnessState, parseCommitmentArgs, parseSettlementWitness,
  planClaim, settleChannel, settlementMessage, signSettlement, XUDT_COMPATIBLE_WITNESS,
} from "../src/sdk/browser/watchtower-settle.ts";
import type { WatchedChannel } from "../src/sdk/browser/watchtower-store.ts";
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
function fakeChain(options: { peerSettledFirst?: boolean; settlementWitness?: (ours: Uint8Array) => Uint8Array; peerTookEverything?: boolean } = {}) {
  const { channel, argsFor } = channelFixture();
  const ours = encodeSettlementWitness(channel.localSettlement, false, channel.localSettlementKey, channel.remoteSettlementKey);
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
    outputs: [{ capacity: 750n * CKB, lock: commitmentLock(argsFor(ours)) }],
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
