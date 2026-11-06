import assert from "node:assert/strict";
import test from "node:test";
import * as ccc from "@ckb-ccc/core";
import { createRemoteWatchtower, remoteWatchUpdate, updatesForStoredChannel, type RemoteWatchUpdate } from "../src/sdk/browser/watchtower-remote.ts";
import type { WatchedChannel } from "../src/sdk/browser/watchtower-store.ts";
import {
  FUNDING_LOCK, assessChannel, buildPenaltyTransaction, commitmentArgs, fundingLockArgs, keyAggXOnly, parseRevocation,
  parseWatchtowerRequest, peerCommitmentKey, revocationWitness, type ChainView,
} from "../src/server/watchtower.ts";
import { COMMITMENT_LOCK, blake160 } from "../src/sdk/browser/watchtower-settle.ts";

const hex = (value: string) => ccc.bytesFrom(`0x${value}`);
// Real secp256k1 points (BIP327's test keys).
const K1 = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
const K2 = "03dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659";
const K3 = "023590a94e768f8e1815c2f24b4d80a8e3149316c3518ce7b7ad338368d038ca66";
const SECRET = "11".repeat(32);
const TLC_SECRET = "22".repeat(32);
const PREIMAGE = "33".repeat(32);
const CHANNEL = `0x${"ab".repeat(32)}`;

const userLock = ccc.Script.from({ codeHash: `0x${"9b".repeat(32)}`, hashType: "type", args: `0x${"01".repeat(20)}` });
function revocationJson(commitment: bigint, capacity = 1000n * 100_000_000n, type?: ccc.ScriptLike) {
  return {
    commitment_number: `0x${commitment.toString(16)}`,
    aggregated_signature: `0x${"5a".repeat(64)}`,
    output: ccc.CellOutput.from({ capacity, lock: userLock, type }).toHex(),
    output_data: type ? `0x10000000${"00".repeat(16)}` : "0x00000000",
  };
}

test("MuSig2 key aggregation matches BIP327's KeyAgg vectors", () => {
  const upper = (bytes: Uint8Array) => ccc.hexFrom(bytes).slice(2).toUpperCase();
  assert.equal(upper(keyAggXOnly([hex(K1), hex(K2), hex(K3)])), "90539EEDE565F5D054F32CC0C220126889ED1E5D193BAF15AEF344FE59D4610C");
  assert.equal(upper(keyAggXOnly([hex(K3), hex(K2), hex(K1)])), "6204DE8B083426DC6EAF9502D27024D53FC826BF7D2012148A0575435DF54B2B");
  assert.equal(upper(keyAggXOnly([hex(K1), hex(K1), hex(K1)])), "B436E3BAD62B8CD409969A224731C193D051162D8C5AE8B109306127DA3AA935");
});

test("funding lock args sort the keys; the peer's commitment key keeps [local, remote]", () => {
  assert.equal(fundingLockArgs(`0x${K1}`, `0x${K2}`), fundingLockArgs(`0x${K2}`, `0x${K1}`));
  assert.equal(fundingLockArgs(`0x${K1}`, `0x${K2}`), ccc.hexFrom(blake160(keyAggXOnly([hex(K1), hex(K2)]))));
  assert.notEqual(peerCommitmentKey(`0x${K1}`, `0x${K2}`), peerCommitmentKey(`0x${K2}`, `0x${K1}`));
});

test("only funding keys and revocation data leave the device", () => {
  const create = remoteWatchUpdate({
    method: "create_watch_channel",
    params: {
      channel_id: CHANNEL,
      funding_udt_type_script: null,
      local_settlement_key: SECRET,
      remote_settlement_key: K2,
      local_funding_pubkey: K1,
      remote_funding_pubkey: K2,
      settlement_data: { local_amount: "0x1", remote_amount: "0x2", tlcs: [{ local_key: TLC_SECRET, remote_key: K3 }] },
    },
  });
  assert.deepEqual(create, { operation: "watch", channelId: CHANNEL, localFundingPubkey: `0x${K1}`, remoteFundingPubkey: `0x${K2}`, fundingUdtTypeScript: null });
  const revoke = remoteWatchUpdate({
    method: "update_revocation",
    params: { channel_id: CHANNEL, revocation_data: { ...revocationJson(3n), extra: SECRET }, settlement_data: { tlcs: [{ local_key: TLC_SECRET }] } },
  });
  assert.equal(revoke?.operation, "revoke");
  assert.deepEqual(Object.keys((revoke as Extract<RemoteWatchUpdate, { operation: "revoke" }>).revocation).sort(), ["aggregated_signature", "commitment_number", "output", "output_data"]);
  for (const update of [create, revoke]) {
    const json = JSON.stringify(update);
    for (const secret of [SECRET, TLC_SECRET]) assert.ok(!json.includes(secret), "a private key would leave the device");
  }
  for (const method of ["update_local_settlement", "update_pending_remote_settlement", "create_preimage", "remove_preimage"] as const) {
    assert.equal(remoteWatchUpdate({ method, params: { channel_id: CHANNEL, preimage: PREIMAGE, settlement_data: {} } }), undefined, method);
  }
  assert.deepEqual(remoteWatchUpdate({ method: "remove_watch_channel", params: { channel_id: CHANNEL } }), { operation: "unwatch", channelId: CHANNEL });
});

test("a stored channel is re-registered with its newest revocation", () => {
  const channel = {
    channelId: CHANNEL, fundingUdtTypeScript: null, localSettlementKey: `0x${SECRET}`, remoteSettlementKey: `0x${K2}`,
    localFundingPubkey: `0x${K1}`, remoteFundingPubkey: `0x${K2}`, localSettlement: { local_amount: "0x1", remote_amount: "0x1", tlcs: [] },
    revocation: revocationJson(7n), createdAt: 0, updatedAt: 0,
  } as WatchedChannel;
  const updates = updatesForStoredChannel(channel);
  assert.deepEqual(updates.map((u) => u.operation), ["watch", "revoke"]);
  assert.ok(!JSON.stringify(updates).includes(SECRET));
});

test("the sender keeps only the newest revocation per channel, in order, and retries", async () => {
  const sent: RemoteWatchUpdate[] = [];
  let fail = true;
  const remote = createRemoteWatchtower({
    send: async (update) => {
      if (fail) { fail = false; throw new Error("offline"); }
      sent.push(update);
    },
    retryMs: 5,
    log: { info: () => undefined, warn: () => undefined },
  });
  const watch = { operation: "watch", channelId: CHANNEL, localFundingPubkey: `0x${K1}`, remoteFundingPubkey: `0x${K2}`, fundingUdtTypeScript: null } as const;
  const revoke = (n: bigint) => ({ operation: "revoke", channelId: CHANNEL, revocation: revocationJson(n) }) as const;
  remote.enqueue(watch);
  remote.enqueue(revoke(3n));
  remote.enqueue(revoke(5n));
  remote.enqueue(revoke(4n));
  assert.equal(remote.pending(), 1);
  await new Promise((resolve) => setTimeout(resolve, 50));
  await remote.flush();
  assert.deepEqual(sent.map((u) => u.operation === "revoke" ? `revoke ${u.revocation.commitment_number}` : u.operation), ["watch", "revoke 0x5"]);
  assert.equal(remote.pending(), 0);
  remote.stop();
});

test("a revocation KeyWay doesn't know the channel for brings the registration along", async () => {
  const sent: string[] = [];
  const known = new Set<string>();
  const remote = createRemoteWatchtower({
    send: async (update) => {
      if (update.operation === "revoke" && !known.has(update.channelId)) throw new Error("This channel is not watched; register it first");
      if (update.operation === "watch") known.add(update.channelId);
      sent.push(update.operation);
    },
    registration: async (channelId) => ({ operation: "watch", channelId, localFundingPubkey: `0x${K1}`, remoteFundingPubkey: `0x${K2}`, fundingUdtTypeScript: null }),
    retryMs: 5,
    log: { info: () => undefined, warn: () => undefined },
  });
  remote.enqueue({ operation: "revoke", channelId: CHANNEL, revocation: revocationJson(1n) });
  await new Promise((resolve) => setTimeout(resolve, 50));
  await remote.flush();
  assert.deepEqual(sent, ["watch", "revoke"]);
  remote.stop();
});

test("the API accepts only well-formed watch data", () => {
  const watch = { operation: "watch", channelId: CHANNEL, localFundingPubkey: `0x${K1}`, remoteFundingPubkey: `0x${K2}`, fundingUdtTypeScript: null, localSettlementKey: SECRET };
  const parsed = parseWatchtowerRequest(watch);
  assert.ok(!JSON.stringify(parsed).includes(SECRET), "unknown fields are dropped");
  assert.throws(() => parseWatchtowerRequest({ ...watch, localFundingPubkey: `0x02${"00".repeat(32)}` }), /funding key/);
  assert.throws(() => parseWatchtowerRequest({ ...watch, channelId: "0x12" }), /channel ID/);
  assert.throws(() => parseWatchtowerRequest({ operation: "drop-everything" }), /Unsupported/);
  const revocation = parseRevocation(revocationJson(9n));
  assert.equal(revocation.commitmentNumber, 9n);
  assert.equal(revocation.outputData, "0x");
  assert.throws(() => parseRevocation({ ...revocationJson(9n), output_data: "0x05000000aa" }), /output data/);
  assert.throws(() => parseRevocation({ ...revocationJson(9n), aggregated_signature: "0x00" }), /signature/);
  assert.throws(() => parseRevocation({ ...revocationJson(9n), output: "0x1234" }), /output/);
  assert.throws(() => parseRevocation({ ...revocationJson(9n), commitment_number: "0x1ffffffffffffffff" }), /commitment number/);
});

test("the penalty witness is Fiber's revocation unlock", () => {
  const peerKey = `0x${"77".repeat(32)}`;
  const witness = ccc.bytesFrom(revocationWitness({ commitmentNumber: 0x0102n, aggregatedSignature: `0x${"5a".repeat(64)}` }, peerKey));
  assert.equal(witness.length, 16 + 1 + 8 + 32 + 64);
  assert.deepEqual([...witness.slice(0, 16)], [16, 0, 0, 0, 16, 0, 0, 0, 16, 0, 0, 0, 16, 0, 0, 0]);
  assert.equal(witness[16], 0, "unlock count 0 selects the revocation path");
  assert.equal(ccc.hexFrom(witness.slice(17, 25)), "0x0000000000000102", "commitment number, big-endian");
  assert.equal(ccc.hexFrom(witness.slice(25, 57)), peerKey);
});

test("the watchtower never pays itself from the channel", async () => {
  const revocation = parseRevocation(revocationJson(2n, 500n));
  await assert.rejects(buildPenaltyTransaction({
    client: {} as ccc.Client,
    commitment: { outPoint: { txHash: `0x${"01".repeat(32)}`, index: 0 }, capacity: 501n },
    revocation, peerKey: `0x${"77".repeat(32)}`, feeSigner: {} as ccc.Signer, cellDeps: [],
  }), /smaller than the commitment cell/);
});

function fakeChain(options: { funded?: boolean; closing?: ccc.Transaction; committed?: boolean }): ChainView {
  const fundingTx = `0x${"f0".repeat(32)}` as ccc.Hex;
  const closingHash = options.closing?.hash();
  return {
    async fundingHistory() {
      return [
        ...(options.funded ? [{ txHash: fundingTx, isInput: false, index: 0 }] : []),
        ...(options.closing ? [{ txHash: closingHash!, isInput: true, index: 0 }] : []),
      ];
    },
    async transaction(hash) {
      return hash === closingHash && options.closing ? { tx: options.closing, committed: options.committed ?? true, status: options.committed === false ? "pending" : "committed" } : undefined;
    },
    async isLive() { return true; },
    async spender() { return undefined; },
  };
}

test("the watchtower tells a revoked commitment of the peer from every other close", async () => {
  const local = `0x${K1}`;
  const remote = `0x${K2}`;
  const row = { funding_lock_args: fundingLockArgs(local, remote), peer_commitment_key: peerCommitmentKey(local, remote), commitment_number: "5" };
  const commitmentTx = (keyHash: Uint8Array, number: bigint) => ccc.Transaction.from({
    inputs: [{ previousOutput: { txHash: `0x${"f0".repeat(32)}`, index: 0 } }],
    outputs: [{ capacity: 1000n, lock: { codeHash: COMMITMENT_LOCK.testnet.codeHash, hashType: "type", args: ccc.hexFrom(ccc.bytesConcat(keyHash, new Uint8Array(8), ccc.numBeToBytes(number, 8), new Uint8Array(21))) } }],
    outputsData: ["0x"],
  });
  const peerHash = blake160(peerCommitmentKey(local, remote));
  const ownHash = blake160(peerCommitmentKey(remote, local));
  assert.deepEqual((await assessChannel(fakeChain({}), row)).state, "watching");
  assert.equal((await assessChannel(fakeChain({ funded: true }), row) as { detail: string }).detail, "open");
  assert.equal((await assessChannel(fakeChain({ funded: true, closing: commitmentTx(peerHash, 3n), committed: false }), row)).state, "watching");
  const cooperative = ccc.Transaction.from({ outputs: [{ capacity: 1n, lock: userLock }, { capacity: 1n, lock: userLock }], outputsData: ["0x", "0x"] });
  assert.match((await assessChannel(fakeChain({ funded: true, closing: cooperative }), row) as { detail: string }).detail, /cooperatively/);
  assert.match((await assessChannel(fakeChain({ funded: true, closing: commitmentTx(ownHash, 3n) }), row) as { detail: string }).detail, /user's node force-closed/);
  assert.match((await assessChannel(fakeChain({ funded: true, closing: commitmentTx(peerHash, 6n) }), row) as { detail: string }).detail, /current state/);
  for (const number of [0n, 5n]) {
    const revoked = await assessChannel(fakeChain({ funded: true, closing: commitmentTx(peerHash, number) }), row);
    assert.equal(revoked.state, "revoked", `commitment ${number} is covered by revocation 5`);
  }
  assert.equal((await assessChannel(fakeChain({ funded: true, closing: commitmentTx(peerHash, 0n) }), { ...row, commitment_number: null })).state, "closed");
  assert.deepEqual(commitmentArgs(commitmentTx(peerHash, 9n).outputs[0].lock.args)?.commitmentNumber, 9n);
  assert.equal(FUNDING_LOCK.codeHash.length, 66);
});

test("keys from the testnet proof give the on-chain funding and commitment locks", async () => {
  const { readFile } = await import("node:fs/promises");
  const fixture = JSON.parse(await readFile(new URL("./fixtures/watchtower-testnet-proof.json", import.meta.url), "utf8"));
  for (const channel of [fixture.penalty, fixture.browser]) {
    assert.equal(fundingLockArgs(channel.localFundingPubkey, channel.remoteFundingPubkey), channel.onChainFundingLockArgs);
    const args = commitmentArgs(channel.onChainCommitmentArgs)!;
    assert.equal(args.keyHash, ccc.hexFrom(blake160(peerCommitmentKey(channel.localFundingPubkey, channel.remoteFundingPubkey))), "the peer's commitment");
  }
  assert.ok(BigInt(fixture.penalty.revocationCommitmentNumber) >= commitmentArgs(fixture.penalty.onChainCommitmentArgs)!.commitmentNumber, "revoked");
  assert.ok(BigInt(fixture.browser.revocationCommitmentNumber) < commitmentArgs(fixture.browser.onChainCommitmentArgs)!.commitmentNumber, "current");
  // The revocation output pays the victim's own lock: that is all the watchtower can do with it.
  assert.equal(ccc.CellOutput.decode(fixture.penalty.revocationOutput).lock.args, fixture.penalty.victimLockArgs);
});
