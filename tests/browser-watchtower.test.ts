import assert from "node:assert/strict";
import test from "node:test";
import * as ccc from "@ckb-ccc/core";
import { createRemoteWatchtower, remoteWatchUpdate, updatesForStoredChannel, type RemoteWatchUpdate } from "../src/sdk/browser/watchtower-remote.ts";
import type { WatchedChannel } from "../src/sdk/browser/watchtower-store.ts";
import {
  FUNDING_LOCK, assessChannel, chainView, type HistoryScan, buildPenaltyTransaction, commitmentArgs, fundingLockArgs, keyAggXOnly, parseRevocation,
  parseWatchtowerRequest, peerCommitmentKey, revocationSignatureValid, revocationWitness, type ChainView,
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

test("one channel's failing update doesn't hold up another's, and a refused one is dropped", async () => {
  const OTHER = `0x${"cd".repeat(32)}`;
  const sent: string[] = [];
  let down = true;
  const remote = createRemoteWatchtower({
    send: async (update) => {
      if (update.channelId === CHANNEL && down) throw new Error("offline");
      if (update.channelId === OTHER && update.operation === "watch") throw Object.assign(new Error("Token channels are not watched yet"), { status: 400 });
      sent.push(`${update.operation} ${update.channelId.slice(0, 4)}`);
    },
    retryMs: 60_000,
    log: { info: () => undefined, warn: () => undefined },
  });
  const third = `0x${"ef".repeat(32)}`;
  remote.enqueue({ operation: "revoke", channelId: CHANNEL, revocation: revocationJson(1n) });
  remote.enqueue({ operation: "watch", channelId: OTHER, localFundingPubkey: `0x${K1}`, remoteFundingPubkey: `0x${K2}`, fundingUdtTypeScript: null });
  remote.enqueue({ operation: "unwatch", channelId: third });
  try {
  await remote.flush();
  assert.deepEqual(sent, ["unwatch 0xef"], "the healthy channel went out; the refused one is gone");
  assert.equal(remote.pending(), 1, "only the failing channel waits");
  remote.enqueue({ operation: "revoke", channelId: OTHER, revocation: revocationJson(1n) });
  assert.equal(remote.pending(), 1, "updates for a refused channel are dropped");
  // A flush (e.g. on stop) doesn't wait for the scheduled retry.
  down = false;
  await remote.flush();
  assert.deepEqual(sent, ["unwatch 0xef", "revoke 0xab"]);
  assert.equal(remote.pending(), 0);
  } finally {
    remote.stop();
  }
});

test("only the API's own refusals are final; other failures are retried", async () => {
  const attempts: string[] = [];
  let failures = 2;
  const remote = createRemoteWatchtower({
    send: async (update) => {
      attempts.push(update.operation);
      // What the API returns for a passing database fault: a 400 that isn't one of its refusals.
      if (failures-- > 0) throw Object.assign(new Error("PostgresError: connection terminated unexpectedly"), { status: 400 });
    },
    retryMs: 5,
    log: { info: () => undefined, warn: () => undefined },
  });
  try {
    remote.enqueue({ operation: "revoke", channelId: CHANNEL, revocation: revocationJson(3n) });
    await new Promise((resolve) => setTimeout(resolve, 100));
    await remote.flush();
    assert.deepEqual(attempts, ["revoke", "revoke", "revoke"]);
    assert.equal(remote.pending(), 0);
  } finally {
    remote.stop();
  }
});

test("a revocation for a channel the device has no record of stops being retried", async () => {
  let lookups = 0;
  const remote = createRemoteWatchtower({
    send: async () => { throw Object.assign(new Error("This channel is not watched; register it first"), { status: 400 }); },
    registration: async () => { lookups++; return undefined; },
    retryMs: 5,
    log: { info: () => undefined, warn: () => undefined },
  });
  try {
    remote.enqueue({ operation: "revoke", channelId: CHANNEL, revocation: revocationJson(3n) });
    await new Promise((resolve) => setTimeout(resolve, 100));
    await remote.flush();
    assert.equal(lookups, 1);
    assert.equal(remote.pending(), 0, "nothing left to warn about on unload");
  } finally {
    remote.stop();
  }
});

type Entry = { txHash: ccc.Hex; blockNumber: bigint; isInput: boolean; cellIndex: bigint };
/** An indexer over `entries` (oldest first); a cursor is the position of the last entry returned, as the real one's. */
function fakeIndexer(entries: () => Entry[], fail?: (order: string, after?: string) => boolean) {
  return {
    async findTransactionsPaged(_key: unknown, order: string, limit: number, after?: string) {
      if (fail?.(order, after)) throw new Error("indexer timeout");
      const all = entries().map((entry, position) => ({ entry, position }));
      const list = order === "desc"
        ? all.filter(({ position }) => after === undefined || position < Number(after)).reverse()
        : all.filter(({ position }) => after === undefined || position > Number(after));
      const page = list.slice(0, Number(limit));
      return { transactions: page.map(({ entry }) => entry), lastCursor: page.length ? String(page.at(-1)!.position) : after ?? "" };
    },
  } as unknown as ccc.Client;
}
const padding = (from: number, count: number): Entry[] =>
  Array.from({ length: count }, (_, i) => ({ txHash: ccc.hexFrom(ccc.numBeToBytes(BigInt(from + i), 32)), blockNumber: BigInt(from + i), isInput: false, cellIndex: 0n }));

test("a padded funding history only delays the backlog scan: it resumes until it reaches the spend", async () => {
  const closingHash = `0x${"c1".repeat(32)}` as ccc.Hex;
  const lock = ccc.Script.from({ ...FUNDING_LOCK, args: `0x${"00".repeat(20)}` });
  // Registered late: 9,000 padded cells, the spend, then 300 more, before the first check.
  const entries = [...padding(1, 9_000), { txHash: closingHash, blockNumber: 9_001n, isInput: true, cellIndex: 1n }, ...padding(9_002, 300)];
  const view = chainView(fakeIndexer(() => entries), { maxPages: 25 });
  const first = await view.fundingHistory(lock, {}, { backlogBudgetMs: 60_000 });
  assert.equal(first.spend, undefined, "neither the newest page nor 25 pages of backlog reach it");
  assert.deepEqual({ cursor: first.cursor, backlog: first.backlog, recent: first.recent }, { cursor: "4999", backlog: true, recent: { from: "9301", seenTo: "9301" } });
  const second = await view.fundingHistory(lock, first, { backlogBudgetMs: 60_000 });
  assert.deepEqual(second.spend, { txHash: closingHash, index: 1 }, "the next pass resumes and reaches it");
});

test("a spend made while the channel is watched is caught in the next pass, padded or not, whatever the backlog", async () => {
  const closingHash = `0x${"c2".repeat(32)}` as ccc.Hex;
  const lock = ccc.Script.from({ ...FUNDING_LOCK, args: `0x${"00".repeat(20)}` });
  let entries = padding(1, 9_000);
  const view = chainView(fakeIndexer(() => entries), { maxPages: 1 });
  const first = await view.fundingHistory(lock, {});
  assert.deepEqual({ cursor: first.cursor, backlog: first.backlog, recent: first.recent }, { cursor: "199", backlog: true, recent: { from: "9000", seenTo: "9000" } });
  // The peer spends, then buries the spend under 1,000 more cells (five pages) before the next pass.
  entries = [...entries, { txHash: closingHash, blockNumber: 9_001n, isInput: true, cellIndex: 0n }, ...padding(9_002, 1_000)];
  const next = await view.fundingHistory(lock, first);
  assert.deepEqual(next.spend, { txHash: closingHash, index: 0 });
  assert.equal(next.cursor, "199", "the backlog scan keeps its place");

  // With nothing new the recent scan reads one page and moves on; new cells move its mark forward.
  entries = padding(1, 9_000);
  const quiet = await view.fundingHistory(lock, first);
  assert.deepEqual(quiet.recent, { from: "9000", seenTo: "9000" });
  entries = [...entries, ...padding(9_001, 50)];
  assert.deepEqual((await view.fundingHistory(lock, quiet)).recent, { from: "9000", seenTo: "9050" });
});

test("a recent range longer than a pass can read is resumed, and a fresh spend still goes first", async () => {
  const closingHash = `0x${"c3".repeat(32)}` as ccc.Hex;
  const lock = ccc.Script.from({ ...FUNDING_LOCK, args: `0x${"00".repeat(20)}` });
  let entries = [...padding(1, 100), { txHash: closingHash, blockNumber: 101n, isInput: true, cellIndex: 0n }, ...padding(102, 500)];
  // A budget of 0: one page of the recent range per pass.
  const view = chainView(fakeIndexer(() => entries), { recentBudgetMs: 0 });
  const scan = { recent: { from: "100", seenTo: "100" } };
  const one = await view.fundingHistory(lock, scan);
  assert.equal(one.spend, undefined);
  assert.deepEqual(one.recent, { from: "100", seenTo: "100", top: "601", cursor: "401" });
  const two = await view.fundingHistory(lock, one);
  assert.deepEqual(two.recent, { from: "100", seenTo: "100", top: "601", cursor: "201" });
  const three = await view.fundingHistory(lock, two);
  assert.deepEqual(three.spend, { txHash: closingHash, index: 0 });
  // Unspent instead, the range completes and the next one starts above it.
  entries = padding(1, 600);
  let state: HistoryScan = scan;
  for (let i = 0; i < 4; i++) state = await view.fundingHistory(lock, state);
  assert.deepEqual(state.recent, { from: "100", seenTo: "600" });
  // A spend at the head while a range is still being read is found from the newest page at once.
  entries = [...padding(1, 600), ...padding(601, 400), { txHash: closingHash, blockNumber: 1_001n, isInput: true, cellIndex: 0n }];
  const midRange = await view.fundingHistory(lock, { recent: { from: "100", seenTo: "600", top: "1000", cursor: "900" } });
  assert.deepEqual(midRange.spend, { txHash: closingHash, index: 0 });
});

test("a failing read keeps the progress made before it", async () => {
  const lock = ccc.Script.from({ ...FUNDING_LOCK, args: `0x${"00".repeat(20)}` });
  const entries = padding(1, 9_000);
  // A backlog page that fails partway returns what was read, with the error.
  const flaky = chainView(fakeIndexer(() => entries, (order, after) => order === "asc" && Number(after) >= 399));
  const partial = await flaky.fundingHistory(lock, { recent: { from: "9000", seenTo: "9000" } }, { backlogBudgetMs: 60_000 });
  assert.deepEqual(partial, { sawOutput: true, cursor: "399", recent: { from: "9000", seenTo: "9000" }, backlog: false, error: "indexer timeout" });
  // A failing recent scan still lets the backlog scan run, and reports the error.
  const newestFails = chainView(fakeIndexer(() => entries, (order) => order === "desc"), { maxPages: 3 });
  const kept = await newestFails.fundingHistory(lock, { cursor: "199", recent: { from: "9000", seenTo: "9000" } }, { backlogBudgetMs: 60_000 });
  assert.deepEqual(kept, { sawOutput: true, cursor: "799", recent: { from: "9000", seenTo: "9000" }, backlog: true, error: "indexer timeout" });
});

test("the funding outpoint is the cell the spend consumed, not the first cell under the lock", async () => {
  const local = `0x${K1}`;
  const remote = `0x${K2}`;
  const realFunding = { txHash: `0x${"ee".repeat(32)}` as ccc.Hex, index: 3 };
  const closing = ccc.Transaction.from({
    inputs: [{ previousOutput: { txHash: `0x${"aa".repeat(32)}`, index: 0 } }, { previousOutput: realFunding }],
    outputs: [{ capacity: 1n, lock: userLock }, { capacity: 1n, lock: userLock }],
    outputsData: ["0x", "0x"],
  });
  const chain: ChainView = {
    // An unrelated cell came first under the lock; the spend is the closing transaction's input 1.
    fundingHistory: async () => ({ sawOutput: true, spend: { txHash: closing.hash(), index: 1 } }),
    transaction: async () => ({ tx: closing, committed: true, status: "committed" }),
    isLive: async () => true,
    spender: async () => undefined,
  };
  const assessment = await assessChannel(chain, { funding_lock_args: fundingLockArgs(local, remote), peer_commitment_key: peerCommitmentKey(local, remote), commitment_number: null });
  assert.equal(assessment.state, "closed");
  assert.equal((assessment as { fundingOutPoint: string }).fundingOutPoint, `${realFunding.txHash}:3`);
  // While the channel is open nothing is reported as its funding outpoint.
  const open = await assessChannel({ ...chain, fundingHistory: async () => ({ sawOutput: true }) }, { funding_lock_args: fundingLockArgs(local, remote), peer_commitment_key: peerCommitmentKey(local, remote), commitment_number: null });
  assert.deepEqual({ state: open.state, fundingOutPoint: (open as { fundingOutPoint?: string }).fundingOutPoint }, { state: "watching", fundingOutPoint: undefined });
});

test("the API accepts only well-formed watch data", () => {
  const watch = { operation: "watch", channelId: CHANNEL, localFundingPubkey: `0x${K1}`, remoteFundingPubkey: `0x${K2}`, fundingUdtTypeScript: null, localSettlementKey: SECRET };
  const parsed = parseWatchtowerRequest(watch);
  assert.ok(!JSON.stringify(parsed).includes(SECRET), "unknown fields are dropped");
  assert.throws(() => parseWatchtowerRequest({ ...watch, localFundingPubkey: `0x02${"00".repeat(32)}` }), /funding key/);
  assert.throws(() => parseWatchtowerRequest({ ...watch, channelId: "0x12" }), /channel ID/);
  assert.throws(() => parseWatchtowerRequest({ operation: "drop-everything" }), /Unsupported/);
  assert.throws(() => parseWatchtowerRequest({ ...watch, fundingUdtTypeScript: { code_hash: `0x${"aa".repeat(32)}`, hash_type: "type", args: "0x" } }), /Token channels/);
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

async function penalty(options: { outputCapacity: bigint; commitmentCapacity: bigint; feeCell: bigint }) {
  const client = new ccc.ClientPublicTestnet();
  const feeSigner = new ccc.SignerCkbPrivateKey(client, `0x${"42".repeat(32)}`);
  const feeLock = (await feeSigner.getRecommendedAddressObj()).script;
  const commitmentOutPoint = ccc.OutPoint.from({ txHash: `0x${"01".repeat(32)}`, index: 0 });
  const commitmentCell = ccc.Cell.from({
    outPoint: commitmentOutPoint,
    cellOutput: { capacity: options.commitmentCapacity, lock: { codeHash: COMMITMENT_LOCK.testnet.codeHash, hashType: "type", args: `0x${"00".repeat(57)}` } },
    outputData: "0x",
  });
  const feeCell = ccc.Cell.from({ outPoint: { txHash: `0x${"0f".repeat(32)}`, index: 0 }, cellOutput: { capacity: options.feeCell, lock: feeLock }, outputData: "0x" });
  // No network: the indexer knows the fee key's one plain cell, and cells resolve to these two.
  Object.assign(client, {
    findCellsPagedNoCache: async (key: { scriptSearchMode?: string }) => ({ cells: key.scriptSearchMode === "exact" ? [feeCell] : [], lastCursor: "" }),
    getCell: async (outPoint: ccc.OutPointLike) => (ccc.OutPoint.from(outPoint).eq(commitmentOutPoint) ? commitmentCell : feeCell),
  });
  const revocation = parseRevocation(revocationJson(2n, options.outputCapacity));
  const tx = await buildPenaltyTransaction({
    client, commitment: { outPoint: commitmentOutPoint, capacity: options.commitmentCapacity },
    revocation, peerKey: `0x${"77".repeat(32)}`, feeSigner, cellDeps: [],
  });
  return { tx, feeIn: options.feeCell };
}

test("the penalty pays the user and returns the watchtower's own capacity less the fee", async () => {
  const CKB = 100_000_000n;
  const { tx, feeIn } = await penalty({ outputCapacity: 1000n * CKB, commitmentCapacity: 1000n * CKB, feeCell: 10_000n * CKB });
  assert.equal(tx.outputs[0].capacity, 1000n * CKB, "the whole commitment goes to the user's output");
  assert.equal(tx.outputs[0].lock.args, userLock.args);
  const fee = feeIn - tx.outputs[1].capacity;
  assert.ok(fee > 0n && fee < 10_000n, `fee ${fee}`);
  assert.equal(tx.inputs.length, 2);
});

test("the watchtower refuses revocations that would move capacity between it and the channel", async () => {
  const CKB = 100_000_000n;
  // A self-dealt revocation larger than the commitment would make the watchtower pay the difference.
  await assert.rejects(penalty({ outputCapacity: 1_000_000n * CKB, commitmentCapacity: 1000n * CKB, feeCell: 2_000_000n * CKB }), /does not match the commitment cell/);
  await assert.rejects(penalty({ outputCapacity: 999n * CKB, commitmentCapacity: 1000n * CKB, feeCell: 10_000n * CKB }), /does not match the commitment cell/);
  // A fee cell too small for a change cell is not used.
  await assert.rejects(penalty({ outputCapacity: 1000n * CKB, commitmentCapacity: 1000n * CKB, feeCell: 61n * CKB }));
});

function fakeChain(options: { funded?: boolean; closing?: ccc.Transaction; committed?: boolean }): ChainView {
  const closingHash = options.closing?.hash();
  return {
    async fundingHistory() {
      return { sawOutput: Boolean(options.funded), ...(options.closing ? { spend: { txHash: closingHash!, index: 0 } } : {}) };
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
  const cooperative = ccc.Transaction.from({ inputs: [{ previousOutput: { txHash: `0x${"f0".repeat(32)}`, index: 0 } }], outputs: [{ capacity: 1n, lock: userLock }, { capacity: 1n, lock: userLock }], outputsData: ["0x", "0x"] });
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
  // The stored signature unlocks the revoked commitment the way the lock checks it, and nothing else.
  const revocation = { commitmentNumber: BigInt(fixture.penalty.revocationCommitmentNumber), aggregatedSignature: fixture.penalty.revocationSignature, output: fixture.penalty.revocationOutput, outputData: "0x" as const };
  const key = peerCommitmentKey(fixture.penalty.localFundingPubkey, fixture.penalty.remoteFundingPubkey);
  assert.equal(revocationSignatureValid(revocation, key, fixture.penalty.onChainCommitmentArgs), true);
  assert.equal(revocationSignatureValid({ ...revocation, commitmentNumber: revocation.commitmentNumber + 1n }, key, fixture.penalty.onChainCommitmentArgs), false);
  assert.equal(revocationSignatureValid(revocation, key, fixture.browser.onChainCommitmentArgs), false);
  // The revocation output pays the victim's own lock: that is all the watchtower can do with it.
  assert.equal(ccc.CellOutput.decode(fixture.penalty.revocationOutput).lock.args, fixture.penalty.victimLockArgs);
});
