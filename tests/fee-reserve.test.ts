import assert from "node:assert/strict";
import test from "node:test";
import * as ccc from "@ckb-ccc/core";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { KEYWAY_OMNILOCK, omnilockArgsFor, omnilockScript, secp256k1Lock } from "../src/sdk/browser/account-lock.ts";
import { FEE_RESERVE, needsFeeReserve, planSweep, sweepSettlement } from "../src/sdk/browser/settlement-sweep.ts";

const CKB = 100_000_000n;
const channel = (state_name: string, state_flags?: string) => ({ state: { state_name, state_flags } });

test("the reserve stays while any channel is open, closing or waiting to settle on-chain", () => {
  assert.equal(needsFeeReserve([]), false);
  assert.equal(needsFeeReserve([channel("CHANNEL_READY")]), true);
  assert.equal(needsFeeReserve([channel("SHUTTING_DOWN", "WAITING_COMMITMENT_CONFIRMATION")]), true);
  assert.equal(needsFeeReserve([channel("CLOSED", "UNCOOPERATIVE_LOCAL | WAITING_ONCHAIN_SETTLEMENT")]), true);
  assert.equal(needsFeeReserve([channel("CLOSED", "COOPERATIVE")]), false);
  // Fiber keeps WAITING_ONCHAIN_SETTLEMENT while its settlement still has work to do, whatever else is set.
  assert.equal(needsFeeReserve([channel("CLOSED", "UNCOOPERATIVE_LOCAL | WAITING_ONCHAIN_SETTLEMENT | ONCHAIN_SETTLEMENT_CONFIRMED")]), true);
  assert.equal(needsFeeReserve([channel("CLOSED", "COOPERATIVE"), channel("CHANNEL_READY")]), true);
  // As Fiber 0.9.1 reports a force close once it has settled: the reserve comes back.
  assert.equal(needsFeeReserve([channel("CLOSED", "UNCOOPERATIVE_LOCAL|WAITING_ONCHAIN_SETTLEMENT")]), true);
  assert.equal(needsFeeReserve([channel("CLOSED", "UNCOOPERATIVE_LOCAL")]), false);
  assert.equal(needsFeeReserve([channel("CLOSED", "UNCOOPERATIVE_REMOTE")]), false);
});

test("a sweep keeps the reserve and sends the rest of a settlement to the user", () => {
  assert.deepEqual(planSweep(FEE_RESERVE + 500n * CKB, 0, FEE_RESERVE), { toUser: 500n * CKB, reserve: FEE_RESERVE });
});

test("a sweep leaves the reserve alone when nothing else has arrived", () => {
  assert.equal(planSweep(FEE_RESERVE, 0, FEE_RESERVE), undefined);
  // Dust that can't be a cell of its own stays with the reserve.
  assert.equal(planSweep(FEE_RESERVE + 10n * CKB, 0, FEE_RESERVE), undefined);
});

test("a sweep still moves tokens while keeping the reserve", () => {
  assert.deepEqual(planSweep(FEE_RESERVE, 1, FEE_RESERVE), { toUser: 0n, reserve: FEE_RESERVE });
});

test("once every channel is closed, the reserve goes back to the user too", () => {
  assert.deepEqual(planSweep(FEE_RESERVE, 0, 0n), { toUser: FEE_RESERVE, reserve: 0n });
});

// Fiber 0.10.1's browser node never drops WAITING_ONCHAIN_SETTLEMENT from a force-closed channel, so the in-page
// watchtower's verdict that a channel is finished on-chain stands in for it (channel-closures.ts).
const ID = `0x${"0a".repeat(32)}`;
const OUTPOINT = `0x${"0b".repeat(32)}00000000`;
const CLOSING = `0x${"0d".repeat(32)}`;
/** A channel as the node lists it; once it reports the channel closed it names the transaction that closed it. */
const listed = (state_name: string, state_flags?: string, id = ID, outPoint = OUTPOINT, shutdown: string | null = state_name === "CLOSED" ? CLOSING : null) =>
  ({ channel_id: id, channel_outpoint: outPoint, shutdown_transaction_hash: shutdown, state: { state_name, state_flags } });
const verdict = (finished: boolean, id = ID, outPoint = OUTPOINT, closingTx = CLOSING) =>
  ({ channelId: id, fundingOutPoint: outPoint, closingTx, ...(finished ? { finished: { status: "settled", evidence: `0x${"0c".repeat(32)}` } } : {}) });
const WAITING = "UNCOOPERATIVE_REMOTE|WAITING_ONCHAIN_SETTLEMENT";

test("a force-closed channel the node keeps waiting on, which the watchtower found finished on-chain, releases the reserve", () => {
  assert.equal(needsFeeReserve([listed("CLOSED", WAITING)], [verdict(true)]), false);
  assert.equal(needsFeeReserve([listed("CLOSED", "UNCOOPERATIVE_LOCAL|WAITING_ONCHAIN_SETTLEMENT")], [verdict(true)]), false);
  assert.equal(needsFeeReserve([listed("CLOSED", WAITING), listed("CLOSED", "COOPERATIVE", `0x${"1a".repeat(32)}`)], [verdict(true)]), false);
});

test("the reserve stays unless every channel is finished, each on positive evidence about that channel", () => {
  // No verdict, or a force close the watchtower has seen but not found finished (the user's share is unclaimed).
  assert.equal(needsFeeReserve([listed("CLOSED", WAITING)]), true);
  assert.equal(needsFeeReserve([listed("CLOSED", WAITING)], []), true);
  assert.equal(needsFeeReserve([listed("CLOSED", WAITING)], [verdict(false)]), true);
  // A verdict about another channel, or about this channel ID on another funding cell.
  assert.equal(needsFeeReserve([listed("CLOSED", WAITING)], [verdict(true, `0x${"1a".repeat(32)}`)]), true);
  assert.equal(needsFeeReserve([listed("CLOSED", WAITING)], [verdict(true, ID, `0x${"1b".repeat(32)}00000000`)]), true);
  // A verdict that followed another closing transaction than the one the node saw close the channel, or a node
  // that names none.
  assert.equal(needsFeeReserve([listed("CLOSED", WAITING)], [verdict(true, ID, OUTPOINT, `0x${"1d".repeat(32)}`)]), true);
  assert.equal(needsFeeReserve([listed("CLOSED", WAITING, ID, OUTPOINT, null)], [verdict(true)]), true);
  // One finished channel doesn't release the reserve another still needs.
  assert.equal(needsFeeReserve([listed("CLOSED", WAITING), listed("CLOSED", WAITING, `0x${"1a".repeat(32)}`)], [verdict(true)]), true);
  assert.equal(needsFeeReserve([listed("CLOSED", WAITING), listed("CHANNEL_READY", undefined, `0x${"1a".repeat(32)}`)], [verdict(true)]), true);
  // The node must itself report the channel closed: a verdict alone doesn't release it.
  assert.equal(needsFeeReserve([listed("CHANNEL_READY")], [verdict(true)]), true);
  assert.equal(needsFeeReserve([listed("CHANNEL_READY", undefined, ID, OUTPOINT, CLOSING)], [verdict(true)]), true);
  assert.equal(needsFeeReserve([listed("SHUTTING_DOWN", "WAITING_COMMITMENT_CONFIRMATION")], [verdict(true)]), true);
  // A channel the node lists without an ID or funding cell can't be matched to any verdict.
  assert.equal(needsFeeReserve([{ state: { state_name: "CLOSED", state_flags: WAITING }, shutdown_transaction_hash: CLOSING }], [verdict(true, "", "")]), true);
});

// A recovery account's address is an Omnilock, whose smallest cell is 95 CKB: a 62 CKB reserve can't be a cell there.
const settlementKey = ccc.hexFrom(secp256k1.utils.randomSecretKey());
const omnilock = omnilockScript({ omnilock: KEYWAY_OMNILOCK.testnet, omnilockArgs: omnilockArgsFor(ccc.hexFrom(secp256k1.getPublicKey(secp256k1.utils.randomSecretKey(), true)), `0x${"42".repeat(32)}`) });
/** A node key holding these plain cells, on a client that never reaches the network; `sent` collects its sweeps. */
async function nodeKeyHolding(capacities: bigint[]) {
  const client = new ccc.ClientPublicTestnet({ url: "http://127.0.0.1:9/" });
  const from = (await new ccc.SignerCkbPrivateKey(client, settlementKey).getRecommendedAddressObj()).script;
  const cells = capacities.map((capacity, index) => ccc.Cell.from({ outPoint: { txHash: `0x${(index + 1).toString(16).padStart(64, "0")}`, index: 0 }, cellOutput: { lock: from, capacity }, outputData: "0x" }));
  const sent: ccc.Transaction[] = [];
  Object.assign(client, {
    findCells: async function* () {},
    findCellsByLock: async function* (lock: ccc.ScriptLike) { for (const cell of cells) if (cell.cellOutput.lock.eq(ccc.Script.from(lock))) yield cell; },
    getFeeRate: async () => 1000n,
    sendTransaction: async (tx: ccc.Transaction) => { sent.push(tx); return tx.hash(); },
  });
  await client.cache.recordCells(cells);
  return { client, from, sent };
}

test("for a recovery account a kept reserve is kept at a size that can be returned later", async () => {
  assert.equal(ccc.fixedPointFrom(ccc.CellOutput.from({ lock: omnilock, capacity: 0n }).occupiedSize), 95n * CKB);
  // A claim has paid out to the node's key: 500 CKB and the 62 CKB reserve. The reserve is still needed.
  const claimed = await nodeKeyHolding([FEE_RESERVE + 500n * CKB]);
  await sweepSettlement(claimed.client, settlementKey, omnilock, FEE_RESERVE, { returnableReserve: true });
  const [first] = claimed.sent;
  const kept = first.outputs.find((output) => output.lock.eq(claimed.from))!;
  assert.equal(kept.capacity, 95n * CKB + 1_000_000n, "what stays is enough for a cell at the account's address, and its fee");
  assert.ok(first.outputs.find((output) => output.lock.eq(omnilock))!.capacity > 465n * CKB);
  // Later the reserve is no longer needed: what was kept can leave.
  const released = await nodeKeyHolding([kept.capacity]);
  await sweepSettlement(released.client, settlementKey, omnilock, 0n, { returnableReserve: true });
  assert.equal(released.sent.length, 1);
  assert.ok(released.sent[0].outputs[0].lock.eq(omnilock) && released.sent[0].outputs[0].capacity >= 95n * CKB);

  // Without the option (the hosted sweep) nothing changes: 62 CKB stays.
  const hosted = await nodeKeyHolding([FEE_RESERVE + 500n * CKB]);
  await sweepSettlement(hosted.client, settlementKey, omnilock, FEE_RESERVE);
  assert.equal(hosted.sent[0].outputs.find((output) => output.lock.eq(hosted.from))!.capacity, FEE_RESERVE);
  // A reserve alone can't be made returnable: it stays as it is while needed, and can't leave on its own after
  // (after a penalty or a cooperative close nothing else passes through the node's key).
  const alone = await nodeKeyHolding([FEE_RESERVE]);
  assert.equal(await sweepSettlement(alone.client, settlementKey, omnilock, FEE_RESERVE, { returnableReserve: true }), undefined);
  assert.equal(await sweepSettlement(alone.client, settlementKey, omnilock, 0n, { returnableReserve: true }), undefined);
  assert.equal(alone.sent.length, 0);
  // An account without recovery (61 CKB smallest cell) is unaffected: 62 CKB stays, and returns on its own.
  const secp = await secp256k1Lock(alone.client, ccc.hexFrom(secp256k1.getPublicKey(secp256k1.utils.randomSecretKey(), true)));
  const plain = await nodeKeyHolding([FEE_RESERVE + 500n * CKB]);
  await sweepSettlement(plain.client, settlementKey, secp, FEE_RESERVE, { returnableReserve: true });
  assert.equal(plain.sent[0].outputs.find((output) => output.lock.eq(plain.from))!.capacity, FEE_RESERVE);
  const back = await nodeKeyHolding([FEE_RESERVE]);
  await sweepSettlement(back.client, settlementKey, secp, 0n, { returnableReserve: true });
  assert.equal(back.sent.length, 1);
});
