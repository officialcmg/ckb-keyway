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

// Review round 3: what else sits on the node's key (anyone can send a cell there) must not move a kept reserve.
/** A node key holding these plain cells and standard token cells, on a client that never reaches the network. */
async function nodeKeyWith(plain: bigint[], tokens: bigint[]) {
  const client = new ccc.ClientPublicTestnet({ url: "http://127.0.0.1:9/" });
  const from = (await new ccc.SignerCkbPrivateKey(client, settlementKey).getRecommendedAddressObj()).script;
  const xudt = await client.getKnownScript(ccc.KnownScript.XUdt);
  const token = ccc.Script.from({ codeHash: xudt.codeHash, hashType: xudt.hashType, args: `0x${"77".repeat(32)}` });
  let next = 1;
  const outPoint = () => ({ txHash: `0x${(next++).toString(16).padStart(64, "0")}`, index: 0 });
  const cells = [
    ...tokens.map((capacity) => ccc.Cell.from({ outPoint: outPoint(), cellOutput: { lock: from, type: token, capacity }, outputData: ccc.hexFrom(ccc.numLeToBytes(1_000n, 16)) })),
    ...plain.map((capacity) => ccc.Cell.from({ outPoint: outPoint(), cellOutput: { lock: from, capacity }, outputData: "0x" })),
  ];
  const sent: ccc.Transaction[] = [];
  Object.assign(client, {
    findCells: async function* () {},
    findSingletonCellByType: async () => undefined,
    findCellsByLock: async function* (lock: ccc.ScriptLike) { for (const cell of cells) if (cell.cellOutput.lock.eq(ccc.Script.from(lock))) yield cell; },
    getFeeRate: async () => 1000n,
    sendTransaction: async (tx: ccc.Transaction) => { sent.push(tx); return tx.hash(); },
  });
  await client.cache.recordCells(cells);
  const kept = (tx: ccc.Transaction) => tx.outputs.filter((output) => output.lock.eq(from) && !output.type).reduce((total, output) => total + output.capacity, 0n);
  return { client, from, sent, token, cells, kept };
}
/** As the server's hosted sweep calls sweepSettlement (managed-node.ts: no options), and as the browser sweep does. */
const SWEEPS: Array<[string, { returnableReserve?: boolean } | undefined]> = [["hosted", undefined], ["browser", { returnableReserve: true }]];

test("a token cell on the node's key that needs topping up can't take the kept reserve with it", async () => {
  for (const [who, options] of SWEEPS) {
    // The reserve, and one standard token cell: 142 CKB under the node's lock, 176 CKB under a recovery account's.
    const key = await nodeKeyWith([FEE_RESERVE], [142n * CKB]);
    assert.equal(await sweepSettlement(key.client, settlementKey, omnilock, FEE_RESERVE, options), undefined, `${who}: nothing beyond the reserve can pay the 34 CKB, so the token cell waits`);
    assert.equal(key.sent.length, 0, `${who}: no transaction may spend the reserve`);
    // With plain CKB beyond the reserve the top-up comes out of that, and the kept output is at least the reserve.
    const rich = await nodeKeyWith([FEE_RESERVE, 100n * CKB], [142n * CKB]);
    await sweepSettlement(rich.client, settlementKey, omnilock, FEE_RESERVE, options);
    assert.equal(rich.sent.length, 1, who);
    assert.equal(rich.sent[0].outputs.find((output) => output.type)!.capacity, 176n * CKB, who);
    assert.ok(rich.kept(rich.sent[0]) >= FEE_RESERVE, `${who}: ${rich.kept(rich.sent[0])} kept`);
    // Two token cells and enough for one top-up beyond the reserve: one moves, one waits, the reserve is whole.
    const two = await nodeKeyWith([FEE_RESERVE + 40n * CKB], [142n * CKB, 142n * CKB]);
    await sweepSettlement(two.client, settlementKey, omnilock, FEE_RESERVE, options);
    assert.equal(two.sent[0].outputs.filter((output) => output.type).length, 1, who);
    assert.ok(two.kept(two.sent[0]) >= FEE_RESERVE, `${who}: ${two.kept(two.sent[0])} kept`);
  }
  // Once no channel needs the reserve it may pay for the top-up, as before.
  const released = await nodeKeyWith([FEE_RESERVE], [142n * CKB]);
  await sweepSettlement(released.client, settlementKey, omnilock, 0n);
  assert.equal(released.sent.length, 1);
  assert.equal(released.kept(released.sent[0]), 0n);
  assert.ok(released.sent[0].outputs[0].type && released.sent[0].outputs[0].capacity > 203n * CKB);
});

test("a sweep that moves only tokens never pays its fee from the kept reserve, and what is left of a short reserve is not swept away", async () => {
  const secp = await secp256k1Lock(new ccc.ClientPublicTestnet({ url: "http://127.0.0.1:9/" }), ccc.hexFrom(secp256k1.getPublicKey(secp256k1.utils.randomSecretKey(), true)));
  for (const [who, options] of SWEEPS) {
    // A token cell with capacity to spare pays the fee itself: the reserve comes through untouched.
    const spare = await nodeKeyWith([FEE_RESERVE], [143n * CKB]);
    await sweepSettlement(spare.client, settlementKey, secp, FEE_RESERVE, options);
    assert.equal(spare.sent.length, 1, who);
    assert.equal(spare.kept(spare.sent[0]), FEE_RESERVE, `${who}: the reserve is exactly as it was`);
    const moved = spare.sent[0].outputs.find((output) => output.type)!;
    assert.ok(moved.lock.eq(secp) && moved.capacity < 143n * CKB && moved.capacity >= 142n * CKB, who);
    // A token cell at its exact minimum has nothing to pay with: it waits rather than draw on the reserve.
    const exact = await nodeKeyWith([FEE_RESERVE], [142n * CKB]);
    assert.equal(await sweepSettlement(exact.client, settlementKey, secp, FEE_RESERVE, options), undefined, who);
    assert.equal(exact.sent.length, 0, who);
    // A reserve already a little short (an earlier sweep paid its fee from it) is still the reserve: it stays.
    const short = await nodeKeyWith([FEE_RESERVE - 100_000n], []);
    assert.equal(await sweepSettlement(short.client, settlementKey, secp, FEE_RESERVE, options), undefined, who);
    assert.equal(short.sent.length, 0, `${who}: a reserve under 62 CKB is not returnable while a channel needs it`);
    // And it isn't drawn into a sweep that moves a token cell past it.
    const beside = await nodeKeyWith([FEE_RESERVE - 100_000n], [143n * CKB]);
    await sweepSettlement(beside.client, settlementKey, secp, FEE_RESERVE, options);
    assert.equal(beside.sent.length, 1, who);
    assert.deepEqual(beside.sent[0].inputs.map((input) => input.previousOutput.toHex()), [beside.cells[0].outPoint.toHex()], `${who}: only the token cell is spent`);
  }
  assert.equal(planSweep(FEE_RESERVE - 1n, 0, FEE_RESERVE), undefined);
  assert.deepEqual(planSweep(FEE_RESERVE - 1n, 1, FEE_RESERVE), { toUser: 0n, reserve: FEE_RESERVE - 1n });
  // Once released, the short reserve leaves like any other plain cell.
  const released = await nodeKeyWith([FEE_RESERVE - 100_000n], []);
  await sweepSettlement(released.client, settlementKey, secp, 0n);
  assert.equal(released.sent.length, 1);
});

test("when the top-ups leave nothing to pay the fee with, the sweep moves one token cell fewer instead of waiting", async () => {
  for (const [who, options] of SWEEPS) {
    // Exactly two top-ups' worth beyond the reserve, two token cells at their minimum: topping both up would leave
    // no payer but the reserve. One moves, and what would have topped up the other pays the fee from beside the reserve.
    const key = await nodeKeyWith([FEE_RESERVE + 68n * CKB], [142n * CKB, 142n * CKB]);
    await sweepSettlement(key.client, settlementKey, omnilock, FEE_RESERVE, options);
    assert.equal(key.sent.length, 1, who);
    assert.equal(key.sent[0].outputs.filter((output) => output.type).length, 1, who);
    assert.ok(key.kept(key.sent[0]) >= FEE_RESERVE, `${who}: ${key.kept(key.sent[0])} kept`);
    // One token cell and exactly its top-up beyond the reserve: nothing smaller is left to try, so it waits.
    const one = await nodeKeyWith([FEE_RESERVE + 34n * CKB], [142n * CKB]);
    assert.equal(await sweepSettlement(one.client, settlementKey, omnilock, FEE_RESERVE, options), undefined, who);
    assert.equal(one.sent.length, 0, who);
  }
});

test("a settlement passing through the node's key still reaches the user with the reserve kept whole", async () => {
  const secp = await secp256k1Lock(new ccc.ClientPublicTestnet({ url: "http://127.0.0.1:9/" }), ccc.hexFrom(secp256k1.getPublicKey(secp256k1.utils.randomSecretKey(), true)));
  for (const [who, options] of SWEEPS) {
    // A claim paid out next to the reserve, and a token cell arrived too.
    const key = await nodeKeyWith([FEE_RESERVE, 500n * CKB], [142n * CKB]);
    await sweepSettlement(key.client, settlementKey, secp, FEE_RESERVE, options);
    const [tx] = key.sent;
    assert.equal(key.kept(tx), FEE_RESERVE, who);
    const toUser = tx.outputs.find((output) => !output.type && output.lock.eq(secp))!;
    assert.ok(toUser.capacity > 499n * CKB && toUser.capacity < 500n * CKB, `${who}: the fee comes out of the user's CKB`);
    assert.equal(tx.outputs.find((output) => output.type)!.capacity, 142n * CKB, who);
  }
});

test("whatever the fee rate, a sweep that would cut into the kept reserve or a cell's own minimum isn't sent", async () => {
  const secp = await secp256k1Lock(new ccc.ClientPublicTestnet({ url: "http://127.0.0.1:9/" }), ccc.hexFrom(secp256k1.getPublicKey(secp256k1.utils.randomSecretKey(), true)));
  // A fee rate at which this sweep costs more than the 0.01 CKB every payer is asked to have to spare.
  const dear = async (plain: bigint[], tokens: bigint[]) => {
    const key = await nodeKeyWith(plain, tokens);
    Object.assign(key.client, { getFeeRate: async () => 100_000_000n });
    return key;
  };
  for (const [who, options] of SWEEPS) {
    // The payer would be the kept output, which holds 0.02 CKB beyond the reserve.
    const dust = await dear([FEE_RESERVE + 2_000_000n], [142n * CKB]);
    assert.equal(await sweepSettlement(dust.client, settlementKey, secp, FEE_RESERVE, options), undefined, who);
    assert.equal(dust.sent.length, 0, who);
    // The payer would be a token cell with 0.02 CKB to spare.
    const token = await dear([FEE_RESERVE], [142n * CKB + 2_000_000n]);
    assert.equal(await sweepSettlement(token.client, settlementKey, secp, FEE_RESERVE, options), undefined, who);
    assert.equal(token.sent.length, 0, who);
  }
  // At the ordinary rate both go through, the reserve whole.
  const dust = await nodeKeyWith([FEE_RESERVE + 2_000_000n], [142n * CKB]);
  await sweepSettlement(dust.client, settlementKey, secp, FEE_RESERVE);
  assert.ok(dust.kept(dust.sent[0]) >= FEE_RESERVE && dust.kept(dust.sent[0]) < FEE_RESERVE + 2_000_000n);
});

test("a reserve cell counts for a channel open only if the node says it is live", async () => {
  const { hasFeeReserve } = await import("../src/sdk/browser/fee-reserve.ts");
  /** The node key's client: its indexer lists one 62 CKB cell; the node answers for it as given. */
  const viewer = async (node: { live: (includeTxPool: boolean) => boolean; created?: string; unreachable?: boolean }) => {
    const client = new ccc.ClientPublicTestnet({ url: "http://127.0.0.1:9/" });
    const lock = (await new ccc.SignerCkbPrivateKey(client, settlementKey).getRecommendedAddressObj()).script;
    const reserve = ccc.Cell.from({ outPoint: { txHash: `0x${"5e".repeat(32)}`, index: 0 }, cellOutput: { lock, capacity: FEE_RESERVE }, outputData: "0x" });
    Object.assign(client, {
      findCellsOnChain: async function* () { yield reserve; },
      getCellLiveNoCache: async (_outPoint: ccc.OutPointLike, _withData?: boolean | null, includeTxPool?: boolean | null) => {
        if (node.unreachable) throw new Error("the RPC is unreachable");
        return node.live(Boolean(includeTxPool)) ? reserve : undefined;
      },
      getTransactionNoCache: async () => node.created && { status: node.created },
    });
    return { client, lock, reserve };
  };
  // Live: the reserve is there.
  const there = await viewer({ live: () => true, created: "committed" });
  assert.equal(await hasFeeReserve(there.client, there.lock), true);
  // The sweep that returned the reserve has committed and this page has forgotten it (each pass rebuilds the
  // client's cache from the chain), but the indexer is behind and still lists the cell.
  const lagging = await viewer({ live: () => false, created: "committed" });
  assert.equal(await hasFeeReserve(lagging.client, lagging.lock), false, "a channel opened now would get no reserve");
  // After a reload the page knows nothing of a sweep it sent before: the cell is live on-chain, and spent by a
  // transaction in the node's pool.
  const reloaded = await viewer({ live: (includeTxPool) => !includeTxPool, created: "committed" });
  assert.equal(await hasFeeReserve(reloaded.client, reloaded.lock), false, "a reserve on its way out doesn't count");
  // This page's own unconfirmed spend still hides the cell, whatever the node says.
  const spent = await viewer({ live: () => true, created: "committed" });
  await spent.client.cache.markUnusable(spent.reserve.outPoint);
  assert.equal(await hasFeeReserve(spent.client, spent.lock), false);
  // A cell on its way in (the change of this page's own claim or sweep): the node has no such cell yet.
  const arriving = await viewer({ live: () => false, created: "pending" });
  assert.equal(await hasFeeReserve(arriving.client, arriving.lock), true);
  // The node can't be asked: not counted (a second reserve is sent and returns with the first).
  const down = await viewer({ live: () => true, unreachable: true });
  assert.equal(await hasFeeReserve(down.client, down.lock), false);
});

test("a reserve just sent counts for the next channel open until the chain lists it, unless a sweep has already taken it", async () => {
  // The account's client sent the reserve; the node key's client (the viewer) asks its own indexer, which lags.
  const { sentReserveStands } = await import("../src/sdk/browser/fee-reserve.ts");
  const txHash = `0x${"5e".repeat(32)}`;
  const outPoint = ccc.OutPoint.from({ txHash, index: 0 });
  const clients = (status: string | undefined, live = false) => {
    const viewer = new ccc.ClientPublicTestnet({ url: "http://127.0.0.1:9/" });
    Object.assign(viewer, { getCellLiveNoCache: async () => live ? {} : undefined });
    const client = new ccc.ClientPublicTestnet({ url: "http://127.0.0.1:9/" });
    Object.assign(client, { getTransactionNoCache: async () => status && { status } });
    return { client, viewer, txHash };
  };
  // On its way in: a second open must not send a second reserve.
  assert.equal(await sentReserveStands(clients("pending")), true);
  assert.equal(await sentReserveStands(clients("proposed")), true);
  // Committed and live, the indexer just hasn't caught up.
  assert.equal(await sentReserveStands(clients("committed", true)), true);
  // Committed and already spent, dropped, or rejected: there is no reserve, the open sends one.
  assert.equal(await sentReserveStands(clients("committed", false)), false);
  assert.equal(await sentReserveStands(clients(undefined)), false);
  assert.equal(await sentReserveStands(clients("rejected")), false);
  // A sweep of the node's key has spent it (still unconfirmed): it is on its way out, whatever the chain says.
  const swept = clients("committed", true);
  await swept.viewer.cache.markUnusable(outPoint);
  assert.equal(await sentReserveStands(swept), false);
});
