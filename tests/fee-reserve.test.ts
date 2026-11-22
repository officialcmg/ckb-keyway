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
/**
 * `findCells` as the indexer answers it over these cells: by lock, and by whether a cell has a type script (the
 * `scriptLenRange` filter the sweep asks with: [0, 1] for plain cells, [1, ...] for cells with a type script).
 */
const servedBy = (cells: () => ccc.Cell[]) => async function* (key: Parameters<ccc.Client["findCells"]>[0]) {
  const [from, to] = (key.filter?.scriptLenRange ?? [0, Number.MAX_SAFE_INTEGER]).map(Number);
  for (const cell of cells()) {
    const typeLength = cell.cellOutput.type ? 65 : 0;
    if (cell.cellOutput.lock.eq(ccc.Script.from(key.script)) && typeLength >= from && typeLength < to) yield cell;
  }
};
/** A node key holding these plain cells, on a client that never reaches the network; `sent` collects its sweeps. */
async function nodeKeyHolding(capacities: bigint[]) {
  const client = new ccc.ClientPublicTestnet({ url: "http://127.0.0.1:9/" });
  const from = (await new ccc.SignerCkbPrivateKey(client, settlementKey).getRecommendedAddressObj()).script;
  const cells = capacities.map((capacity, index) => ccc.Cell.from({ outPoint: { txHash: `0x${(index + 1).toString(16).padStart(64, "0")}`, index: 0 }, cellOutput: { lock: from, capacity }, outputData: "0x" }));
  const sent: ccc.Transaction[] = [];
  Object.assign(client, {
    findCells: servedBy(() => cells),
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
    findCells: servedBy(() => cells),
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

test("for a recovery account, keeping the reserve at a returnable size never holds a payout back, and a sweep that would move nothing isn't sent", async () => {
  // A claim of 108 CKB paid out next to the 62 CKB reserve. Keeping 95 CKB would leave 75 CKB, too little for a
  // cell at the account's address: the user is paid from beyond the plain reserve instead.
  const claimed = await nodeKeyHolding([FEE_RESERVE + 108n * CKB]);
  await sweepSettlement(claimed.client, settlementKey, omnilock, FEE_RESERVE, { returnableReserve: true });
  assert.equal(claimed.sent.length, 1);
  assert.equal(claimed.sent[0].outputs.find((output) => output.lock.eq(claimed.from))!.capacity, FEE_RESERVE);
  const paid = claimed.sent[0].outputs.find((output) => output.lock.eq(omnilock))!;
  assert.ok(paid.capacity > 107n * CKB && paid.capacity < 108n * CKB, `${paid.capacity} to the user`);
  // 78 CKB next to the reserve can't be a cell at the account's address either way: nothing can leave the key,
  // and no transaction is sent that would only rewrite the key's own cells at a fee.
  for (const options of [{ returnableReserve: true }, undefined]) {
    const small = await nodeKeyHolding([FEE_RESERVE + 78n * CKB]);
    assert.equal(await sweepSettlement(small.client, settlementKey, omnilock, FEE_RESERVE, options), undefined);
    assert.equal(small.sent.length, 0);
  }
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

// Review round 4: how many cells sit on the node's key, and in what order the indexer lists them, must not decide
// whether a sweep finds the key's CKB.

test("the key's plain CKB is found and moved however many token cells are listed before it, and the reserve is returned", async () => {
  const secp = await secp256k1Lock(new ccc.ClientPublicTestnet({ url: "http://127.0.0.1:9/" }), ccc.hexFrom(secp256k1.getPublicKey(secp256k1.utils.randomSecretKey(), true)));
  // Fifty token cells at their exact minimum, listed before the key's plain cells (nodeKeyWith lists tokens first).
  const crowd = Array.from({ length: 50 }, () => 142n * CKB);
  for (const [who, options] of SWEEPS) {
    // No channel needs the reserve any more: it is found behind the fifty token cells, and pays the fee for the
    // forty-nine that move with it (at their minimum they have nothing to pay with). It stays on the key for the
    // one that found no room (review round 5), and goes back to the user with that one, in the next sweep.
    const released = await nodeKeySpending([...cellsOf(50, "token", 142n * CKB), { kind: "plain", capacity: FEE_RESERVE }]);
    await sweepSettlement(released.client, settlementKey, secp, 0n, options);
    assert.equal(released.sent.length, 1, `${who}: the reserve must not stay on the key for good`);
    assert.equal(released.sent[0].inputs.length, 50, `${who}: ${released.sent[0].inputs.length} inputs`);
    assert.equal(released.sent[0].outputs.filter((output) => output.type && output.lock.eq(secp)).length, 49, who);
    await sweepSettlement(released.client, settlementKey, secp, 0n, options);
    assert.equal(released.sent.length, 2, `${who}: the last token cell and the reserve follow`);
    const back = released.sent[1].outputs.find((output) => output.lock.eq(secp) && !output.type);
    assert.ok(back && back.capacity > 61n * CKB && back.capacity <= FEE_RESERVE, `${who}: the reserve reaches the user`);
    assert.ok(released.sent[1].outputs.every((output) => output.lock.eq(secp)), `${who}: nothing stays on the key`);

    // The reserve is still needed and a settlement has arrived: the two plain cells are found behind the token
    // cells, and the token cells that fit beside them move along. Two token cells found no room, so the settlement
    // stays on the key with the reserve for now (review round 5), and reaches the user with the sweep that moves
    // them; the reserve stays whole throughout.
    const kept = await nodeKeySpending([...cellsOf(50, "token", 142n * CKB), { kind: "plain", capacity: FEE_RESERVE }, { kind: "plain", capacity: 300n * CKB }]);
    const keptOnKey = (tx: ccc.Transaction) => tx.outputs.filter((output) => output.lock.eq(kept.from) && !output.type).reduce((total, output) => total + output.capacity, 0n);
    await sweepSettlement(kept.client, settlementKey, secp, FEE_RESERVE, options);
    assert.equal(kept.sent.length, 1, `${who}: a settlement must not wait behind token cells for good`);
    assert.equal(kept.sent[0].inputs.length, 50, who);
    assert.equal(kept.sent[0].outputs.filter((output) => output.type).length, 48, who);
    assert.ok(keptOnKey(kept.sent[0]) > FEE_RESERVE + 299n * CKB, `${who}: ${keptOnKey(kept.sent[0])} kept`);
    await sweepSettlement(kept.client, settlementKey, secp, FEE_RESERVE, options);
    assert.equal(kept.sent.length, 2, who);
    assert.equal(keptOnKey(kept.sent[1]), FEE_RESERVE, `${who}: ${keptOnKey(kept.sent[1])} kept`);
    const paid = kept.sent[1].outputs.find((output) => output.lock.eq(secp) && !output.type);
    assert.ok(paid && paid.capacity > 299n * CKB && paid.capacity <= 300n * CKB, `${who}: the settlement reaches the user`);
    assert.equal(kept.sent[1].outputs.filter((output) => output.type).length, 2, who);
  }
});

test("token cells that are put off don't take the place of ones that can move, and one sweep spends fifty cells at most", async () => {
  const secp = await secp256k1Lock(new ccc.ClientPublicTestnet({ url: "http://127.0.0.1:9/" }), ccc.hexFrom(secp256k1.getPublicKey(secp256k1.utils.randomSecretKey(), true)));
  for (const [who, options] of SWEEPS) {
    // Fifty token cells that nothing can top up (a recovery account's address needs 34 CKB more for each, and the
    // only plain CKB is the reserve, which is kept), listed before two that need no top-up and can pay a fee.
    const key = await nodeKeyWith([FEE_RESERVE], [...Array.from({ length: 50 }, () => 142n * CKB), 177n * CKB, 177n * CKB]);
    await sweepSettlement(key.client, settlementKey, omnilock, FEE_RESERVE, options);
    assert.equal(key.sent.length, 1, `${who}: the two cells that can move must not wait behind fifty that can't`);
    const tokens = key.sent[0].outputs.filter((output) => output.type);
    assert.equal(tokens.length, 2, who);
    assert.ok(tokens.every((output) => output.lock.eq(omnilock) && output.capacity >= 176n * CKB), who);
    assert.equal(key.kept(key.sent[0]), FEE_RESERVE, `${who}: the reserve is exactly as it was`);

    // Sixty plain cells and ten token cells: one sweep takes fifty plain cells, the rest goes with the next. The
    // token cells found no room in the first, so it pays nothing out yet (review round 5): the fifty cells become
    // one on the key, which makes the room, and everything reaches the user with the second.
    const many = await nodeKeySpending([...cellsOf(10, "token", 143n * CKB), ...cellsOf(60, "plain", 100n * CKB)]);
    await sweepSettlement(many.client, settlementKey, secp, 0n, options);
    assert.equal(many.sent.length, 1, who);
    assert.equal(many.sent[0].inputs.length, 50, who);
    assert.equal(many.sent[0].outputs.length, 1, who);
    assert.ok(many.sent[0].outputs[0].lock.eq(many.from) && many.sent[0].outputs[0].capacity > 4_999n * CKB, who);
    await sweepSettlement(many.client, settlementKey, secp, 0n, options);
    assert.equal(many.sent.length, 2, who);
    assert.equal(many.sent[1].inputs.length, 21, who);
    assert.ok(many.sent[1].outputs.every((output) => output.lock.eq(secp)), `${who}: nothing stays on the key`);
    assert.ok(many.sent[1].outputs.find((output) => !output.type)!.capacity > 5_999n * CKB, who);
    assert.equal(many.sent[1].outputs.filter((output) => output.type).length, 10, who);
  }
});

test("a sweep told that its node has stopped builds nothing more than it would have sent, and sends nothing", async () => {
  const secp = await secp256k1Lock(new ccc.ClientPublicTestnet({ url: "http://127.0.0.1:9/" }), ccc.hexFrom(secp256k1.getPublicKey(secp256k1.utils.randomSecretKey(), true)));
  const key = await nodeKeyWith([FEE_RESERVE + 500n * CKB], []);
  let live = false;
  assert.equal(await sweepSettlement(key.client, settlementKey, secp, 0n, { returnableReserve: true, live: () => live }), undefined);
  assert.equal(key.sent.length, 0, "nothing is sent with the node's key once its node has stopped");
  live = true;
  assert.ok(await sweepSettlement(key.client, settlementKey, secp, 0n, { returnableReserve: true, live: () => live }));
  assert.equal(key.sent.length, 1);
});

// Review round 5: a sweep spends fifty cells at most, so a key with more is emptied over several sweeps. What one
// sweep pays out must not be what the next one needed.
type KeyCell = { kind: "plain" | "token" | "other"; capacity: bigint };
const cellsOf = (count: number, kind: KeyCell["kind"], capacity: bigint): KeyCell[] => Array.from({ length: count }, () => ({ kind, capacity }));
/**
 * A node key whose cells change as its sweeps are sent: a sweep's inputs are gone and its outputs under the key's
 * lock are there for the next one. `other` cells carry a type script no sweep moves. `drain` sweeps until a sweep
 * sends nothing, and says what is left on the key.
 */
async function nodeKeySpending(specs: KeyCell[]) {
  const client = new ccc.ClientPublicTestnet({ url: "http://127.0.0.1:9/" });
  const from = (await new ccc.SignerCkbPrivateKey(client, settlementKey).getRecommendedAddressObj()).script;
  const xudt = await client.getKnownScript(ccc.KnownScript.XUdt);
  const token = ccc.Script.from({ codeHash: xudt.codeHash, hashType: xudt.hashType, args: `0x${"77".repeat(32)}` });
  const other = ccc.Script.from({ codeHash: `0x${"ab".repeat(32)}`, hashType: "type", args: "0x" });
  let next = 1;
  let cells = specs.map(({ kind, capacity }) => ccc.Cell.from({
    outPoint: { txHash: `0x${(next++).toString(16).padStart(64, "0")}`, index: 0 },
    cellOutput: { lock: from, capacity, ...(kind === "plain" ? {} : { type: kind === "token" ? token : other }) },
    outputData: kind === "plain" ? "0x" : ccc.hexFrom(ccc.numLeToBytes(1_000n, 16)),
  }));
  const sent: ccc.Transaction[] = [];
  Object.assign(client, {
    findCells: servedBy(() => [...cells]),
    findSingletonCellByType: async () => undefined,
    findCellsByLock: async function* (lock: ccc.ScriptLike) { for (const cell of [...cells]) if (cell.cellOutput.lock.eq(ccc.Script.from(lock))) yield cell; },
    getFeeRate: async () => 1000n,
    sendTransaction: async (tx: ccc.Transaction) => {
      sent.push(tx);
      const spent = new Set(tx.inputs.map((input) => `${input.previousOutput.txHash}:${input.previousOutput.index}`));
      cells = cells.filter((cell) => !spent.has(`${cell.outPoint.txHash}:${cell.outPoint.index}`));
      tx.outputs.forEach((output, index) => {
        if (output.lock.eq(from)) cells.push(ccc.Cell.from({ outPoint: { txHash: tx.hash(), index }, cellOutput: output, outputData: tx.outputsData[index] ?? "0x" }));
      });
      await client.cache.clear();
      await client.cache.recordCells(cells);
      return tx.hash();
    },
  });
  await client.cache.recordCells(cells);
  const plainOnKey = () => cells.filter((cell) => !cell.cellOutput.type).reduce((total, cell) => total + cell.cellOutput.capacity, 0n);
  const drain = async (to: ccc.ScriptLike, keep: bigint, options?: { returnableReserve?: boolean }, rounds = 12) => {
    for (let round = 0; round < rounds; round++) {
      if (!await sweepSettlement(client, settlementKey, to, keep, options)) break;
      assert.ok(plainOnKey() >= keep, `sweep ${sent.length} left ${plainOnKey()} of the ${keep} reserve on the key`);
      assert.ok(sent[sent.length - 1].inputs.length <= 50, `sweep ${sent.length} spends ${sent[sent.length - 1].inputs.length} cells`);
    }
    return { sweeps: sent.length, tokens: cells.filter((cell) => cell.cellOutput.type?.eq(token)).length, plain: plainOnKey(), cells: cells.length };
  };
  /** Everything the sweeps sent to `to`: its CKB (the capacity of token cells included), and the number of token cells. */
  const reached = (to: ccc.ScriptLike) => {
    const outputs = sent.flatMap((tx) => tx.outputs).filter((output) => output.lock.eq(ccc.Script.from(to)));
    return { ckb: outputs.reduce((total, output) => total + output.capacity, 0n), tokens: outputs.filter((output) => output.type).length };
  };
  return { client, from, sent, drain, reached };
}

test("a key emptied over several sweeps: no sweep pays out the CKB that the token cells it leaves for the next one need", async () => {
  const secp = await secp256k1Lock(new ccc.ClientPublicTestnet({ url: "http://127.0.0.1:9/" }), ccc.hexFrom(secp256k1.getPublicKey(secp256k1.utils.randomSecretKey(), true)));
  const reserve: KeyCell = { kind: "plain", capacity: FEE_RESERVE };
  for (const [who, options] of SWEEPS) {
    // Fifty token cells at their exact minimum and the reserve, which no channel needs any more. One sweep has
    // room for the reserve and forty-nine of them; the fiftieth has nothing to pay a fee with by itself.
    for (const [order, specs] of [["token cells listed first", [...cellsOf(50, "token", 142n * CKB), reserve]], ["the reserve listed first", [reserve, ...cellsOf(50, "token", 142n * CKB)]]] as Array<[string, KeyCell[]]>) {
      const key = await nodeKeySpending(specs);
      const left = await key.drain(secp, 0n, options);
      assert.equal(left.tokens, 0, `${who}, ${order}: ${left.tokens} token cell(s) left on the key with nothing to move them`);
      assert.equal(left.cells, 0, `${who}, ${order}: the key is empty`);
      assert.equal(key.reached(secp).tokens, 50, `${who}, ${order}`);
      // Fifty cells of 142 CKB and the 62 CKB reserve came in: the user has all of it but the fees.
      assert.ok(key.reached(secp).ckb > 50n * 142n * CKB + FEE_RESERVE - 1n * CKB, `${who}, ${order}: ${key.reached(secp).ckb} reached the user`);
    }
    // A recovery account (each token cell needs 34 CKB more at its address): one token cell and fifty plain cells.
    // The plain cells fill a sweep; the CKB the token cell's move takes must still be there afterwards.
    for (const keep of [0n, FEE_RESERVE]) {
      for (const [order, specs] of [["the token cell listed first", [{ kind: "token", capacity: 142n * CKB }, ...cellsOf(50, "plain", 100n * CKB)]], ["the plain cells listed first", [...cellsOf(50, "plain", 100n * CKB), { kind: "token", capacity: 142n * CKB }]]] as Array<[string, KeyCell[]]>) {
        const key = await nodeKeySpending(specs);
        const left = await key.drain(omnilock, keep, options);
        const about = `${who}, reserve ${keep === 0n ? "not needed" : "kept"}, ${order}`;
        assert.equal(left.tokens, 0, `${about}: the token cell is left on the key with nothing to move it`);
        assert.equal(key.reached(omnilock).tokens, 1, about);
        // 5142 CKB came in: the user has all of it but the reserve that is kept and the fees.
        assert.ok(key.reached(omnilock).ckb + left.plain > 5_142n * CKB - 1n * CKB, `${about}: ${key.reached(omnilock).ckb} to the user, ${left.plain} on the key`);
        if (keep > 0n) assert.ok(left.plain < 96n * CKB, `${about}: only the reserve stays, not ${left.plain}`);
        else assert.equal(left.plain, 0n, about);
      }
    }
    // Many sweeps on a little CKB: 148 token cells at their minimum and 200 CKB. The CKB pays four sweeps' fees
    // and reaches the user with the last token cells, not before.
    for (const [to, minimum] of [[secp, 142n], [omnilock, 176n]] as Array<[ccc.Script, bigint]>) {
      const long = await nodeKeySpending([{ kind: "plain", capacity: 200n * CKB }, ...cellsOf(148, "token", minimum * CKB)]);
      const end = await long.drain(to, 0n, options);
      assert.equal(end.tokens, 0, `${who}: ${end.tokens} of 148 token cells left behind`);
      assert.equal(end.cells, 0, who);
      assert.equal(end.sweeps, 4, who);
      assert.ok(long.reached(to).ckb > 148n * minimum * CKB + 199n * CKB, who);
    }
    // More token cells than any sweep or search limit of earlier versions: 501 that need 34 CKB each, and 20,000 CKB.
    const legion = await nodeKeySpending([{ kind: "plain", capacity: 20_000n * CKB }, ...cellsOf(501, "token", 142n * CKB)]);
    const emptied = await legion.drain(omnilock, 0n, options, 20);
    assert.equal(emptied.tokens, 0, `${who}: ${emptied.tokens} of 501 token cells left behind`);
    assert.equal(emptied.cells, 0, who);
    assert.ok(legion.reached(omnilock).ckb > 20_000n * CKB + 501n * 142n * CKB - 1n * CKB, who);
    // A reserve that is kept is exactly the reserve again once the last token cell has moved: nothing that was
    // held with it stays behind (200 CKB and fifty token cells that need no top-up; the server's sweep keeps 62,
    // the page's 95.01 for a recovery account).
    const exact = await nodeKeySpending([{ kind: "plain", capacity: 200n * CKB }, ...cellsOf(50, "token", 177n * CKB)]);
    const settled = await exact.drain(omnilock, FEE_RESERVE, options);
    assert.equal(settled.tokens, 0, who);
    assert.equal(settled.plain, options?.returnableReserve ? 95n * CKB + 1_000_000n : FEE_RESERVE, `${who}: ${settled.plain} left on the key`);
    // More of both than one sweep takes, and the token cells need topping up: every one of them moves.
    const crowded = await nodeKeySpending([...cellsOf(60, "plain", 100n * CKB), ...cellsOf(60, "token", 142n * CKB)]);
    const after = await crowded.drain(omnilock, 0n, options);
    assert.equal(after.tokens, 0, `${who}: ${after.tokens} of sixty token cells left behind`);
    assert.equal(after.cells, 0, who);
    assert.ok(crowded.reached(omnilock).ckb > 6_000n * CKB + 60n * 142n * CKB - 1n * CKB, who);
  }
});

test("cells a sweep can't move don't hide the token cells listed after them, however many there are", async () => {
  for (const [who, options] of SWEEPS) {
    // Anyone can send cells to the key. Six hundred with a type script no sweep moves, then a token payout that
    // can pay for its own move. (The first version of this fix counted five hundred cells and stopped.)
    const key = await nodeKeySpending([...cellsOf(600, "other", 200n * CKB), { kind: "token", capacity: 177n * CKB }]);
    const left = await key.drain(omnilock, 0n, options);
    assert.equal(left.tokens, 0, `${who}: the token cell behind them is never looked at`);
    assert.equal(left.cells, 600, `${who}: the other cells stay where they are`);
  }
});

test("a reserve this page sent doesn't count for the next open once any transaction on its way spends it, the page's own or not", async () => {
  // Hosted mode: the server sweeps the node's key, so the page's client has no mark for that sweep. The node's
  // answer with its transaction pool taken into account is what tells.
  const { sentReserveStands } = await import("../src/sdk/browser/fee-reserve.ts");
  const txHash = `0x${"5f".repeat(32)}`;
  const client = new ccc.ClientPublicTestnet({ url: "http://127.0.0.1:9/" });
  Object.assign(client, {
    getTransactionNoCache: async () => ({ status: "committed" }),
    // Live in the chain's last block; spent by a transaction in the pool.
    getCellLiveNoCache: async (_outPoint: unknown, _withData?: boolean, includeTxPool?: boolean) => includeTxPool ? undefined : {},
  });
  assert.equal(await sentReserveStands({ client, viewer: client, txHash }), false, "a channel opened now would be left without a reserve");
});
