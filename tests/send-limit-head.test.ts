// The server's search for the account's send-limit cell (sendLimitHead), against an indexer full of cells anyone
// can plant at the account's public secp256k1 address: look-alike send-limit cells and plain Type ID cells.
import assert from "node:assert/strict";
import test from "node:test";
import * as ccc from "@ckb-ccc/core";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { secp256k1Lock } from "../src/sdk/browser/account-lock.ts";
import { encodeSendLimitSettings, recordEntriesBytes, setSendLimitRecord } from "../src/sdk/browser/send-limits.ts";
import { sendLimitHead, sendLimitRpc } from "../src/server/send-limits.ts";
import { fakeLit } from "./lit-action-fixture.ts";

const CKB = 100_000_000n;
const privateKey = secp256k1.utils.randomSecretKey();
const publicKey = ccc.hexFrom(secp256k1.getPublicKey(privateKey, true));
const stranger = ccc.Script.from({ codeHash: `0x${"99".repeat(32)}`, hashType: "type", args: "0x" });
const typeId = (args: ccc.HexLike) => ccc.Script.from({ codeHash: "0x00000000000000000000000000000000000000000000000000545950455f4944", hashType: "type", args });
const settings = encodeSendLimitSettings({ fingerprint: `0x${"11".repeat(32)}`, tokensUnlimited: false, ckb: 100n * CKB, tokens: new Map() });
const RECORD = "0x4b575352010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
let nonce = 1;
const outside = () => ({ previousOutput: { txHash: `0x${(nonce++).toString(16).padStart(64, "0")}`, index: 0 } });

/**
 * Committed transactions, oldest first, one a block, behind a fake CKB node (the indexer included). The search and
 * the CCC client both reach that node, and every request to it is counted.
 */
function chain() {
  const txs: ccc.Transaction[] = [];
  const byHash = new Map<string, ccc.Transaction>();
  const add = (tx: ccc.Transaction) => { txs.push(tx); byHash.set(tx.hash(), tx); return tx; };
  const node = fakeLit({ privateKey, pkpId: "0x01", lookup: (hash) => { const tx = byHash.get(hash); return tx ? { tx, status: "committed" } : undefined; }, transactions: () => txs });
  sendLimitRpc.fetch = node.fetch;
  const client = new ccc.ClientPublicTestnet({ url: "https://testnet.ckb.dev/" });
  // As CCC's own requestor, over the same node; the node answers get_transaction in batches only.
  type Transform = ((value: unknown) => unknown) | undefined;
  const request = async (method: string, params: unknown[], into: Transform[] = [], out?: Transform) => {
    const sent = await Promise.all([...params, ...Array(Math.max(into.length - params.length, 0)).fill(undefined)].map((value, i) => into[i] ? into[i]!(value) : value));
    const call = { id: 0, jsonrpc: "2.0", method, params: sent };
    const batched = method === "get_transaction";
    const reply = await (await node.fetch("https://testnet.ckb.dev/", { body: JSON.stringify(batched ? [call] : call), headers: {} })).json();
    const result = (batched ? reply[0] : reply).result;
    return out ? out(result) : result;
  };
  Object.assign(client, { requestor: { request } });
  return { add, client, requests: node.requests };
}

/** A look-alike: a send-limit-shaped cell at the address, made by a transaction that spends only outsiders' cells. */
function lookalike(secp: ccc.Script, count = 1) {
  const tx = ccc.Transaction.from({
    inputs: [outside()],
    outputs: Array.from({ length: count }, () => ({ lock: secp, type: typeId(ccc.hexFrom(crypto.getRandomValues(new Uint8Array(32)))), capacity: 174n * CKB })),
    outputsData: Array.from({ length: count }, () => settings),
  });
  setSendLimitRecord(tx, 0, RECORD);
  return tx;
}

async function account(world: ReturnType<typeof chain>) {
  const secp = await secp256k1Lock(world.client, publicKey);
  const funding = world.add(ccc.Transaction.from({ inputs: [outside()], outputs: [{ lock: secp, capacity: 1_000n * CKB }, { lock: secp, capacity: 500n * CKB }], outputsData: ["0x", "0x"] }));
  return { secp, funding };
}

/** The account's own genesis: the key's plain cell as input 0, the send-limit cell as output 0. */
function genesis(secp: ccc.Script, from: ccc.OutPoint) {
  const input = ccc.CellInput.from({ previousOutput: from });
  return ccc.Transaction.from({ inputs: [input], outputs: [{ lock: secp, type: typeId(ccc.hashTypeId(input, 0)), capacity: 174n * CKB }, { lock: secp, capacity: 825n * CKB }], outputsData: [settings, "0x"] });
}

test("look-alike send-limit cells anyone plants, older or newer, don't hide the account's own", async () => {
  const world = chain();
  const { secp, funding } = await account(world);
  for (let i = 0; i < 4; i++) world.add(lookalike(secp));
  const made = world.add(genesis(secp, ccc.OutPoint.from({ txHash: funding.hash(), index: 0 })));
  const head = await sendLimitHead(world.client, { litPublicKey: publicKey }, []);
  assert.equal(head?.outPoint.txHash, made.hash(), "the genesis behind four older look-alikes");
  assert.equal(head?.recordEntriesBytes, 0);

  // A change the key signed: someone else's cell is input 0, the send-limit input carries the record.
  const theirs = world.add(ccc.Transaction.from({ inputs: [outside()], outputs: [{ lock: stranger, capacity: 100n * CKB }], outputsData: ["0x"] }));
  const change = ccc.Transaction.from({
    inputs: [{ previousOutput: { txHash: theirs.hash(), index: 0 } }, { previousOutput: { txHash: made.hash(), index: 0 } }],
    outputs: [{ lock: stranger, capacity: 100n * CKB }, { ...made.outputs[0], capacity: 174n * CKB - 1_000n }],
    outputsData: ["0x", settings],
  });
  setSendLimitRecord(change, 1, RECORD);
  world.add(change);
  for (let i = 0; i < 4; i++) world.add(lookalike(secp));
  const next = await sendLimitHead(world.client, { litPublicKey: publicKey }, []);
  assert.equal(next?.outPoint.txHash, change.hash(), "the chained cell behind four newer look-alikes");
  assert.equal(next?.outPoint.index, 1);
  assert.equal(next?.recordEntriesBytes, recordEntriesBytes(RECORD), "the record its transaction carries");
});

test("look-alikes alone aren't send limits", async () => {
  const world = chain();
  const { secp } = await account(world);
  for (let i = 0; i < 3; i++) world.add(lookalike(secp));
  assert.equal(await sendLimitHead(world.client, { litPublicKey: publicKey }, []), undefined);
});

test("64 or about 1000 newer look-alikes, each in its own block, can't hide the account's own, and cost a few requests", async () => {
  for (const planted of [64, 1000]) {
    const world = chain();
    const { secp, funding } = await account(world);
    const made = world.add(genesis(secp, ccc.OutPoint.from({ txHash: funding.hash(), index: 0 })));
    for (let i = 0; i < planted; i++) world.add(lookalike(secp));
    const head = await sendLimitHead(world.client, { litPublicKey: publicKey }, []);
    assert.equal(head?.outPoint.txHash, made.hash(), `behind ${planted} look-alikes`);
    // Pages of cells, batches of history (256 blocks each) and the one creating transaction.
    assert.ok(world.requests.length <= 9, `${planted} look-alikes took ${world.requests.length} requests`);
  }
});

test("past the Action's 1024 look-alikes the search says so, never 'no send limits', in a bounded number of requests", async () => {
  const world = chain();
  const { secp, funding } = await account(world);
  world.add(genesis(secp, ccc.OutPoint.from({ txHash: funding.hash(), index: 0 })));
  // Thousands of plain Type ID cells the data filter passes over, then more look-alikes than the Action reads.
  world.add(ccc.Transaction.from({
    inputs: [outside()],
    outputs: Array.from({ length: 3200 }, (_, i) => ({ lock: secp, type: typeId(ccc.hexFrom(ccc.numLeToBytes(i + 1, 32))), capacity: 125n * CKB })),
    outputsData: Array.from({ length: 3200 }, () => "0x"),
  }));
  world.add(lookalike(secp, 1100));
  await assert.rejects(sendLimitHead(world.client, { litPublicKey: publicKey }, []), /too many look-alike send-limit cells/);
  // Five pages on each of the two nodes.
  assert.ok(world.requests.length <= 10, `made ${world.requests.length} requests`);
  assert.ok(world.requests.every(({ methods }) => methods.every((method) => method === "get_cells")));
});

test("the record is read only from the account's own send-limit input, never a co-signer's witness (audit L12)", async () => {
  // A co-signer's witness isn't covered by the account's signature: a smaller record-shaped one there would shrink
  // the room later sends reserve for the record.
  const SMALL = "0x4b5753520100";
  const world = chain();
  const { secp, funding } = await account(world);
  const made = world.add(genesis(secp, ccc.OutPoint.from({ txHash: funding.hash(), index: 0 })));
  const theirs = world.add(ccc.Transaction.from({ inputs: [outside()], outputs: [{ lock: stranger, capacity: 100n * CKB }], outputsData: ["0x"] }));
  const change = ccc.Transaction.from({
    inputs: [{ previousOutput: { txHash: theirs.hash(), index: 0 } }, { previousOutput: { txHash: made.hash(), index: 0 } }],
    outputs: [{ lock: stranger, capacity: 100n * CKB }, { ...made.outputs[0], capacity: 174n * CKB - 1_000n }],
    outputsData: ["0x", settings],
  });
  setSendLimitRecord(change, 0, SMALL);
  setSendLimitRecord(change, 1, RECORD);

  // Pending (from the account's own list) and committed (found on chain): the same record either way.
  const pending = await sendLimitHead(world.client, { litPublicKey: publicKey }, [{ transaction: change, status: "pending" }]);
  assert.equal(pending?.outPoint.txHash, change.hash());
  assert.equal(pending?.recordEntriesBytes, recordEntriesBytes(RECORD), "the send-limit input's record, not input 0's");
  world.add(change);
  const committed = await sendLimitHead(world.client, { litPublicKey: publicKey }, []);
  assert.equal(committed?.outPoint.txHash, change.hash());
  assert.equal(committed?.recordEntriesBytes, recordEntriesBytes(RECORD));

  // A record only on someone else's input: the Action won't chain on this cell, so it isn't taken as one.
  const orphan = ccc.Transaction.from({
    inputs: [{ previousOutput: { txHash: world.add(ccc.Transaction.from({ inputs: [outside()], outputs: [{ lock: stranger, capacity: 100n * CKB }], outputsData: ["0x"] })).hash(), index: 0 } }, { previousOutput: { txHash: change.hash(), index: 1 } }],
    outputs: [{ lock: stranger, capacity: 100n * CKB }, { ...change.outputs[1], capacity: 174n * CKB - 2_000n }],
    outputsData: ["0x", settings],
  });
  setSendLimitRecord(orphan, 0, RECORD);
  world.add(orphan);
  await assert.rejects(sendLimitHead(world.client, { litPublicKey: publicKey }, []), /isn't one this account made/);
});
