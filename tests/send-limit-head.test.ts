// The server's search for the account's send-limit cell (sendLimitHead), against an indexer full of cells anyone
// can plant at the account's public secp256k1 address: look-alike send-limit cells and plain Type ID cells.
import assert from "node:assert/strict";
import test from "node:test";
import * as ccc from "@ckb-ccc/core";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { secp256k1Lock } from "../src/sdk/browser/account-lock.ts";
import { encodeSendLimitSettings, setSendLimitRecord } from "../src/sdk/browser/send-limits.ts";
import { sendLimitHead } from "../src/server/send-limits.ts";

const CKB = 100_000_000n;
const publicKey = ccc.hexFrom(secp256k1.getPublicKey(secp256k1.utils.randomSecretKey(), true));
const stranger = ccc.Script.from({ codeHash: `0x${"99".repeat(32)}`, hashType: "type", args: "0x" });
const typeId = (args: ccc.HexLike) => ccc.Script.from({ codeHash: "0x00000000000000000000000000000000000000000000000000545950455f4944", hashType: "type", args });
const settings = encodeSendLimitSettings({ fingerprint: `0x${"11".repeat(32)}`, tokensUnlimited: false, ckb: 100n * CKB, tokens: new Map() });
let nonce = 1;
const outside = () => ({ previousOutput: { txHash: `0x${(nonce++).toString(16).padStart(64, "0")}`, index: 0 } });

/** Committed transactions, oldest first, one a block, behind a CCC client that counts what it asks the node for. */
function chain() {
  const txs: ccc.Transaction[] = [];
  const byHash = new Map<string, ccc.Transaction>();
  const counts = { lookups: 0, cellsRead: 0 };
  const add = (tx: ccc.Transaction) => { txs.push(tx); byHash.set(tx.hash(), tx); return tx; };
  const client = new ccc.ClientPublicTestnet({ url: "https://testnet.ckb.dev/" });
  Object.assign(client, {
    getTransaction: async (hash: ccc.HexLike) => {
      counts.lookups++;
      const tx = byHash.get(ccc.hexFrom(hash));
      return tx ? { transaction: tx, status: "committed", blockNumber: BigInt(txs.indexOf(tx)) } : undefined;
    },
    // As ckb-indexer: the lock's history in a block range, an entry per input spent from it and output made at it.
    findTransactionsPaged: async (key: ccc.ClientIndexerSearchKeyTransactionLike, _order: "asc" | "desc", limit: number) => {
      counts.lookups++;
      const search = ccc.ClientIndexerSearchKey.from(key);
      const [from, to] = search.filter?.blockRange ?? [0n, BigInt(txs.length)];
      const transactions = txs.slice(Number(from), Number(to)).flatMap((tx) => {
        const blockNumber = BigInt(txs.indexOf(tx));
        const spends = tx.inputs.flatMap((input, cellIndex) => {
          const spentCell = byHash.get(input.previousOutput.txHash)?.outputs[Number(input.previousOutput.index)];
          return spentCell?.lock.eq(search.script) ? [{ txHash: tx.hash(), blockNumber, txIndex: 0n, isInput: true, cellIndex: BigInt(cellIndex) }] : [];
        });
        const makes = tx.outputs.flatMap((output, cellIndex) => output.lock.eq(search.script) ? [{ txHash: tx.hash(), blockNumber, txIndex: 0n, isInput: false, cellIndex: BigInt(cellIndex) }] : []);
        return [...spends, ...makes];
      });
      return { lastCursor: "0x", transactions: transactions.slice(0, limit) };
    },
    // As ckb-indexer: live cells under the lock, matching the type script by prefix and the data by its filter.
    findCellsOnChain: async function* (key: ccc.ClientIndexerSearchKeyLike, order: "asc" | "desc" = "asc") {
      const search = ccc.ClientIndexerSearchKey.from(key);
      const spent = new Set(txs.flatMap((tx) => tx.inputs.map((input) => `${input.previousOutput.txHash}:${input.previousOutput.index}`)));
      const live: ccc.Cell[] = [];
      for (const tx of txs) {
        const hash = tx.hash();
        tx.outputs.forEach((output, index) => {
          const data = ccc.hexFrom(tx.outputsData[index]);
          if (spent.has(`${hash}:${index}`) || !output.lock.eq(search.script)) return;
          const type = search.filter?.script;
          if (type && !(output.type && output.type.codeHash === type.codeHash && output.type.hashType === type.hashType && output.type.args.startsWith(type.args))) return;
          const wanted = search.filter?.outputData;
          if (wanted && (search.filter?.outputDataSearchMode === "exact" ? data !== wanted : !data.startsWith(wanted))) return;
          live.push(ccc.Cell.from({ outPoint: { txHash: hash, index }, cellOutput: output, outputData: data }));
        });
      }
      for (const cell of order === "desc" ? live.reverse() : live) {
        counts.cellsRead++;
        yield cell;
      }
    },
  });
  return { add, client, counts };
}

/** A look-alike: a send-limit-shaped cell at the address, made by a transaction that spends only outsiders' cells. */
function lookalike(secp: ccc.Script, inputs = 1) {
  const tx = ccc.Transaction.from({
    inputs: Array.from({ length: inputs }, outside),
    outputs: [{ lock: secp, type: typeId(ccc.hexFrom(crypto.getRandomValues(new Uint8Array(32)))), capacity: 174n * CKB }],
    outputsData: [settings],
  });
  // Record-shaped witnesses on every input, so each one would be worth looking up.
  for (let i = 0; i < inputs; i++) setSendLimitRecord(tx, i, "0x4b57535201");
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

  // A change the key signed: someone else's cell is input 0, the send-limit input carries the record.
  const theirs = world.add(ccc.Transaction.from({ inputs: [outside()], outputs: [{ lock: stranger, capacity: 100n * CKB }], outputsData: ["0x"] }));
  const change = ccc.Transaction.from({
    inputs: [{ previousOutput: { txHash: theirs.hash(), index: 0 } }, { previousOutput: { txHash: made.hash(), index: 0 } }],
    outputs: [{ lock: stranger, capacity: 100n * CKB }, { ...made.outputs[0], capacity: 174n * CKB - 1_000n }],
    outputsData: ["0x", settings],
  });
  setSendLimitRecord(change, 1, "0x4b57535201");
  world.add(change);
  for (let i = 0; i < 4; i++) world.add(lookalike(secp));
  const next = await sendLimitHead(world.client, { litPublicKey: publicKey }, []);
  assert.equal(next?.outPoint.txHash, change.hash(), "the chained cell behind four newer look-alikes");
  assert.equal(next?.outPoint.index, 1);
});

test("look-alikes alone aren't send limits", async () => {
  const world = chain();
  const { secp } = await account(world);
  for (let i = 0; i < 3; i++) world.add(lookalike(secp));
  assert.equal(await sendLimitHead(world.client, { litPublicKey: publicKey }, []), undefined);
});

test("planted cells can't make the search page through everything or look up without bound", async () => {
  const world = chain();
  const { secp, funding } = await account(world);
  world.add(genesis(secp, ccc.OutPoint.from({ txHash: funding.hash(), index: 0 })));
  // Thousands of plain Type ID cells, then newer look-alikes whose making transactions have 64 inputs each.
  world.add(ccc.Transaction.from({
    inputs: [outside()],
    outputs: Array.from({ length: 3200 }, (_, i) => ({ lock: secp, type: typeId(ccc.hexFrom(ccc.numLeToBytes(i + 1, 32))), capacity: 125n * CKB })),
    outputsData: Array.from({ length: 3200 }, () => "0x"),
  }));
  for (let i = 0; i < 200; i++) world.add(lookalike(secp, 64));
  // Too many to look through says so; it never reads as "no send limits", which would offer them again.
  await assert.rejects(sendLimitHead(world.client, { litPublicKey: publicKey }, []), /too many look-alike send-limit cells/);
  assert.ok(world.counts.cellsRead <= 65, `read ${world.counts.cellsRead} cells`);
  assert.ok(world.counts.lookups <= 128, `made ${world.counts.lookups} lookups`);
});

test("a look-alike costs the search the same two lookups however many inputs its transaction has", async () => {
  const world = chain();
  const { secp, funding } = await account(world);
  const made = world.add(genesis(secp, ccc.OutPoint.from({ txHash: funding.hash(), index: 0 })));
  // Newer look-alikes, each made by a transaction with a record-shaped witness on all 64 of its inputs.
  for (let i = 0; i < 40; i++) world.add(lookalike(secp, 64));
  const head = await sendLimitHead(world.client, { litPublicKey: publicKey }, []);
  assert.equal(head?.outPoint.txHash, made.hash());
  assert.ok(world.counts.lookups <= 2 * 41, `made ${world.counts.lookups} lookups`);
});
