import assert from "node:assert/strict";
import test from "node:test";
import * as ccc from "@ckb-ccc/core";
import { database } from "../src/server/database.ts";
import { listPendingTransactions, recordPendingTransaction, UNSENT_GRACE_MS } from "../src/server/pending-transactions.ts";

const enabled = Boolean(process.env.KEYWAY_AUTH_TEST_DATABASE_URL);
const lock = ccc.Script.from({ codeHash: `0x${"9b".repeat(32)}`, hashType: "type", args: "0x" });
const tx = (marker: number) => ccc.Transaction.from({ inputs: [{ previousOutput: { txHash: `0x${marker.toString(16).padStart(64, "0")}`, index: 0 } }], outputs: [{ lock, capacity: BigInt(marker) }], outputsData: ["0x"] });

test("pending transactions are listed in signing order until the node reports them committed, rejected or gone", { skip: !enabled }, async (t) => {
  process.env.DATABASE_URL = process.env.KEYWAY_AUTH_TEST_DATABASE_URL;
  const sql = await database();
  const user = crypto.randomUUID();
  const other = crypto.randomUUID();
  const [a, b, c, d, e] = [1, 2, 3, 4, 5].map(tx);
  for (const transaction of [a, b, c, d, e]) await recordPendingTransaction(user, transaction);
  await recordPendingTransaction(other, tx(6));
  // Recording the same transaction twice keeps one entry in its first place.
  await recordPendingTransaction(user, a);

  const status = new Map<string, string>([[a.hash(), "pending"], [b.hash(), "committed"], [c.hash(), "rejected"], [d.hash(), "unknown"], [e.hash(), "proposed"]]);
  const listed = await listPendingTransactions(user, async (hash) => status.get(hash));
  assert.deepEqual(listed.map(({ transaction }) => transaction.hash()), [a.hash(), d.hash(), e.hash()], "committed and rejected ones are dropped; an unknown one waits for its client");
  assert.equal((await listPendingTransactions(other, async () => "pending")).length, 1, "only the account's own");

  // Signed but never sent: dropped once the grace period is over.
  const later = Date.now() + UNSENT_GRACE_MS + 1_000;
  assert.deepEqual((await listPendingTransactions(user, async (hash) => status.get(hash), later)).map(({ transaction }) => transaction.hash()), [a.hash(), e.hash()]);
  // In the pool, then lost from it: the grace period runs from when the pool last held it.
  status.set(a.hash(), "unknown");
  assert.equal((await listPendingTransactions(user, async (hash) => status.get(hash))).length, 2);
  assert.equal((await listPendingTransactions(user, async (hash) => status.get(hash), later)).length, 1);
  // A node that can't answer keeps the entry.
  assert.equal((await listPendingTransactions(user, async () => { throw new Error("node down"); })).length, 1);
  t.after(async () => { await sql`delete from keyway_v2_pending_transactions where user_id in (${user}, ${other})`; });
});
