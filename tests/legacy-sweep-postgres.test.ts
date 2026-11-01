import assert from "node:assert/strict";
import test from "node:test";
import * as ccc from "@ckb-ccc/core";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { secp256k1Lock, type KeyWayRecovery } from "../src/sdk/browser/account-lock.ts";
import { database } from "../src/server/database.ts";
import { formatCkbSignature } from "../src/server/funding-transaction.ts";
import { sweepLegacyAddress, type LegacySweepContext } from "../src/server/legacy-sweep.ts";
import { saveWallet, type ReadyWallet } from "../src/server/user-wallet.ts";
import { anchoredRecovery } from "./recovery-fixture.ts";

const enabled = Boolean(process.env.KEYWAY_AUTH_TEST_DATABASE_URL);
const CKB = 100_000_000n;

let nextCell = 1;
async function harness(withRecovery: boolean | ((recovery: KeyWayRecovery) => KeyWayRecovery) = true) {
  const privateKey = secp256k1.utils.randomSecretKey();
  const publicKey = ccc.hexFrom(secp256k1.getPublicKey(privateKey, true));
  const anchor = await anchoredRecovery(publicKey, { seed: nextCell++ + 1_000_000 });
  const recovery = typeof withRecovery === "function" ? withRecovery(anchor.recovery) : anchor.recovery;
  const client = new ccc.ClientPublicTestnet({ url: "https://testnet.ckb.dev/" });
  const secp = await secp256k1Lock(client, publicKey);
  const cells: ccc.Cell[] = [];
  const addRaw = async (cell: ccc.Cell) => {
    await client.cache.recordCells([cell]);
    cells.push(cell);
  };
  const addCell = async (capacity: bigint) => addRaw(ccc.Cell.from({ outPoint: { txHash: `0x${(nextCell++).toString(16).padStart(64, "e")}`, index: 0 }, cellOutput: { lock: secp, capacity }, outputData: "0x" }));
  /** What the node says about each sent transaction. */
  const pool = new Map<string, { status: ccc.TransactionStatus; transaction: ccc.Transaction }>();
  Object.assign(client, {
    findSingletonCellByType: async () => undefined,
    findCellsByLock: async function* (lock: ccc.ScriptLike) { for (const cell of cells) if (cell.cellOutput.lock.eq(ccc.Script.from(lock))) yield cell; },
    getTransaction: async (hash: ccc.HexLike) => pool.get(ccc.hexFrom(hash)) ?? anchored.get(ccc.hexFrom(hash)),
    sendTransactionDry: async () => 1_000_000n,
  });
  const anchored = new Map(anchor.transactions.map((transaction) => [transaction.hash(), { status: "committed" as const, transaction }]));
  await addCell(300n * CKB);

  const user = { id: crypto.randomUUID() };
  const wallet: ReadyWallet = {
    version: 1, status: "ready", litPkpId: `0x${"11".repeat(20)}`, litPublicKey: publicKey, ckbAddress: "ckt1new",
    encryptedFiberKey: "ciphertext", primaryDeviceIdHash: "a".repeat(64), hasOpenedChannel: false,
    createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(), ...(withRecovery ? { recovery } : {}),
  };
  await saveWallet(user, wallet);
  const broadcasts: ccc.Transaction[] = [];
  const signings: string[] = [];
  let gate: Promise<void> | undefined;
  let failNext = false;
  const context: LegacySweepContext = {
    user, client,
    recordSigning: async (userId) => { signings.push(userId); },
    signDigest: async (digest) => {
      const raw = secp256k1.sign(ccc.bytesFrom(digest), privateKey, { prehash: false, format: "recovered" });
      return formatCkbSignature({ recoveryParam: raw[0] as 0 | 1, r: ccc.hexFrom(raw.slice(1, 33)), s: ccc.hexFrom(raw.slice(33, 65)) });
    },
    broadcast: async (transaction) => {
      await gate;
      if (failNext) { failNext = false; throw new Error("PoolRejectedTransactionByMinFeeRate"); }
      broadcasts.push(transaction);
      pool.set(transaction.hash(), { status: "pending", transaction });
      return transaction.hash();
    },
  };
  return {
    user, context, broadcasts, signings, pool, addCell, addRaw, recovery, client, publicKey,
    hold: () => { let release!: () => void; gate = new Promise((resolve) => { release = resolve; }); return () => { release(); gate = undefined; }; },
    failOnce: () => { failNext = true; },
  };
}

test("the sign-in sweep never double-sends", { skip: !enabled }, async (t) => {
  process.env.DATABASE_URL = process.env.KEYWAY_AUTH_TEST_DATABASE_URL;
  const sql = await database();

  await t.test("concurrent sign-ins build one transaction; the others step aside", async () => {
    const h = await harness();
    const release = h.hold();
    const runs = Promise.all([1, 2, 3].map(() => sweepLegacyAddress(h.context)));
    await new Promise((resolve) => setTimeout(resolve, 200));
    release();
    const results = await runs;
    assert.deepEqual(results.map(({ status }) => status).sort(), ["busy", "busy", "swept"]);
    assert.equal(h.broadcasts.length, 1);
    assert.equal(h.signings.length, 1, "counted as a signing event");
    const [row] = await sql<Array<{ transaction_hash: string }>>`select transaction_hash from keyway_v2_legacy_sweeps where user_id = ${h.user.id}`;
    assert.equal(row.transaction_hash, h.broadcasts[0].hash());
    // It moves the user's own funds, so it doesn't count toward the daily email-confirmation amount.
    const [{ count }] = await sql<Array<{ count: number }>>`select count(*)::int as count from keyway_v2_signed_outflows where user_id = ${h.user.id}`;
    assert.equal(count, 0);
  });

  await t.test("a sweep in the mempool isn't rebuilt, even when more funds arrive", async () => {
    const h = await harness();
    const first = await sweepLegacyAddress(h.context);
    assert.equal(first.status, "swept");
    await h.addCell(500n * CKB);
    for (const status of ["pending", "proposed"] as const) {
      h.pool.get(h.broadcasts[0].hash())!.status = status;
      assert.deepEqual(await sweepLegacyAddress(h.context), { status: "pending", transactionHash: h.broadcasts[0].hash() });
    }
    assert.equal(h.broadcasts.length, 1);

    // Once committed, its inputs are skipped even while the indexer still lists them; the new cell moves.
    h.pool.get(h.broadcasts[0].hash())!.status = "committed";
    const second = await sweepLegacyAddress(h.context);
    assert.equal(second.status, "swept");
    assert.equal(h.broadcasts.length, 2);
    assert.equal(h.broadcasts[1].inputs.length, 1);
    assert.ok(!h.broadcasts[1].inputs[0].previousOutput.eq(h.broadcasts[0].inputs[0].previousOutput));
  });

  await t.test("a rejected or failed sweep is retried at the next sign-in", async () => {
    const h = await harness();
    await sweepLegacyAddress(h.context);
    h.pool.get(h.broadcasts[0].hash())!.status = "rejected";
    assert.equal((await sweepLegacyAddress(h.context)).status, "swept");
    assert.equal(h.broadcasts.length, 2);
    assert.equal(h.broadcasts[1].hash(), h.broadcasts[0].hash(), "the same cells give the same transaction");

    h.pool.get(h.broadcasts[1].hash())!.status = "rejected";
    h.failOnce();
    await assert.rejects(sweepLegacyAddress(h.context), /MinFeeRate/);
    const rows = await sql`select 1 from keyway_v2_legacy_sweeps where user_id = ${h.user.id}`;
    assert.equal(rows.length, 0, "a send that failed leaves nothing to wait for");
    assert.equal((await sweepLegacyAddress(h.context)).status, "swept");
  });

  await t.test("a sent sweep the node doesn't know yet is waited for, then forgotten", async () => {
    const h = await harness();
    await sweepLegacyAddress(h.context);
    h.pool.clear();
    assert.equal((await sweepLegacyAddress(h.context)).status, "pending");
    await sql`update keyway_v2_legacy_sweeps set sent_at = now() - interval '11 minutes' where user_id = ${h.user.id}`;
    assert.equal((await sweepLegacyAddress(h.context)).status, "swept");
  });

  await t.test("signs nothing for a recovery record the chain doesn't back", async () => {
    // A record pointing at a list made from someone else's cell (written straight into the database).
    const other = await anchoredRecovery(ccc.hexFrom(secp256k1.getPublicKey(secp256k1.utils.randomSecretKey(), true)), { seed: nextCell++ + 2_000_000 });
    const h = await harness((own) => ({ ...own, enableTransactionHash: other.enable.hash() }));
    const original = h.client.getTransaction.bind(h.client);
    Object.assign(h.client, { getTransaction: async (hash: ccc.HexLike) => ccc.hexFrom(hash) === other.enable.hash() ? { status: "committed", transaction: other.enable } : original(hash) });
    await assert.rejects(sweepLegacyAddress(h.context), /recovery record doesn't match the chain/);
    assert.equal(h.signings.length, 0);
    assert.equal(h.broadcasts.length, 0);
  });

  await t.test("leaves a token cell the node refuses to move and sweeps the rest", async () => {
    const h = await harness();
    const xudt = await h.client.getKnownScript(ccc.KnownScript.XUdt);
    const secp = await secp256k1Lock(h.client, h.publicKey);
    const token = ccc.Cell.from({ outPoint: { txHash: `0x${(nextCell++).toString(16).padStart(64, "f")}`, index: 0 }, cellOutput: { lock: secp, capacity: 142n * CKB, type: { codeHash: xudt.codeHash, hashType: xudt.hashType, args: `0x${"77".repeat(32)}` } }, outputData: ccc.hexFrom(ccc.numLeToBytes(5n, 16)) });
    await h.addRaw(token);
    Object.assign(h.client, { sendTransactionDry: async (transaction: ccc.Transaction) => {
      const index = transaction.inputs.findIndex(({ previousOutput }) => previousOutput.eq(token.outPoint));
      if (index >= 0) throw new Error(`Verification failed Script(TransactionScriptError { source: Inputs[${index}].Type, cause: ValidationFailure: see error code -52 })`);
      return 1_000_000n;
    } });
    assert.equal((await sweepLegacyAddress(h.context)).status, "swept");
    assert.equal(h.broadcasts.length, 1);
    assert.ok(!h.broadcasts[0].inputs.some(({ previousOutput }) => previousOutput.eq(token.outPoint)));
    assert.ok(h.broadcasts[0].outputs.every((output) => !output.type));
  });

  await t.test("does nothing for accounts without recovery or with nothing at the old address", async () => {
    const off = await harness(false);
    assert.deepEqual(await sweepLegacyAddress(off.context), { status: "off" });
    assert.equal(off.broadcasts.length, 0);
    const h = await harness();
    await sweepLegacyAddress(h.context);
    h.pool.get(h.broadcasts[0].hash())!.status = "committed";
    assert.deepEqual(await sweepLegacyAddress(h.context), { status: "empty" });
    assert.equal(h.broadcasts.length, 1);
  });
});
