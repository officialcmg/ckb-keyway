import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import * as ccc from "@ckb-ccc/core";
import { database } from "../src/server/database.ts";
import {
  MAX_WATCHED_CHANNELS, fundingLockArgs, parseWatchtowerRequest, peerCommitmentKey, runWatchtowerPass, watchtowerRequest, type ChainView,
} from "../src/server/watchtower.ts";
import { COMMITMENT_LOCK, blake160 } from "../src/sdk/browser/watchtower-settle.ts";

const enabled = Boolean(process.env.KEYWAY_AUTH_TEST_DATABASE_URL);
const K1 = "0x02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
const K2 = "0x03dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659";
const userLock = { codeHash: `0x${"9b".repeat(32)}`, hashType: "type", args: `0x${"01".repeat(20)}` } as const;

const channelId = () => ccc.hexFrom(crypto.getRandomValues(new Uint8Array(32)));
const watch = (id: string) => parseWatchtowerRequest({ operation: "watch", channelId: id, localFundingPubkey: K1, remoteFundingPubkey: K2, fundingUdtTypeScript: null });
const revoke = (id: string, n: number, type?: ccc.ScriptLike) => parseWatchtowerRequest({
  operation: "revoke",
  channelId: id,
  revocation: {
    commitment_number: `0x${n.toString(16)}`,
    aggregated_signature: `0x${"5a".repeat(64)}`,
    output: ccc.CellOutput.from({ capacity: 1000n, lock: userLock, type }).toHex(),
    output_data: "0x00000000",
  },
});

test("browser-node watchtower storage and passes", { skip: !enabled }, async (t) => {
  process.env.DATABASE_URL = process.env.KEYWAY_AUTH_TEST_DATABASE_URL;
  const sql = await database();

  await t.test("keeps only the newest revocation, per user", async () => {
    const ana = { id: crypto.randomUUID() };
    const bo = { id: crypto.randomUUID() };
    const id = channelId();
    await assert.rejects(watchtowerRequest(ana, revoke(id, 1)), /not watched/);
    await watchtowerRequest(ana, watch(id));
    await watchtowerRequest(ana, watch(id)); // a repeat from a restarted tab is fine
    assert.equal(((await watchtowerRequest(ana, revoke(id, 3))) as { stored: boolean }).stored, true);
    assert.equal(((await watchtowerRequest(ana, revoke(id, 2))) as { stored: boolean }).stored, false);
    assert.equal(((await watchtowerRequest(ana, revoke(id, 3))) as { stored: boolean }).stored, false);
    const status = (await watchtowerRequest(ana, { operation: "status" })) as { channels: Array<{ channelId: string; commitmentNumber: string }> };
    assert.deepEqual(status.channels.map((c) => [c.channelId, c.commitmentNumber]), [[id, "0x3"]]);
    // Another user neither sees nor changes it.
    assert.deepEqual(((await watchtowerRequest(bo, { operation: "status" })) as { channels: unknown[] }).channels, []);
    await assert.rejects(watchtowerRequest(bo, revoke(id, 9)), /not watched/);
    assert.equal(((await watchtowerRequest(bo, { operation: "unwatch", channelId: id })) as { channel: unknown }).channel, null);
    // Other funding keys under the same ID are refused rather than replacing the record.
    await assert.rejects(watchtowerRequest(ana, parseWatchtowerRequest({ operation: "watch", channelId: id, localFundingPubkey: K2, remoteFundingPubkey: K1, fundingUdtTypeScript: null })), /other funding keys/);
    // A CKB channel's revocation can't carry a token type script.
    await assert.rejects(watchtowerRequest(ana, revoke(id, 10, { codeHash: `0x${"aa".repeat(32)}`, hashType: "type", args: "0x" })), /asset/);
  });

  await t.test("limits open channels per user", async () => {
    const user = { id: crypto.randomUUID() };
    await sql`insert into keyway_v2_watchtower_channels (user_id, channel_id, local_funding_pubkey, remote_funding_pubkey, funding_lock_args, peer_commitment_key)
      select ${user.id}, '0x' || lpad(to_hex(n), 64, '0'), ${K1}, ${K2}, ${fundingLockArgs(K1, K2)}, ${peerCommitmentKey(K1, K2)} from generate_series(1, ${MAX_WATCHED_CHANNELS}) n`;
    await assert.rejects(watchtowerRequest(user, watch(channelId())), /already watches/);
  });

  // The 2026-11-06 testnet run: real funding keys, the real signed revocation (number 2) and the on-chain lock
  // args of the revoked commitment (number 1) that the watchtower punished.
  const proof = JSON.parse(await readFile(new URL("./fixtures/watchtower-testnet-proof.json", import.meta.url), "utf8")).penalty;
  async function revokedChannel(signature: string) {
    const user = { id: crypto.randomUUID() };
    const id = channelId();
    await sql`delete from keyway_v2_watchtower_channels where state in ('watching', 'penalty-sent')`;
    await watchtowerRequest(user, parseWatchtowerRequest({ operation: "watch", channelId: id, localFundingPubkey: proof.localFundingPubkey, remoteFundingPubkey: proof.remoteFundingPubkey, fundingUdtTypeScript: null }));
    await watchtowerRequest(user, parseWatchtowerRequest({
      operation: "revoke", channelId: id,
      revocation: { commitment_number: `0x${BigInt(proof.revocationCommitmentNumber).toString(16)}`, aggregated_signature: signature, output: proof.revocationOutput, output_data: "0x00000000" },
    }));
    const closing = ccc.Transaction.from({
      inputs: [{ previousOutput: { txHash: `0x${"f0".repeat(32)}`, index: 0 } }],
      outputs: [{ capacity: ccc.CellOutput.decode(proof.revocationOutput).capacity, lock: { codeHash: COMMITMENT_LOCK.testnet.codeHash, hashType: "type", args: ccc.hexFrom(ccc.bytesConcat(ccc.bytesFrom(proof.onChainCommitmentArgs), new Uint8Array(21))) } }],
      outputsData: ["0x"],
    });
    return { user, id, closing };
  }

  await t.test("a pass punishes a revoked commitment once and follows it to the end", async () => {
    const { user, id, closing } = await revokedChannel(proof.revocationSignature);
    const penalty = `0x${"cd".repeat(32)}` as ccc.Hex;
    let spent = false;
    let penaltyStatus = "pending";
    const chain: ChainView = {
      async fundingHistory() {
        return { sawOutput: true, ...(spent ? { spend: { txHash: closing.hash(), index: 0 } } : {}) };
      },
      async transaction(hash) {
        if (hash === closing.hash()) return { tx: closing, committed: true, status: "committed" };
        if (hash === penalty) return { tx: ccc.Transaction.from({}), committed: penaltyStatus === "committed", status: penaltyStatus };
        return undefined;
      },
      async isLive() { return true; },
      async spender() { return undefined; },
    };
    const punished: string[] = [];
    const pass = () => runWatchtowerPass({ sql, chain, punish: async (row) => { punished.push(row.channel_id); return penalty; }, log: () => undefined });
    const state = async () => (await sql<Array<{ state: string; detail: string; penalty_tx: string | null }>>`select state, detail, penalty_tx from keyway_v2_watchtower_channels where channel_id = ${id}`)[0];

    await pass();
    assert.deepEqual(await state(), { state: "watching", detail: "open", penalty_tx: null });
    // The user's tab closed (Fiber's ChannelClosed may even arrive): the record stays until the close is resolved.
    await watchtowerRequest(user, { operation: "unwatch", channelId: id });
    spent = true;
    await pass();
    assert.equal((await state()).state, "penalty-sent");
    await pass(); // still pending: not sent again
    assert.deepEqual(punished, [id]);
    penaltyStatus = "committed";
    await pass();
    assert.equal((await state()).state, "penalized");
  });

  await t.test("a revocation that doesn't unlock the commitment is never sent", async () => {
    const forged = `0x${"5a".repeat(64)}`;
    const { id, closing } = await revokedChannel(forged);
    const chain: ChainView = {
      fundingHistory: async () => ({ sawOutput: true, spend: { txHash: closing.hash(), index: 0 } }),
      transaction: async (hash) => (hash === closing.hash() ? { tx: closing, committed: true, status: "committed" } : undefined),
      isLive: async () => true,
      spender: async () => undefined,
    };
    let punished = 0;
    for (let i = 0; i < 2; i++) await runWatchtowerPass({ sql, chain, punish: async () => { punished++; return `0x${"cd".repeat(32)}`; }, log: () => undefined });
    assert.equal(punished, 0);
    assert.equal((await sql<Array<{ state: string }>>`select state from keyway_v2_watchtower_channels where channel_id = ${id}`)[0].state, "invalid");
  });

  await t.test("a failing penalty is retried with backoff", async () => {
    const { id, closing } = await revokedChannel(proof.revocationSignature);
    const chain: ChainView = {
      fundingHistory: async () => ({ sawOutput: true, spend: { txHash: closing.hash(), index: 0 } }),
      transaction: async (hash) => (hash === closing.hash() ? { tx: closing, committed: true, status: "committed" } : undefined),
      isLive: async () => true,
      spender: async () => undefined,
    };
    let tries = 0;
    for (let i = 0; i < 3; i++) await runWatchtowerPass({ sql, chain, punish: async () => { tries++; throw new Error("fee key empty"); }, log: () => undefined });
    assert.equal(tries, 1, "the second and third pass wait for the backoff");
    const [row] = await sql<Array<{ state: string; attempts: number }>>`select state, attempts from keyway_v2_watchtower_channels where channel_id = ${id}`;
    assert.deepEqual({ ...row }, { state: "watching", attempts: 1 });
  });

  await t.test("a check that fails shows in the channel's status", async () => {
    const user = { id: crypto.randomUUID() };
    const id = channelId();
    await sql`delete from keyway_v2_watchtower_channels where state in ('watching', 'penalty-sent')`;
    await watchtowerRequest(user, watch(id));
    const chain: ChainView = { fundingHistory: async () => { throw new Error("indexer unavailable"); }, transaction: async () => undefined, isLive: async () => false, spender: async () => undefined };
    await runWatchtowerPass({ sql, chain, punish: async () => { throw new Error("no"); }, log: () => undefined });
    const status = (await watchtowerRequest(user, { operation: "status" })) as { channels: Array<{ state: string; detail: string }> };
    assert.deepEqual(status.channels.map((c) => [c.state, c.detail]), [["watching", "check failed: indexer unavailable"]]);
  });

  await t.test("a channel that was never funded and was removed is dropped", async () => {
    const user = { id: crypto.randomUUID() };
    const id = channelId();
    await watchtowerRequest(user, watch(id));
    await watchtowerRequest(user, { operation: "unwatch", channelId: id });
    const chain: ChainView = { fundingHistory: async () => ({ sawOutput: false }), transaction: async () => undefined, isLive: async () => false, spender: async () => undefined };
    await runWatchtowerPass({ sql, chain, punish: async () => { throw new Error("no"); }, log: () => undefined });
    assert.equal((await sql`select 1 from keyway_v2_watchtower_channels where channel_id = ${id}`).length, 0);
  });
});
