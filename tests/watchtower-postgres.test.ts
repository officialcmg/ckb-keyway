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
const K3 = "0x023590a94e768f8e1815c2f24b4d80a8e3149316c3518ce7b7ad338368d038ca66";
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
  const proofRevocation = (id: string, signature: string = proof.revocationSignature) => parseWatchtowerRequest({
    operation: "revoke", channelId: id,
    revocation: { commitment_number: `0x${BigInt(proof.revocationCommitmentNumber).toString(16)}`, aggregated_signature: signature, output: proof.revocationOutput, output_data: "0x00000000" },
  });
  async function revokedChannel(signature: string, { uploaded = true } = {}) {
    const user = { id: crypto.randomUUID() };
    const id = channelId();
    await sql`delete from keyway_v2_watchtower_channels where state in ('watching', 'penalty-sent')`;
    await watchtowerRequest(user, parseWatchtowerRequest({ operation: "watch", channelId: id, localFundingPubkey: proof.localFundingPubkey, remoteFundingPubkey: proof.remoteFundingPubkey, fundingUdtTypeScript: null }));
    if (uploaded) await watchtowerRequest(user, proofRevocation(id, signature));
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
    const chain: ChainView = { fundingHistory: async () => { throw new Error("indexer unavailable"); }, transaction: async () => undefined, isLive: async () => false };
    await runWatchtowerPass({ sql, chain, punish: async () => { throw new Error("no"); }, log: () => undefined });
    const status = (await watchtowerRequest(user, { operation: "status" })) as { channels: Array<{ state: string; detail: string }> };
    assert.deepEqual(status.channels.map((c) => [c.state, c.detail]), [["watching", "check failed: indexer unavailable"]]);
  });

  await t.test("a check that fails after finding the spend keeps the scan's progress", async () => {
    const user = { id: crypto.randomUUID() };
    const id = channelId();
    await sql`delete from keyway_v2_watchtower_channels where state in ('watching', 'penalty-sent')`;
    await watchtowerRequest(user, watch(id));
    const spendHash = `0x${"ab".repeat(32)}` as ccc.Hex;
    let historyReads = 0;
    const chain: ChainView = {
      fundingHistory: async () => { historyReads++; return { sawOutput: true, spend: { txHash: spendHash, index: 0 }, cursor: "c1" }; },
      transaction: async () => { throw new Error("node unavailable"); },
      isLive: async () => true,
    };
    const pass = () => runWatchtowerPass({ sql, chain, punish: async () => { throw new Error("no"); }, log: () => undefined });
    await pass();
    await pass();
    assert.equal(historyReads, 1, "the second pass goes straight to the saved spend");
    const [row] = await sql<Array<{ history_cursor: string; funding_spend: string; detail: string }>>`select history_cursor, funding_spend, detail from keyway_v2_watchtower_channels where channel_id = ${id}`;
    assert.deepEqual({ ...row }, { history_cursor: "c1", funding_spend: `${spendHash}:0`, detail: "check failed: node unavailable" });
  });

  await t.test("channels catching up on a long backlog never hold up another channel's penalty", async () => {
    const { id: revokedId, closing } = await revokedChannel(proof.revocationSignature);
    const user = { id: crypto.randomUUID() };
    // Two channels on their own funding locks (a pass reads a lock shared by channels once).
    const backlogged = [[channelId(), K2], [channelId(), K3]] as const;
    for (const [id, key] of backlogged) await watchtowerRequest(user, parseWatchtowerRequest({ operation: "watch", channelId: id, localFundingPubkey: K1, remoteFundingPubkey: key, fundingUdtTypeScript: null }));
    const paddedLocks = new Set([fundingLockArgs(K1, K2), fundingLockArgs(K1, K3)]);
    const events: string[] = [];
    const chain: ChainView = {
      async fundingHistory(lock, _scan, options) {
        if (!paddedLocks.has(lock.args)) return { sawOutput: true, spend: { txHash: closing.hash(), index: 0 } };
        const budget = options?.backlogBudgetMs ?? 0;
        events.push(budget === 0 ? "check" : `catch-up ${Math.round(budget / 10) * 10}`);
        await new Promise((resolve) => setTimeout(resolve, budget)); // uses its whole budget
        return { sawOutput: true, backlog: true };
      },
      transaction: async (hash) => (hash === closing.hash() ? { tx: closing, committed: true, status: "committed" } : undefined),
      isLive: async () => true,
    };
    await runWatchtowerPass({
      sql, chain, concurrency: 1, catchUpBudgetMs: 400, log: () => undefined,
      punish: async (row) => { events.push(`punish ${row.channel_id === revokedId}`); return `0x${"cd".repeat(32)}`; },
    });
    // Every channel is checked (and the revoked one punished) before any backlog gets catch-up time, which is
    // shared: the first of two channels gets half.
    assert.deepEqual(events.filter((event) => !event.startsWith("catch-up")).sort(), ["check", "check", "punish true"]);
    assert.ok(events.findIndex((event) => event.startsWith("catch-up")) > events.indexOf("punish true"));
    const catchUp = events.filter((event) => event.startsWith("catch-up"));
    assert.equal(catchUp.length, 2);
    assert.ok(Number(catchUp[0].split(" ")[1]) <= 200, catchUp[0]);
  });

  await t.test("funded channels are checked before unfunded ones, and a close that leaves the chain is watched again", async () => {
    await sql`delete from keyway_v2_watchtower_channels`;
    const user = { id: crypto.randomUUID() };
    const [fundedId, unfundedId, closedId] = [channelId(), channelId(), channelId()];
    for (const id of [unfundedId, fundedId, closedId]) await watchtowerRequest(user, watch(id));
    await sql`update keyway_v2_watchtower_channels set funding_seen = true where channel_id in (${fundedId}, ${closedId})`;
    await sql`update keyway_v2_watchtower_channels set history_cursor = 'funded' where channel_id = ${fundedId}`;
    const goneClose = `0x${"9e".repeat(32)}`;
    await sql`update keyway_v2_watchtower_channels set state = 'closed', closing_tx = ${goneClose}, funding_spend = ${`${goneClose}:0`} where channel_id = ${closedId}`;
    const order: string[] = [];
    const chain: ChainView = {
      async fundingHistory(_lock, scan) {
        order.push(scan.cursor ?? "unfunded");
        return { sawOutput: scan.cursor === "funded" };
      },
      transaction: async () => undefined,
      isLive: async () => false,
    };
    await runWatchtowerPass({ sql, chain, concurrency: 1, punish: async () => { throw new Error("no"); }, log: () => undefined });
    const rows = await sql<Array<{ channel_id: string; state: string; funding_seen: boolean; funding_spend: string | null }>>`
      select channel_id, state, funding_seen, funding_spend from keyway_v2_watchtower_channels order by channel_id`;
    const byId = Object.fromEntries(rows.map((row) => [row.channel_id, row]));
    assert.deepEqual(order, ["funded", "unfunded"], "the funded channel first; the closed one isn't scanned");
    assert.deepEqual({ state: byId[closedId].state, funding_spend: byId[closedId].funding_spend }, { state: "watching", funding_spend: null });
  });

  await t.test("a close that is reorganized away and replaced by a revoked commitment is punished", async () => {
    const { id, closing } = await revokedChannel(proof.revocationSignature);
    const cooperative = ccc.Transaction.from({
      inputs: [{ previousOutput: { txHash: `0x${"f0".repeat(32)}`, index: 0 } }],
      outputs: [{ capacity: 1000n, lock: userLock }, { capacity: 1000n, lock: userLock }],
      outputsData: ["0x", "0x"],
    });
    let onChain = cooperative;
    const punished: string[] = [];
    const chain: ChainView = {
      fundingHistory: async () => ({ sawOutput: true, spend: { txHash: onChain.hash(), index: 0 } }),
      transaction: async (hash) => (hash === onChain.hash() ? { tx: onChain, committed: true, status: "committed" } : undefined),
      isLive: async () => true,
    };
    const pass = () => runWatchtowerPass({ sql, chain, punish: async (row) => { punished.push(row.channel_id); return `0x${"cd".repeat(32)}`; }, log: () => undefined });
    const state = async () => (await sql<Array<{ state: string }>>`select state from keyway_v2_watchtower_channels where channel_id = ${id}`)[0].state;
    await pass();
    assert.equal(await state(), "closed");
    // A reorganization replaces the cooperative close with the peer's revoked commitment.
    onChain = closing;
    await pass(); // the close is found gone: watched again
    await pass(); // the revoked commitment is found and punished
    assert.equal(await state(), "penalty-sent");
    assert.deepEqual(punished, [id]);
  });

  // The peer publishes commitment 1 before the revocation that covers it (number 2) reaches KeyWay, e.g. because the
  // user's tab closed while the upload was being retried.
  for (const when of ["after the pass", "during the check"] as const) {
    await t.test(`a covering revocation that arrives ${when} gets the peer punished`, async () => {
      const { user, id, closing } = await revokedChannel(proof.revocationSignature, { uploaded: false });
      const penalty = `0x${"cd".repeat(32)}` as ccc.Hex;
      let uploadDuringCheck = when === "during the check";
      const chain: ChainView = {
        fundingHistory: async () => ({ sawOutput: true, spend: { txHash: closing.hash(), index: 0 } }),
        async transaction(hash) {
          if (hash === closing.hash() && uploadDuringCheck) {
            uploadDuringCheck = false;
            assert.equal(((await watchtowerRequest(user, proofRevocation(id))) as { stored: boolean }).stored, true);
          }
          if (hash === closing.hash()) return { tx: closing, committed: true, status: "committed" };
          if (hash === penalty) return { tx: ccc.Transaction.from({}), committed: false, status: "pending" };
          return undefined;
        },
        isLive: async () => true,
      };
      const punished: string[] = [];
      const pass = () => runWatchtowerPass({ sql, chain, punish: async (row) => { punished.push(row.channel_id); return penalty; }, log: () => undefined });
      const state = async () => (await sql<Array<{ state: string }>>`select state from keyway_v2_watchtower_channels where channel_id = ${id}`)[0].state;
      await pass();
      if (when === "after the pass") {
        assert.equal(await state(), "closed", "without a revocation the close looks like the current state");
        assert.equal(((await watchtowerRequest(user, proofRevocation(id))) as { stored: boolean }).stored, true);
      }
      assert.equal(await state(), "watching");
      await pass();
      await pass();
      assert.equal(await state(), "penalty-sent");
      assert.deepEqual(punished, [id]);
    });
  }

  await t.test("a revocation reopens only a close it can punish, even with the account at the cap", async () => {
    await sql`delete from keyway_v2_watchtower_channels`;
    // The peer force-closes with commitment 1 (the testnet proof's) before any revocation reached KeyWay; the other
    // two channels close cooperatively and by the user's own commitment.
    const { user, id: peerClosed, closing: peerClose } = await revokedChannel(proof.revocationSignature, { uploaded: false });
    const [cooperative, ownClose] = [channelId(), channelId()];
    await watchtowerRequest(user, parseWatchtowerRequest({ operation: "watch", channelId: cooperative, localFundingPubkey: K1, remoteFundingPubkey: K2, fundingUdtTypeScript: null }));
    await watchtowerRequest(user, parseWatchtowerRequest({ operation: "watch", channelId: ownClose, localFundingPubkey: K1, remoteFundingPubkey: K3, fundingUdtTypeScript: null }));
    const closeWith = (byte: string, outputs: ccc.CellOutputLike[]) => ccc.Transaction.from({
      inputs: [{ previousOutput: { txHash: `0x${byte.repeat(32)}`, index: 0 } }], outputs, outputsData: outputs.map(() => "0x"),
    });
    const ownNumber = new Uint8Array(8);
    new DataView(ownNumber.buffer).setBigUint64(0, 1n);
    const closes = new Map([
      [fundingLockArgs(proof.localFundingPubkey, proof.remoteFundingPubkey), peerClose],
      [fundingLockArgs(K1, K2), closeWith("e1", [{ capacity: 1000n, lock: userLock }, { capacity: 1000n, lock: userLock }])],
      // The user's own commitment: another key hash than the peer's.
      [fundingLockArgs(K1, K3), closeWith("e2", [{ capacity: 1000n, lock: { codeHash: COMMITMENT_LOCK.testnet.codeHash, hashType: "type", args: ccc.hexFrom(ccc.bytesConcat(new Uint8Array(20).fill(0xee), new Uint8Array(8), ownNumber)) } }])],
    ]);
    const chain: ChainView = {
      fundingHistory: async (lock) => ({ sawOutput: true, spend: { txHash: closes.get(lock.args)!.hash(), index: 0 } }),
      async transaction(hash) {
        const tx = [...closes.values()].find((close) => close.hash() === hash);
        return tx ? { tx, committed: true, status: "committed" } : undefined;
      },
      isLive: async () => true,
    };
    await runWatchtowerPass({ sql, chain, punish: async () => { throw new Error("no"); }, log: () => undefined });
    // The closes stayed on-chain through the window: they no longer count toward the cap.
    await sql`update keyway_v2_watchtower_channels set resolution_confirmed = true where user_id = ${user.id} and state = 'closed'`;
    const state = async (id: string) => ({ ...(await sql<Array<{ state: string; resolution_confirmed: boolean }>>`select state, resolution_confirmed from keyway_v2_watchtower_channels where channel_id = ${id}`)[0] });
    const closed = { state: "closed", resolution_confirmed: true };
    const stored = async (request: ReturnType<typeof revoke>) => ((await watchtowerRequest(user, request)) as { stored: boolean }).stored;

    // Nothing a revocation covers closed these two, however new it is.
    for (const id of [cooperative, ownClose]) {
      assert.equal(await stored(revoke(id, 5)), true);
      assert.deepEqual(await state(id), closed);
    }
    // Revocation 0 doesn't cover the peer's commitment 1.
    assert.equal(await stored(revoke(peerClosed, 0)), true);
    assert.deepEqual(await state(peerClosed), closed);

    // Revocation 2 (the proof's) does. The account already has as many channels checked every pass as it may, but a
    // revoked close left alone would lose the user the channel: it reopens, and the next pass punishes it.
    await sql`insert into keyway_v2_watchtower_channels (user_id, channel_id, local_funding_pubkey, remote_funding_pubkey, funding_lock_args, peer_commitment_key)
      select ${user.id}, '0x' || lpad(to_hex(n), 64, '0'), ${K1}, ${K2}, ${fundingLockArgs(K1, K2)}, ${peerCommitmentKey(K1, K2)} from generate_series(1, ${MAX_WATCHED_CHANNELS}) n`;
    assert.equal(await stored(proofRevocation(peerClosed)), true);
    assert.deepEqual(await state(peerClosed), { state: "watching", resolution_confirmed: false });
    const punished: string[] = [];
    await sql`update keyway_v2_watchtower_channels set state = 'closed', resolution_confirmed = true where user_id = ${user.id} and channel_id <> ${peerClosed} and state = 'watching'`;
    await runWatchtowerPass({ sql, chain, punish: async (row) => { punished.push(row.channel_id); return `0x${"cd".repeat(32)}`; }, log: () => undefined });
    assert.deepEqual(punished, [peerClosed]);
    assert.equal((await state(peerClosed)).state, "penalty-sent");
    await sql`delete from keyway_v2_watchtower_channels where user_id = ${user.id}`;
  });

  await t.test("a revoked commitment already spent is recorded as missed without walking its lock's history", async () => {
    const { id, closing } = await revokedChannel(proof.revocationSignature);
    let walks = 0;
    const chain = {
      fundingHistory: async () => ({ sawOutput: true, spend: { txHash: closing.hash(), index: 0 } }),
      transaction: async (hash: ccc.Hex) => (hash === closing.hash() ? { tx: closing, committed: true, status: "committed" } : undefined),
      isLive: async () => false,
      // What the pass used to call: a walk of the commitment lock's whole history, which anyone can pad.
      spender: async () => { walks++; return undefined; },
    } as ChainView;
    await runWatchtowerPass({ sql, chain, punish: async () => { throw new Error("no"); }, log: () => undefined });
    assert.equal(walks, 0);
    assert.equal((await sql<Array<{ state: string }>>`select state from keyway_v2_watchtower_channels where channel_id = ${id}`)[0].state, "missed");
  });

  await t.test("funded channels are checked from each account in turn, each account within its share of the pass", async () => {
    await sql`delete from keyway_v2_watchtower_channels`;
    const flooder = { id: crypto.randomUUID() };
    const honest = { id: crypto.randomUUID() };
    // The flooder's channels sit on locks that are slow to read (padded); the honest account's on a quick one.
    const flooderIds = Array.from({ length: 5 }, channelId);
    for (const id of flooderIds) await watchtowerRequest(flooder, watch(id));
    const honestId = channelId();
    await watchtowerRequest(honest, parseWatchtowerRequest({ operation: "watch", channelId: honestId, localFundingPubkey: K3, remoteFundingPubkey: K2, fundingUdtTypeScript: null }));
    // The honest channel was checked more recently than every one of the flooder's.
    await sql`update keyway_v2_watchtower_channels set funding_seen = true, checked_at = now() - interval '1 hour' where user_id = ${flooder.id}`;
    await sql`update keyway_v2_watchtower_channels set funding_seen = true, checked_at = now() - interval '1 minute' where user_id = ${honest.id}`;
    // Distinct scan positions, so no two channels share a read.
    await sql`update keyway_v2_watchtower_channels set history_cursor = channel_id`;
    const honestLock = fundingLockArgs(K3, K2);
    const order: string[] = [];
    const chain: ChainView = {
      async fundingHistory(lock, scan) {
        order.push(scan.cursor!);
        if (lock.args !== honestLock) await new Promise((resolve) => setTimeout(resolve, 60));
        return { sawOutput: true, cursor: scan.cursor };
      },
      transaction: async () => undefined,
      isLive: async () => true,
    };
    await runWatchtowerPass({ sql, chain, concurrency: 1, accountBudgetMs: 100, punish: async () => { throw new Error("no"); }, log: () => undefined });
    assert.ok(order.indexOf(honestId) <= 1, `the honest account's channel is checked in the first turn: ${order.indexOf(honestId)}`);
    const flooderChecks = order.filter((id) => id !== honestId).length;
    assert.ok(flooderChecks >= 1 && flooderChecks < flooderIds.length, `the flooder's checks stop at its share: ${flooderChecks}`);
    // The ones left over go first next pass.
    const unchecked: string[] = flooderIds.filter((id) => !order.includes(id));
    order.length = 0;
    await runWatchtowerPass({ sql, chain, concurrency: 1, accountBudgetMs: 100, punish: async () => { throw new Error("no"); }, log: () => undefined });
    assert.ok(unchecked.includes(order.filter((id) => id !== honestId)[0]));
    await sql`delete from keyway_v2_watchtower_channels`;
  });

  await t.test("closed channels count toward the cap until confirmed, and a pass reads each lock and transaction once", async () => {
    await sql`delete from keyway_v2_watchtower_channels`;
    const flooder = { id: crypto.randomUUID() };
    // The same funding keys under many channel IDs: one funding lock.
    const ids = Array.from({ length: MAX_WATCHED_CHANNELS }, channelId);
    for (const id of ids) await watchtowerRequest(flooder, watch(id));
    const honest = { id: crypto.randomUUID() };
    const honestId = channelId();
    await watchtowerRequest(honest, parseWatchtowerRequest({ operation: "watch", channelId: honestId, localFundingPubkey: K1, remoteFundingPubkey: K3, fundingUdtTypeScript: null }));
    const close = `0x${"c1".repeat(32)}` as ccc.Hex;
    const historyReads = new Map<string, number>();
    const transactionReads = new Map<string, number>();
    const chain: ChainView = {
      async fundingHistory(lock) {
        historyReads.set(lock.args, (historyReads.get(lock.args) ?? 0) + 1);
        return { sawOutput: true };
      },
      async transaction(hash) {
        transactionReads.set(hash, (transactionReads.get(hash) ?? 0) + 1);
        return hash === close ? { tx: ccc.Transaction.from({}), committed: true, status: "committed" } : undefined;
      },
      isLive: async () => false,
    };
    const pass = () => runWatchtowerPass({ sql, chain, punish: async () => { throw new Error("no"); }, log: () => undefined });
    await pass();
    assert.deepEqual([...historyReads.values()].sort(), [1, 1], "one read for the flooder's lock, one for the honest channel's");
    // Every flooder channel closes by the same transaction; the honest one stays open.
    await sql`update keyway_v2_watchtower_channels set state = 'closed', closing_tx = ${close}, funding_spend = ${`${close}:0`} where user_id = ${flooder.id}`;
    await pass();
    assert.equal(transactionReads.get(close), 1);
    await assert.rejects(watchtowerRequest(flooder, watch(channelId())), /already watches/);
  });

  await t.test("a close is confirmed only by a check after the window, even after an outage", async () => {
    await sql`delete from keyway_v2_watchtower_channels`;
    const user = { id: crypto.randomUUID() };
    const [kept, dropped] = [channelId(), channelId()];
    for (const id of [kept, dropped]) await watchtowerRequest(user, watch(id));
    const keptClose = `0x${"7a".repeat(32)}`;
    const droppedClose = `0x${"7b".repeat(32)}`;
    // Both closed long ago (past the 30-day retention), while the watchtower was down; one close was then reorganized away.
    await sql`update keyway_v2_watchtower_channels set state = 'closed', funding_seen = true, closing_tx = ${keptClose}, funding_spend = ${`${keptClose}:0`}, updated_at = now() - interval '40 days' where channel_id = ${kept}`;
    await sql`update keyway_v2_watchtower_channels set state = 'closed', funding_seen = true, closing_tx = ${droppedClose}, funding_spend = ${`${droppedClose}:0`}, updated_at = now() - interval '40 days' where channel_id = ${dropped}`;
    const chain: ChainView = {
      fundingHistory: async () => ({ sawOutput: true }),
      transaction: async (hash) => (hash === keptClose ? { tx: ccc.Transaction.from({}), committed: true, status: "committed" } : undefined),
      isLive: async () => false,
    };
    await runWatchtowerPass({ sql, chain, punish: async () => { throw new Error("no"); }, log: () => undefined });
    const rows = await sql<Array<{ channel_id: string; state: string; resolution_confirmed: boolean }>>`select channel_id, state, resolution_confirmed from keyway_v2_watchtower_channels`;
    const byId = Object.fromEntries(rows.map((row) => [row.channel_id, { state: row.state, confirmed: row.resolution_confirmed }]));
    assert.deepEqual(byId[kept], { state: "closed", confirmed: true });
    assert.deepEqual(byId[dropped], { state: "watching", confirmed: false });
  });

  await t.test("unfunded channels are checked from each account in turn", async () => {
    await sql`delete from keyway_v2_watchtower_channels`;
    const flooder = { id: crypto.randomUUID() };
    const honest = { id: crypto.randomUUID() };
    for (let i = 0; i < 5; i++) await watchtowerRequest(flooder, watch(channelId()));
    const honestId = channelId();
    await watchtowerRequest(honest, watch(honestId));
    const chain: ChainView = { fundingHistory: async () => ({ sawOutput: false }), transaction: async () => undefined, isLive: async () => false };
    await runWatchtowerPass({ sql, chain, unfundedPerPass: 2, punish: async () => { throw new Error("no"); }, log: () => undefined });
    const checked = await sql<Array<{ user_id: string; channel_id: string }>>`select user_id, channel_id from keyway_v2_watchtower_channels where checked_at is not null`;
    assert.equal(checked.length, 2);
    assert.ok(checked.some((row) => row.channel_id === honestId), "the other account's channel is checked in the first pass");
  });

  await t.test("a channel that was never funded and was removed is dropped", async () => {
    const user = { id: crypto.randomUUID() };
    const id = channelId();
    await watchtowerRequest(user, watch(id));
    await watchtowerRequest(user, { operation: "unwatch", channelId: id });
    const chain: ChainView = { fundingHistory: async () => ({ sawOutput: false }), transaction: async () => undefined, isLive: async () => false };
    await runWatchtowerPass({ sql, chain, punish: async () => { throw new Error("no"); }, log: () => undefined });
    assert.equal((await sql`select 1 from keyway_v2_watchtower_channels where channel_id = ${id}`).length, 0);
  });
});
