/**
 * How long the watchtower takes to punish a revoked commitment under load. It runs the real pass and the real
 * history scans (`runWatchtowerPass`, `chainView`) against Postgres and a simulated indexer that adds a fixed delay
 * to every request, as a public RPC does.
 *
 * - CHANNELS channels in all, each with its funding cell and nothing else;
 * - BACKLOGGED of them padded with BACKLOG cells under the funding lock before their first check (catching up for
 *   the whole run);
 * - one revoked channel whose spend was already buried before its first check: BURIED padded cells, the revoked
 *   commitment, then 300 more cells (more than the newest page).
 *
 * Prints when the penalty was sent, counted from the first pass.
 *
 *   KEYWAY_AUTH_TEST_DATABASE_URL=postgres://… npx tsx research/browser-watchtower/timing.ts
 */
import { readFile } from "node:fs/promises";
import * as ccc from "@ckb-ccc/core";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { database } from "../../src/server/database.ts";
import { chainView, fundingLockArgs, parseWatchtowerRequest, peerCommitmentKey, runWatchtowerPass, watchtowerRequest } from "../../src/server/watchtower.ts";
import { COMMITMENT_LOCK } from "../../src/sdk/browser/watchtower-settle.ts";

const env = (name: string, fallback: number) => Number(process.env[name] ?? fallback);
const CHANNELS = env("CHANNELS", 600);
const BACKLOGGED = env("BACKLOGGED", 10);
const BACKLOG = env("BACKLOG", 100_000);
const BURIED = env("BURIED", 40_000);
const LATENCY_MS = env("LATENCY_MS", 100);
const PAGE = 200;

process.env.DATABASE_URL = process.env.KEYWAY_AUTH_TEST_DATABASE_URL;
const sql = await database();
await sql`delete from keyway_v2_watchtower_channels`;

const proof = JSON.parse(await readFile(new URL("../../tests/fixtures/watchtower-testnet-proof.json", import.meta.url), "utf8")).penalty;
const randomKey = () => ccc.hexFrom(secp256k1.getPublicKey(secp256k1.utils.randomSecretKey(), true));
const channelId = () => ccc.hexFrom(crypto.getRandomValues(new Uint8Array(32)));

// Histories: a length and a function from position to entry, so a padded history costs no memory.
type Entry = { txHash: ccc.Hex; blockNumber: bigint; txIndex: bigint; isInput: boolean; cellIndex: bigint };
const histories = new Map<string, { length: number; at: (position: number) => Entry }>();
const pad = (position: number): Entry => ({ txHash: ccc.hexFrom(ccc.numBeToBytes(BigInt(position + 1), 32)), blockNumber: BigInt(position + 1), txIndex: 0n, isInput: false, cellIndex: 0n });

const tip = 1_000_000;
const users = Array.from({ length: Math.ceil(CHANNELS / 50) }, () => ({ id: crypto.randomUUID() }));
for (let i = 0; i < CHANNELS - 1; i++) {
  const local = randomKey();
  const remote = randomKey();
  await watchtowerRequest(users[Math.floor(i / 50)], parseWatchtowerRequest({ operation: "watch", channelId: channelId(), localFundingPubkey: local, remoteFundingPubkey: remote, fundingUdtTypeScript: null }));
  const length = i < BACKLOGGED ? BACKLOG : 1;
  histories.set(fundingLockArgs(local, remote), { length, at: (p) => ({ ...pad(p), blockNumber: BigInt(tip - length + p) }) });
}

// The revoked channel, with the real signed revocation from the testnet run.
const victim = { id: crypto.randomUUID() };
const revokedId = channelId();
await watchtowerRequest(victim, parseWatchtowerRequest({ operation: "watch", channelId: revokedId, localFundingPubkey: proof.localFundingPubkey, remoteFundingPubkey: proof.remoteFundingPubkey, fundingUdtTypeScript: null }));
await watchtowerRequest(victim, parseWatchtowerRequest({
  operation: "revoke", channelId: revokedId,
  revocation: { commitment_number: `0x${BigInt(proof.revocationCommitmentNumber).toString(16)}`, aggregated_signature: proof.revocationSignature, output: proof.revocationOutput, output_data: "0x00000000" },
}));
const closing = ccc.Transaction.from({
  inputs: [{ previousOutput: { txHash: `0x${"f0".repeat(32)}`, index: 0 } }],
  outputs: [{ capacity: ccc.CellOutput.decode(proof.revocationOutput).capacity, lock: { codeHash: COMMITMENT_LOCK.testnet.codeHash, hashType: "type", args: ccc.hexFrom(ccc.bytesConcat(ccc.bytesFrom(proof.onChainCommitmentArgs), new Uint8Array(21))) } }],
  outputsData: ["0x"],
});
const buriedLength = BURIED + 1 + 300;
histories.set(fundingLockArgs(proof.localFundingPubkey, proof.remoteFundingPubkey), {
  length: buriedLength,
  at: (p) => (p === BURIED
    ? { txHash: closing.hash(), blockNumber: BigInt(tip - buriedLength + p), txIndex: 0n, isInput: true, cellIndex: 0n }
    : { ...pad(p), blockNumber: BigInt(tip - buriedLength + p) }),
});

let requests = 0;
const delay = () => { requests++; return new Promise((resolve) => setTimeout(resolve, LATENCY_MS)); };
const client = {
  async findTransactionsPaged(key: { script: ccc.Script }, order: "asc" | "desc", limit: number, after?: string) {
    await delay();
    const history = histories.get(key.script.args) ?? { length: 0, at: pad };
    const positions: number[] = [];
    if (order === "asc") for (let p = after === undefined ? 0 : Number(after) + 1; p < history.length && positions.length < Number(limit); p++) positions.push(p);
    else for (let p = after === undefined ? history.length - 1 : Number(after) - 1; p >= 0 && positions.length < Number(limit); p--) positions.push(p);
    return { transactions: positions.map(history.at), lastCursor: positions.length ? String(positions.at(-1)) : after ?? "" };
  },
  async getTransaction(hash: ccc.Hex) {
    await delay();
    return hash === closing.hash() ? { transaction: closing, status: "committed" } : undefined;
  },
  async getCellLive() {
    await delay();
    return {};
  },
} as unknown as ccc.Client;

console.log(`${CHANNELS} channels (${BACKLOGGED} with ${BACKLOG} padded cells; the revoked one's spend under ${BURIED} before it and 300 after), ${LATENCY_MS} ms per request, ${PAGE} entries per page`);
const started = Date.now();
const seconds = () => ((Date.now() - started) / 1000).toFixed(1);
let penaltyAt: string | undefined;
for (let pass = 1; !penaltyAt && pass <= 30; pass++) {
  const passStarted = Date.now();
  await runWatchtowerPass({
    sql,
    chain: chainView(client),
    punish: async () => { penaltyAt = seconds(); return `0x${"cd".repeat(32)}`; },
    log: () => undefined,
  });
  console.log(`pass ${pass}: ${((Date.now() - passStarted) / 1000).toFixed(1)} s, ${requests} requests so far${penaltyAt ? `; penalty sent at ${penaltyAt} s` : ""}`);
  // The runner starts a pass every 60 s; a longer pass is followed at once.
  const wait = 60_000 - (Date.now() - passStarted);
  if (!penaltyAt && wait > 0) await new Promise((resolve) => setTimeout(resolve, wait));
}
console.log(penaltyAt ? `penalty sent ${penaltyAt} s after the first pass started` : "no penalty within 30 passes");
await sql`delete from keyway_v2_watchtower_channels`;
await sql.end();
