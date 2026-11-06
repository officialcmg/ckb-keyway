import * as ccc from "@ckb-ccc/core";
import { schnorr, secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import type { User } from "./auth-user.ts";
import { database, type DatabaseSql } from "./database.ts";
import { COMMITMENT_LOCK, XUDT_COMPATIBLE_WITNESS, blake160, commitmentLockCellDeps } from "../sdk/browser/watchtower-settle.ts";

/**
 * KeyWay's watchtower for browser nodes. It punishes a peer that publishes a revoked commitment while the user's
 * tab is closed, and nothing else.
 *
 * A browser node sends it, per channel, only the two funding public keys (to find the channel on-chain) and the
 * latest revocation data Fiber produces on every RevokeAndAck: a commitment number, the 64-byte MuSig2 signature
 * both parties made over the revocation output, and that output. The commitment lock's revocation path checks only
 * that signature over output 0, its data and the lock args (fiber-scripts commitment-lock `auth()`), so the
 * watchtower can add its own cell to pay the fee but cannot change where the money goes: output 0 pays the whole
 * channel to the user's own shutdown script. It never receives the node key, the settlement key, TLC keys,
 * preimages or settlement data; claiming the user's share after an honest force close stays with the in-page
 * watchtower (watchtower-settle.ts).
 */

export const NETWORK = "testnet" as const;
/** Fiber 0.9.1's funding lock (config/testnet/config.yml `FundingLock`). */
export const FUNDING_LOCK = { codeHash: "0x6c67887fe201ee0c7853f1682c0b77c0e6214044c156c7558269390a8afa6d7c", hashType: "type" } as const;
/** Fiber's revocation tx fee rate (watchtower/actor.rs `FeeCalculator::new(1000)`), shannons per 1000 bytes. */
const FEE_RATE = 1000n;
/** Active (not yet finished) channels one user may have watched; Fiber nodes rarely hold more than a few. */
export const MAX_WATCHED_CHANNELS = 64;
const MAX_OUTPUT_BYTES = 512;
const MAX_OUTPUT_DATA_BYTES = 64;
const FINISHED_RETENTION_DAYS = 30;
/** A penalty that fails to build or send is retried after 1, 2, 4 … minutes, at most every 5 minutes. */
const MAX_RETRY_MS = 5 * 60_000;
/** The most a penalty may cost the watchtower (Fiber's fee is about 0.00001 CKB). */
const MAX_PENALTY_FEE = 100_000n;
const CHANGE_RESERVE = ccc.fixedPointFrom(62);
/**
 * A funding lock's history is read by two scans (see `fundingHistory`). Anyone can create cells under the lock (only
 * spending needs both parties), so a peer could pad the history; each padding cell locks 61 CKB for good.
 *
 * - The recent scan reads every entry added since the channel was registered, newest first, up to
 *   `RECENT_BUDGET_MS` per channel per pass; a range it can't finish is resumed from a saved cursor next pass.
 * - The backlog scan reads what was there before, oldest first, from a saved cursor. Every pass first gives each
 *   channel one page, then shares `CATCH_UP_BUDGET_MS` between the channels still catching up.
 *
 * So a spend made while the channel is watched is seen in the first pass after it (unless the peer pads more than a
 * pass can read after it, at 61 CKB a cell), and no channel's backlog delays another's check.
 */
const RECENT_BUDGET_MS = 20_000;
/** Blocks the recent scan reads again each pass, since a reorganization can replace them (CKB's are a few deep). */
const REORG_DEPTH = 24n;
const CATCH_UP_BUDGET_MS = 120_000;
/** The longest one indexer page request may take. */
const PAGE_TIMEOUT_MS = 15_000;
/** Channels never seen funded that are checked per pass (see `runWatchtowerPass`). */
const UNFUNDED_PER_PASS = 500;
/** How long a close or penalty must stay on-chain before it is final (24 blocks are about 4 minutes). */
const REORG_RECHECK_MINUTES = 30;
/** Channels whose recent history is checked at the same time in a pass. */
const CHECK_CONCURRENCY = 8;
const HISTORY_PAGE_SIZE = 200;
/** A channel whose funding never appears on-chain (an abandoned open) is dropped after this long. */
const UNFUNDED_RETENTION_DAYS = 14;

// ---------------------------------------------------------------------------------------------------------------
// MuSig2 key aggregation (BIP327 KeyAgg, as the `musig2` crate Fiber uses): Fiber's funding and commitment locks
// commit to blake160 of the aggregated x-only key.

const encoder = new TextEncoder();
function taggedHash(tag: string, ...parts: Uint8Array[]): Uint8Array {
  const tagHash = sha256(encoder.encode(tag));
  return sha256(ccc.bytesConcat(tagHash, tagHash, ...parts));
}
const sameBytes = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((byte, i) => byte === b[i]);
const compareBytes = (a: Uint8Array, b: Uint8Array) => {
  for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
};

/** The aggregated x-only public key of `keys` (33-byte compressed points), in the given order. */
export function keyAggXOnly(keys: Uint8Array[]): Uint8Array {
  const list = taggedHash("KeyAgg list", ...keys);
  const second = keys.find((key) => !sameBytes(key, keys[0]));
  let total = secp256k1.Point.ZERO;
  for (const key of keys) {
    const coefficient = second && sameBytes(key, second)
      ? 1n
      : BigInt(ccc.hexFrom(taggedHash("KeyAgg coefficient", list, key))) % secp256k1.Point.Fn.ORDER;
    total = total.add(secp256k1.Point.fromBytes(key).multiply(coefficient));
  }
  return total.toBytes(true).slice(1);
}

/** The funding cell's lock args: blake160 of the aggregate of both funding keys, sorted (watchtower/store.rs). */
export function fundingLockArgs(localFundingPubkey: ccc.HexLike, remoteFundingPubkey: ccc.HexLike): ccc.Hex {
  const keys = [ccc.bytesFrom(localFundingPubkey), ccc.bytesFrom(remoteFundingPubkey)].sort(compareBytes);
  return ccc.hexFrom(blake160(keyAggXOnly(keys)));
}

/**
 * The key of the commitment lock on the peer's commitments: the aggregate of [local, remote] (channel.rs
 * `get_commitment_lock_script_xonly(true)`). The node's own commitments use [remote, local].
 */
export function peerCommitmentKey(localFundingPubkey: ccc.HexLike, remoteFundingPubkey: ccc.HexLike): ccc.Hex {
  return ccc.hexFrom(keyAggXOnly([ccc.bytesFrom(localFundingPubkey), ccc.bytesFrom(remoteFundingPubkey)]));
}

// ---------------------------------------------------------------------------------------------------------------
// Requests

export type Revocation = {
  commitmentNumber: bigint;
  /** 64-byte MuSig2 signature both parties made over the revocation output. */
  aggregatedSignature: ccc.Hex;
  /** The revocation output, molecule-encoded CellOutput, as Fiber sends it. */
  output: ccc.Hex;
  /** The output's data, raw (Fiber sends it molecule-encoded; the length prefix is removed here). */
  outputData: ccc.Hex;
};

export type WatchtowerRequest =
  | { operation: "watch"; channelId: ccc.Hex; localFundingPubkey: ccc.Hex; remoteFundingPubkey: ccc.Hex; fundingUdtTypeScript: ccc.Script | null }
  | { operation: "revoke"; channelId: ccc.Hex; revocation: Revocation }
  | { operation: "unwatch"; channelId: ccc.Hex }
  | { operation: "status" };

function hexOf(value: unknown, bytes: number | [number, number], name: string): ccc.Hex {
  const text = typeof value === "string" ? value.replace(/^0x/i, "") : "";
  const [min, max] = typeof bytes === "number" ? [bytes, bytes] : bytes;
  if (!/^(?:[0-9a-fA-F]{2})*$/.test(text) || text.length < min * 2 || text.length > max * 2) throw new Error(`Invalid watchtower ${name}`);
  return `0x${text.toLowerCase()}`;
}
function pubkeyOf(value: unknown, name: string): ccc.Hex {
  const key = hexOf(value, 33, name);
  try {
    secp256k1.Point.fromBytes(ccc.bytesFrom(key));
  } catch {
    throw new Error(`Invalid watchtower ${name}`);
  }
  return key;
}
function scriptOf(value: unknown): ccc.Script | null {
  if (value === null || value === undefined) return null;
  const script = value as { code_hash?: unknown; hash_type?: unknown; args?: unknown };
  if (typeof script !== "object" || !["type", "data", "data1", "data2"].includes(String(script.hash_type))) throw new Error("Invalid watchtower token script");
  return ccc.Script.from({
    codeHash: hexOf(script.code_hash, 32, "token script"),
    hashType: script.hash_type as ccc.HashType,
    args: hexOf(script.args, [0, 256], "token script"),
  });
}

/** Reads Fiber's RevocationData JSON (fiber-json-types watchtower.rs), checking every field's shape. */
export function parseRevocation(value: unknown): Revocation {
  const data = value as { commitment_number?: unknown; aggregated_signature?: unknown; output?: unknown; output_data?: unknown } | null;
  if (!data || typeof data !== "object") throw new Error("Invalid watchtower revocation");
  if (typeof data.commitment_number !== "string" || !/^0x[0-9a-f]{1,16}$/i.test(data.commitment_number)) throw new Error("Invalid watchtower commitment number");
  const output = hexOf(data.output, [1, MAX_OUTPUT_BYTES], "revocation output");
  let decoded: ccc.CellOutput;
  try {
    decoded = ccc.CellOutput.decode(output);
  } catch {
    throw new Error("Invalid watchtower revocation output");
  }
  if (decoded.toHex() !== output) throw new Error("Invalid watchtower revocation output");
  const packedData = ccc.bytesFrom(hexOf(data.output_data, [4, 4 + MAX_OUTPUT_DATA_BYTES], "revocation output data"));
  const length = new DataView(packedData.buffer, packedData.byteOffset).getUint32(0, true);
  if (length !== packedData.length - 4) throw new Error("Invalid watchtower revocation output data");
  return {
    commitmentNumber: BigInt(data.commitment_number),
    aggregatedSignature: hexOf(data.aggregated_signature, 64, "revocation signature"),
    output,
    outputData: ccc.hexFrom(packedData.slice(4)),
  };
}

export function parseWatchtowerRequest(body: Record<string, unknown>): WatchtowerRequest {
  switch (body.operation) {
    case "watch":
      // Token channels need the token's cell deps and an amount check this watchtower doesn't do yet.
      if (body.fundingUdtTypeScript !== null && body.fundingUdtTypeScript !== undefined) throw new Error("Token channels are not watched yet");
      return {
        operation: "watch",
        channelId: hexOf(body.channelId, 32, "channel ID"),
        localFundingPubkey: pubkeyOf(body.localFundingPubkey, "funding key"),
        remoteFundingPubkey: pubkeyOf(body.remoteFundingPubkey, "funding key"),
        fundingUdtTypeScript: scriptOf(body.fundingUdtTypeScript),
      };
    case "revoke":
      return { operation: "revoke", channelId: hexOf(body.channelId, 32, "channel ID"), revocation: parseRevocation(body.revocation) };
    case "unwatch":
      return { operation: "unwatch", channelId: hexOf(body.channelId, 32, "channel ID") };
    case "status":
      return { operation: "status" };
    default:
      throw new Error("Unsupported watchtower operation");
  }
}

// ---------------------------------------------------------------------------------------------------------------
// Storage

export type WatchState = "watching" | "penalty-sent" | "penalized" | "closed" | "missed" | "invalid";

type Row = {
  user_id: string;
  channel_id: string;
  local_funding_pubkey: string;
  remote_funding_pubkey: string;
  funding_lock_args: string;
  peer_commitment_key: string;
  funding_udt_type_script: { codeHash: string; hashType: string; args: string } | null;
  commitment_number: string | null;
  aggregated_signature: string | null;
  revocation_output: string | null;
  revocation_output_data: string | null;
  state: WatchState;
  detail: string | null;
  funding_out_point: string | null;
  history_cursor: string | null;
  /** The recent scan's position (`RecentScan`, as JSON). */
  recent_scan: string | null;
  funding_seen: boolean;
  funding_spend: string | null;
  closing_tx: string | null;
  penalty_tx: string | null;
  resolution_confirmed: boolean;
  unwatch_requested_at: Date | null;
  checked_at: Date | null;
  attempts: number;
  created_at: Date;
  updated_at: Date;
};

export type WatchedChannelStatus = {
  channelId: string;
  state: WatchState;
  detail: string | null;
  commitmentNumber: string | null;
  fundingOutPoint: string | null;
  closingTransaction: string | null;
  penaltyTransaction: string | null;
  checkedAt: string | null;
  updatedAt: string;
};

function publicStatus(row: Row): WatchedChannelStatus {
  return {
    channelId: row.channel_id,
    state: row.state,
    detail: row.detail,
    commitmentNumber: row.commitment_number === null ? null : `0x${BigInt(row.commitment_number).toString(16)}`,
    fundingOutPoint: row.funding_out_point,
    closingTransaction: row.closing_tx,
    penaltyTransaction: row.penalty_tx,
    checkedAt: row.checked_at?.toISOString() ?? null,
    updatedAt: row.updated_at.toISOString(),
  };
}

/** Handles one request from a signed-in user's browser node. Each user sees and changes only their own channels. */
export async function watchtowerRequest(user: User, request: WatchtowerRequest, sql?: DatabaseSql): Promise<unknown> {
  const db = sql ?? await database();
  if (request.operation === "status") {
    const rows = await db<Row[]>`select * from keyway_v2_watchtower_channels where user_id = ${user.id} order by created_at`;
    return { channels: rows.map(publicStatus) };
  }
  if (request.operation === "watch") {
    const fundingArgs = fundingLockArgs(request.localFundingPubkey, request.remoteFundingPubkey);
    const peerKey = peerCommitmentKey(request.localFundingPubkey, request.remoteFundingPubkey);
    const script = request.fundingUdtTypeScript ? { codeHash: request.fundingUdtTypeScript.codeHash, hashType: request.fundingUdtTypeScript.hashType, args: request.fundingUdtTypeScript.args } : null;
    return db.begin(async (tx) => {
      await tx`select pg_advisory_xact_lock(hashtextextended(${`watchtower:${user.id}`}, 0))`;
      const [existing] = await tx<Row[]>`select * from keyway_v2_watchtower_channels where user_id = ${user.id} and channel_id = ${request.channelId}`;
      if (existing) {
        // Fiber sends the keys once per channel; they never change. A different pair is a different channel.
        if (existing.local_funding_pubkey !== request.localFundingPubkey || existing.remote_funding_pubkey !== request.remoteFundingPubkey) {
          throw new Error("This channel is already watched with other funding keys");
        }
        return { channel: publicStatus(existing) };
      }
      const [{ count }] = await tx<Array<{ count: string }>>`
        select count(*) from keyway_v2_watchtower_channels where user_id = ${user.id} and state in ('watching', 'penalty-sent')
      `;
      if (Number(count) >= MAX_WATCHED_CHANNELS) throw new Error(`The watchtower already watches ${MAX_WATCHED_CHANNELS} open channels for this account`);
      const [row] = await tx<Row[]>`
        insert into keyway_v2_watchtower_channels (
          user_id, channel_id, local_funding_pubkey, remote_funding_pubkey, funding_lock_args, peer_commitment_key, funding_udt_type_script
        ) values (
          ${user.id}, ${request.channelId}, ${request.localFundingPubkey}, ${request.remoteFundingPubkey}, ${fundingArgs}, ${peerKey},
          ${script ? tx.json(script) : null}
        ) returning *
      `;
      return { channel: publicStatus(row) };
    });
  }
  if (request.operation === "revoke") {
    const { revocation } = request;
    return db.begin(async (tx) => {
      const [existing] = await tx<Row[]>`
        select * from keyway_v2_watchtower_channels where user_id = ${user.id} and channel_id = ${request.channelId} for update
      `;
      if (!existing) throw new Error("This channel is not watched; register it first");
      // A revocation for a token channel pays the token back; for a CKB channel it has no type script.
      const output = ccc.CellOutput.decode(revocation.output);
      const expectedType = existing.funding_udt_type_script;
      if ((output.type ? 1 : 0) !== (expectedType ? 1 : 0) || (output.type && expectedType && !output.type.eq(ccc.Script.from(expectedType as ccc.ScriptLike)))) {
        throw new Error("The revocation output does not match the channel's asset");
      }
      // Only the newest revocation is kept: the commitment lock accepts it for every older commitment too.
      if (existing.commitment_number !== null && BigInt(existing.commitment_number) >= revocation.commitmentNumber) {
        return { channel: publicStatus(existing), stored: false };
      }
      const [row] = await tx<Row[]>`
        update keyway_v2_watchtower_channels set
          commitment_number = ${revocation.commitmentNumber.toString()},
          aggregated_signature = ${revocation.aggregatedSignature},
          revocation_output = ${revocation.output},
          revocation_output_data = ${revocation.outputData},
          updated_at = now()
        where user_id = ${user.id} and channel_id = ${request.channelId}
        returning *
      `;
      return { channel: publicStatus(row), stored: true };
    });
  }
  // Fiber removes a channel when it closes. A revoked commitment can be what closed it, so the watchtower keeps
  // following the channel until it knows how it closed; only then is the record dropped (see the pass).
  const [row] = await db<Row[]>`
    update keyway_v2_watchtower_channels set unwatch_requested_at = coalesce(unwatch_requested_at, now()), updated_at = now()
    where user_id = ${user.id} and channel_id = ${request.channelId}
    returning *
  `;
  return { channel: row ? publicStatus(row) : null };
}

// ---------------------------------------------------------------------------------------------------------------
// Chain

const u64be = (value: bigint) => {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, value, false);
  return out;
};

/** The revocation witness: header ‖ 0x00 (revocation) ‖ commitment number (BE) ‖ x-only key ‖ signature (actor.rs `build_revocation_tx`). */
export function revocationWitness(revocation: Pick<Revocation, "commitmentNumber" | "aggregatedSignature">, peerKey: ccc.HexLike): ccc.Hex {
  return ccc.hexFrom(ccc.bytesConcat(
    XUDT_COMPATIBLE_WITNESS, new Uint8Array([0]), u64be(revocation.commitmentNumber), ccc.bytesFrom(peerKey), ccc.bytesFrom(revocation.aggregatedSignature),
  ));
}

/** The commitment lock args' parts: key hash, delay, commitment number (big-endian). */
export function commitmentArgs(args: ccc.HexLike) {
  const bytes = ccc.bytesFrom(args);
  if (bytes.length < 36) return undefined;
  return { keyHash: ccc.hexFrom(bytes.slice(0, 20)), commitmentNumber: new DataView(bytes.buffer, bytes.byteOffset + 28, 8).getBigUint64(0, false) };
}

/**
 * Checks the revocation's signature the way the commitment lock will (fiber-scripts commitment-lock `auth()`):
 * BIP340 Schnorr by the peer-commitment key over blake2b(output ‖ u32le(data length) ‖ data ‖ args[0..28] ‖ number).
 */
export function revocationSignatureValid(revocation: Revocation, peerKey: ccc.HexLike, commitmentLockArgs: ccc.HexLike): boolean {
  const args = ccc.bytesFrom(commitmentLockArgs);
  const data = ccc.bytesFrom(revocation.outputData);
  const length = new Uint8Array(4);
  new DataView(length.buffer).setUint32(0, data.length, true);
  const message = ccc.bytesFrom(ccc.hashCkb(ccc.bytesConcat(
    ccc.bytesFrom(revocation.output), length, data, args.slice(0, 28), u64be(revocation.commitmentNumber),
  )));
  try {
    return schnorr.verify(ccc.bytesFrom(revocation.aggregatedSignature), message, ccc.bytesFrom(peerKey));
  } catch {
    return false;
  }
}

/**
 * Builds the penalty transaction: the revoked commitment cell in, the revocation output out (the whole channel to
 * the user's shutdown script), plus the watchtower's own plain cells to pay the fee and their change. The
 * watchtower never takes anything from the channel: the revocation output must hold at least the commitment
 * cell's capacity, so the change can only come from the watchtower's own inputs.
 */
export async function buildPenaltyTransaction(options: {
  client: ccc.Client;
  commitment: { outPoint: ccc.OutPointLike; capacity: bigint };
  revocation: Revocation;
  peerKey: ccc.HexLike;
  feeSigner: ccc.Signer;
  cellDeps?: ccc.CellDepLike[];
}): Promise<ccc.Transaction> {
  const output = ccc.CellOutput.decode(options.revocation.output);
  // Fiber's revocation output is exactly the commitment cell (both are the channel minus the commitment fee). A
  // larger one would make the watchtower pay the difference; a smaller one would hand part of the channel to it.
  if (output.capacity !== options.commitment.capacity) throw new Error("The revocation output does not match the commitment cell");
  if (output.type) throw new Error("Token channels are not watched yet");
  const feeLock = (await options.feeSigner.getRecommendedAddressObj()).script;
  const tx = ccc.Transaction.from({
    cellDeps: options.cellDeps ?? await commitmentLockCellDeps(options.client, NETWORK),
    inputs: [{ previousOutput: options.commitment.outPoint, since: 0 }],
    outputs: [output, { capacity: 0, lock: feeLock }],
    outputsData: [options.revocation.outputData, "0x"],
    witnesses: [revocationWitness(options.revocation, options.peerKey)],
  });
  await tx.addCellDepsOfKnownScripts(options.client, ccc.KnownScript.Secp256k1Blake160);
  // Enough of the watchtower's own capacity for a change cell (61 CKB) and the fee, as Fiber's min_total_capacity.
  await tx.completeInputsByCapacity(options.feeSigner, CHANGE_RESERVE);
  await tx.completeFeeChangeToOutput(options.feeSigner, 1, FEE_RATE);
  for (const input of tx.inputs.slice(1)) {
    await input.completeExtraInfos(options.client);
    if (!input.cellOutput?.lock.eq(feeLock) || input.cellOutput.type || (input.outputData && input.outputData !== "0x")) throw new Error("The penalty fee must come from plain watchtower cells");
  }
  const feeIn = tx.inputs.slice(1).reduce((sum, input) => sum + input.cellOutput!.capacity, 0n);
  // Everything the watchtower put in comes back as change, less the fee: it neither takes from the channel nor pays
  // more than a fee.
  const spent = feeIn - tx.outputs[1].capacity;
  if (spent < 0n || spent > MAX_PENALTY_FEE) throw new Error("The penalty would move more than its fee between the channel and the watchtower");
  if (tx.outputs[1].capacity < ccc.fixedPointFrom(61)) throw new Error("The penalty change cell is too small");
  return options.feeSigner.signOnlyTransaction(tx);
}

export type ChainView = {
  /**
   * Reads the funding lock's history from where `scan` left it (see `RECENT_BUDGET_MS`): whether any output was
   * seen, the first spend found, and the scan's new position. Never throws: a failed read returns the progress made
   * before it, with the error.
   */
  fundingHistory(lock: ccc.Script, scan: HistoryScan, options?: { backlogBudgetMs?: number; recentScan?: boolean }): Promise<HistoryProgress>;
  transaction(hash: ccc.Hex): Promise<{ tx: ccc.Transaction; committed: boolean; status: string } | undefined>;
  isLive(outPoint: ccc.OutPoint): Promise<boolean>;
  spender(outPoint: ccc.OutPoint, lock: ccc.Script): Promise<ccc.Hex | undefined>;
};

/**
 * Where the two scans of a funding lock's history stand. `cursor` is the backlog scan's position (oldest first).
 * `recent` covers everything after block `from` (the newest block when the channel was first checked): entries up
 * to block `seenTo` have been read; a range in progress reads `(seenTo - REORG_DEPTH, top]` newest first from
 * `cursor`. Each range re-reads the last `REORG_DEPTH` blocks before `seenTo`, so a spend that a reorganization moved
 * into blocks already read is still found.
 */
export type HistoryScan = { cursor?: string; recent?: RecentScan };
export type RecentScan = { from: string; seenTo: string; top?: string; cursor?: string };

export function chainView(client: ccc.Client, options: { recentBudgetMs?: number; maxPages?: number; pageTimeoutMs?: number } = {}): ChainView {
  const recentBudget = options.recentBudgetMs ?? RECENT_BUDGET_MS;
  const key = (lock: ccc.Script) => ({ script: lock, scriptType: "lock" as const, scriptSearchMode: "exact" as const });
  const pageTimeout = options.pageTimeoutMs ?? PAGE_TIMEOUT_MS;
  // Every page request is bounded, so a slow indexer can't hold one channel's check (or another's share of the
  // catch-up time) for long: a page that times out is an error, and the scan resumes from its saved position.
  const page = async (lock: ccc.Script, order: "asc" | "desc", after?: string) => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        client.findTransactionsPaged(key(lock), order, HISTORY_PAGE_SIZE, after),
        new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error(`indexer page timed out after ${pageTimeout} ms`)), pageTimeout); }),
      ]);
    } finally {
      clearTimeout(timer);
    }
  };
  const spendOf = (item: { txHash: ccc.Hex; cellIndex: ccc.Num }) => ({ txHash: item.txHash, index: Number(item.cellIndex) });
  const message = (error: unknown) => (error instanceof Error ? error.message : String(error));
  return {
    async fundingHistory(lock, scan, { backlogBudgetMs = 0, recentScan = true } = {}) {
      let sawOutput = false;
      let recent = scan.recent ? { ...scan.recent } : undefined;
      let cursor = scan.cursor;
      const progress = (extra: Partial<HistoryProgress> = {}): HistoryProgress => ({
        sawOutput, ...(cursor ? { cursor } : {}), ...(recent ? { recent } : {}), backlog: false, ...extra,
      });

      // The backlog scan (run second): what was under the lock before the recent scan started, oldest first, from the saved
      // cursor. Nothing is skipped, so however long the padded history, every entry is read once.
      const backlog = async (): Promise<HistoryProgress> => {
        const started = Date.now();
        for (let pages = 0; pages < (options.maxPages ?? Infinity); pages++) {
          let result: Awaited<ReturnType<typeof page>>;
          try {
            result = await page(lock, "asc", cursor);
          } catch (error) {
            return progress({ error: message(error) });
          }
          for (const item of result.transactions) {
            // Past the start of the recent scan: that scan reads the rest.
            if (recent && BigInt(item.blockNumber) > BigInt(recent.from)) return progress();
            sawOutput = true;
            if (item.isInput) return progress({ spend: spendOf(item) });
          }
          if (result.transactions.length === 0) return progress();
          cursor = result.lastCursor;
          if (result.transactions.length < HISTORY_PAGE_SIZE) return progress();
          if (Date.now() - started >= backlogBudgetMs) break;
        }
        return progress({ backlog: true });
      };

      // A catch-up call skips the recent scan, which ran earlier in the same pass.
      if (!recentScan && recent) return backlog();
      // The recent scan (run first): every entry added since the channel was first checked, newest first.
      try {
        if (!recent) {
          // First check: the newest page marks where the recent scan starts; what is older is the backlog's.
          const newest = await page(lock, "desc");
          const spend = newest.transactions.find((item) => item.isInput);
          sawOutput ||= newest.transactions.length > 0;
          if (spend) return progress({ spend: spendOf(spend) });
          const top = newest.transactions[0]?.blockNumber;
          if (top !== undefined) recent = { from: String(top), seenTo: String(top) };
        } else {
          const started = Date.now();
          if (recent.cursor && recent.top !== undefined) {
            // A range is still being read: first read everything added above it (newest first), so a spend made
            // since isn't kept waiting behind the old range. These entries are read again by the next range.
            let after: string | undefined;
            reading: for (;;) {
              const result = await page(lock, "desc", after);
              for (const item of result.transactions) {
                if (BigInt(item.blockNumber) <= BigInt(recent.top) - REORG_DEPTH) break reading;
                if (item.isInput) return progress({ spend: spendOf(item) });
              }
              if (result.transactions.length < HISTORY_PAGE_SIZE || Date.now() - started >= recentBudget) break;
              after = result.lastCursor;
            }
          }
          for (;;) {
            const result = await page(lock, "desc", recent.cursor);
            let done = result.transactions.length < HISTORY_PAGE_SIZE;
            for (const item of result.transactions) {
              if (BigInt(item.blockNumber) <= BigInt(recent.seenTo) - REORG_DEPTH) {
                done = true;
                break;
              }
              recent.top ??= String(item.blockNumber);
              sawOutput = true;
              if (item.isInput) return progress({ spend: spendOf(item) });
            }
            if (done) {
              const top = recent.top !== undefined && BigInt(recent.top) > BigInt(recent.seenTo) ? recent.top : recent.seenTo;
              recent = { from: recent.from, seenTo: top };
              break;
            }
            recent.cursor = result.lastCursor;
            if (Date.now() - started >= recentBudget) break;
          }
        }
      } catch (error) {
        // The backlog scan still runs; the recent scan resumes from its saved position next pass.
        const failed = message(error);
        const rest = await backlog();
        return { ...rest, error: rest.error ?? failed };
      }
      return backlog();

    },
    async transaction(hash) {
      const response = await client.getTransaction(hash);
      return response ? { tx: response.transaction, committed: response.status === "committed", status: response.status } : undefined;
    },
    async isLive(outPoint) {
      return Boolean(await client.getCellLive(outPoint, false));
    },
    async spender(outPoint, lock) {
      for await (const item of client.findTransactions({ script: lock, scriptType: "lock", scriptSearchMode: "exact" }, "asc", 50)) {
        if (!item.isInput) continue;
        const tx = (await client.getTransaction(item.txHash))?.transaction;
        if (tx?.inputs.some((input) => input.previousOutput.eq(outPoint))) return item.txHash;
      }
      return undefined;
    },
  };
}

export type HistoryProgress = {
  sawOutput: boolean;
  spend?: { txHash: ccc.Hex; index: number };
  cursor?: string;
  recent?: RecentScan;
  /** The backlog scan stopped for its budget with more to read. */
  backlog?: boolean;
  error?: string;
};

/** What the scan of the funding lock's history has established so far, saved with the channel between passes. */
export type ScanState = Pick<Row, "history_cursor" | "recent_scan" | "funding_seen" | "funding_spend">;

export type Assessment = { scan: ScanState; backlog?: boolean } & (
  | { state: "watching"; detail: string }
  | { state: "closed"; detail: string; closingTx: ccc.Hex; fundingOutPoint: string }
  | { state: "revoked"; closingTx: ccc.Hex; fundingOutPoint: string; commitment: Commitment }
);

export type Commitment = { outPoint: ccc.OutPoint; capacity: bigint; lock: ccc.Script };

const parseRecentScan = (value: string | null | undefined): RecentScan | undefined => {
  try {
    return value ? (JSON.parse(value) as RecentScan) : undefined;
  } catch {
    return undefined;
  }
};

/**
 * Where a watched channel stands on-chain (the decision Fiber's `run_periodic_check` makes): still open, closed
 * by a transaction that needs nothing from the watchtower, or closed by a revoked commitment of the peer.
 */
export async function assessChannel(
  chain: ChainView,
  row: Pick<Row, "funding_lock_args" | "peer_commitment_key" | "commitment_number"> & Partial<ScanState>,
  /** Called with the scan's progress before anything else can fail, so a failing check never loses it. */
  saveScan?: (scan: ScanState) => Promise<unknown>,
  options: { backlogBudgetMs?: number; recentScan?: boolean } = {},
): Promise<Assessment> {
  const scan: ScanState = {
    history_cursor: row.history_cursor ?? null,
    recent_scan: row.recent_scan ?? null,
    funding_seen: row.funding_seen ?? false,
    funding_spend: row.funding_spend ?? null,
  };
  let backlog = false;
  if (!scan.funding_spend) {
    const fundingLock = ccc.Script.from({ ...FUNDING_LOCK, args: row.funding_lock_args });
    const recent = parseRecentScan(scan.recent_scan);
    const progress = await chain.fundingHistory(fundingLock, { ...(scan.history_cursor ? { cursor: scan.history_cursor } : {}), ...(recent ? { recent } : {}) }, options);
    scan.funding_seen ||= progress.sawOutput;
    scan.history_cursor = progress.cursor ?? scan.history_cursor;
    scan.recent_scan = progress.recent ? JSON.stringify(progress.recent) : scan.recent_scan;
    if (progress.spend) scan.funding_spend = `${progress.spend.txHash}:${progress.spend.index}`;
    backlog = Boolean(progress.backlog) && !scan.funding_spend;
    await saveScan?.(scan);
    if (progress.error && !scan.funding_spend) throw new Error(progress.error);
  }
  if (!scan.funding_spend) return { scan, backlog, state: "watching", detail: scan.funding_seen ? "open" : "funding not on-chain yet" };
  const [spendHash, spendIndex] = scan.funding_spend.split(":");
  const spent = { txHash: spendHash as ccc.Hex, index: Number(spendIndex) };
  const closing = await chain.transaction(spent.txHash);
  if (!closing || closing.status === "rejected" || closing.status === "unknown") {
    // Dropped (e.g. by a reorganization): forget it, and the recent scan, which re-reads the last blocks, finds
    // whatever spends the funding cell instead.
    scan.funding_spend = null;
    await saveScan?.(scan);
    return { scan, state: "watching", detail: "the closing transaction left the chain; looking again" };
  }
  if (!closing.committed) return { scan, state: "watching", detail: "closing transaction not committed yet" };
  // The funding cell is the one this 2-of-2 spend consumed; outputs under the lock can be anyone's.
  const consumed = closing.tx.inputs[spent.index]?.previousOutput;
  if (!consumed) throw new Error(`the closing transaction ${spent.txHash} has no input ${spent.index}`);
  const fundingOutPoint = `${consumed.txHash}:${Number(consumed.index)}`;
  const base = { scan, closingTx: spent.txHash, fundingOutPoint };
  const output = closing.tx.outputs[0];
  const commitment = COMMITMENT_LOCK[NETWORK];
  if (closing.tx.outputs.length !== 1 || output.lock.codeHash !== commitment.codeHash || output.lock.hashType !== "type") {
    return { ...base, state: "closed", detail: "closed cooperatively" };
  }
  const args = commitmentArgs(output.lock.args);
  if (!args) return { ...base, state: "closed", detail: "unexpected closing transaction" };
  if (args.keyHash !== ccc.hexFrom(blake160(row.peer_commitment_key))) {
    return { ...base, state: "closed", detail: "the user's node force-closed; the wallet claims the user's share when it next runs" };
  }
  if (row.commitment_number === null || BigInt(row.commitment_number) < args.commitmentNumber) {
    return { ...base, state: "closed", detail: "the peer force-closed with the current state; the wallet claims the user's share when it next runs" };
  }
  return {
    ...base,
    state: "revoked",
    commitment: { outPoint: ccc.OutPoint.from({ txHash: spent.txHash, index: 0 }), capacity: output.capacity, lock: output.lock },
  };
}

export type PassDependencies = {
  sql: DatabaseSql;
  chain: ChainView;
  /** Builds and sends the penalty; returns its hash. */
  punish(row: Row, commitment: Commitment): Promise<ccc.Hex>;
  log?: (message: string) => void;
  /** Channels checked at the same time (default `CHECK_CONCURRENCY`). */
  concurrency?: number;
  /** Time shared by the channels still catching up on a backlog, per pass (default `CATCH_UP_BUDGET_MS`). */
  catchUpBudgetMs?: number;
  /** Channels never seen funded checked per pass (default `UNFUNDED_PER_PASS`). */
  unfundedPerPass?: number;
};

/**
 * One pass over every channel still being watched. Every channel is checked first (its recent history, one page of
 * its backlog, and a penalty if it needs one), several at a time; then the channels still catching up on a backlog
 * share the rest of the pass's catch-up budget. A channel's backlog never delays another channel's check.
 */
export async function runWatchtowerPass(deps: PassDependencies): Promise<void> {
  const { sql } = deps;
  const log = deps.log ?? ((message: string) => console.info(`[watchtower] ${message}`));
  await sql`
    delete from keyway_v2_watchtower_channels
    where state in ('penalized', 'closed', 'missed', 'invalid') and updated_at < now() - ${`${FINISHED_RETENTION_DAYS} days`}::interval
      -- A close or penalty is kept until it is confirmed, however long the watchtower was down.
      and (resolution_confirmed or state in ('missed', 'invalid'))
  `;
  // Channels whose funding is on-chain are all checked, every pass, first. Ones never seen funded can't have been
  // closed yet; at most UNFUNDED_PER_PASS of them are checked per pass, so registrations can't slow down the funded
  // channels' checks.
  const funded = await sql<Row[]>`
    select * from keyway_v2_watchtower_channels where state in ('watching', 'penalty-sent') and (funding_seen or funding_spend is not null)
    order by checked_at asc nulls first
  `;
  // Taken from each account in turn (every account's least recently checked first), so one account's
  // registrations only delay its own channels.
  const unfunded = await sql<Row[]>`
    select * from (
      select *, row_number() over (partition by user_id order by checked_at asc nulls first, created_at asc) as turn
      from keyway_v2_watchtower_channels
      where state in ('watching', 'penalty-sent') and not funding_seen and funding_spend is null
    ) waiting
    order by turn, checked_at asc nulls first, created_at asc
    limit ${deps.unfundedPerPass ?? UNFUNDED_PER_PASS}
  `;
  // Closes and penalties are confirmed again every pass until a check made REORG_RECHECK_MINUTES after them still
  // finds them on-chain: a reorganization can drop them, and a watchtower that was down meanwhile still checks.
  const recent = await sql<Row[]>`
    select * from keyway_v2_watchtower_channels where state in ('closed', 'penalized') and not resolution_confirmed
  `;
  const rows = [...funded, ...unfunded];
  // Penalties are sent one at a time, so two never pick the same fee cells.
  let sending: Promise<unknown> = Promise.resolve();
  const punish: PassDependencies["punish"] = (row, commitment) => {
    const sent = sending.then(() => deps.punish(row, commitment));
    sending = sent.catch(() => undefined);
    return sent;
  };
  const check = async (row: Row, backlogBudgetMs: number) => {
    try {
      return await checkChannel({ ...deps, punish }, row, log, backlogBudgetMs);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      log(`${row.channel_id}: check failed: ${message}`);
      // Shown in the user's status, so a channel the watchtower can't currently check isn't reported as fine.
      const detail = `check failed: ${message.replace(/\s+/g, " ").slice(0, 200)}`;
      await sql`update keyway_v2_watchtower_channels set checked_at = now(), detail = ${detail} where user_id = ${row.user_id} and channel_id = ${row.channel_id}`;
      return false;
    }
  };

  const behind: Row[] = [];
  const queue = [...rows];
  await Promise.all(Array.from({ length: Math.min(deps.concurrency ?? CHECK_CONCURRENCY, queue.length) }, async () => {
    for (let row = queue.shift(); row; row = queue.shift()) if (await check(row, 0)) behind.push(row);
  }));
  for (const row of recent) {
    try {
      await confirmResolution(deps, row, log);
    } catch (error) {
      log(`${row.channel_id}: could not confirm the ${row.state} state: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  // Catching up: each channel gets an equal share of what is left of the budget, so one long backlog can't take it.
  const deadline = Date.now() + (deps.catchUpBudgetMs ?? CATCH_UP_BUDGET_MS);
  for (let i = 0; i < behind.length; i++) {
    const share = (deadline - Date.now()) / (behind.length - i);
    if (share <= 0) break;
    const [row] = await sql<Row[]>`
      select * from keyway_v2_watchtower_channels
      where user_id = ${behind[i].user_id} and channel_id = ${behind[i].channel_id} and state in ('watching', 'penalty-sent')
    `;
    if (row) await check(row, share);
  }
}

/** Checks one channel and acts on what it finds; says whether its backlog scan has more to read. */
/** Puts a recently resolved channel back under watch if the transaction that resolved it left the chain. */
async function confirmResolution(deps: PassDependencies, row: Row, log: (message: string) => void) {
  const hash = row.state === "penalized" ? row.penalty_tx : row.closing_tx;
  if (!hash) return;
  const found = await deps.chain.transaction(hash as ccc.Hex);
  if (found?.committed) {
    // Final once it has stayed on-chain through the window.
    await deps.sql`
      update keyway_v2_watchtower_channels set resolution_confirmed = true
      where user_id = ${row.user_id} and channel_id = ${row.channel_id} and state = ${row.state}
        and updated_at < now() - ${`${REORG_RECHECK_MINUTES} minutes`}::interval
    `;
    return;
  }
  if (row.state === "penalized") {
    // The revoked commitment is checked again next pass, and the penalty sent again if it is gone.
    log(`${row.channel_id}: the penalty ${hash} left the chain; checking the commitment again`);
    await deps.sql`
      update keyway_v2_watchtower_channels set state = 'penalty-sent', detail = 'the penalty left the chain; checking again', updated_at = now()
      where user_id = ${row.user_id} and channel_id = ${row.channel_id} and state = 'penalized'
    `;
    return;
  }
  log(`${row.channel_id}: the closing transaction ${hash} left the chain; watching again`);
  await deps.sql`
    update keyway_v2_watchtower_channels set
      state = 'watching', detail = 'the close left the chain; watching again', funding_spend = null, closing_tx = null, funding_out_point = null, updated_at = now()
    where user_id = ${row.user_id} and channel_id = ${row.channel_id} and state = 'closed'
  `;
}

async function checkChannel(deps: PassDependencies, row: Row, log: (message: string) => void, backlogBudgetMs: number): Promise<boolean> {
  const { sql, chain } = deps;
  const save = (fields: Partial<Pick<Row, "state" | "detail" | "funding_out_point" | "closing_tx" | "penalty_tx">>) => sql`
    update keyway_v2_watchtower_channels set
      state = ${fields.state ?? row.state},
      detail = ${fields.detail ?? row.detail},
      funding_out_point = ${fields.funding_out_point ?? row.funding_out_point},
      closing_tx = ${fields.closing_tx ?? row.closing_tx},
      penalty_tx = ${fields.penalty_tx ?? row.penalty_tx},
      checked_at = now(),
      updated_at = case when ${fields.state ?? row.state} <> state or ${fields.detail ?? row.detail}::text is distinct from detail then now() else updated_at end
    where user_id = ${row.user_id} and channel_id = ${row.channel_id}
  `;
  // The scan's progress is saved as soon as it is known, so a check that fails afterwards (or partway through
  // the history) resumes where it got to instead of starting over.
  const assessment = await assessChannel(chain, row, async (scan) => {
    if (scan.history_cursor === row.history_cursor && scan.recent_scan === row.recent_scan && scan.funding_seen === row.funding_seen && scan.funding_spend === row.funding_spend) return;
    await sql`
      update keyway_v2_watchtower_channels set
        history_cursor = ${scan.history_cursor}, recent_scan = ${scan.recent_scan}, funding_seen = ${scan.funding_seen}, funding_spend = ${scan.funding_spend}
      where user_id = ${row.user_id} and channel_id = ${row.channel_id}
    `;
  }, { backlogBudgetMs, recentScan: backlogBudgetMs === 0 });
  const { scan } = assessment;
  if (assessment.state === "watching") {
    const age = Date.now() - row.created_at.getTime();
    if (!scan.funding_seen && (row.unwatch_requested_at || age > UNFUNDED_RETENTION_DAYS * 86_400_000)) {
      await sql`delete from keyway_v2_watchtower_channels where user_id = ${row.user_id} and channel_id = ${row.channel_id}`;
      log(`${row.channel_id}: never funded; dropped`);
      return false;
    }
    if (row.detail !== assessment.detail) log(`${row.channel_id}: ${assessment.detail}`);
    await save({ detail: assessment.detail });
    return Boolean(assessment.backlog);
  }
  if (assessment.state === "closed") {
    log(`${row.channel_id}: ${assessment.detail} (${assessment.closingTx})`);
    await save({ state: "closed", detail: assessment.detail, closing_tx: assessment.closingTx, funding_out_point: assessment.fundingOutPoint });
    return false;
  }
  // The peer published a revoked commitment.
  const { commitment } = assessment;
  if (row.penalty_tx) {
    const sent = await chain.transaction(row.penalty_tx as ccc.Hex);
    if (sent?.committed) {
      log(`${row.channel_id}: penalty committed (${row.penalty_tx})`);
      await save({ state: "penalized", detail: "the peer published a revoked commitment; the penalty sent the whole channel to the user", closing_tx: assessment.closingTx });
      return false;
    }
    if (sent && sent.status !== "rejected" && sent.status !== "unknown") {
      await save({ detail: `penalty ${sent.status}` });
      return false;
    }
  }
  if (!(await chain.isLive(commitment.outPoint))) {
    const by = await chain.spender(commitment.outPoint, commitment.lock);
    log(`${row.channel_id}: revoked commitment already spent by ${by ?? "an unknown transaction"}`);
    await save({ state: "missed", detail: "the revoked commitment was spent before the penalty", closing_tx: assessment.closingTx });
    return false;
  }
  const revocation = storedRevocation(row);
  if (!revocation || !revocationSignatureValid(revocation, row.peer_commitment_key, commitment.lock.args)) {
    // The lock would reject it: never spend on it, never retry it.
    log(`${row.channel_id}: the revoked commitment ${assessment.closingTx} can't be punished with the stored revocation (bad signature)`);
    await save({ state: "invalid", detail: "the stored revocation does not unlock this commitment", closing_tx: assessment.closingTx });
    return false;
  }
  if (row.attempts > 0 && row.checked_at && Date.now() - row.checked_at.getTime() < Math.min(MAX_RETRY_MS, 60_000 * 2 ** (row.attempts - 1))) return false;
  log(`${row.channel_id}: the peer published revoked commitment ${assessment.closingTx}; sending the penalty`);
  let hash: ccc.Hex;
  try {
    hash = await deps.punish(row, commitment);
  } catch (error) {
    await sql`update keyway_v2_watchtower_channels set attempts = attempts + 1, checked_at = now() where user_id = ${row.user_id} and channel_id = ${row.channel_id}`;
    throw error;
  }
  log(`${row.channel_id}: penalty sent ${hash}`);
  await sql`update keyway_v2_watchtower_channels set attempts = attempts + 1 where user_id = ${row.user_id} and channel_id = ${row.channel_id}`;
  await save({ state: "penalty-sent", detail: "penalty sent", penalty_tx: hash, closing_tx: assessment.closingTx, funding_out_point: assessment.fundingOutPoint });
  return false;
}

function storedRevocation(row: Row): Revocation | undefined {
  if (row.commitment_number === null || !row.aggregated_signature || !row.revocation_output || row.revocation_output_data === null) return undefined;
  return {
    commitmentNumber: BigInt(row.commitment_number),
    aggregatedSignature: row.aggregated_signature as ccc.Hex,
    output: row.revocation_output as ccc.Hex,
    outputData: row.revocation_output_data as ccc.Hex,
  };
}

/** The penalty, built from a stored row and sent with the watchtower's fee key. */
export function penaltySender(client: ccc.Client, feeSigner: ccc.Signer) {
  return async (row: Row, commitment: Commitment) => {
    const revocation = storedRevocation(row);
    if (!revocation) throw new Error("No revocation data");
    const tx = await buildPenaltyTransaction({ client, commitment, revocation, peerKey: row.peer_commitment_key, feeSigner });
    return client.sendTransaction(tx);
  };
}

/**
 * Runs the watchtower inside this process when `KEYWAY_WATCHTOWER_FEE_KEY` is set: a pass starts every 60 s (as
 * Fiber's own watchtower; a pass that runs longer is followed at once by the next), by whichever API instance holds the watchtower's advisory lock, so replicas never race.
 * Returns a function that stops it.
 */
export function startWatchtower(env: NodeJS.ProcessEnv = process.env): () => Promise<void> {
  const feeKey = env.KEYWAY_WATCHTOWER_FEE_KEY;
  if (!feeKey) {
    console.warn("[watchtower] KEYWAY_WATCHTOWER_FEE_KEY is not set; the browser-node watchtower is not running in this process");
    return async () => undefined;
  }
  if (!/^0x[0-9a-fA-F]{64}$/.test(feeKey)) throw new Error("KEYWAY_WATCHTOWER_FEE_KEY must be a 0x-prefixed 32-byte key");
  const client = env.KEYWAY_WATCHTOWER_CKB_RPC_URL ? new ccc.ClientPublicTestnet({ url: env.KEYWAY_WATCHTOWER_CKB_RPC_URL }) : new ccc.ClientPublicTestnet();
  const feeSigner = new ccc.SignerCkbPrivateKey(client, feeKey);
  const seconds = Number(env.KEYWAY_WATCHTOWER_INTERVAL_SECONDS ?? 60);
  const interval = (Number.isFinite(seconds) && seconds >= 5 ? seconds : 60) * 1000;
  let stopped = false;
  let running: Promise<void> | undefined;
  let lock: Awaited<ReturnType<DatabaseSql["reserve"]>> | undefined;
  const tick = async () => {
    const sql = await database();
    const connection = lock ?? await sql.reserve();
    let locked = false;
    try {
      // Asked every pass (it is re-entrant for the holder), so a connection that was lost and replaced can't keep
      // running while another instance has taken the lock.
      [{ locked }] = await connection<Array<{ locked: boolean }>>`select pg_try_advisory_lock(hashtext('keyway-watchtower')) as locked`;
    } finally {
      if (!locked) {
        connection.release();
        if (lock === connection) lock = undefined;
      }
    }
    if (!locked) return;
    if (!lock) console.info(`[watchtower] running; fee address ${await feeSigner.getRecommendedAddress()}`);
    lock = connection;
    await runWatchtowerPass({ sql, chain: chainView(client), punish: penaltySender(client, feeSigner) });
  };
  const loop = () => {
    if (stopped) return;
    const started = Date.now();
    running = tick().catch((error) => {
      console.error("[watchtower] pass failed", error instanceof Error ? error.message : error);
      // Give the lock up (a broken connection has lost it anyway) and take it again next time.
      const held = lock;
      lock = undefined;
      if (held) return held`select pg_advisory_unlock_all()`.then(() => undefined, () => undefined).finally(() => held.release());
    }).finally(() => {
      running = undefined;
      // Passes start on a fixed cadence, not a fixed gap after the last one ended.
      if (!stopped) timer = setTimeout(loop, Math.max(1000, interval - (Date.now() - started)));
    });
  };
  let timer: ReturnType<typeof setTimeout> | undefined = setTimeout(loop, 1000);
  return async () => {
    stopped = true;
    if (timer) clearTimeout(timer);
    await running;
    if (lock) {
      await lock`select pg_advisory_unlock_all()`.catch(() => undefined);
      lock.release();
      lock = undefined;
    }
  };
}
