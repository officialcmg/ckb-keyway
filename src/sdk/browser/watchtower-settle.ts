import * as ccc from "@ckb-ccc/core";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import type { SettlementDataJson, SettlementTlcJson, WatchedChannel } from "./watchtower-store";

/**
 * Claims the user's share of a force-closed channel from its commitment cell, and the payments (TLCs) still in
 * flight that are the user's, the way Fiber 0.9.1's watchtower does (fiber-lib watchtower/actor.rs
 * `build_settlement_tx`, channel.rs `settlement_data_to_witness`; fiber-scripts commitment-lock). Fiber's browser
 * build has no watchtower (see watchtower-bridge.ts), so the page does this with the data the node handed it,
 * including the payment preimages. As in Fiber, the claim pays to the node's own CKB key (the settlement key),
 * which also pays the fee from its reserve cell; the settlement sweep then moves it to the user.
 */

/** Fiber's commitment lock and the cells its code needs, per network (Fiber 0.9.1's config/<network>/config.yml). */
export const COMMITMENT_LOCK = {
  testnet: {
    codeHash: "0x740dee83f87c6f309824d8fd3fbdd3c8380ee6fc9acc90b1a748438afcdf81d8",
    typeIdArgs: "0xf7e458887495cf70dd30d1543cad47dc1dfe9d874177bf19291e4db478d5751b",
    ckbAuth: { txHash: "0x12c569a258dd9c5bd99f632bb8314b1263b90921ba31496467580d6b79dd14a7", index: 0 },
  },
  mainnet: {
    codeHash: "0x2d45c4d3ed3e942f1945386ee82a5d1b7e4bb16d7fe1ab015421174ab747406c",
    typeIdArgs: "0xdb16e6dcb17f670e5fb7c556d81e522ec5edb069ad2fa3e898e7ccea6c26a39f",
    ckbAuth: { txHash: "0x95006eee7b4c0c8ad66e0514c88ed0ae43fc8db27793427de86a348ec720b9d6", index: 0 },
  },
} as const;

const TYPE_ID_CODE_HASH = "0x00000000000000000000000000000000000000000000000000545950455f4944";
/** WitnessArgs-compatible header Fiber puts in front of commitment witnesses (XUDT_COMPATIBLE_WITNESS). */
export const XUDT_COMPATIBLE_WITNESS = new Uint8Array([16, 0, 0, 0, 16, 0, 0, 0, 16, 0, 0, 0, 16, 0, 0, 0]);
const UNLOCK_REMOTE_SLOT = 0xfe;
const UNLOCK_LOCAL_SLOT = 0xff;
const ZERO20 = new Uint8Array(20);

export const blake160 = (data: ccc.BytesLike): Uint8Array => ccc.bytesFrom(ccc.hashCkb(data)).slice(0, 20);
const u128le = (value: bigint) => { const out = new Uint8Array(16); let v = value; for (let i = 0; i < 16; i++) { out[i] = Number(v & 0xffn); v >>= 8n; } return out; };
const u64le = (value: bigint) => u128le(value).slice(0, 8);
const readLe = (bytes: Uint8Array) => bytes.reduceRight((acc, byte) => (acc << 8n) | BigInt(byte), 0n);
const equal = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((byte, i) => byte === b[i]);
const concat = (...parts: Uint8Array[]) => ccc.bytesConcat(...parts);
const pubkeyOf = (privateKey: ccc.HexLike) => secp256k1.getPublicKey(ccc.bytesFrom(privateKey), true);

/** The commitment lock's args: aggregated key hash, delay (since), commitment number, settlement witness hash. */
export function parseCommitmentArgs(args: ccc.HexLike) {
  const bytes = ccc.bytesFrom(args);
  if (bytes.length < 56) throw new Error("Not a commitment lock");
  return {
    prefix: bytes.slice(0, 36),
    delaySince: readLe(bytes.slice(20, 28)),
    commitmentNumber: bytes.slice(28, 36).reduce((acc, byte) => (acc << 8n) | BigInt(byte), 0n),
    witnessHash: bytes.slice(36, 56),
  };
}

const HASH_ALGORITHMS: Record<string, number> = { CkbHash: 0, ckb_hash: 0, Sha256: 1, sha256: 1 };

/** Fiber's settlement witness for a commitment (channel.rs `settlement_data_to_witness`). */
export function encodeSettlementWitness(data: SettlementDataJson, forRemote: boolean, localSettlementKey: ccc.HexLike, remoteSettlementKey: ccc.HexLike): Uint8Array {
  const localHash = blake160(pubkeyOf(localSettlementKey));
  const remoteHash = blake160(remoteSettlementKey);
  const tlcs = data.tlcs.map((tlc) => {
    const offered = "Offered" in tlc.tlc_id;
    const algorithm = HASH_ALGORITHMS[tlc.hash_algorithm];
    if (algorithm === undefined) throw new Error(`Unknown hash algorithm ${tlc.hash_algorithm}`);
    const local = blake160(pubkeyOf(ccc.hexFrom(`0x${tlc.local_key.replace(/^0x/, "")}`)));
    const remote = blake160(ccc.hexFrom(`0x${tlc.remote_key.replace(/^0x/, "")}`));
    const expirySeconds = BigInt(tlc.expiry) / 1000n;
    return concat(
      new Uint8Array([(algorithm << 1) + (offered ? 0 : 1)]),
      u128le(BigInt(tlc.payment_amount)),
      ccc.bytesFrom(tlc.payment_hash).slice(0, 20),
      forRemote ? remote : local,
      forRemote ? local : remote,
      u64le((0b0100_0000n << 56n) | expirySeconds),
    );
  });
  if (tlcs.length > 255) throw new Error("Too many TLCs");
  const local = concat(localHash, u128le(BigInt(data.local_amount)));
  const remote = concat(remoteHash, u128le(BigInt(data.remote_amount)));
  return concat(new Uint8Array([tlcs.length]), ...tlcs, ...(forRemote ? [remote, local] : [local, remote]));
}

/** A settlement witness as the commitment lock reads it: pending TLCs, then two (pubkey hash, amount) slots. */
export type SettlementWitness = {
  pendingTlcs: Uint8Array[];
  /** The first slot ("remote" in Fiber's watchtower): emptied by unlock type 0xFE. */
  first: { pubkeyHash: Uint8Array; amount: bigint };
  /** The second slot ("local" in Fiber's watchtower): emptied by unlock type 0xFF. */
  second: { pubkeyHash: Uint8Array; amount: bigint };
  unlocks: Array<{ type: number; withPreimage: boolean }>;
};

/** Reads a settlement witness (without the 16-byte header; with the leading unlock count when `withUnlockCount`). */
export function parseSettlementWitness(bytes: Uint8Array, withUnlockCount = true): SettlementWitness | undefined {
  let offset = withUnlockCount ? 1 : 0;
  const take = (length: number) => {
    if (offset + length > bytes.length) throw new Error("short");
    const value = bytes.slice(offset, offset + length);
    offset += length;
    return value;
  };
  try {
    const count = take(1)[0];
    const pendingTlcs = Array.from({ length: count }, () => take(85));
    const first = { pubkeyHash: take(20), amount: readLe(take(16)) };
    const second = { pubkeyHash: take(20), amount: readLe(take(16)) };
    const unlocks: SettlementWitness["unlocks"] = [];
    while (offset < bytes.length) {
      const [type, preimage] = take(2);
      take(65);
      if (preimage === 1) take(32);
      unlocks.push({ type, withPreimage: preimage === 1 });
    }
    return { pendingTlcs, first, second, unlocks };
  } catch {
    return undefined;
  }
}

/** Applies a witness's unlocks, giving the settlement state of the cell its transaction created (Fiber's `update`). */
export function applyUnlocks(witness: SettlementWitness): SettlementWitness | undefined {
  const next: SettlementWitness = { ...witness, first: { ...witness.first }, second: { ...witness.second }, unlocks: [] };
  const settled = new Set<number>();
  for (const unlock of witness.unlocks) {
    if (unlock.type === UNLOCK_LOCAL_SLOT) next.second = { pubkeyHash: ZERO20, amount: 0n };
    else if (unlock.type === UNLOCK_REMOTE_SLOT) next.first = { pubkeyHash: ZERO20, amount: 0n };
    else if (unlock.type < witness.pendingTlcs.length) settled.add(unlock.type);
    else return undefined;
  }
  next.pendingTlcs = witness.pendingTlcs.filter((_, index) => !settled.has(index));
  return next;
}

export function encodeWitnessState(witness: SettlementWitness): Uint8Array {
  return concat(
    new Uint8Array([witness.pendingTlcs.length]), ...witness.pendingTlcs,
    witness.first.pubkeyHash, u128le(witness.first.amount), witness.second.pubkeyHash, u128le(witness.second.amount),
  );
}

export type ClaimPlan = {
  /** The settlement witness the claim puts on-chain (Fiber's `new_settlement_witness`). */
  witnessState: Uint8Array;
  unlockType: number;
  /** The payment preimage that unlocks a received TLC, for a preimage claim. */
  preimage?: ccc.Hex;
  /** The key the commitment lock checks for this unlock: the settlement key, or the TLC's own key. */
  signingKey: ccc.Hex;
  /** Capacity left in a successor commitment cell for the peer, or undefined when the claim empties the cell. */
  successor?: { capacity: bigint; args: ccc.Hex };
  /** The input `since`: the delay this unlock waits for on the first settlement, else 0. */
  since: bigint;
  /** For a TLC claimed after its expiry: the absolute timestamp `since` the fee inputs carry (the TLC's expiry). */
  feeSince?: bigint;
};
export type ClaimDecision = { claim: ClaimPlan } | { skip: string };

/** One of the commitment's pending TLCs, as far as this node can claim it. */
type PendingTlc = {
  index: number;
  amount: bigint;
  /** The TLC's expiry as an absolute timestamp `since`, and in milliseconds. */
  expirySince: bigint;
  expiryMs: number;
  /** How this node can claim it, with which key: with the preimage (before the peer reclaims it) or once expired. */
  ours?: { path: "preimage" | "expiry"; key: ccc.Hex; paymentHash: ccc.Hex; hashAlgorithm: string };
};

const RELATIVE_EPOCH = 0xa0n << 56n;
const EPOCH_MASK = 0x00ff_ffff_ffff_ffffn;

/**
 * `delay` (a relative epoch `since`) times n/d, normalized exactly as the commitment lock does (its `mul`), so an
 * input `since` set to it is what the lock requires: 1/3 of the delay for a preimage claim, 2/3 for an expiry claim.
 */
export function delayFraction(delay: bigint, numerator: bigint, denominator: bigint): bigint {
  const value = delay & EPOCH_MASK;
  const number = value & 0xff_ffffn;
  const index = (value >> 24n) & 0xffffn;
  const length = (value >> 40n) & 0xffffn;
  if (length === 0n) throw new Error("Invalid commitment delay");
  const fullNumerator = numerator * (number * length + index);
  const newDenominator = denominator * length;
  const scale = newDenominator > 1800n ? newDenominator / 1800n + 1n : 1n;
  return RELATIVE_EPOCH | (fullNumerator / newDenominator) | (((fullNumerator % newDenominator) / scale) << 24n) | ((newDenominator / scale) << 40n);
}

/** Whether a relative epoch `since` has passed for a cell created in epoch `created`, at epoch `tip`. */
export function epochDelayPassed(created: ccc.EpochLike, since: bigint, tip: ccc.EpochLike): boolean {
  const value = since & EPOCH_MASK;
  const rational = (like: ccc.EpochLike) => {
    const e = ccc.Epoch.from(like);
    return e.denominator === 0n ? [e.integer, 1n] as const : [e.integer * e.denominator + e.numerator, e.denominator] as const;
  };
  const [a, b] = rational(created);
  const [c, d] = rational([value & 0xff_ffffn, (value >> 24n) & 0xffffn, (value >> 40n) & 0xffffn]);
  const [t, u] = rational(tip);
  // created + delay <= tip, compared as fractions
  return (a * d + c * b) * u <= t * b * d;
}

/** A preimage's payment hash, by the TLC's hash algorithm. */
function paymentHashOf(preimage: ccc.HexLike, algorithm: string): ccc.Hex {
  return HASH_ALGORITHMS[algorithm] === 1 ? ccc.hexFrom(sha256(ccc.bytesFrom(preimage))) : ccc.hashCkb(preimage);
}

/**
 * Matches each pending TLC in a settlement witness with the node's settlement data, which holds the TLC's own
 * private key: a TLC is the node's to claim on one path only, the one whose pubkey hash slot is the node's key.
 * The commitment lock checks: an offered TLC with the preimage by the first slot, after expiry by the second; a
 * received TLC with the preimage by the second slot, after expiry by the first (fiber-scripts commitment-lock).
 */
function pendingTlcs(channel: ClaimChannel, state: SettlementWitness): PendingTlc[] {
  const known: Array<{ bytes: Uint8Array; tlc: SettlementTlcJson }> = [];
  for (const [data, forRemote] of [[channel.localSettlement, false], [channel.remoteSettlement, true], [channel.pendingRemoteSettlement, true]] as const) {
    for (const tlc of data?.tlcs ?? []) {
      try {
        known.push({ bytes: encodeSettlementWitness({ local_amount: "0x0", remote_amount: "0x0", tlcs: [tlc] }, forRemote, channel.localSettlementKey, channel.remoteSettlementKey).slice(1, 86), tlc });
      } catch {
        // A TLC the node can't encode is never matched.
      }
    }
  }
  return state.pendingTlcs.map((bytes, index) => {
    const expirySince = readLe(bytes.slice(77, 85));
    const pending: PendingTlc = { index, amount: readLe(bytes.slice(1, 17)), expirySince, expiryMs: Number(expirySince & 0x00ff_ffff_ffff_ffffn) * 1000 };
    const match = known.find((item) => equal(item.bytes, bytes));
    if (!match) return pending;
    const key = ccc.hexFrom(`0x${match.tlc.local_key.replace(/^0x/, "")}`);
    const mine = blake160(pubkeyOf(key));
    const offered = (bytes[0] & 1) === 0;
    const [first, second] = [bytes.slice(37, 57), bytes.slice(57, 77)];
    const preimageSlot = offered ? first : second;
    const expirySlot = offered ? second : first;
    const path = equal(preimageSlot, mine) ? "preimage" : equal(expirySlot, mine) ? "expiry" : undefined;
    if (path) pending.ours = { path, key, paymentHash: ccc.hexFrom(match.tlc.payment_hash), hashAlgorithm: match.tlc.hash_algorithm };
    return pending;
  });
}

type ClaimChannel = Pick<WatchedChannel, "localSettlementKey" | "remoteSettlementKey" | "localSettlement" | "remoteSettlement" | "pendingRemoteSettlement">;

/**
 * Decides the next claim from a live commitment cell, as Fiber 0.9.1's watchtower does (`build_settlement_tx`), one
 * unlock per transaction. `previousWitness` is the settlement witness that created the cell (undefined for the
 * commitment transaction's own output, i.e. the first settlement).
 *
 * Pending TLCs come first, the most urgent first: one the node can unlock with a payment preimage it holds (the
 * peer can take it back once it expires), soonest expiry first, then one that has expired and is the node's to take
 * back. Then the user's own share, only once no TLC may still become the user's (the party that settles second can
 * take the whole cell): first to settle, it leaves a successor for the peer; second, it empties the cell, as Fiber's
 * watchtower does. On the first settlement each
 * unlock also waits for its share of the commitment's delay (`delayPassed`, given the input `since` it needs).
 */
export function planClaim(options: {
  channel: ClaimChannel;
  cell: { capacity: bigint; args: ccc.HexLike };
  previousWitness?: Uint8Array;
  /** Preimages the node handed the watchtower, by full payment hash. */
  preimages?: ReadonlyMap<string, string>;
  now?: number;
  delayPassed?: (since: bigint) => boolean;
}): ClaimDecision {
  const { channel, cell } = options;
  const now = options.now ?? Date.now();
  const delayPassed = options.delayPassed ?? (() => true);
  const args = parseCommitmentArgs(cell.args);
  const ours = blake160(pubkeyOf(channel.localSettlementKey));
  let state: SettlementWitness | undefined;
  const first = !options.previousWitness;
  if (first) {
    // Which commitment is on-chain: ours (local data) or the peer's (its acknowledged or pending data).
    const candidates: Array<[SettlementDataJson | undefined, boolean]> = [
      [channel.localSettlement, false], [channel.remoteSettlement, true], [channel.pendingRemoteSettlement, true],
    ];
    for (const [data, forRemote] of candidates) {
      if (!data) continue;
      const encoded = encodeSettlementWitness(data, forRemote, channel.localSettlementKey, channel.remoteSettlementKey);
      if (equal(blake160(encoded), args.witnessHash)) { state = parseSettlementWitness(encoded, false); break; }
    }
    if (!state) return { skip: "the on-chain commitment matches none of the node's settlement data (an old commitment needs revocation, which this does not do)" };
  } else {
    const parsed = parseSettlementWitness(options.previousWitness!);
    state = parsed && applyUnlocks(parsed);
    if (!state) return { skip: "could not read the previous settlement witness" };
  }
  const current = state;
  const occupied = (successorArgs: ccc.Hex) => ccc.fixedPointFrom(8 + 32 + 1 + ccc.bytesFrom(successorArgs).length);
  const successorFor = (unlockType: number) => {
    const after = applyUnlocks({ ...current, unlocks: [{ type: unlockType, withPreimage: false }] })!;
    return { after, args: ccc.hexFrom(concat(args.prefix, blake160(encodeWitnessState(after)), new Uint8Array([1]))) };
  };

  // Pending TLCs, most urgent first.
  const tlcs = pendingTlcs(channel, current);
  const preimageOf = (tlc: PendingTlc) => {
    if (tlc.ours?.path !== "preimage") return undefined;
    const preimage = options.preimages?.get(tlc.ours.paymentHash.toLowerCase());
    // Only a preimage that hashes to the TLC's full payment hash (the lock checks the first 20 bytes).
    return preimage && paymentHashOf(preimage, tlc.ours.hashAlgorithm) === tlc.ours.paymentHash.toLowerCase() ? ccc.hexFrom(preimage) : undefined;
  };
  const preimageSince = first ? delayFraction(args.delaySince, 1n, 3n) : 0n;
  const expirySince = first ? delayFraction(args.delaySince, 2n, 3n) : 0n;
  const claimable = [
    ...tlcs.filter((tlc) => preimageOf(tlc) && delayPassed(preimageSince)).sort((a, b) => a.expiryMs - b.expiryMs),
    ...tlcs.filter((tlc) => tlc.ours?.path === "expiry" && now > tlc.expiryMs && delayPassed(expirySince)).sort((a, b) => a.expiryMs - b.expiryMs),
  ];
  for (const tlc of claimable) {
    const { args: successorArgs } = successorFor(tlc.index);
    const left = cell.capacity - tlc.amount;
    // The lock requires the rest to stay in a successor cell, which must be able to exist.
    if (left < 0n || (left > 0n && left < occupied(successorArgs))) continue;
    const preimage = preimageOf(tlc);
    return {
      claim: {
        witnessState: encodeWitnessState(current),
        unlockType: tlc.index,
        ...(preimage ? { preimage } : {}),
        signingKey: tlc.ours!.key,
        since: preimage ? preimageSince : expirySince,
        ...(preimage ? {} : { feeSince: tlc.expirySince }),
        ...(left > 0n ? { successor: { capacity: left, args: successorArgs } } : {}),
      },
    };
  }
  // TLCs the node may still claim: ones it holds the key for, unless it needed a preimage it doesn't have and the
  // TLC has expired (the peer takes those back).
  const waitingOnes = tlcs.filter((tlc) => tlc.ours && !(tlc.ours.path === "preimage" && !preimageOf(tlc) && now > tlc.expiryMs));
  const waitingTlcs = waitingOnes.length > 0;
  const waiting = (reason: string) => ({ skip: waitingTlcs ? "waiting for a pending payment to resolve" : reason });

  // The user's own share.
  let unlockType: number;
  let mine: bigint;
  let otherSettled: boolean;
  if (equal(current.first.pubkeyHash, ours)) { unlockType = UNLOCK_REMOTE_SLOT; mine = current.first.amount; otherSettled = equal(current.second.pubkeyHash, ZERO20); }
  else if (equal(current.second.pubkeyHash, ours)) { unlockType = UNLOCK_LOCAL_SLOT; mine = current.second.amount; otherSettled = equal(current.first.pubkeyHash, ZERO20); }
  else return waiting("the user's share is already claimed");
  // Whoever settles second may take the whole cell, TLCs included (the lock checks no output once both slots are
  // empty), and Fiber's watchtower does. While the peer's share is unsettled the user's waits, as Fiber's does, until
  // no TLC may still become the user's: settled first, it would let the peer sweep them. Once the peer has settled,
  // this differs from Fiber, which takes the whole cell at once: the user's TLCs are claimed one by one first (as
  // they become claimable), so the peer's still-pending ones aren't taken before their time. A TLC that could only
  // be claimed alone by leaving a successor too small to exist never could be, so then the whole cell is taken.
  const stranded = (tlc: PendingTlc) => {
    const left = cell.capacity - tlc.amount;
    return left > 0n && left < occupied(successorFor(tlc.index).args);
  };
  if (waitingTlcs && !(otherSettled && waitingOnes.every(stranded))) return { skip: "waiting for a pending payment to resolve" };
  if (mine === 0n && !otherSettled) return { skip: "the user has no share in this channel" };
  const since = first ? args.delaySince : 0n;
  if (!delayPassed(since)) return { skip: "waiting for the commitment delay" };
  const base = { witnessState: encodeWitnessState(current), unlockType, signingKey: ccc.hexFrom(channel.localSettlementKey), since };
  // Settling second, the claim empties the cell, as Fiber's does: what TLCs remain are the peer's to take back,
  // and Fiber's watchtower claims nothing more once its own slot is empty, so a successor would hold them for good.
  if (otherSettled) return { claim: base };
  const { args: successorArgs } = successorFor(unlockType);
  const left = cell.capacity - mine;
  if (cell.capacity <= mine) return { skip: "the commitment cell holds less than the user's share" };
  // The peer's part (and any TLCs) stays in a successor cell, which must hold at least its own occupied capacity.
  if (left < occupied(successorArgs)) return { skip: "the peer's remaining part is too small for a commitment cell" };
  return { claim: { ...base, successor: { capacity: left, args: successorArgs } } };
}

/** The message a commitment-lock signature signs: the transaction hash with no cell deps (Fiber's `compute_tx_message`). */
export function settlementMessage(tx: ccc.Transaction): ccc.Hex {
  const bare = tx.clone();
  bare.cellDeps = [];
  return bare.hash();
}

/**
 * Signs the claim's commitment input (witness 0) with the key its unlock needs: the channel's settlement key, or a
 * TLC's key. The signature sits at the end of the witness, or before the preimage of a preimage unlock.
 */
export function signSettlement(tx: ccc.Transaction, settlementKey: ccc.HexLike, withPreimage = false) {
  const message = ccc.bytesFrom(settlementMessage(tx));
  const recovered = secp256k1.sign(message, ccc.bytesFrom(settlementKey), { prehash: false, format: "recovered" });
  const signature = concat(recovered.slice(1), recovered.slice(0, 1));
  const witness = ccc.bytesFrom(tx.witnesses[0]);
  const end = witness.length - (withPreimage ? 32 : 0);
  tx.witnesses[0] = ccc.hexFrom(concat(witness.slice(0, end - 65), signature, witness.slice(end)));
}

/** The commitment lock's cell deps: its code (found by type ID, so contract upgrades are followed) and ckb_auth. */
export async function commitmentLockCellDeps(client: ccc.Client, network: "testnet" | "mainnet"): Promise<ccc.CellDepLike[]> {
  const contract = COMMITMENT_LOCK[network];
  const code = await client.findSingletonCellByType({ codeHash: TYPE_ID_CODE_HASH, hashType: "type", args: contract.typeIdArgs }, true);
  if (!code) throw new Error("Could not find Fiber's commitment lock contract");
  return [{ outPoint: code.outPoint, depType: "code" }, { outPoint: contract.ckbAuth, depType: "code" }];
}

type ChannelRef = { channelId: string; fundingOutPoint: ccc.OutPointLike };

/** The transaction that spent `outPoint`, found through the indexer by the cell's lock. */
async function spentBy(client: ccc.Client, outPoint: ccc.OutPoint, lock: ccc.Script): Promise<ccc.Transaction | undefined> {
  for await (const found of client.findTransactions({ script: lock, scriptType: "lock", scriptSearchMode: "exact" }, "desc", 50)) {
    if (!found.isInput) continue;
    const tx = (await client.getTransaction(found.txHash))?.transaction;
    if (tx?.inputs.some((input) => input.previousOutput.eq(outPoint))) return tx;
  }
  return undefined;
}

/** The chain's median block time at the tip, in milliseconds (`get_block_median_time`), if the client can ask. */
async function medianTime(client: ccc.Client): Promise<number | undefined> {
  const requestor = (client as { requestor?: { request(method: string, params: unknown[]): Promise<unknown> } }).requestor;
  if (!requestor) return undefined;
  const tip = await client.getTipHeader();
  const median = await requestor.request("get_block_median_time", [tip.hash]);
  return typeof median === "string" ? Number(BigInt(median)) : undefined;
}

export type SettleResult = { channelId: string; txHash?: ccc.Hex; status: string };

/**
 * One pass of the in-page watchtower over a channel: finds its commitment on-chain, follows any settlements to
 * the live commitment cell, and claims the user's share once the commitment's delay has passed.
 */
export async function settleChannel(options: {
  client: ccc.Client;
  network: "testnet" | "mainnet";
  channel: WatchedChannel;
  ref: ChannelRef;
  /** The node's CKB key: it pays the fee from its reserve and receives the claim (the sweep moves it on). */
  nodeKey: ccc.HexLike;
  /** The payment preimages the node handed the watchtower (watchtower-store.ts), by payment hash. */
  preimage?: (paymentHash: string) => Promise<string | undefined>;
  now?: number;
  /** For checks only: builds the claim before the delay has passed and hands it to `submit` instead of sending it. */
  dryRun?: { submit: (tx: ccc.Transaction) => Promise<ccc.Hex> };
}): Promise<SettleResult> {
  const { client, channel } = options;
  const result = (status: string, txHash?: ccc.Hex): SettleResult => ({ channelId: channel.channelId, status, ...(txHash ? { txHash } : {}) });
  if (channel.fundingUdtTypeScript) return result("token channels are not settled by the in-page watchtower");
  const funding = ccc.OutPoint.from(options.ref.fundingOutPoint);
  const fundingTx = (await client.getTransaction(funding.txHash))?.transaction;
  const fundingOutput = fundingTx?.outputs[Number(funding.index)];
  if (!fundingOutput) return result("funding transaction not found");
  if (await client.getCellLive(funding, false)) return result("open");
  const commitmentTx = await spentBy(client, funding, fundingOutput.lock);
  if (!commitmentTx) return result("funding spent; closing transaction not indexed yet");
  const codeHash = COMMITMENT_LOCK[options.network].codeHash;
  const isCommitment = (output?: ccc.CellOutput) => output?.lock.codeHash === codeHash && output.lock.hashType === "type";
  if (!isCommitment(commitmentTx.outputs[0])) return result("closed cooperatively");
  if (commitmentTx.outputs[0].type) return result("token channels are not settled by the in-page watchtower");
  const prefix = ccc.bytesFrom(commitmentTx.outputs[0].lock.args).slice(0, 36);

  // Follow the commitment cell through any settlements to the one that is live now.
  let cell = ccc.OutPoint.from({ txHash: commitmentTx.hash(), index: 0 });
  let output = commitmentTx.outputs[0];
  let previousWitness: Uint8Array | undefined;
  for (let step = 0; step < 300; step++) {
    if (await client.getCellLive(cell, false)) break;
    const next = await spentBy(client, cell, output.lock);
    if (!next) return result("commitment cell spent; settlement not indexed yet");
    const inputIndex = next.inputs.findIndex((input) => input.previousOutput.eq(cell));
    const witness = ccc.bytesFrom(next.witnesses[inputIndex] ?? "0x");
    if (witness.length <= 16 || !equal(witness.slice(0, 16), XUDT_COMPATIBLE_WITNESS)) return result("unexpected settlement witness");
    const successor = next.outputs.findIndex((o) => isCommitment(o) && equal(ccc.bytesFrom(o.lock.args).slice(0, 36), prefix));
    if (successor < 0) return result("settled");
    previousWitness = witness.slice(16);
    cell = ccc.OutPoint.from({ txHash: next.hash(), index: successor });
    output = next.outputs[successor];
  }

  // The first settlement waits for (a share of) the commitment's delay, counted in epochs from its block.
  let delayPassed: ((since: bigint) => boolean) | undefined;
  if (!previousWitness && !options.dryRun) {
    const created = await client.getTransaction(cell.txHash);
    const header = created?.blockHash ? await client.getHeaderByHash(created.blockHash) : undefined;
    if (!header) return result("commitment not confirmed yet");
    const tip = await client.getTipHeader();
    delayPassed = (since) => epochDelayPassed(header.epoch, since, tip.epoch);
  }
  // A received payment is claimed with its preimage, which the node handed the watchtower when it learned it.
  const preimages = new Map<string, string>();
  for (const data of [channel.localSettlement, channel.remoteSettlement, channel.pendingRemoteSettlement]) {
    for (const tlc of data?.tlcs ?? []) {
      const hash = String(tlc.payment_hash).toLowerCase();
      if (preimages.has(hash)) continue;
      const preimage = await options.preimage?.(hash);
      if (preimage) preimages.set(hash, preimage);
    }
  }
  // TLC expiries are absolute timestamp `since` values, which CKB checks against the median time of recent blocks
  // (minutes behind the wall clock): judged by that time, as Fiber does, an expiry claim isn't sent before it can
  // be accepted, and a TLC isn't counted as the peer's before the peer can take it back.
  const hasTlcs = [channel.localSettlement, channel.remoteSettlement, channel.pendingRemoteSettlement].some((data) => data?.tlcs.length);
  const now = options.now ?? (hasTlcs ? await medianTime(client) : undefined) ?? Date.now();
  const decision = planClaim({
    channel, cell: { capacity: output.capacity, args: output.lock.args }, previousWitness, preimages, now, delayPassed,
  });
  if ("skip" in decision) return result(decision.skip);
  const plan = decision.claim;

  const signer = new ccc.SignerCkbPrivateKey(client, options.nodeKey);
  const nodeLock = (await signer.getRecommendedAddressObj()).script;
  const unlock = plan.preimage
    ? concat(new Uint8Array([plan.unlockType, 1]), new Uint8Array(65), ccc.bytesFrom(plan.preimage))
    : concat(new Uint8Array([plan.unlockType, 0]), new Uint8Array(65));
  const tx = ccc.Transaction.from({
    cellDeps: await commitmentLockCellDeps(client, options.network),
    inputs: [{ previousOutput: cell, since: plan.since }],
    outputs: [
      ...(plan.successor ? [{ capacity: plan.successor.capacity, lock: { ...output.lock, args: plan.successor.args } }] : []),
      { capacity: output.capacity - (plan.successor?.capacity ?? 0n), lock: nodeLock },
    ],
    outputsData: plan.successor ? ["0x", "0x"] : ["0x"],
    witnesses: [ccc.hexFrom(concat(XUDT_COMPATIBLE_WITNESS, new Uint8Array([1]), plan.witnessState, unlock))],
  });
  await tx.addCellDepsOfKnownScripts(client, ccc.KnownScript.Secp256k1Blake160);
  // As Fiber does, the node's own key adds at least one plain cell (its fee reserve) and pays the fee.
  await tx.completeInputsAddOne(signer);
  await tx.completeFeeChangeToOutput(signer, tx.outputs.length - 1, 1000);
  // A TLC claimed after its expiry: the lock reads the expiry off an input's absolute timestamp `since`, which the
  // node's own fee inputs carry (as in Fiber). Setting it changes no size, so the fee stands.
  if (plan.feeSince !== undefined) for (const input of tx.inputs.slice(1)) input.since = plan.feeSince;
  signSettlement(tx, plan.signingKey, Boolean(plan.preimage));
  const signed = await signer.signOnlyTransaction(tx);
  return result("claimed", await (options.dryRun?.submit(signed) ?? client.sendTransaction(signed)));
}
