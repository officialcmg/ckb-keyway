import * as ccc from "@ckb-ccc/core";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import type { SettlementDataJson, SettlementTlcJson, WatchedChannel } from "./watchtower-store";

/**
 * Claims the user's share of a force-closed channel from its commitment cell, and the payments (TLCs) still in
 * flight that are the user's, following Fiber 0.10.1 (d9b6bbd), including legacy and V2 commitments
 * (fiber-lib watchtower/actor.rs `build_settlement_tx`, fiber-types/watchtower.rs; fiber-scripts commitment-lock). Fiber's browser
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
  const channelFeatures = bytes.length === 58 ? bytes[57] : 0;
  if (bytes.length > 58 || (bytes.length === 58 && channelFeatures !== 1)) throw new Error("Unsupported commitment channel features");
  return {
    prefix: bytes.slice(0, 36),
    delaySince: readLe(bytes.slice(20, 28)),
    commitmentNumber: bytes.slice(28, 36).reduce((acc, byte) => (acc << 8n) | BigInt(byte), 0n),
    witnessHash: bytes.slice(36, 56),
    channelFeatures,
  };
}

const HASH_ALGORITHMS: Record<string, number> = { CkbHash: 0, ckb_hash: 0, Sha256: 1, sha256: 1 };

/** Fiber's settlement witness for a commitment (channel.rs `settlement_data_to_witness`). */
export function encodeSettlementWitness(data: SettlementDataJson, forRemote: boolean, localSettlementKey: ccc.HexLike, remoteSettlementKey: ccc.HexLike, channelFeatures: 0 | 1 = 0): Uint8Array {
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
      ccc.bytesFrom(tlc.payment_hash).slice(0, channelFeatures === 1 ? 32 : 20),
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
export function parseSettlementWitness(bytes: Uint8Array, withUnlockCount = true, channelFeatures: 0 | 1 = 0): SettlementWitness | undefined {
  let offset = withUnlockCount ? 1 : 0;
  const take = (length: number) => {
    if (offset + length > bytes.length) throw new Error("short");
    const value = bytes.slice(offset, offset + length);
    offset += length;
    return value;
  };
  try {
    const count = take(1)[0];
    const pendingTlcs = Array.from({ length: count }, () => take(channelFeatures === 1 ? 97 : 85));
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
  /** Whether the TLC is in the node's settlement data at all. One that isn't can't be told the peer's from the user's. */
  known: boolean;
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
  const hashLength = channel.channelFeatures === 1 ? 32 : 20;
  const tlcLength = 65 + hashLength;
  const known: Array<{ bytes: Uint8Array; tlc: SettlementTlcJson }> = [];
  for (const [data, forRemote] of [[channel.localSettlement, false], [channel.remoteSettlement, true], [channel.pendingRemoteSettlement, true]] as const) {
    for (const tlc of data?.tlcs ?? []) {
      try {
        known.push({ bytes: encodeSettlementWitness({ local_amount: "0x0", remote_amount: "0x0", tlcs: [tlc] }, forRemote, channel.localSettlementKey, channel.remoteSettlementKey, channel.channelFeatures).slice(1, 1 + tlcLength), tlc });
      } catch {
        // A TLC the node can't encode is never matched.
      }
    }
  }
  return state.pendingTlcs.map((bytes, index) => {
    const expirySince = readLe(bytes.slice(tlcLength - 8, tlcLength));
    const match = known.find((item) => equal(item.bytes, bytes));
    const pending: PendingTlc = { index, known: Boolean(match), amount: readLe(bytes.slice(1, 17)), expirySince, expiryMs: Number(expirySince & 0x00ff_ffff_ffff_ffffn) * 1000 };
    if (!match) return pending;
    const key = ccc.hexFrom(`0x${match.tlc.local_key.replace(/^0x/, "")}`);
    const mine = blake160(pubkeyOf(key));
    const offered = (bytes[0] & 1) === 0;
    const [first, second] = [bytes.slice(17 + hashLength, 37 + hashLength), bytes.slice(37 + hashLength, 57 + hashLength)];
    const preimageSlot = offered ? first : second;
    const expirySlot = offered ? second : first;
    const path = equal(preimageSlot, mine) ? "preimage" : equal(expirySlot, mine) ? "expiry" : undefined;
    if (path) pending.ours = { path, key, paymentHash: ccc.hexFrom(match.tlc.payment_hash), hashAlgorithm: match.tlc.hash_algorithm };
    return pending;
  });
}

type ClaimChannel = Pick<WatchedChannel, "channelFeatures" | "localSettlementKey" | "remoteSettlementKey" | "localSettlement" | "remoteSettlement" | "pendingRemoteSettlement">;

/**
 * Decides the next claim from a live commitment cell, as Fiber 0.9.1's watchtower does (`build_settlement_tx`), one
 * unlock per transaction. `previousWitness` is the settlement witness that created the cell (undefined for the
 * commitment transaction's own output, i.e. the first settlement).
 *
 * Once the peer has settled its share, the user's claim takes the whole cell at once, as Fiber's does. Otherwise
 * pending TLCs come first, the most urgent first: one the node can unlock with a payment preimage it holds (the peer
 * can take it back once it expires), soonest expiry first, then one that has expired and is the node's to take back.
 * Then the user's own share, only once no TLC may still become the user's (the party that settles second can take
 * the whole cell) and none is left that the node's data can't classify, leaving a successor for the peer. On the
 * first settlement each unlock also waits for its share of the commitment's delay (`delayPassed`, given the input
 * `since` it needs).
 *
 * A skip that is one of FINISHED says nothing in the cell is, or can still become, the user's: it is never given
 * while the cell holds a TLC the node has a key for (whatever its expiry, with or without its preimage) or one it
 * can't classify.
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
  if (args.channelFeatures !== (channel.channelFeatures ?? 0)) return { skip: "the commitment's channel features do not match the stored channel" };
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
      const encoded = encodeSettlementWitness(data, forRemote, channel.localSettlementKey, channel.remoteSettlementKey, channel.channelFeatures);
      if (equal(blake160(encoded), args.witnessHash)) { state = parseSettlementWitness(encoded, false, channel.channelFeatures); break; }
    }
    if (!state) return { skip: "the on-chain commitment matches none of the node's settlement data (an old commitment needs revocation, which this does not do)" };
  } else {
    const parsed = parseSettlementWitness(options.previousWitness!, true, channel.channelFeatures);
    state = parsed && applyUnlocks(parsed);
    if (!state) return { skip: "could not read the previous settlement witness" };
  }
  const current = state;
  const occupied = (successorArgs: ccc.Hex) => ccc.fixedPointFrom(8 + 32 + 1 + ccc.bytesFrom(successorArgs).length);
  const successorFor = (unlockType: number) => {
    const after = applyUnlocks({ ...current, unlocks: [{ type: unlockType, withPreimage: false }] })!;
    return { after, args: ccc.hexFrom(concat(args.prefix, blake160(encodeWitnessState(after)), new Uint8Array(args.channelFeatures ? [1, args.channelFeatures] : [1]))) };
  };

  // Which slot is the user's, and whether the peer has already emptied its own.
  let unlockType: number | undefined;
  let mine = 0n;
  let otherSettled = false;
  if (equal(current.first.pubkeyHash, ours)) { unlockType = UNLOCK_REMOTE_SLOT; mine = current.first.amount; otherSettled = equal(current.second.pubkeyHash, ZERO20); }
  else if (equal(current.second.pubkeyHash, ours)) { unlockType = UNLOCK_LOCAL_SLOT; mine = current.second.amount; otherSettled = equal(current.first.pubkeyHash, ZERO20); }
  const since = first ? args.delaySince : 0n;
  const base = unlockType === undefined ? undefined : { witnessState: encodeWitnessState(current), unlockType, signingKey: ccc.hexFrom(channel.localSettlementKey), since };
  // The peer has settled its share: settling second, the user's claim empties the cell, pending TLCs and all (the
  // lock checks no output once both slots are empty), at once, as Fiber 0.9.1's watchtower does
  // (`two_parties_all_settled`). That secures every payment that may still become the user's in one transaction,
  // rather than one per pass while the peer can take the others back once they expire, and an outgoing payment
  // that hasn't expired yet doesn't hold the user's share back.
  if (base && otherSettled) {
    if (!delayPassed(since)) return { skip: "waiting for the commitment delay" };
    return { claim: base };
  }

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
  // TLCs the node may still claim on what it knows now: ones it holds the key for, unless it needed a preimage it
  // doesn't have and the TLC has expired (the peer can take those back).
  const waitingTlcs = tlcs.some((tlc) => tlc.ours && !(tlc.ours.path === "preimage" && !preimageOf(tlc) && now > tlc.expiryMs));
  // TLCs the node holds a key for at all. One that has expired without its preimage is still the user's to claim
  // if the preimage arrives before the peer takes it back (the claimable list above takes it, expired or not), so
  // while any is in the cell the channel is not finished: only the chain showing them gone ends the watch.
  const heldTlcs = tlcs.some((tlc) => tlc.ours);
  // TLCs that match none of the node's data (it may be incomplete), so they can't be told the peer's from the
  // user's, and the node has no key to claim them with.
  const unclassifiedTlcs = tlcs.some((tlc) => !tlc.ours);
  const WAITING = "waiting for a pending payment to resolve";
  const UNCLASSIFIED = "a pending payment in the cell matches none of the node's data";
  const HELD = "a pending payment is still in the cell, to be claimed if its preimage arrives";

  // The user's slot is not in the cell. A status that ends the watch for good (FINISHED) says nothing in the cell
  // is the user's, so it is given only when the slot was emptied (not when the witness simply doesn't name the
  // user's key) and no pending payment is left that is, or may be, the user's.
  if (!base) {
    if (waitingTlcs) return { skip: WAITING };
    // Emptied by the user's own claim: one slot is blank and the other is the peer's. Anything else is a witness
    // this channel's keys don't account for.
    const peer = blake160(channel.remoteSettlementKey);
    const emptied = (equal(current.first.pubkeyHash, ZERO20) && equal(current.second.pubkeyHash, peer))
      || (equal(current.second.pubkeyHash, ZERO20) && equal(current.first.pubkeyHash, peer));
    if (!emptied) return { skip: "the settlement witness does not name the user's settlement key" };
    if (unclassifiedTlcs) return { skip: `the user's share is already claimed, but ${UNCLASSIFIED}` };
    if (heldTlcs) return { skip: `the user's share is already claimed; ${HELD}` };
    return { skip: "the user's share is already claimed" };
  }
  // The user's own share, settling first. Whoever settles second may take the whole cell, TLCs included, so it
  // waits, as Fiber's does, until no TLC may still become the user's.
  if (waitingTlcs) return { skip: WAITING };
  // A TLC that can't be classified holds the share back too, as in Fiber's watchtower (watchtower/actor.rs
  // `build_settlement_tx`: a TLC without a matching key is never taken off `pending_tlcs_count`, and the node's own
  // slot is unlocked only at zero). Settling first would hand the peer the whole remaining cell, that TLC included,
  // although it may be one the user is owed back; waiting costs time, and once the peer settles its own share the
  // claim above takes the whole cell. The price: while the peer leaves its share unclaimed, the user's waits too.
  if (unclassifiedTlcs) return { skip: `waiting for the peer to settle its share first: ${UNCLASSIFIED}` };
  if (mine === 0n) return { skip: heldTlcs ? `the user has no share in this channel; ${HELD}` : "the user has no share in this channel" };
  if (!delayPassed(since)) return { skip: "waiting for the commitment delay" };
  const { args: successorArgs } = successorFor(base.unlockType);
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

export type SettleResult = {
  channelId: string;
  txHash?: ccc.Hex;
  status: string;
  /** Set once the funding cell is seen spent by a commitment (a force close, by either side): that transaction. */
  closingTx?: ccc.Hex;
  /** With a status in FINISHED: the transaction the status rests on, for `isBuried`. */
  evidence?: ccc.Hex;
  /**
   * Set when the pass read the live commitment cell and found something still to settle or wait for (any status
   * outside FINISHED, a claim just sent included). It contradicts an earlier verdict that the channel was finished.
   */
  unsettled?: true;
};

/**
 * A pass that failed after it had seen a commitment spend the funding cell still says so (`closingTx`), and, if it
 * failed while building or sending a claim, that there is something still to settle (`unsettled`).
 */
export type SettleFailure = Error & { closingTx?: ccc.Hex; unsettled?: true };

/**
 * Statuses after which the channel needs nothing more from the watchtower: nothing is left under its commitment
 * lock, or what is left isn't the user's. A cooperative close is left to Fiber's own remove_watch_channel, so an
 * unexpected closing transaction never drops the data.
 */
export const FINISHED: ReadonlySet<string> = new Set(["settled", "the user's share is already claimed", "the user has no share in this channel"]);

/** Blocks a transaction must be under before a verdict resting on it is kept for good (as the server watchtower's REORG_DEPTH). */
export const FINAL_DEPTH = 24n;

/**
 * Whether a transaction is on-chain with FINAL_DEPTH blocks on top of it. A verdict that a channel is finished
 * is acted on (its watchtower record dropped, its fee reserve released) only once the transaction it rests on is,
 * so a reorganization that undoes the transaction finds the watchtower still able to claim.
 */
export async function isBuried(client: ccc.Client, txHash: ccc.HexLike): Promise<boolean> {
  const found = await client.getTransactionNoCache(txHash);
  if (found?.status !== "committed") return false;
  const number = found.blockNumber ?? (found.blockHash ? (await client.getHeaderByHash(found.blockHash))?.number : undefined);
  if (number === undefined) return false;
  return (await client.getTip()) - number >= FINAL_DEPTH;
}

/**
 * One pass of the in-page watchtower over a channel: finds its commitment on-chain, follows any settlements to
 * the live commitment cell, and claims the user's share once the commitment's delay has passed.
 */
type SettleOptions = {
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
};

export async function settleChannel(options: SettleOptions): Promise<SettleResult> {
  const seen: { closingTx?: ccc.Hex; claiming?: boolean } = {};
  try {
    return await settle(options, seen);
  } catch (cause) {
    // Building or sending a claim can fail (no fee cell on the node's key, an RPC error) after the pass has
    // already seen that the channel is force-closed, and that something in it is the user's: the failure carries
    // both along.
    const error: SettleFailure = cause instanceof Error ? cause : new Error(String(cause));
    if (seen.closingTx) error.closingTx = seen.closingTx;
    if (seen.claiming) error.unsettled = true;
    throw error;
  }
}

/** Where a channel's funding cell has gone on-chain. */
type FundingFate =
  /** Nothing that says the channel is force-closed: the status to report. */
  | { status: string }
  /** A commitment transaction spent it: a force close, by either side. */
  | { commitmentTx: ccc.Transaction };

/** Where a force-closed channel's commitment cell has gone, followed through every settlement since. */
type CommitmentFate =
  /** The commitment cell (the commitment's own output, or a settlement's successor) that is live now. */
  | { live: { cell: ccc.OutPoint; output: ccc.CellOutput; previousWitness?: Uint8Array } }
  /** Nothing is left under the commitment lock: this transaction spent the last cell and left no successor. */
  | { settledBy: ccc.Hex }
  /** It can't be followed to its end right now: the status to report. */
  | { status: string };

const isCommitmentOutput = (network: "testnet" | "mainnet", output?: ccc.CellOutput) =>
  output?.lock.codeHash === COMMITMENT_LOCK[network].codeHash && output.lock.hashType === "type";

/** What spent a channel's funding cell, if anything has. */
async function fundingFate(client: ccc.Client, network: "testnet" | "mainnet", fundingOutPoint: ccc.OutPointLike): Promise<FundingFate> {
  const funding = ccc.OutPoint.from(fundingOutPoint);
  const fundingTx = (await client.getTransaction(funding.txHash))?.transaction;
  const fundingOutput = fundingTx?.outputs[Number(funding.index)];
  if (!fundingOutput) return { status: "funding transaction not found" };
  if (await client.getCellLive(funding, false)) return { status: "open" };
  const commitmentTx = await spentBy(client, funding, fundingOutput.lock);
  if (!commitmentTx) return { status: "funding spent; closing transaction not indexed yet" };
  if (!isCommitmentOutput(network, commitmentTx.outputs[0])) return { status: "closed cooperatively" };
  return { commitmentTx };
}

/** Follows a commitment transaction's cell through any settlements to the one that is live now, or to its end. */
async function commitmentFate(client: ccc.Client, network: "testnet" | "mainnet", commitmentTx: ccc.Transaction): Promise<CommitmentFate> {
  const prefix = ccc.bytesFrom(commitmentTx.outputs[0].lock.args).slice(0, 36);
  let cell = ccc.OutPoint.from({ txHash: commitmentTx.hash(), index: 0 });
  let output = commitmentTx.outputs[0];
  let previousWitness: Uint8Array | undefined;
  for (let step = 0; step < 300; step++) {
    if (await client.getCellLive(cell, false)) return { live: { cell, output, ...(previousWitness ? { previousWitness } : {}) } };
    const next = await spentBy(client, cell, output.lock);
    if (!next) return { status: "commitment cell spent; settlement not indexed yet" };
    const inputIndex = next.inputs.findIndex((input) => input.previousOutput.eq(cell));
    const witness = ccc.bytesFrom(next.witnesses[inputIndex] ?? "0x");
    if (witness.length <= 16 || !equal(witness.slice(0, 16), XUDT_COMPATIBLE_WITNESS)) return { status: "unexpected settlement witness" };
    // The lock requires a settlement that leaves anything behind to put it in output 0 (its successor); any other
    // commitment-locked output isn't this channel's.
    const successor = next.outputs[0];
    if (!isCommitmentOutput(network, successor) || !equal(ccc.bytesFrom(successor.lock.args).slice(0, 36), prefix)) return { settledBy: next.hash() };
    previousWitness = witness.slice(16);
    cell = ccc.OutPoint.from({ txHash: next.hash(), index: 0 });
    output = successor;
  }
  return { status: "too many settlements to follow in one pass" };
}

/** What the chain alone shows of a channel's close, read without any of the channel's data. */
export type ForceCloseOnChain = {
  /** The commitment transaction that spent the funding cell, if one did. */
  closingTx?: ccc.Hex;
  /** Set once nothing is left under the commitment lock: the transaction that spent its last cell. */
  settledBy?: ccc.Hex;
};

/**
 * Whether a force-closed channel has nothing left to settle, by the chain alone: its commitment cell, followed
 * through every settlement (each leaves what remains in output 0), is gone. For a channel the watchtower holds no
 * record of (an earlier SDK removed it, and Fiber hands only Channel V2 channels over again), this is all that
 * can be known: who the remaining funds belong to can't be told without the record, so nothing short of "nothing
 * is left" (`settledBy`) says the channel is finished. Anything else (open, closed cooperatively, a transaction
 * the indexer doesn't show yet, a live commitment cell) leaves `settledBy` unset.
 */
export async function forceCloseSettled(client: ccc.Client, network: "testnet" | "mainnet", fundingOutPoint: ccc.OutPointLike): Promise<ForceCloseOnChain> {
  const funding = await fundingFate(client, network, fundingOutPoint);
  if (!("commitmentTx" in funding)) return {};
  const closingTx = funding.commitmentTx.hash();
  const fate = await commitmentFate(client, network, funding.commitmentTx);
  return { closingTx, ...("settledBy" in fate ? { settledBy: fate.settledBy } : {}) };
}

async function settle(options: SettleOptions, seen: { closingTx?: ccc.Hex; claiming?: boolean }): Promise<SettleResult> {
  const { client, channel } = options;
  let closingTx: ccc.Hex | undefined;
  /** `onLiveCell`: the status was read off the live commitment cell, so anything outside FINISHED is unsettled. */
  const result = (status: string, txHash?: ccc.Hex, evidence?: ccc.Hex, onLiveCell = false): SettleResult => ({
    channelId: channel.channelId, status,
    ...(txHash ? { txHash } : {}), ...(closingTx ? { closingTx } : {}), ...(evidence && FINISHED.has(status) ? { evidence } : {}),
    ...(onLiveCell && (txHash || !FINISHED.has(status)) ? { unsettled: true as const } : {}),
  });
  const funding = await fundingFate(client, options.network, options.ref.fundingOutPoint);
  if (!("commitmentTx" in funding)) return result(funding.status);
  const { commitmentTx } = funding;
  // From here the channel is force-closed on-chain, whatever the node itself still says about it.
  closingTx = seen.closingTx = commitmentTx.hash();
  // A token channel's close is seen (above: reads only), but its claim is not built here.
  if (channel.fundingUdtTypeScript || commitmentTx.outputs[0].type) return result("token channels are not settled by the in-page watchtower");

  // Follow the commitment cell through any settlements to the one that is live now.
  const fate = await commitmentFate(client, options.network, commitmentTx);
  if ("settledBy" in fate) return result("settled", undefined, fate.settledBy);
  if (!("live" in fate)) return result(fate.status);
  const { cell, output, previousWitness } = fate.live;

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
  // A status that ends the watch rests on the transaction that created the cell it was read from.
  if ("skip" in decision) return result(decision.skip, undefined, cell.txHash, true);
  const plan = decision.claim;
  seen.claiming = true;

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
  return result("claimed", await (options.dryRun?.submit(signed) ?? client.sendTransaction(signed)), undefined, true);
}

/**
 * The claims and sweeps sent with the node's key (`record`), so each watchtower pass can start from what the chain
 * says (`refresh`). ccc 1.16.1's `sendTransaction` marks a transaction's inputs spent and its outputs usable in the
 * client's cache, which lets one pass's claims chain on each other's change; but a claim the chain then drops would
 * leave its payout cached as usable and the real fee reserve as spent for the life of the page, so every later claim
 * and sweep would spend a cell that doesn't exist. `refresh` clears the cache, then marks again the sends the node
 * still has in its mempool: all their outputs usable first, then all their inputs spent, so one that spends
 * another's change keeps it spent whatever order they come in. Sends that are committed, dropped or rejected are
 * forgotten. Give this client to nothing else: clearing its cache would also forget other sends.
 *
 * Everything that uses the client (a pass with its refresh and claims, a sweep) runs through `exclusive`, one at a
 * time: a send that lands while a refresh is rebuilding the cache would otherwise have its spent marks overwritten
 * (ccc's `markUsable` clears a cell's spent flag), and the next claim would pick a cell that is already spent.
 */
export function trackNodeKeySends(client: ccc.Client) {
  const sent = new Set<ccc.Hex>();
  let queue: Promise<unknown> = Promise.resolve();
  return {
    record(hash: ccc.Hex) {
      sent.add(hash);
    },
    /** Runs `task` once every earlier one has finished. */
    exclusive<T>(task: () => Promise<T>): Promise<T> {
      const run = queue.then(task);
      queue = run.catch(() => undefined);
      return run;
    },
    async refresh() {
      await client.cache.clear();
      const pending: ccc.Transaction[] = [];
      for (const hash of [...sent]) {
        const found = await client.getTransactionNoCache(hash).catch(() => null);
        // Unreachable: not marked this pass (a claim may then conflict with it and is retried), asked again next.
        if (found === null) continue;
        if (found?.status === "pending" || found?.status === "proposed") pending.push(found.transaction);
        else sent.delete(hash);
      }
      for (const tx of pending) {
        await client.cache.markUsable(tx.outputs.map((cellOutput, index) => ({ cellOutput, outputData: tx.outputsData[index] ?? "0x", outPoint: { txHash: tx.hash(), index } })));
      }
      for (const tx of pending) await client.cache.markUnusable(tx.inputs.map((input) => input.previousOutput));
    },
  };
}
