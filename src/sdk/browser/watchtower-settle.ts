import * as ccc from "@ckb-ccc/core";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import type { SettlementDataJson, WatchedChannel } from "./watchtower-store";

/**
 * Claims the user's share of a force-closed channel from its commitment cell, the way Fiber 0.9.1's watchtower
 * does (fiber-lib watchtower/actor.rs `build_settlement_tx`, channel.rs `settlement_data_to_witness`), for
 * channels with no pending TLCs. Fiber's browser build has no watchtower (see watchtower-bridge.ts), so the page
 * does this with the data the node handed it. As in Fiber, the claim pays to the node's own CKB key (the
 * settlement key), which also pays the fee from its reserve cell; the settlement sweep then moves it to the user.
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
  /** Capacity left in a successor commitment cell for the peer, or undefined when the claim empties the cell. */
  successor?: { capacity: bigint; args: ccc.Hex };
  /** The input `since`: the commitment's delay for the first settlement, else 0. */
  since: bigint;
};
export type ClaimDecision = { claim: ClaimPlan } | { skip: string };

/**
 * Decides how to claim the user's share from a live commitment cell. `previousWitness` is the settlement
 * witness that created the cell (undefined for the commitment transaction's own output, i.e. the first settlement).
 */
export function planClaim(options: {
  channel: Pick<WatchedChannel, "localSettlementKey" | "remoteSettlementKey" | "localSettlement" | "remoteSettlement" | "pendingRemoteSettlement">;
  cell: { capacity: bigint; args: ccc.HexLike };
  previousWitness?: Uint8Array;
}): ClaimDecision {
  const { channel, cell } = options;
  const args = parseCommitmentArgs(cell.args);
  const ours = blake160(pubkeyOf(channel.localSettlementKey));
  let state: SettlementWitness | undefined;
  let since = 0n;
  if (!options.previousWitness) {
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
    since = args.delaySince;
  } else {
    const parsed = parseSettlementWitness(options.previousWitness);
    state = parsed && applyUnlocks(parsed);
    if (!state) return { skip: "could not read the previous settlement witness" };
  }
  if (state.pendingTlcs.length > 0) return { skip: "the commitment has pending TLCs, which this claim does not settle" };
  let unlockType: number;
  let mine: bigint;
  let otherSettled: boolean;
  if (equal(state.first.pubkeyHash, ours)) { unlockType = UNLOCK_REMOTE_SLOT; mine = state.first.amount; otherSettled = equal(state.second.pubkeyHash, ZERO20); }
  else if (equal(state.second.pubkeyHash, ours)) { unlockType = UNLOCK_LOCAL_SLOT; mine = state.second.amount; otherSettled = equal(state.first.pubkeyHash, ZERO20); }
  else return { skip: "the user's share is already claimed" };
  if (otherSettled) return { claim: { witnessState: encodeWitnessState(state), unlockType, since } };
  if (mine === 0n) return { skip: "the user has no share in this channel" };
  const after = applyUnlocks({ ...state, unlocks: [{ type: unlockType, withPreimage: false }] })!;
  const successorArgs = ccc.hexFrom(concat(args.prefix, blake160(encodeWitnessState(after)), new Uint8Array([1])));
  if (cell.capacity <= mine) return { skip: "the commitment cell holds less than the user's share" };
  return { claim: { witnessState: encodeWitnessState(state), unlockType, since, successor: { capacity: cell.capacity - mine, args: successorArgs } } };
}

/** The message a commitment-lock signature signs: the transaction hash with no cell deps (Fiber's `compute_tx_message`). */
export function settlementMessage(tx: ccc.Transaction): ccc.Hex {
  const bare = tx.clone();
  bare.cellDeps = [];
  return bare.hash();
}

/** Signs the claim's commitment input (witness 0) with the channel's settlement key. */
export function signSettlement(tx: ccc.Transaction, settlementKey: ccc.HexLike) {
  const message = ccc.bytesFrom(settlementMessage(tx));
  const recovered = secp256k1.sign(message, ccc.bytesFrom(settlementKey), { prehash: false, format: "recovered" });
  const signature = concat(recovered.slice(1), recovered.slice(0, 1));
  const witness = ccc.bytesFrom(tx.witnesses[0]);
  tx.witnesses[0] = ccc.hexFrom(concat(witness.slice(0, witness.length - 65), signature));
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
  /** For checks only: builds the claim before the delay has passed and hands it to `submit` instead of sending it. */
  dryRun?: { submit: (tx: ccc.Transaction) => Promise<ccc.Hex> };
}): Promise<SettleResult> {
  const { client, channel } = options;
  const result = (status: string, txHash?: ccc.Hex): SettleResult => ({ channelId: channel.channelId, status, ...(txHash ? { txHash } : {}) });
  const funding = ccc.OutPoint.from(options.ref.fundingOutPoint);
  const fundingTx = (await client.getTransaction(funding.txHash))?.transaction;
  const fundingOutput = fundingTx?.outputs[Number(funding.index)];
  if (!fundingOutput) return result("funding transaction not found");
  if (await client.getCellLive(funding, false)) return result("open");
  const commitmentTx = await spentBy(client, funding, fundingOutput.lock);
  if (!commitmentTx) return result("funding spent; closing transaction not indexed yet");
  const codeHash = COMMITMENT_LOCK[options.network].codeHash;
  const isCommitment = (output?: ccc.CellOutput) => output?.lock.codeHash === codeHash && output.lock.hashType === "type";
  if (commitmentTx.outputs.length !== 1 || !isCommitment(commitmentTx.outputs[0])) return result("closed cooperatively");
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

  const decision = planClaim({ channel, cell: { capacity: output.capacity, args: output.lock.args }, previousWitness });
  if ("skip" in decision) return result(decision.skip);
  const plan = decision.claim;

  if (plan.since !== 0n && !options.dryRun) {
    // The first settlement waits for the commitment's delay, counted in epochs from the commitment's block.
    const created = await client.getTransaction(cell.txHash);
    const header = created?.blockHash ? await client.getHeaderByHash(created.blockHash) : undefined;
    const tip = await client.getTipHeader();
    if (!header) return result("commitment not confirmed yet");
    const delay = ccc.epochFromHex(ccc.numToHex(plan.since & 0x00ff_ffff_ffff_ffffn));
    const ready = header.epoch;
    const rational = (e: ccc.Epoch) => [e[0] * e[2] + e[1], e[2]] as const;
    const [a, b] = rational(ready);
    const [c, d] = rational(delay);
    const [t, u] = rational(tip.epoch);
    // ready + delay <= tip, compared as fractions
    if ((a * d + c * b) * u > t * b * d) return result("waiting for the commitment delay");
  }

  const signer = new ccc.SignerCkbPrivateKey(client, options.nodeKey);
  const nodeLock = (await signer.getRecommendedAddressObj()).script;
  const unlock = concat(new Uint8Array([plan.unlockType, 0]), new Uint8Array(65));
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
  signSettlement(tx, channel.localSettlementKey);
  const signed = await signer.signOnlyTransaction(tx);
  return result("claimed", await (options.dryRun?.submit(signed) ?? client.sendTransaction(signed)));
}
