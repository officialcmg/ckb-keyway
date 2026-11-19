import * as ccc from "@ckb-ccc/core";
import { hasPlainTokenArgs, isXudtCompatible } from "./tokens";

const RUSD_CONTRACT_TYPE_ID_ARGS = "0x97d30b723c0b2c66e9cb8d4d0df4ab5d7222cbb00d4a9a2055ce2e5d7f0d8b0f";

/**
 * Fiber 0.9.1's watchtower claims a force-closed channel's funds only if the node's own key holds a plain
 * CKB cell to pay the fee (`watchtower/actor.rs`); without one, the user's share stays locked. So the user
 * keeps one small cell of their own CKB on their node's key while any channel might need settling, and gets
 * it back once every channel is fully closed.
 */
export const FEE_RESERVE = 62n * 100_000_000n;
/** The smallest plain CKB cell (61 CKB of occupied capacity). */
export const MIN_PLAIN_CELL = 61n * 100_000_000n;

type ChannelState = { channel_id?: unknown; channel_outpoint?: unknown; shutdown_transaction_hash?: unknown; state: { state_name: string; state_flags?: unknown } };
/**
 * A channel the in-page watchtower has established as finished on-chain (channel-closures.ts): on which funding
 * cell, and after which commitment transaction spent it.
 */
export type FinishedOnChain = { channelId: string; fundingOutPoint: string; closingTx: string; finished?: unknown };

/** A channel ID or transaction hash as a key: 32 bytes of lower-case hex, or undefined for anything else. */
export function channelKey(value: unknown): string | undefined {
  return typeof value === "string" && /^0x[0-9a-f]{64}$/i.test(value) ? value.toLowerCase() : undefined;
}
/** The transaction the node says closed the channel (`shutdown_transaction_hash`), once it reports the channel closed. */
export function closedBy(channel: ChannelState): string | undefined {
  return isClosed(channel.state) ? channelKey(channel.shutdown_transaction_hash) : undefined;
}
/** A funding cell as Fiber names it in `channel_outpoint` (a serialized out point, 36 bytes of hex), as a key. */
export function outPointKey(value: unknown): string | undefined {
  return typeof value === "string" && /^0x[0-9a-f]{72}$/i.test(value) ? value.toLowerCase() : undefined;
}

/** A channel's state flags, which Fiber sends as one string such as "UNCOOPERATIVE_LOCAL|WAITING_ONCHAIN_SETTLEMENT". */
function stateFlags(flags: unknown): Set<string> {
  return new Set(JSON.stringify(flags ?? "").match(/\b[A-Z][A-Z0-9_]*\b/g) ?? []);
}

/**
 * True once a channel is closed and not waiting for its on-chain settlement. Fiber 0.9.1 reports a force close as
 * UNCOOPERATIVE_LOCAL|WAITING_ONCHAIN_SETTLEMENT (or _REMOTE) and drops WAITING_ONCHAIN_SETTLEMENT once it has
 * settled. Flags are read as whole names. The hosted node server (managed-host/index.mjs) keeps its own copy; a
 * test holds the two equal.
 */
export function channelFinished({ state }: ChannelState): boolean {
  if (!isClosed(state)) return false;
  return !stateFlags(state.state_flags).has("WAITING_ONCHAIN_SETTLEMENT");
}

const isClosed = (state: ChannelState["state"]) => String(state?.state_name).replaceAll("_", "").toLowerCase() === "closed";

/**
 * True for a channel the node reports closed but still waiting for its on-chain settlement: a force close, by
 * either side, whose funds may still be under the commitment lock.
 */
export function waitingOnChain(channel: ChannelState): boolean {
  return isClosed(channel.state) && !channelFinished(channel);
}

/**
 * True while any channel is open, closing, or closed but not yet settled on-chain.
 *
 * Fiber 0.10.1's browser node never drops WAITING_ONCHAIN_SETTLEMENT from a force-closed channel (it waits for a
 * settlement record its build can't write), so for a channel the node itself reports closed, the in-page
 * watchtower's verdict that nothing is left to claim (`finishedOnChain`) counts as settled. Both must agree, about
 * the same funding cell and the same closing transaction: a channel the node still calls open keeps the reserve
 * whatever the verdict says, so does one the node saw closed by another transaction than the verdict followed,
 * and so does a force-closed channel without a verdict, whose claim the reserve pays for.
 */
export function needsFeeReserve(channels: ChannelState[], finishedOnChain: readonly FinishedOnChain[] = []): boolean {
  const settledOnChain = (channel: ChannelState) => {
    const id = channelKey(channel.channel_id);
    const outPoint = outPointKey(channel.channel_outpoint);
    const closing = closedBy(channel);
    return id !== undefined && outPoint !== undefined && closing !== undefined
      && finishedOnChain.some((item) => Boolean(item.finished) && item.channelId === id && item.fundingOutPoint === outPoint && item.closingTx === closing);
  };
  return channels.some((channel) => !channelFinished(channel) && !settledOnChain(channel));
}

/**
 * How a sweep splits the key's plain CKB: the reserve stays, the rest goes to the user. Undefined when there's
 * nothing to move beyond the reserve. With a reserve to keep and less than it on the key, all of it stays: what is
 * there is what is left of the reserve, and `reserve` comes back smaller than was asked for.
 */
export function planSweep(plainTotal: bigint, tokenCells: number, keepReserve: bigint): { toUser: bigint; reserve: bigint } | undefined {
  let reserve = keepReserve > 0n ? (plainTotal >= keepReserve ? keepReserve : plainTotal) : 0n;
  let toUser = plainTotal - reserve;
  // Too little for a cell of its own: it stays with the reserve.
  if (reserve > 0n && toUser < MIN_PLAIN_CELL + SWEEP_FEE_MARGIN) { reserve += toUser; toUser = 0n; }
  if (tokenCells === 0 && toUser === 0n) return undefined;
  return { toUser, reserve };
}

const MAX_CELLS = 50;
const SWEEP_FEE_MARGIN = 1_000_000n;

/**
 * Stopgap until Fiber pays force-closed channels to their close address: moves everything at a node's
 * settlement key to the user's own address, keeping tokens as they are, with the fee taken from the CKB.
 * `keepReserve` CKB stays on the key as the watchtower's fee reserve (see FEE_RESERVE); pass 0n once
 * every channel is settled to return it too. Cells with a type script it can't move safely are left where
 * they are, and so are token cells the plain CKB can't bring up to the destination lock's minimum. Returns the
 * transaction hash, or undefined when there is nothing to sweep.
 *
 * While a reserve is to be kept, only the plain CKB beyond it is spent on anything: token top-ups, the fee, the
 * user's output. A token cell that can't be topped up from that waits on the key, a sweep whose fee nothing but
 * the reserve could pay isn't sent, and plain CKB that adds up to less than the reserve isn't touched. So the
 * output kept on the key is never smaller than `keepReserve`, whatever else sits on the key (anyone can send a
 * cell there).
 *
 * `returnableReserve`: a reserve smaller than the destination's smallest cell (62 CKB against the 95 CKB of a
 * recovery account's Omnilock) could never be returned on its own. With this set, a sweep that keeps the reserve
 * keeps that smallest cell's worth instead whenever the key holds enough, so the reserve can leave later.
 */
export async function sweepSettlement(client: ccc.Client, settlementKey: ccc.HexLike, destination: ccc.ScriptLike, keepReserve = 0n, options: { returnableReserve?: boolean } = {}): Promise<string | undefined> {
  const signer = new ccc.SignerCkbPrivateKey(client, settlementKey);
  const from = (await signer.getRecommendedAddressObj()).script;
  const to = ccc.Script.from(destination);
  if (from.eq(to)) return undefined;

  const xudt = await client.getKnownScript(ccc.KnownScript.XUdt);
  const movable = (type: ccc.Script | undefined) => !type
    || (((type.codeHash === xudt.codeHash && type.hashType === xudt.hashType) || isXudtCompatible(type)) && hasPlainTokenArgs(type));
  const cells: ccc.Cell[] = [];
  for await (const cell of client.findCellsByLock(from, undefined, true)) {
    if (movable(cell.cellOutput.type)) cells.push(cell);
    if (cells.length >= MAX_CELLS) break;
  }
  if (cells.length === 0) return undefined;

  // Token cells move as they are, each at least at what it occupies under the destination's lock (an Omnilock
  // needs 176 CKB for a standard xUDT cell where secp256k1 needs 142); the difference comes out of the plain CKB
  // that isn't the reserve. Token cells that can't be topped up from that stay on the key for a later sweep. Plain
  // CKB is pooled: the reserve stays on the key, the rest goes to the user.
  const keeping = keepReserve > 0n;
  const allPlain = cells.filter((cell) => !cell.cellOutput.type);
  const allPlainTotal = allPlain.reduce((total, cell) => total + cell.cellOutput.capacity, 0n);
  // Less than the reserve on the key: it is what is left of the reserve, and no part of it moves or pays for anything.
  const short = keeping && allPlainTotal < keepReserve;
  const plainCells = short ? [] : allPlain;
  const plainTotal = short ? 0n : allPlainTotal;
  const spendable = keeping ? plainTotal - (short ? 0n : keepReserve) : plainTotal;
  const sized = cells.filter((cell) => cell.cellOutput.type).map((cell) => {
    const output = ccc.CellOutput.from({ lock: to, type: cell.cellOutput.type, capacity: 0n });
    const minimum = ccc.fixedPointFrom(output.occupiedSize + ccc.bytesFrom(cell.outputData).length);
    output.capacity = ccc.numMax(cell.cellOutput.capacity, minimum);
    return { cell, output, minimum, extra: output.capacity - cell.cellOutput.capacity };
  }).sort((a, b) => a.extra < b.extra ? -1 : a.extra > b.extra ? 1 : 0);
  let budget = 0n;
  const affordable = sized.filter(({ extra: needed }) => {
    if (budget + needed > spendable) return false;
    budget += needed;
    return true;
  });
  // Too little for a plain cell of its own at the destination (95 CKB at an Omnilock): it joins the reserve, or
  // rides in the first token cell, or waits for a later sweep.
  const minimumPlain = ccc.fixedPointFrom(ccc.CellOutput.from({ lock: to, capacity: 0n }).occupiedSize);
  const returnable = minimumPlain + SWEEP_FEE_MARGIN;

  // The fee comes out of the user's CKB; else out of what the kept output holds beyond the reserve; else out of a
  // token cell's capacity beyond what it occupies. Never out of the reserve, and never out of capacity a cell needs
  // to exist. When every CKB beyond the reserve went into top-ups and nothing can pay, the token cell that needs
  // the largest top-up is left for a later sweep and the rest is tried again; with nothing left to try, the sweep waits.
  for (let count = affordable.length; count >= 0; count--) {
    const tokens = affordable.slice(0, count).map(({ cell, output, minimum, extra }) => ({ cell, minimum, extra, output: output.clone() }));
    const extra = tokens.reduce((total, token) => total + token.extra, 0n);
    const rest = plainTotal - extra;
    // The reserve is kept at a returnable size only when that doesn't hold back a payout: if what would go to the
    // user beyond it is too little for a cell at the destination, while beyond the plain reserve it is enough, the
    // user is paid and the reserve stays as it is.
    const wantsReturnable = options.returnableReserve && keeping && !short && keepReserve < returnable && rest >= returnable;
    const beyondReturnable = rest - returnable;
    const holdsBack = wantsReturnable && beyondReturnable < minimumPlain + SWEEP_FEE_MARGIN && rest - keepReserve >= minimumPlain + SWEEP_FEE_MARGIN;
    const keep = wantsReturnable && !holdsBack ? returnable : (short ? 0n : keepReserve);
    const plan = planSweep(rest, tokens.length, keep);
    if (!plan) continue;
    let { toUser, reserve } = plan;
    if (toUser > 0n && toUser < minimumPlain + SWEEP_FEE_MARGIN) {
      if (reserve > 0n) reserve += toUser;
      else if (tokens.length > 0) tokens[0].output.capacity += toUser;
      else continue;
      toUser = 0n;
    }
    // Nothing leaves the key: no transaction that only turns the key's cells into one of its own, at a fee.
    if (toUser === 0n && tokens.length === 0) continue;
    const plainOutputs = [
      ...(toUser > 0n ? [{ lock: to, capacity: toUser }] : []),
      ...(reserve > 0n ? [{ lock: from, capacity: reserve }] : []),
    ];
    const tx = ccc.Transaction.from({
      inputs: [...plainCells, ...tokens.map(({ cell }) => cell)].map((cell) => ({ previousOutput: cell.outPoint })),
      outputs: [...tokens.map(({ output }) => output), ...plainOutputs],
      outputsData: [...tokens.map(({ cell }) => cell.outputData), ...plainOutputs.map(() => "0x")],
    });
    const userIndex = toUser > 0n ? tokens.length : undefined;
    const reserveIndex = reserve > 0n ? tokens.length + (toUser > 0n ? 1 : 0) : undefined;
    const floor = (index: number) => index === reserveIndex ? keep : index === userIndex ? minimumPlain : tokens[index].minimum;
    const spare = (index: number) => tx.outputs[index].capacity - floor(index);
    const payer = [userIndex, reserveIndex, ...tokens.map((_token, index) => index).sort((x, y) => spare(x) > spare(y) ? -1 : spare(x) < spare(y) ? 1 : 0)]
      .find((index): index is number => index !== undefined && spare(index) >= SWEEP_FEE_MARGIN);
    if (payer === undefined) continue;
    await tx.addCellDepsOfKnownScripts(client, ccc.KnownScript.Secp256k1Blake160);
    await addTokenCellDeps(client, tx, tokens.map(({ cell }) => cell));
    // Every cell that may be spent is already an input: the fee must not draw in another of the key's cells.
    await tx.completeFeeChangeToOutput(signer, payer, undefined, undefined, { shouldAddInputs: false });
    // Whatever the fee rate turned out to be: the payer still holds what it must, and the reserve is whole.
    if (tx.outputs[payer].capacity < floor(payer)) return undefined;
    if (reserveIndex !== undefined && tx.outputs[reserveIndex].capacity < keep) return undefined;
    return signer.sendTransaction(tx);
  }
  return undefined;
}

const TYPE_ID_CODE_HASH = "0x00000000000000000000000000000000000000000000000000545950455f4944";

/** Cell deps for moving xUDT cells: CCC's xUDT deployment, and the RUSD contract for xUDT-compatible ones. */
export async function addTokenCellDeps(client: ccc.Client, tx: ccc.Transaction, cells: Array<{ cellOutput: { type?: ccc.Script } }>): Promise<void> {
  if (cells.some((cell) => cell.cellOutput.type && !isXudtCompatible(cell.cellOutput.type))) {
    await tx.addCellDepsOfKnownScripts(client, ccc.KnownScript.XUdt);
  }
  if (cells.some((cell) => cell.cellOutput.type && isXudtCompatible(cell.cellOutput.type))) {
    const contract = await client.findSingletonCellByType({ codeHash: TYPE_ID_CODE_HASH, hashType: "type", args: RUSD_CONTRACT_TYPE_ID_ARGS }, true);
    if (!contract) throw new Error("Could not find the token contract to move token cells");
    tx.addCellDeps({ outPoint: contract.outPoint, depType: "code" });
  }
}
