import * as ccc from "@ckb-ccc/core";
import { isXudtCompatible } from "./tokens";

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

type ChannelState = { state: { state_name: string; state_flags?: unknown } };

/** True while any channel is open, closing, or closed but not yet settled on-chain. */
export function needsFeeReserve(channels: ChannelState[]): boolean {
  return channels.some(({ state }) => {
    if (String(state.state_name) !== "CLOSED") return true;
    const flags = JSON.stringify(state.state_flags ?? "");
    return flags.includes("WAITING_ONCHAIN_SETTLEMENT") && !flags.includes("ONCHAIN_SETTLEMENT_CONFIRMED");
  });
}

/**
 * How a sweep splits the key's plain CKB: the reserve stays (when there's enough for it), the rest goes to
 * the user. Undefined when there's nothing to move beyond the reserve.
 */
export function planSweep(plainTotal: bigint, tokenCells: number, keepReserve: bigint): { toUser: bigint; reserve: bigint } | undefined {
  let reserve = keepReserve > 0n && plainTotal >= keepReserve ? keepReserve : 0n;
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
 * they are. Returns the transaction hash, or undefined when there is nothing to sweep.
 */
export async function sweepSettlement(client: ccc.Client, settlementKey: ccc.HexLike, destination: ccc.ScriptLike, keepReserve = 0n): Promise<string | undefined> {
  const signer = new ccc.SignerCkbPrivateKey(client, settlementKey);
  const from = (await signer.getRecommendedAddressObj()).script;
  const to = ccc.Script.from(destination);
  if (from.eq(to)) return undefined;

  const xudt = await client.getKnownScript(ccc.KnownScript.XUdt);
  const movable = (type: ccc.Script | undefined) => !type
    || (type.codeHash === xudt.codeHash && type.hashType === xudt.hashType)
    || isXudtCompatible(type);
  const cells: ccc.Cell[] = [];
  for await (const cell of client.findCellsByLock(from, undefined, true)) {
    if (movable(cell.cellOutput.type)) cells.push(cell);
    if (cells.length >= MAX_CELLS) break;
  }
  if (cells.length === 0) return undefined;

  // Token cells move as they are. Plain CKB is pooled: the reserve stays on the key, the rest goes to the user.
  const tokens = cells.filter((cell) => cell.cellOutput.type);
  const plainTotal = cells.filter((cell) => !cell.cellOutput.type).reduce((total, cell) => total + cell.cellOutput.capacity, 0n);
  const plan = planSweep(plainTotal, tokens.length, keepReserve);
  if (!plan) return undefined;
  const { toUser, reserve } = plan;
  const plainOutputs = [
    ...(toUser > 0n ? [{ lock: to, capacity: toUser }] : []),
    ...(reserve > 0n ? [{ lock: from, capacity: reserve }] : []),
  ];
  const tx = ccc.Transaction.from({
    inputs: cells.map((cell) => ({ previousOutput: cell.outPoint })),
    outputs: [...tokens.map((cell) => ({ lock: to, type: cell.cellOutput.type, capacity: cell.cellOutput.capacity })), ...plainOutputs],
    outputsData: [...tokens.map((cell) => cell.outputData), ...plainOutputs.map(() => "0x")],
  });
  await tx.addCellDepsOfKnownScripts(client, ccc.KnownScript.Secp256k1Blake160);
  if (cells.some((cell) => cell.cellOutput.type && !isXudtCompatible(cell.cellOutput.type))) {
    await tx.addCellDepsOfKnownScripts(client, ccc.KnownScript.XUdt);
  }
  if (cells.some((cell) => cell.cellOutput.type && isXudtCompatible(cell.cellOutput.type))) {
    const contract = await client.findSingletonCellByType({ codeHash: TYPE_ID_CODE_HASH, hashType: "type", args: RUSD_CONTRACT_TYPE_ID_ARGS }, true);
    if (!contract) throw new Error("Could not find the token contract to move token cells");
    tx.addCellDeps({ outPoint: contract.outPoint, depType: "code" });
  }

  // The fee comes out of the user's CKB, else the reserve, else a token cell's spare capacity.
  const indexed = tx.outputs.map((output, index) => ({ output, index }));
  const plain = indexed.filter(({ output }) => !output.type);
  const payer = plain[0] ?? indexed.reduce((best, item) => item.output.capacity > best.output.capacity ? item : best);
  await tx.completeFeeChangeToOutput(signer, payer.index);
  return signer.sendTransaction(tx);
}

const TYPE_ID_CODE_HASH = "0x00000000000000000000000000000000000000000000000000545950455f4944";
