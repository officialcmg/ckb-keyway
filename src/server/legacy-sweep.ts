import * as ccc from "@ckb-ccc/core";
import { isAdminListCell, omnilockArgsFor, omnilockScript, secp256k1Lock, verifyRecoveryAnchor, OMNILOCK_OWNER_WITNESS_LOCK_LENGTH, SECP256K1_WITNESS_LOCK_LENGTH, type KeyWayRecovery } from "../sdk/browser/account-lock.ts";
import { addTokenCellDeps } from "../sdk/browser/settlement-sweep.ts";
import { hasPlainTokenArgs, isXudtCompatible } from "../sdk/browser/tokens.ts";
import type { User } from "./auth-user.ts";
import { database, type DatabaseSql } from "./database.ts";
import { signAccountGroups, type SigningGroup } from "./funding-transaction.ts";
import { sign, type SigningContext } from "./general-signing.ts";
import { recordSigningEvent } from "./security-alerts.ts";
import { feeRateCap, formatCkb } from "./transaction-policy.ts";
import { readWallet, type ReadyWallet } from "./user-wallet.ts";

/**
 * After recovery is on, funds can still reach the account's old secp256k1 address (old payers, channels
 * opened before, Fiber settlement and fee-reserve sweeps from nodes started before). There is no monitoring
 * service: each time a recovery user signs in, KeyWay moves what it can from the old address to the
 * account's Omnilock address, built and signed here with the account's own Lit key and no approval dialog.
 */
export type LegacySweepContext = Pick<SigningContext, "user" | "signDigest"> & {
  recordSigning?: (userId: string) => Promise<void>;
  client?: ccc.Client;
  broadcast?: (transaction: ccc.Transaction) => Promise<ccc.Hex>;
};

export type LegacySweepResult =
  | { status: "off" | "busy" | "empty" }
  | { status: "pending"; transactionHash: string }
  | { status: "short"; shortCkb: string }
  | { status: "swept"; transactionHash: string; movedCkb: string; tokenCells: number; topUp: boolean };

const FEE_RATE = 1500n;
const MAX_CELLS = 60;
/** How long a sent sweep the node no longer knows is still treated as in flight. */
const UNKNOWN_GRACE_MS = 10 * 60_000;

/**
 * Starts the sweep after the sign-in response, so signing in never waits for it or fails because of it.
 * Failures are logged; the next sign-in tries again.
 */
export function sweepLegacyAfterSignIn(user: User, context: Omit<LegacySweepContext, "user"> = {}): void {
  setImmediate(() => {
    void sweepLegacyAddress({ ...context, user }).then((result) => {
      if (result.status === "swept") console.info("[keyway] moved funds from the old address to the recovery address", { tx: result.transactionHash, ckb: result.movedCkb, tokenCells: result.tokenCells });
      if (result.status === "short") console.info("[keyway] funds at the old address can't cover a cell at the recovery address yet", { short: result.shortCkb });
    }).catch((error) => console.error("[keyway] old address sweep failed", { cause: error instanceof Error ? error.message.slice(0, 200) : "sweep" }));
  });
}

/**
 * One sweep for one user. A database lock lets only one sign-in sweep at a time (others return "busy"), and
 * the last sweep's hash is kept until it is committed or gone, so a sweep still in the mempool is never
 * rebuilt into a conflicting transaction.
 */
export async function sweepLegacyAddress(context: LegacySweepContext): Promise<LegacySweepResult> {
  const client = context.client ?? new ccc.ClientPublicTestnet();
  return withSweepLock(context.user.id, async (sql) => {
    const wallet = await readWallet(context.user, sql);
    if (wallet?.status !== "ready" || !wallet.recovery) return { status: "off" };
    // Only to a recovery list the chain shows this account made.
    await verifyRecoveryAnchor(client, wallet.litPublicKey, wallet.recovery);

    const [last] = await sql<Array<{ transaction_hash: string; sent_at: Date }>>`
      select transaction_hash, sent_at from keyway_v2_legacy_sweeps where user_id = ${context.user.id}
    `;
    let spent: ccc.OutPoint[] = [];
    if (last) {
      const found = await client.getTransaction(last.transaction_hash);
      const decision = lastSweepDecision(found?.status, last.sent_at, new Date());
      if (decision === "wait") return { status: "pending", transactionHash: last.transaction_hash };
      // The indexer can still list a committed sweep's inputs for a while; they are never reused.
      if (decision === "committed") spent = found!.transaction.inputs.map(({ previousOutput }) => previousOutput);
      await sql`delete from keyway_v2_legacy_sweeps where user_id = ${context.user.id}`;
    }

    // A token cell whose own scripts refuse the move (the node's dry run names it) is left out and the sweep
    // rebuilt, so one such cell doesn't hold back everything else.
    const exclude = [...spent];
    for (let attempt = 0; ; attempt++) {
      const plan = await planLegacySweep(client, wallet, exclude);
      if (plan.left.length > 0 && attempt === 0) {
        console.info("[keyway] cells left at the old address", { cells: plan.left.map(describeCell) });
      }
      if (plan.status === "empty") return { status: "empty" };
      if (plan.status === "short") return { status: "short", shortCkb: formatCkb(plan.shortBy) };

      await checkLegacySweepTransaction(client, plan.transaction, wallet.litPublicKey, wallet.recovery);
      await (context.recordSigning ?? recordSigningEvent)(context.user.id);
      const signed = await signAccountGroups(plan.transaction, plan.groups, client, (digest) => sign({ wallet, signDigest: context.signDigest }, digest));
      const blamed = attempt < MAX_BLAMED ? await blamedTokenCell(client, signed) : undefined;
      if (blamed) {
        console.info("[keyway] a token cell at the old address can't be moved; leaving it", { outPoint: `${blamed.txHash}:${blamed.index}` });
        exclude.push(blamed);
        continue;
      }
      const transactionHash = signed.hash();
      // Recorded before sending, so a crash in between can't lead to a second, conflicting transaction.
      await sql`
        insert into keyway_v2_legacy_sweeps (user_id, transaction_hash, sent_at) values (${context.user.id}, ${transactionHash}, now())
        on conflict (user_id) do update set transaction_hash = excluded.transaction_hash, sent_at = excluded.sent_at
      `;
      try {
        await (context.broadcast ?? ((transaction) => client.sendTransaction(transaction, "passthrough")))(signed);
      } catch (error) {
        await sql`delete from keyway_v2_legacy_sweeps where user_id = ${context.user.id} and transaction_hash = ${transactionHash}`;
        throw error;
      }
      return { status: "swept", transactionHash, movedCkb: formatCkb(plan.movedShannons), tokenCells: plan.tokenCells, topUp: Boolean(plan.topUp) };
    }
  });
}

/** How many cells a sweep leaves out before giving up until the next sign-in. */
const MAX_BLAMED = 3;

/**
 * The input of the old address a node's dry run refuses because of that input's type script, if any. Only token
 * cells carry a type script here, so this is a token the sweep can't move.
 */
export async function blamedTokenCell(client: ccc.Client, transaction: ccc.Transaction): Promise<ccc.OutPoint | undefined> {
  try {
    await client.sendTransactionDry(transaction, "passthrough");
    return undefined;
  } catch (error) {
    const match = /Inputs\[(\d+)\]\.Type/i.exec(error instanceof Error ? error.message : String(error));
    return match ? transaction.inputs[Number(match[1])]?.previousOutput : undefined;
  }
}

/**
 * What to do about the last sweep: wait while the node has it in its pool (or briefly after sending, while
 * it may not have reached the node), skip its inputs once committed, or forget it once rejected or gone.
 */
export function lastSweepDecision(status: ccc.TransactionStatus | undefined, sentAt: Date, now: Date): "wait" | "committed" | "gone" {
  if (status === "sent" || status === "pending" || status === "proposed") return "wait";
  if (status === "committed") return "committed";
  if (status === "rejected") return "gone";
  return now.getTime() - sentAt.getTime() < UNKNOWN_GRACE_MS ? "wait" : "gone";
}

async function withSweepLock(userId: string, task: (sql: DatabaseSql) => Promise<LegacySweepResult>): Promise<LegacySweepResult> {
  const sql = await database();
  const connection = await sql.reserve();
  const key = `keyway-legacy-sweep:${userId}`;
  try {
    const [{ locked }] = await connection<Array<{ locked: boolean }>>`select pg_try_advisory_lock(hashtextextended(${key}, 0)) as locked`;
    if (!locked) return { status: "busy" };
    try {
      return await task(connection as unknown as DatabaseSql);
    } finally {
      await connection`select pg_advisory_unlock(hashtextextended(${key}, 0))`;
    }
  } finally {
    connection.release();
  }
}

type TokenScripts = { xudt: ccc.ScriptInfo; sudt: ccc.ScriptInfo };

async function tokenScripts(client: ccc.Client): Promise<TokenScripts> {
  const [xudt, sudt] = await Promise.all([client.getKnownScript(ccc.KnownScript.XUdt), client.getKnownScript(ccc.KnownScript.SUdt)]);
  return { xudt, sudt };
}

const matches = (type: ccc.Script, known: ccc.ScriptInfo) => type.codeHash === known.codeHash && type.hashType === known.hashType;

/** Plain CKB, a standard token (xUDT without extension flags, sUDT, or xUDT-compatible such as RUSD) with its amount, or anything else. */
export function sweepCellKind(cell: { cellOutput: ccc.CellOutput; outputData: ccc.Hex }, known: TokenScripts): "plain" | "token" | "other" {
  const type = cell.cellOutput.type;
  if (!type) return cell.outputData === "0x" ? "plain" : "other";
  const token = matches(type, known.xudt) || matches(type, known.sudt) || isXudtCompatible(type);
  return token && hasPlainTokenArgs(type) && ccc.bytesFrom(cell.outputData).length >= 16 ? "token" : "other";
}

const occupied = (output: ccc.CellOutput, data: ccc.HexLike) => ccc.fixedPointFrom(output.occupiedSize + ccc.bytesFrom(data).length);

export type LegacySweepPlan = { left: ccc.Cell[] } & (
  | { status: "empty" }
  | { status: "short"; shortBy: bigint }
  | { status: "ready"; transaction: ccc.Transaction; groups: SigningGroup[]; movedShannons: bigint; tokenCells: number; topUp?: ccc.Cell }
);

/**
 * The sweep, built from the chain alone. Every plain cell at the old address is merged into one plain
 * output; token cells move one-to-one with their data, at exactly their Omnilock minimum (176 CKB for a
 * standard xUDT, up from 142 at the old lock), any capacity beyond it joining the plain CKB; the fee comes
 * out of the moved CKB. When the moved CKB can't also cover
 * a 95 CKB plain cell, it is added to the first token cell instead. When even the token cells can't be
 * covered (a lone token cell at the old address usually holds 142 CKB), the largest plain cell at the new
 * address joins as an input and the merged plain output goes back there, so nothing is stranded; with no
 * such cell the sweep waits for a later sign-in. Other cells (Nervos DAO, NFTs, unknown types, cells with
 * data) are left where they are.
 */
export async function planLegacySweep(client: ccc.Client, wallet: ReadyWallet, exclude: ccc.OutPoint[] = []): Promise<LegacySweepPlan> {
  const recovery = requiredRecovery(wallet);
  const secp = await secp256k1Lock(client, wallet.litPublicKey);
  const omnilock = omnilockScript({ omnilock: recovery.omnilock, omnilockArgs: omnilockArgsFor(wallet.litPublicKey, recovery.adminListTypeHash) });
  const known = await tokenScripts(client);
  const cells: ccc.Cell[] = [];
  for await (const cell of client.findCellsByLock(secp, null, true)) {
    if (!exclude.some((outPoint) => outPoint.eq(cell.outPoint))) cells.push(cell);
  }
  cells.sort((a, b) => outPointKey(a).localeCompare(outPointKey(b)));
  const left = cells.filter((cell) => sweepCellKind(cell, known) === "other");
  // Beyond the cap, the rest moves at a later sign-in.
  const movable = cells.filter((cell) => sweepCellKind(cell, known) !== "other").slice(0, MAX_CELLS);
  if (movable.length === 0) return { status: "empty", left };
  const tokens = movable.filter((cell) => cell.cellOutput.type);

  const minimumPlain = occupied(ccc.CellOutput.from({ lock: omnilock, capacity: 0n }), "0x");
  const attempt = async (topUp: ccc.Cell | undefined, withPlain: boolean) => {
    const inputCells = topUp ? [...movable, topUp] : movable;
    const tokenOutputs = tokens.map((cell) => {
      const output = ccc.CellOutput.from({ lock: omnilock, type: cell.cellOutput.type, capacity: 0n });
      output.capacity = occupied(output, cell.outputData);
      return output;
    });
    const plain = withPlain ? [ccc.CellOutput.from({ lock: omnilock, capacity: 0n })] : [];
    const transaction = ccc.Transaction.from({
      inputs: inputCells.map((cell) => ({ previousOutput: cell.outPoint })),
      outputs: [...tokenOutputs, ...plain],
      outputsData: [...tokens.map((cell) => cell.outputData), ...plain.map(() => "0x")],
    });
    await transaction.addCellDepsOfKnownScripts(client, ccc.KnownScript.Secp256k1Blake160);
    if (topUp) transaction.addCellDeps(recovery.omnilock.cellDeps);
    await addTokenCellDeps(client, transaction, tokens.filter((cell) => !matches(cell.cellOutput.type!, known.sudt)));
    if (tokens.some((cell) => matches(cell.cellOutput.type!, known.sudt))) await transaction.addCellDepsOfKnownScripts(client, ccc.KnownScript.SUdt);
    await transaction.prepareSighashAllWitness(secp, SECP256K1_WITNESS_LOCK_LENGTH, client);
    if (topUp) await transaction.prepareSighashAllWitness(omnilock, OMNILOCK_OWNER_WITNESS_LOCK_LENGTH, client);
    const fee = (BigInt(transaction.toBytes().length + 4) * FEE_RATE + 999n) / 1000n;
    // CCC fills a zero capacity with the occupied size, so the plain output is counted out here.
    const tokenCapacity = transaction.outputs.reduce((sum, output) => sum + (output.type ? output.capacity : 0n), 0n);
    const spare = inputCells.reduce((sum, cell) => sum + cell.cellOutput.capacity, 0n) - tokenCapacity - fee;
    return { transaction, spare };
  };
  const groups: SigningGroup[] = [{ script: secp, kind: "secp256k1" }];
  const ready = (transaction: ccc.Transaction, topUp?: ccc.Cell) => ({
    status: "ready" as const, left, transaction, topUp, tokenCells: tokens.length,
    groups: topUp ? [...groups, { script: omnilock, kind: "omnilock" as const }] : groups,
    movedShannons: movable.reduce((sum, cell) => sum + cell.cellOutput.capacity, 0n),
  });

  const merged = await attempt(undefined, true);
  if (merged.spare >= minimumPlain) {
    merged.transaction.outputs[merged.transaction.outputs.length - 1].capacity = merged.spare;
    return ready(merged.transaction);
  }
  if (tokens.length > 0) {
    const tokensOnly = await attempt(undefined, false);
    if (tokensOnly.spare >= 0n) {
      tokensOnly.transaction.outputs[0].capacity += tokensOnly.spare;
      return ready(tokensOnly.transaction);
    }
  }
  const topUp = await largestPlainCell(client, omnilock, recovery);
  if (topUp) {
    const joined = await attempt(topUp, true);
    if (joined.spare >= minimumPlain) {
      joined.transaction.outputs[joined.transaction.outputs.length - 1].capacity = joined.spare;
      return ready(joined.transaction, topUp);
    }
  }
  return { status: "short", left, shortBy: minimumPlain - merged.spare };
}

async function largestPlainCell(client: ccc.Client, lock: ccc.Script, recovery: KeyWayRecovery): Promise<ccc.Cell | undefined> {
  let best: ccc.Cell | undefined;
  for await (const cell of client.findCellsByLock(lock, null, true)) {
    if (cell.cellOutput.type || cell.outputData !== "0x" || isAdminListCell(cell, recovery)) continue;
    if (!best || cell.cellOutput.capacity > best.cellOutput.capacity) best = cell;
  }
  return best;
}

/**
 * The policy for this one transaction shape, checked independently of how it was built: inputs are the
 * account's old secp256k1 cells, plain or standard tokens, plus at most one plain cell of the account's own
 * Omnilock; every output is locked by that Omnilock (computed from the key and the AdminList, never taken
 * from a request); tokens move one-to-one with their data; at most one plain output, without data; no header
 * deps; the fee within the cap. Anything else is refused.
 */
export async function checkLegacySweepTransaction(client: ccc.Client, transaction: ccc.Transaction, publicKey: ccc.HexLike, recovery: KeyWayRecovery): Promise<void> {
  const refuse = (reason: string) => { throw new Error(`The old address sweep doesn't match what KeyWay allows: ${reason}`); };
  const secp = await secp256k1Lock(client, publicKey);
  const omnilock = omnilockScript({ omnilock: recovery.omnilock, omnilockArgs: omnilockArgsFor(publicKey, recovery.adminListTypeHash) });
  const known = await tokenScripts(client);
  if (transaction.version !== 0n || transaction.headerDeps.length > 0) refuse("unexpected version or header deps");
  const inputCells = await Promise.all(transaction.inputs.map((input) => input.getCell(client)));
  const fromOld = inputCells.filter(({ cellOutput }) => cellOutput.lock.eq(secp));
  const fromNew = inputCells.filter(({ cellOutput }) => cellOutput.lock.eq(omnilock));
  if (fromOld.length === 0) refuse("nothing comes from the old address");
  if (fromOld.length + fromNew.length !== inputCells.length) refuse("an input isn't this account's");
  if (fromOld.some((cell) => sweepCellKind(cell, known) === "other")) refuse("an input from the old address isn't plain CKB or a standard token");
  if (fromNew.length > 1) refuse("more than one input from the new address");
  if (fromNew.some((cell) => sweepCellKind(cell, known) !== "plain" || isAdminListCell(cell, recovery))) refuse("the input from the new address isn't plain CKB");

  const outputs = transaction.outputs.map((cellOutput, index) => ({ cellOutput, outputData: ccc.hexFrom(transaction.outputsData[index] ?? "0x") }));
  if (outputs.length === 0) refuse("nothing moves");
  outputs.forEach(({ cellOutput }, index) => {
    if (!cellOutput.lock.eq(omnilock)) refuse(`output ${index} goes somewhere other than the account's recovery address`);
  });
  if (outputs.filter((cell) => sweepCellKind(cell, known) === "plain").length > 1) refuse("more than one plain output");
  if (outputs.some((cell) => sweepCellKind(cell, known) === "other")) refuse("an output isn't plain CKB or a moved token");
  const tokenKeys = (cells: Array<{ cellOutput: ccc.CellOutput; outputData: ccc.Hex }>) =>
    cells.filter(({ cellOutput }) => cellOutput.type).map(({ cellOutput, outputData }) => `${cellOutput.type!.hash()}:${outputData}`).sort();
  if (JSON.stringify(tokenKeys(fromOld)) !== JSON.stringify(tokenKeys(outputs))) refuse("tokens don't move one-to-one with their data");

  const fee = inputCells.reduce((sum, { cellOutput }) => sum + cellOutput.capacity, 0n) - transaction.getOutputsCapacity();
  const cap = BigInt(transaction.toBytes().length + 4) * feeRateCap();
  if (fee <= 0n || fee > cap) refuse("the fee is outside KeyWay's limit");
}

function requiredRecovery(wallet: ReadyWallet): KeyWayRecovery {
  if (!wallet.recovery) throw new Error("Account recovery is off");
  return wallet.recovery;
}

function describeCell(cell: ccc.Cell) {
  return { outPoint: `${cell.outPoint.txHash}:${cell.outPoint.index}`, type: cell.cellOutput.type?.codeHash ?? null, dataBytes: ccc.bytesFrom(cell.outputData).length, ckb: formatCkb(cell.cellOutput.capacity) };
}

function outPointKey(cell: ccc.Cell): string {
  return `${cell.outPoint.txHash}:${cell.outPoint.index.toString().padStart(10, "0")}`;
}
