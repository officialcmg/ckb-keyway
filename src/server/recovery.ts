import * as ccc from "@ckb-ccc/core";
import { adminListTypeScript, omnilockArgsFor, secp256k1Lock, type KeyWayRecovery } from "../sdk/browser/account-lock.ts";
import { backupAuth, describeBackup, parseBackups, verifyBackupOwnership, type RecoveryBackup } from "../sdk/browser/recovery-backups.ts";
import { adminListData, whitelistTree } from "../sdk/browser/recovery-smt.ts";
import { addTokenCellDeps } from "../sdk/browser/settlement-sweep.ts";
import { formatAsset, isXudtCompatible } from "../sdk/browser/tokens.ts";
import { withUserLock } from "./database.ts";
import { serializeTransaction, signAccountGroups } from "./funding-transaction.ts";
import { consumeRequest, hashText, issueRequest, limit, loadRequest, sendCode, sign, verifyCode, type SigningContext } from "./general-signing.ts";
import { feeRateCap, formatCkb } from "./transaction-policy.ts";
import { readWallet, saveWallet, type ReadyWallet } from "./user-wallet.ts";

/** What the recovery service needs beyond signing: a CKB client and a way to broadcast, both replaceable in tests. */
export type RecoveryContext = SigningContext & {
  client?: ccc.Client;
  broadcast?: (transaction: ccc.Transaction) => Promise<ccc.Hex>;
};

const FEE_RATE = 1500n;
const MAX_CELLS = 60;
const SECP_WITNESS_LOCK_LENGTH = 65;

export type RecoveryPreview = {
  network: "CKB testnet";
  /** The account's new Omnilock address. */
  newAddress: string;
  /** Its secp256k1 address, which stays the account's too. */
  legacyAddress: string;
  backups: Array<RecoveryBackup & { label: string }>;
  /** CKB held by the AdminList cell that lists the backups. */
  adminListCkb: string;
  /** The smallest plain cell at the new address. */
  minimumCellCkb: string;
  /** Extra capacity token cells need at the longer Omnilock lock. */
  tokenCellsExtraCkb: string;
  /** AdminList plus the token cells' extra capacity: CKB that stops being spendable. */
  lockedCkb: string;
  feeCkb: string;
  /** Plain CKB that arrives at the new address after the AdminList, token cells and fee. */
  movedCkb: string;
  tokens: Array<{ asset: string; amount: string; amountText: string }>;
  /** Cells the transaction can't move (other contracts' cells, cells with data); they stay at the old address. */
  cellsLeft: number;
  transactionHash: string;
};

export type RecoveryPlan = {
  transaction: ccc.Transaction;
  inputCells: ccc.Cell[];
  secp: ccc.Script;
  omnilock: ccc.Script;
  adminListType: ccc.Script;
  adminListData: ccc.Hex;
  preview: RecoveryPreview;
};

/** Turning recovery on: preview, request-email-code, enable. The emailed code is always required. */
export async function recoverySetup(context: RecoveryContext, body: Record<string, unknown>): Promise<unknown> {
  const client = context.client ?? new ccc.ClientPublicTestnet();
  if (context.wallet.recovery) throw new Error("Account recovery is already on");
  const backups = parseBackups(body.backups);
  if (body.operation === "preview") {
    await limit(context, "sign", { max: 10, window: 60 });
    await verifyBackups(client, context.wallet, body.backups as unknown[]);
    const plan = await planRecovery(client, context.wallet, backups);
    const confirmationNonce = await issueRequest(context.user, "recovery", planDigest(plan, backups), { lines: recoveryLines(plan.preview) }, true);
    return { preview: plan.preview, confirmationNonce, requiresEmailCode: true };
  }
  const nonce = requiredNonce(body.confirmationNonce);
  if (body.operation === "request-email-code") {
    const plan = await planRecovery(client, context.wallet, backups);
    const request = await loadRequest(context.user, "recovery", nonce, planDigest(plan, backups));
    await sendCode(context, "recovery", nonce, "Turn on account recovery", request.summary.lines ?? []);
    return { sent: true };
  }
  if (body.operation !== "enable") throw new Error("A valid recovery operation is required");
  return withUserLock(context.user.id, async (sql) => {
    const wallet = await readWallet(context.user, sql);
    if (!wallet || wallet.status !== "ready") throw new Error("KeyWay wallet is not provisioned");
    if (wallet.recovery) throw new Error("Account recovery is already on");
    await verifyBackups(client, wallet, body.backups as unknown[]);
    const plan = await planRecovery(client, wallet, backups);
    // The digest binds the approval to this exact transaction; any change in the account's cells refuses it.
    const digest = planDigest(plan, backups);
    await loadRequest(context.user, "recovery", nonce, digest).catch(() => {
      throw new Error("This approval expired or your account changed since the preview. Review turning on recovery again");
    });
    await verifyCode(context.user, "recovery", nonce, body.emailCode);
    await consumeRequest(context.user, "recovery", nonce);
    await checkRecoveryTransaction(client, plan.transaction, wallet.litPublicKey, backups);
    await context.recordSigning(context.user.id);
    const signed = await signAccountGroups(plan.transaction, [{ script: plan.secp, kind: "secp256k1" }], client, (message) => sign({ ...context, wallet }, message));
    const transactionHash = await (context.broadcast ?? ((transaction) => client.sendTransaction(transaction, "passthrough")))(signed);
    const recovery: KeyWayRecovery = {
      omnilockArgs: plan.omnilock.args,
      adminListTypeArgs: plan.adminListType.args,
      adminListTypeHash: plan.adminListType.hash(),
      adminListOutPoint: { txHash: transactionHash, index: 0 },
      legacyAddress: plan.preview.legacyAddress,
      enabledAt: new Date().toISOString(),
      backups,
    };
    const updated: ReadyWallet = { ...wallet, ckbAddress: plan.preview.newAddress, recovery, updatedAt: new Date().toISOString() };
    await saveWallet(context.user, updated, sql);
    return { transactionHash, recovery, ckbAddress: updated.ckbAddress, transaction: serializeTransaction(signed) };
  });
}

async function verifyBackups(client: ccc.Client, wallet: ReadyWallet, proofs: unknown[]): Promise<void> {
  const account = ccc.Address.fromScript(await secp256k1Lock(client, wallet.litPublicKey), client).toString();
  for (const proof of proofs) await verifyBackupOwnership(client, account, proof);
}

function planDigest(plan: RecoveryPlan, backups: RecoveryBackup[]): string {
  return hashText(JSON.stringify({ transaction: serializeTransaction(plan.transaction), backups }));
}

/** Movable cells: plain CKB, and xUDT tokens (CCC's deployment or RUSD's) whose data starts with the amount. */
function cellKind(cell: ccc.Cell, xudt: ccc.ScriptInfo): "plain" | "token" | "other" {
  const type = cell.cellOutput.type;
  if (!type) return cell.outputData === "0x" ? "plain" : "other";
  const isXudt = (type.codeHash === xudt.codeHash && type.hashType === xudt.hashType) || isXudtCompatible(type);
  return isXudt && ccc.bytesFrom(cell.outputData).length >= 16 ? "token" : "other";
}

const occupied = (output: ccc.CellOutput, data: ccc.HexLike) => ccc.fixedPointFrom(output.occupiedSize + ccc.bytesFrom(data).length);

/**
 * The one transaction that turns recovery on, built from the account's own secp256k1 cells: input 0 is its
 * largest plain cell, which fixes the AdminList's Type ID and so the new address. Output 0 is the AdminList
 * (Type ID, locked by the new Omnilock, RCRule data with the backups' root, at its exact occupied capacity),
 * then each token cell moves as it is, and the rest of the CKB less the fee goes to the new address.
 */
export async function planRecovery(client: ccc.Client, wallet: ReadyWallet, backups: RecoveryBackup[]): Promise<RecoveryPlan> {
  const secp = await secp256k1Lock(client, wallet.litPublicKey);
  const xudt = await client.getKnownScript(ccc.KnownScript.XUdt);
  const cells: ccc.Cell[] = [];
  for await (const cell of client.findCellsByLock(secp, null, true)) cells.push(cell);
  cells.sort((a, b) => outPointKey(a).localeCompare(outPointKey(b)));
  const plain = cells.filter((cell) => cellKind(cell, xudt) === "plain");
  const tokens = cells.filter((cell) => cellKind(cell, xudt) === "token");
  if (plain.length === 0) throw new Error("Your balance can't cover turning on recovery: it needs plain CKB at your address");
  if (plain.length + tokens.length > MAX_CELLS) throw new Error("Your account has too many cells to move in one transaction");
  const first = plain.reduce((best, cell) => cell.cellOutput.capacity > best.cellOutput.capacity ? cell : best);
  const inputCells = [first, ...[...plain, ...tokens].filter((cell) => cell !== first)];

  const input0 = ccc.CellInput.from({ previousOutput: first.outPoint });
  const adminListType = adminListTypeScript({ adminListTypeArgs: ccc.hashTypeId(input0, 0) });
  const omnilock = await ccc.Script.fromKnownScript(client, ccc.KnownScript.OmniLock, omnilockArgsFor(wallet.litPublicKey, adminListType.hash()));
  const { root } = whitelistTree(await Promise.all(backups.map((backup) => backupAuth(client, backup))));
  const data = adminListData(root);

  const adminList = ccc.CellOutput.from({ lock: omnilock, type: adminListType, capacity: 0n });
  adminList.capacity = occupied(adminList, data);
  const tokenOutputs = tokens.map((cell) => {
    const output = ccc.CellOutput.from({ lock: omnilock, type: cell.cellOutput.type, capacity: 0n });
    output.capacity = ccc.numMax(cell.cellOutput.capacity, occupied(output, cell.outputData));
    return output;
  });
  const change = ccc.CellOutput.from({ lock: omnilock, capacity: 0n });
  const transaction = ccc.Transaction.from({
    inputs: inputCells.map((cell) => ({ previousOutput: cell.outPoint })),
    outputs: [adminList, ...tokenOutputs, change],
    outputsData: [data, ...tokens.map((cell) => cell.outputData), "0x"],
  });
  await transaction.addCellDepsOfKnownScripts(client, ccc.KnownScript.Secp256k1Blake160);
  await addTokenCellDeps(client, transaction, tokens);
  transaction.witnesses = inputCells.map((_, index) => index === 0
    ? ccc.hexFrom(ccc.WitnessArgs.from({ lock: ccc.hexFrom(new Uint8Array(SECP_WITNESS_LOCK_LENGTH)) }).toBytes())
    : "0x");

  const totalIn = inputCells.reduce((sum, cell) => sum + cell.cellOutput.capacity, 0n);
  const fee = (BigInt(transaction.toBytes().length + 4) * FEE_RATE + 999n) / 1000n;
  const reserved = adminList.capacity + tokenOutputs.reduce((sum, output) => sum + output.capacity, 0n);
  const minimum = occupied(change, "0x");
  if (totalIn < reserved + fee + minimum) {
    throw new Error(`Your balance can't cover turning on recovery: it needs ${formatCkb(reserved + fee + minimum - totalIn)} CKB more`);
  }
  transaction.outputs[transaction.outputs.length - 1].capacity = totalIn - reserved - fee;

  const tokenTotals = new Map<string, bigint>();
  for (const cell of tokens) {
    const asset = cell.cellOutput.type!.hash();
    tokenTotals.set(asset, (tokenTotals.get(asset) ?? 0n) + ccc.numLeFromBytes(ccc.bytesFrom(cell.outputData).slice(0, 16)));
  }
  const tokenExtra = tokenOutputs.reduce((sum, output, index) => sum + output.capacity - tokens[index].cellOutput.capacity, 0n);
  return {
    transaction, inputCells, secp, omnilock, adminListType, adminListData: data,
    preview: {
      network: "CKB testnet",
      newAddress: ccc.Address.fromScript(omnilock, client).toString(),
      legacyAddress: ccc.Address.fromScript(secp, client).toString(),
      backups: backups.map((backup) => ({ ...backup, label: describeBackup(backup) })),
      adminListCkb: formatCkb(adminList.capacity),
      minimumCellCkb: formatCkb(minimum),
      tokenCellsExtraCkb: formatCkb(tokenExtra),
      lockedCkb: formatCkb(adminList.capacity + tokenExtra),
      feeCkb: formatCkb(fee),
      movedCkb: formatCkb(totalIn - reserved - fee),
      tokens: [...tokenTotals].map(([asset, amount]) => ({ asset, amount: amount.toString(), amountText: formatAsset(amount, asset) })),
      cellsLeft: cells.length - inputCells.length,
      transactionHash: transaction.hash(),
    },
  };
}

/**
 * Checks the transaction against the rules of turning recovery on, independently of how it was built: it
 * spends only the account's secp256k1 cells, output 0 is the AdminList for input 0's Type ID with exactly
 * these backups, every other output goes to the Omnilock that AdminList belongs to, tokens are kept whole,
 * and the fee is within the cap.
 */
export async function checkRecoveryTransaction(client: ccc.Client, transaction: ccc.Transaction, publicKey: ccc.HexLike, backups: RecoveryBackup[]): Promise<void> {
  const refuse = (reason: string) => { throw new Error(`The recovery transaction doesn't match what KeyWay computed: ${reason}`); };
  const secp = await secp256k1Lock(client, publicKey);
  const inputCells = await Promise.all(transaction.inputs.map((input) => input.getCell(client)));
  if (inputCells.length === 0 || inputCells.some(({ cellOutput }) => !cellOutput.lock.eq(secp))) refuse("an input isn't this account's");
  if (inputCells[0].cellOutput.type || inputCells[0].outputData !== "0x") refuse("input 0 isn't plain CKB");
  const adminListType = adminListTypeScript({ adminListTypeArgs: ccc.hashTypeId(transaction.inputs[0], 0) });
  const omnilock = await ccc.Script.fromKnownScript(client, ccc.KnownScript.OmniLock, omnilockArgsFor(publicKey, adminListType.hash()));
  const { root } = whitelistTree(await Promise.all(backups.map((backup) => backupAuth(client, backup))));
  const [adminList, ...rest] = transaction.outputs;
  if (!adminList || !adminList.lock.eq(omnilock) || !adminList.type?.eq(adminListType)) refuse("output 0 isn't the account's recovery list");
  const data = ccc.hexFrom(transaction.outputsData[0] ?? "0x");
  if (data !== adminListData(root)) refuse("the recovery list doesn't hold exactly these backups");
  if (adminList.capacity !== occupied(adminList, data)) refuse("the recovery list's capacity is wrong");
  if (rest.length === 0) refuse("nothing moves to the new address");
  rest.forEach((output, index) => {
    if (!output.lock.eq(omnilock)) refuse(`output ${index + 1} goes somewhere other than your new address`);
    if (output.type?.codeHash === adminListType.codeHash) refuse(`output ${index + 1} is a second Type ID cell`);
    if (!output.type && ccc.hexFrom(transaction.outputsData[index + 1] ?? "0x") !== "0x") refuse(`output ${index + 1} carries data`);
  });
  const tokens = (cells: Array<{ cellOutput: ccc.CellOutput; outputData: ccc.Hex }>) => {
    const totals = new Map<string, bigint>();
    for (const { cellOutput, outputData } of cells) {
      if (!cellOutput.type) continue;
      const key = cellOutput.type.hash();
      totals.set(key, (totals.get(key) ?? 0n) + ccc.numLeFromBytes(ccc.bytesFrom(outputData).slice(0, 16)));
    }
    return totals;
  };
  const before = tokens(inputCells);
  const after = tokens(rest.map((cellOutput, index) => ({ cellOutput, outputData: ccc.hexFrom(transaction.outputsData[index + 1] ?? "0x") })));
  if (before.size !== after.size || [...before].some(([asset, amount]) => after.get(asset) !== amount)) refuse("tokens don't all move to the new address");
  const fee = inputCells.reduce((sum, { cellOutput }) => sum + cellOutput.capacity, 0n) - transaction.getOutputsCapacity();
  const cap = BigInt(transaction.toBytes().length + 4) * feeRateCap();
  if (fee <= 0n || fee > cap) refuse("the fee is outside KeyWay's limit");
}

/** Lines for the confirmation email, naming the backups. */
export function recoveryLines(preview: RecoveryPreview): string[] {
  return [
    "Turn on account recovery",
    ...preview.backups.map(({ label }) => `Backup: ${label}`),
    `New address: ${preview.newAddress.slice(0, 12)}…${preview.newAddress.slice(-6)}`,
    "Your address will change because you're turning on recovery.",
    `Locks ${preview.lockedCkb} CKB (${preview.adminListCkb} CKB for the recovery list)`,
    `Network fee ${preview.feeCkb} CKB`,
    `Network ${preview.network}`,
  ];
}

function outPointKey(cell: ccc.Cell): string {
  return `${cell.outPoint.txHash}:${cell.outPoint.index.toString().padStart(10, "0")}`;
}

function requiredNonce(value: unknown): string {
  if (typeof value !== "string" || !/^[0-9a-f-]{36}$/i.test(value)) throw new Error("A recovery confirmation is required");
  return value;
}
