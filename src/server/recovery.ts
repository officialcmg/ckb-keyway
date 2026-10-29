import * as ccc from "@ckb-ccc/core";
import { adminListTypeScript, omnilockArgsFor, omnilockLock, secp256k1Lock, OMNILOCK_OWNER_WITNESS_LOCK_LENGTH, type KeyWayRecovery } from "../sdk/browser/account-lock.ts";
import { backupAuth, describeBackup, MAX_RECOVERY_BACKUPS, parseBackup, parseBackups, verifyBackupOwnership, type RecoveryBackup } from "../sdk/browser/recovery-backups.ts";
import { readRecoveryList, recoveryListRecord, recoveryListRecordOf, setRecoveryListRecord } from "../sdk/browser/recovery-list.ts";
import { adminListData, whitelistTree } from "../sdk/browser/recovery-smt.ts";
import { addTokenCellDeps } from "../sdk/browser/settlement-sweep.ts";
import { formatAsset, isXudtCompatible } from "../sdk/browser/tokens.ts";
import { withUserLock } from "./database.ts";
import { createRecoveryNoticeEmailTemplate } from "./email-template.ts";
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
    await sendRecoveryNotice(context, "Account recovery is on", updated.ckbAddress, backups, transactionHash);
    return { transactionHash, recovery, ckbAddress: updated.ckbAddress, transaction: serializeTransaction(signed) };
  });
}

/**
 * Emails the account's address, its backups and the rescue page after the change is on chain, so the user can
 * reach their funds with a backup even if KeyWay is gone. The change already happened, so a failed email is
 * logged, not thrown.
 */
async function sendRecoveryNotice(context: RecoveryContext, heading: string, address: string, backups: RecoveryBackup[], transactionHash: string): Promise<void> {
  try {
    const template = createRecoveryNoticeEmailTemplate(context.appName, { heading, address, backups: backups.map(({ kind, address }) => `${kind === "evm" ? "EVM wallet" : "JoyID"} ${address}`), network: "CKB testnet" });
    await context.sendEmail(await context.email(), template, `keyway-recovery-notice/${transactionHash}`);
  } catch (error) {
    console.error("[keyway] recovery notice email failed", { cause: error instanceof Error ? error.message.slice(0, 200) : "email" });
  }
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
 * then each token cell moves as it is, and the rest of the CKB less the fee goes to the new address. Witness 0
 * records the full backup list (`recoveryListRecord`) in its output_type.
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
  // The full list goes on chain beside the AdminList (output 0), so it can be rebuilt without KeyWay.
  setRecoveryListRecord(transaction, 0, await recoveryListRecord(client, backups));

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
 * these backups and their on-chain record, every other output goes to the Omnilock that AdminList belongs to,
 * tokens are kept whole, and the fee is within the cap.
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
  if (recoveryListRecordOf(transaction, 0) !== await recoveryListRecord(client, backups)) refuse("the recorded backup list isn't exactly these backups");
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

export type BackupChange = { change: "add" | "remove"; backup: RecoveryBackup };

export type BackupChangePreview = {
  network: "CKB testnet";
  change: "add" | "remove";
  backup: RecoveryBackup & { label: string };
  /** The list after the change. */
  backups: Array<RecoveryBackup & { label: string }>;
  feeCkb: string;
  transactionHash: string;
};

export type BackupChangePlan = {
  transaction: ccc.Transaction;
  omnilock: ccc.Script;
  adminList: ccc.Cell;
  backups: RecoveryBackup[];
  preview: BackupChangePreview;
};

const backupKey = (backup: RecoveryBackup) => `${backup.kind}:${backup.address}`;

/**
 * Adding or removing a backup: preview, request-email-code, apply. The emailed code is always required, and
 * adding needs the new backup's signature over the recovery challenge. Removing the last backup is refused.
 */
export async function recoveryBackupChange(context: RecoveryContext, body: Record<string, unknown>): Promise<unknown> {
  const client = context.client ?? new ccc.ClientPublicTestnet();
  if (!context.wallet.recovery) throw new Error("Account recovery is off");
  const change = parseBackupChange(body);
  if (body.operation === "preview") {
    await limit(context, "sign", { max: 10, window: 60 });
    if (change.change === "add") await verifyBackups(client, context.wallet, [body.backup]);
    const plan = await planBackupChange(client, context.wallet, change);
    const confirmationNonce = await issueRequest(context.user, "recovery", changeDigest(plan, change), { lines: backupChangeLines(plan.preview) }, true);
    return { preview: plan.preview, confirmationNonce, requiresEmailCode: true };
  }
  const nonce = requiredNonce(body.confirmationNonce);
  if (body.operation === "request-email-code") {
    const plan = await planBackupChange(client, context.wallet, change);
    const request = await loadRequest(context.user, "recovery", nonce, changeDigest(plan, change));
    await sendCode(context, "recovery", nonce, change.change === "add" ? "Add a recovery backup" : "Remove a recovery backup", request.summary.lines ?? []);
    return { sent: true };
  }
  if (body.operation !== "apply") throw new Error("A valid backup operation is required");
  return withUserLock(context.user.id, async (sql) => {
    const wallet = await readWallet(context.user, sql);
    if (!wallet || wallet.status !== "ready") throw new Error("KeyWay wallet is not provisioned");
    if (!wallet.recovery) throw new Error("Account recovery is off");
    if (change.change === "add") await verifyBackups(client, wallet, [body.backup]);
    const plan = await planBackupChange(client, wallet, change);
    await loadRequest(context.user, "recovery", nonce, changeDigest(plan, change)).catch(() => {
      throw new Error("This approval expired or your account changed since the preview. Review the backup change again");
    });
    await verifyCode(context.user, "recovery", nonce, body.emailCode);
    await consumeRequest(context.user, "recovery", nonce);
    await checkBackupChangeTransaction(client, plan.transaction, wallet.recovery, plan.backups);
    await context.recordSigning(context.user.id);
    const signed = await signAccountGroups(plan.transaction, [{ script: plan.omnilock, kind: "omnilock" }], client, (message) => sign({ ...context, wallet }, message));
    const transactionHash = await (context.broadcast ?? ((transaction) => client.sendTransaction(transaction, "passthrough")))(signed);
    const recovery: KeyWayRecovery = { ...wallet.recovery, adminListOutPoint: { txHash: transactionHash, index: 0 }, backups: plan.backups };
    await saveWallet(context.user, { ...wallet, recovery, updatedAt: new Date().toISOString() }, sql);
    const heading = change.change === "add" ? "A recovery backup was added" : "A recovery backup was removed";
    await sendRecoveryNotice(context, heading, wallet.ckbAddress, plan.backups, transactionHash);
    return { transactionHash, recovery, transaction: serializeTransaction(signed) };
  });
}

function parseBackupChange(body: Record<string, unknown>): BackupChange {
  if (body.change !== "add" && body.change !== "remove") throw new Error("Say whether to add or remove the backup");
  return { change: body.change, backup: parseBackup(body.backup) };
}

function changeDigest(plan: BackupChangePlan, change: BackupChange): string {
  return hashText(JSON.stringify({ transaction: serializeTransaction(plan.transaction), change }));
}

/** The list as it is on chain: its record, or for a list without one, the stored list if it matches the root. */
async function currentBackups(client: ccc.Client, recovery: KeyWayRecovery): Promise<{ adminList: ccc.Cell; backups: RecoveryBackup[] }> {
  try {
    const list = await readRecoveryList(client, recovery);
    return { adminList: list.cell, backups: list.entries.map(({ backup }) => backup) };
  } catch (error) {
    if (!(error instanceof Error) || !/doesn't record its backups/.test(error.message) || !recovery.backups) throw error;
    const adminList = await client.findSingletonCellByType(adminListTypeScript(recovery), true);
    const { root } = whitelistTree(await Promise.all(recovery.backups.map((backup) => backupAuth(client, backup))));
    if (!adminList || ccc.hexFrom(adminList.outputData) !== adminListData(root)) throw new Error("KeyWay's copy of your backups doesn't match the recovery list on chain");
    return { adminList, backups: recovery.backups };
  }
}

/**
 * The list-update transaction: input 0 is the AdminList cell, then the account's plain Omnilock cells, largest
 * first, until they cover the fee and a change cell. Output 0 recreates the AdminList (same lock, Type ID and
 * capacity) with the new root, and witness 0 records the new list; the rest goes back to the account's own
 * address. Everything is under the account's Omnilock, so the one owner signature covers it.
 */
export async function planBackupChange(client: ccc.Client, wallet: ReadyWallet, change: BackupChange): Promise<BackupChangePlan> {
  const recovery = wallet.recovery;
  if (!recovery) throw new Error("Account recovery is off");
  const omnilock = await omnilockLock(client, recovery);
  const { adminList, backups: current } = await currentBackups(client, recovery);
  if (!adminList.cellOutput.lock.eq(omnilock)) throw new Error("The recovery list isn't this account's");
  const listed = current.some((backup) => backupKey(backup) === backupKey(change.backup));
  let backups: RecoveryBackup[];
  if (change.change === "add") {
    if (listed) throw new Error(`${describeBackup(change.backup)} is already a backup`);
    if (current.length >= MAX_RECOVERY_BACKUPS) throw new Error(`At most ${MAX_RECOVERY_BACKUPS} backups can be added`);
    backups = [...current, change.backup];
  } else {
    if (!listed) throw new Error(`${describeBackup(change.backup)} isn't a backup`);
    if (current.length === 1) throw new Error("Keep at least one backup. Add another backup before removing this one");
    backups = current.filter((backup) => backupKey(backup) !== backupKey(change.backup));
  }
  const { root } = whitelistTree(await Promise.all(backups.map((backup) => backupAuth(client, backup))));
  const data = adminListData(root);

  const plain: ccc.Cell[] = [];
  for await (const cell of client.findCellsByLock(omnilock, null, true)) {
    if (!cell.cellOutput.type && cell.outputData === "0x") plain.push(cell);
  }
  plain.sort((a, b) => a.cellOutput.capacity === b.cellOutput.capacity ? outPointKey(a).localeCompare(outPointKey(b)) : a.cellOutput.capacity > b.cellOutput.capacity ? -1 : 1);
  const output = ccc.CellOutput.from(adminList.cellOutput);
  const changeOutput = ccc.CellOutput.from({ lock: omnilock, capacity: 0n });
  const minimum = occupied(changeOutput, "0x");
  const transaction = ccc.Transaction.from({ inputs: [{ previousOutput: adminList.outPoint }], outputs: [output, changeOutput], outputsData: [data, "0x"] });
  await transaction.addCellDepsOfKnownScripts(client, ccc.KnownScript.OmniLock);
  let funded = 0n;
  let fee = 0n;
  for (const cell of plain) {
    transaction.inputs.push(ccc.CellInput.from({ previousOutput: cell.outPoint }));
    funded += cell.cellOutput.capacity;
    transaction.witnesses = [ccc.hexFrom(ccc.WitnessArgs.from({ lock: ccc.hexFrom(new Uint8Array(OMNILOCK_OWNER_WITNESS_LOCK_LENGTH)) }).toBytes())];
    setRecoveryListRecord(transaction, 0, await recoveryListRecord(client, backups));
    fee = (BigInt(transaction.toBytes().length + 4) * FEE_RATE + 999n) / 1000n;
    if (funded >= minimum + fee) break;
    if (transaction.inputs.length > MAX_CELLS) break;
  }
  if (funded < minimum + fee) throw new Error(`Your balance can't cover changing backups: it needs ${formatCkb(minimum + fee - funded)} CKB more`);
  transaction.outputs[1].capacity = funded - fee;
  const label = (backup: RecoveryBackup) => ({ ...backup, label: describeBackup(backup) });
  return {
    transaction, omnilock, adminList, backups,
    preview: {
      network: "CKB testnet",
      change: change.change,
      backup: label(change.backup),
      backups: backups.map(label),
      feeCkb: formatCkb(fee),
      transactionHash: transaction.hash(),
    },
  };
}

/**
 * Checks a list-update transaction independently of how it was built: input 0 is the account's AdminList and
 * every other input is plain CKB at the account's Omnilock; output 0 recreates the AdminList with the same lock,
 * Type ID and capacity, the root of exactly `backups` and their record; every other output is plain CKB at the
 * account's own address; the fee is within the cap.
 */
export async function checkBackupChangeTransaction(client: ccc.Client, transaction: ccc.Transaction, recovery: KeyWayRecovery, backups: RecoveryBackup[]): Promise<void> {
  const refuse = (reason: string) => { throw new Error(`The backup change doesn't match what KeyWay computed: ${reason}`); };
  const omnilock = await omnilockLock(client, recovery);
  const type = adminListTypeScript(recovery);
  const inputCells = await Promise.all(transaction.inputs.map((input) => input.getCell(client)));
  if (inputCells.length < 2 || inputCells.some(({ cellOutput }) => !cellOutput.lock.eq(omnilock))) refuse("an input isn't this account's");
  if (!inputCells[0].cellOutput.type?.eq(type)) refuse("input 0 isn't the recovery list");
  if (inputCells.slice(1).some(({ cellOutput, outputData }) => cellOutput.type || outputData !== "0x")) refuse("an input isn't plain CKB");
  const [adminList, ...rest] = transaction.outputs;
  if (!adminList || !adminList.lock.eq(omnilock) || !adminList.type?.eq(type) || adminList.capacity !== inputCells[0].cellOutput.capacity) refuse("output 0 doesn't recreate the recovery list");
  const { root } = whitelistTree(await Promise.all(backups.map((backup) => backupAuth(client, backup))));
  if (ccc.hexFrom(transaction.outputsData[0] ?? "0x") !== adminListData(root)) refuse("the recovery list doesn't hold exactly these backups");
  if (recoveryListRecordOf(transaction, 0) !== await recoveryListRecord(client, backups)) refuse("the recorded backup list isn't exactly these backups");
  if (rest.length === 0) refuse("nothing returns to your address");
  rest.forEach((output, index) => {
    if (!output.lock.eq(omnilock) || output.type || ccc.hexFrom(transaction.outputsData[index + 1] ?? "0x") !== "0x") refuse(`output ${index + 1} isn't plain CKB at your address`);
  });
  const fee = inputCells.reduce((sum, { cellOutput }) => sum + cellOutput.capacity, 0n) - transaction.getOutputsCapacity();
  const cap = BigInt(transaction.toBytes().length + 4) * feeRateCap();
  if (fee <= 0n || fee > cap) refuse("the fee is outside KeyWay's limit");
}

/** Lines for the confirmation email, naming the backup being added or removed. */
export function backupChangeLines(preview: BackupChangePreview): string[] {
  return [
    preview.change === "add" ? "Add a recovery backup" : "Remove a recovery backup",
    `${preview.change === "add" ? "Adding" : "Removing"}: ${preview.backup.label}`,
    ...(preview.change === "add" ? ["This backup will be able to move everything in your account without KeyWay."] : []),
    `Backups after this change: ${preview.backups.length}`,
    `Network fee ${preview.feeCkb} CKB`,
    `Network ${preview.network}`,
  ];
}
