import * as ccc from "@ckb-ccc/core";
import { adminListTypeScript, type KeyWayRecovery } from "./account-lock";
import { backupAuth, backupPreimage, execAuth, OMNILOCK_AUTH_EXEC, type RecoveryBackup, type RecoverySalt } from "./recovery-backups";
import { adminListData, whitelistTree } from "./recovery-smt";

/**
 * The backup list, written on chain by every transaction that creates or changes a recovery list, so the list's
 * proofs can be rebuilt from the chain alone. The AdminList cell keeps only the SMT root; the list goes in the
 * `output_type` field of the WitnessArgs at the AdminList output's index, which Omnilock (it reads only `lock`)
 * and Type ID ignore, and which the transaction's signature covers.
 *
 * Format, version 3: "KWRL" ‖ 0x03 ‖ count (1 byte) ‖ the backups' 21-byte auths (0xFD ‖ blake160(preimage)), in
 * order. Only salted auths: no address, passkey hash or verifier, so the record can't link the account to the
 * same backup's other accounts. Whoever holds a backup computes its auth for this account (`backupAuth` with the
 * account's salt) and finds it in the list (`recoveryListEntry`); its proof comes from the whole list.
 */
export const RECOVERY_LIST_MAGIC = "0x4b57524c";
export const RECOVERY_LIST_VERSION = 3;
const AUTH_LENGTH = 21;

/** A backup on an account's list: its auth there and the preimage its witness carries. */
export type RecoveryListEntry = {
  backup: RecoveryBackup;
  auth: ccc.Hex;
  /** The exec identity's preimage (verifier and salted id). */
  preimage: ccc.Hex;
};

/** The record for these auths, in order. */
export function recoveryListRecord(auths: ccc.HexLike[]): ccc.Hex {
  const entries = auths.map((auth) => ccc.bytesFrom(auth));
  if (entries.length === 0 || entries.length > 255) throw new Error("A recovery list holds 1 to 255 backups");
  if (entries.some((auth) => auth.length !== AUTH_LENGTH || auth[0] !== OMNILOCK_AUTH_EXEC)) throw new Error("A recovery list holds only exec auths");
  return ccc.hexFrom(ccc.bytesConcat(RECOVERY_LIST_MAGIC, [RECOVERY_LIST_VERSION, entries.length], ...entries));
}

/** Reads a record back into its auths. Throws on anything but a well-formed version 3 record. */
export function decodeRecoveryList(record: ccc.HexLike): ccc.Hex[] {
  const bytes = ccc.bytesFrom(record);
  const invalid = () => new Error("The on-chain recovery list is malformed");
  if (bytes.length < 6 || ccc.hexFrom(bytes.slice(0, 4)) !== RECOVERY_LIST_MAGIC) throw invalid();
  if (bytes[4] !== RECOVERY_LIST_VERSION) throw new Error(`Unknown recovery list version ${bytes[4]}`);
  const count = bytes[5];
  if (count === 0 || bytes.length !== 6 + count * AUTH_LENGTH) throw invalid();
  const auths: ccc.Hex[] = [];
  for (let at = 6; at < bytes.length; at += AUTH_LENGTH) {
    if (bytes[at] !== OMNILOCK_AUTH_EXEC) throw invalid();
    auths.push(ccc.hexFrom(bytes.slice(at, at + AUTH_LENGTH)));
  }
  if (new Set(auths).size !== auths.length) throw invalid();
  return auths;
}

/**
 * The entry for `backup` in a list of auths for the account with this salt, or undefined when the backup isn't
 * on it. The auth is computed from the backup and the salt, so a match means this backup is a member.
 */
export async function recoveryListEntry(client: ccc.Client, list: { auths: ccc.Hex[]; salt: RecoverySalt }, backup: RecoveryBackup): Promise<RecoveryListEntry | undefined> {
  const preimage = await backupPreimage(client, backup, list.salt);
  const auth = execAuth(preimage);
  return list.auths.includes(auth) ? { backup, auth, preimage } : undefined;
}

/** Puts the record in the WitnessArgs at `index` (the AdminList output's), keeping its lock and input_type. */
export function setRecoveryListRecord(transaction: ccc.Transaction, index: number, record: ccc.HexLike): void {
  const witness = transaction.getWitnessArgsAt(index) ?? ccc.WitnessArgs.from({});
  witness.outputType = ccc.hexFrom(record);
  transaction.setWitnessArgsAt(index, witness);
}

/** The record a transaction carries for its output `index`, if any. */
export function recoveryListRecordOf(transaction: ccc.Transaction, index: number): ccc.Hex | undefined {
  try {
    return transaction.getWitnessArgsAt(index)?.outputType;
  } catch {
    return undefined;
  }
}

export type OnChainRecoveryList = {
  /** The live AdminList cell. */
  cell: ccc.Cell;
  /** The members' salted auths, in order. */
  auths: ccc.Hex[];
  /** The account's salt: the AdminList's type hash. */
  salt: ccc.Hex;
  root: ccc.Hex;
  /** Each member's compiled SMT proof, by auth. */
  proofs: Record<string, ccc.Hex>;
};

/**
 * Rebuilds an account's backup list and proofs from chain data alone: the live AdminList cell, found by its Type
 * ID as Omnilock finds it (whatever its lock), then `recoveryListFrom`.
 */
export async function readRecoveryList(client: ccc.Client, recovery: Pick<KeyWayRecovery, "adminListTypeArgs">): Promise<OnChainRecoveryList> {
  const found = await client.findSingletonCellByType(adminListTypeScript(recovery), true);
  if (!found) throw new Error("The recovery list isn't on chain");
  const list = await recoveryListFrom(client, found.outPoint);
  if (!list.cell.cellOutput.type?.eq(adminListTypeScript(recovery))) throw new Error("The recovery list isn't on chain");
  return list;
}

/**
 * The backup list in the AdminList cell at `outPoint`: the cell is taken from the transaction that created it,
 * after checking that transaction's hash, so the node can't change what the list holds; the record in that
 * transaction gives the members, and must hash to the cell's root.
 */
export async function recoveryListFrom(client: ccc.Client, outPoint: ccc.OutPointLike): Promise<OnChainRecoveryList> {
  const { txHash, index } = ccc.OutPoint.from(outPoint);
  const created = await client.getTransaction(txHash);
  if (!created || created.transaction.hash() !== txHash) throw new Error("The recovery list's transaction isn't available");
  const output = created.transaction.outputs[Number(index)];
  if (!output) throw new Error("The recovery list isn't on chain");
  const cell = ccc.Cell.from({ outPoint: { txHash, index }, cellOutput: output, outputData: created.transaction.outputsData[Number(index)] ?? "0x" });
  const record = recoveryListRecordOf(created.transaction, Number(index));
  if (!record) throw new Error("The recovery list's transaction doesn't record its backups");
  const auths = decodeRecoveryList(record);
  const { root, proofs } = whitelistTree(auths);
  if (adminListData(root) !== ccc.hexFrom(cell.outputData)) throw new Error("The recorded backups don't match the recovery list on chain");
  if (!cell.cellOutput.type) throw new Error("The recovery list isn't on chain");
  return { cell, auths, salt: cell.cellOutput.type.hash(), root, proofs };
}

/** The auths of these backups in the account with this salt, in order. */
export async function backupAuths(client: ccc.Client, backups: RecoveryBackup[], salt: RecoverySalt): Promise<ccc.Hex[]> {
  return Promise.all(backups.map((backup) => backupAuth(client, backup, salt)));
}

/** The account's salt: its AdminList type hash. */
export function recoverySalt(recovery: Pick<KeyWayRecovery, "adminListTypeHash">): ccc.Hex {
  return ccc.hexFrom(recovery.adminListTypeHash);
}
