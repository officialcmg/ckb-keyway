import * as ccc from "@ckb-ccc/core";
import { adminListTypeScript, type KeyWayRecovery } from "./account-lock";
import {
  backupAuth,
  evmBackupAuth,
  execAuth,
  joyIdLock,
  joyIdPreimage,
  joyIdPubkeyHash,
  OMNILOCK_AUTH_ETHEREUM_DISPLAYING,
  OMNILOCK_AUTH_EXEC,
  type RecoveryBackup,
} from "./recovery-backups";
import { adminListData, whitelistTree } from "./recovery-smt";

/**
 * The full backup list, written on chain by every transaction that creates or changes a recovery list, so the
 * list and its proofs can be rebuilt from the chain alone. The AdminList cell keeps only the SMT root; the list
 * goes in the `output_type` field of the WitnessArgs at the AdminList output's index, which Omnilock (it reads
 * only `lock`) and Type ID ignore, and which the transaction's signature covers.
 *
 * Format, version 1: "KWRL" ‖ 0x01 ‖ count (1 byte) ‖ entries, each an Omnilock auth flag and what that auth
 * is made from:
 * - 0x12 (EVM wallet) ‖ 20-byte address; auth = 0x12 ‖ address.
 * - 0xFD (JoyID passkey) ‖ 62-byte exec preimage (verifier code hash, hash type, place, bounds, blake160 of the
 *   public key); auth = 0xFD ‖ blake160(preimage). The JoyID address is the main-key lock with args
 *   0x0001 ‖ the preimage's last 20 bytes.
 */
export const RECOVERY_LIST_MAGIC = "0x4b57524c";
export const RECOVERY_LIST_VERSION = 1;
const PREIMAGE_LENGTH = 62;

export type RecoveryListEntry = {
  backup: RecoveryBackup;
  auth: ccc.Hex;
  /** The exec identity's preimage, for a JoyID backup; its witness carries it. */
  preimage?: ccc.Hex;
};

/** The record for these backups, in order. */
export async function recoveryListRecord(client: ccc.Client, backups: RecoveryBackup[]): Promise<ccc.Hex> {
  const entries = await Promise.all(backups.map(async (backup) => {
    if (backup.kind === "evm") return ccc.bytesFrom(evmBackupAuth(backup.address));
    return ccc.bytesConcat([OMNILOCK_AUTH_EXEC], joyIdPreimage(joyIdPubkeyHash(await joyIdLock(client, backup.address))));
  }));
  if (entries.length === 0 || entries.length > 255) throw new Error("A recovery list holds 1 to 255 backups");
  return ccc.hexFrom(ccc.bytesConcat(RECOVERY_LIST_MAGIC, [RECOVERY_LIST_VERSION, entries.length], ...entries));
}

/** Reads a record back into its backups and their auths. Throws on anything but a well-formed version 1 record. */
export async function decodeRecoveryList(client: ccc.Client, record: ccc.HexLike): Promise<RecoveryListEntry[]> {
  const bytes = ccc.bytesFrom(record);
  const invalid = () => new Error("The on-chain recovery list is malformed");
  if (bytes.length < 6 || ccc.hexFrom(bytes.slice(0, 4)) !== RECOVERY_LIST_MAGIC) throw invalid();
  if (bytes[4] !== RECOVERY_LIST_VERSION) throw new Error(`Unknown recovery list version ${bytes[4]}`);
  const joyId = await client.getKnownScript(ccc.KnownScript.JoyId);
  const entries: RecoveryListEntry[] = [];
  let at = 6;
  for (let index = 0; index < bytes[5]; index++) {
    const flag = bytes[at];
    if (flag === OMNILOCK_AUTH_ETHEREUM_DISPLAYING && at + 21 <= bytes.length) {
      const address = ccc.hexFrom(bytes.slice(at + 1, at + 21));
      entries.push({ backup: { kind: "evm", address }, auth: evmBackupAuth(address) });
      at += 21;
    } else if (flag === OMNILOCK_AUTH_EXEC && at + 1 + PREIMAGE_LENGTH <= bytes.length) {
      const preimage = ccc.hexFrom(bytes.slice(at + 1, at + 1 + PREIMAGE_LENGTH));
      const lock = ccc.Script.from({ codeHash: joyId.codeHash, hashType: joyId.hashType, args: ccc.bytesConcat("0x0001", ccc.bytesFrom(preimage).slice(42)) });
      entries.push({ backup: { kind: "joyid", address: ccc.Address.fromScript(lock, client).toString() }, auth: execAuth(preimage), preimage });
      at += 1 + PREIMAGE_LENGTH;
    } else {
      throw invalid();
    }
  }
  if (at !== bytes.length) throw invalid();
  return entries;
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
  entries: RecoveryListEntry[];
  root: ccc.Hex;
  /** Each member's compiled SMT proof, by auth. */
  proofs: Record<string, ccc.Hex>;
};

/**
 * Rebuilds an account's backup list and proofs from chain data alone: the live AdminList cell (by its Type ID),
 * the record in the transaction that created it, and a check that the record hashes to the cell's root.
 */
export async function readRecoveryList(client: ccc.Client, recovery: Pick<KeyWayRecovery, "adminListTypeArgs">): Promise<OnChainRecoveryList> {
  const cell = await client.findSingletonCellByType(adminListTypeScript(recovery), true);
  if (!cell) throw new Error("The recovery list isn't on chain");
  const created = await client.getTransaction(cell.outPoint.txHash);
  if (!created) throw new Error("The recovery list's transaction isn't available");
  const record = recoveryListRecordOf(created.transaction, Number(cell.outPoint.index));
  if (!record) throw new Error("The recovery list's transaction doesn't record its backups");
  const entries = await decodeRecoveryList(client, record);
  const { root, proofs } = whitelistTree(entries.map(({ auth }) => auth));
  if (adminListData(root) !== ccc.hexFrom(cell.outputData)) throw new Error("The recorded backups don't match the recovery list on chain");
  return { cell, entries, root, proofs };
}

/** The auths of these backups, in order. */
export async function backupAuths(client: ccc.Client, backups: RecoveryBackup[]): Promise<ccc.Hex[]> {
  return Promise.all(backups.map((backup) => backupAuth(client, backup)));
}
