import * as ccc from "@ckb-ccc/core";
import { adminListTypeScript, type KeyWayRecovery } from "./account-lock";
import {
  backupAuth,
  EVM_PERSONAL_SIGN_VERIFIER,
  evmPreimage,
  execAuth,
  joyIdLock,
  joyIdPreimage,
  joyIdPubkeyHash,
  JOYID_WEBAUTHN_VERIFIER,
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
 * Format, version 2: "KWRL" ‖ 0x02 ‖ count (1 byte) ‖ entries, each 0xFD ‖ the 62-byte exec preimage (verifier
 * code hash, hash type, place, bounds, the backup's 20-byte id); auth = 0xFD ‖ blake160(preimage). The verifier
 * says what kind of backup it is: KeyWay's EVM verifier (the id is the address) or its WebAuthn verifier (the id is
 * blake160 of the passkey's public key; the JoyID address is the main-key lock with args 0x0001 ‖ the id).
 */
export const RECOVERY_LIST_MAGIC = "0x4b57524c";
export const RECOVERY_LIST_VERSION = 2;
const PREIMAGE_LENGTH = 62;

export type RecoveryListEntry = {
  backup: RecoveryBackup;
  auth: ccc.Hex;
  /** The exec identity's preimage; the backup's witness carries it. */
  preimage: ccc.Hex;
};

/** The record for these backups, in order. */
export async function recoveryListRecord(client: ccc.Client, backups: RecoveryBackup[]): Promise<ccc.Hex> {
  const entries = await Promise.all(backups.map(async (backup) => ccc.bytesConcat([OMNILOCK_AUTH_EXEC], await backupPreimage(client, backup))));
  if (entries.length === 0 || entries.length > 255) throw new Error("A recovery list holds 1 to 255 backups");
  return ccc.hexFrom(ccc.bytesConcat(RECOVERY_LIST_MAGIC, [RECOVERY_LIST_VERSION, entries.length], ...entries));
}

/** The exec preimage of a backup's identity. */
export async function backupPreimage(client: ccc.Client, backup: RecoveryBackup): Promise<ccc.Hex> {
  if (backup.kind === "evm") return evmPreimage(backup.address);
  return joyIdPreimage(joyIdPubkeyHash(await joyIdLock(client, backup.address)));
}

/** Reads a record back into its backups and their auths. Throws on anything but a well-formed version 2 record. */
export async function decodeRecoveryList(client: ccc.Client, record: ccc.HexLike): Promise<RecoveryListEntry[]> {
  const bytes = ccc.bytesFrom(record);
  const invalid = () => new Error("The on-chain recovery list is malformed");
  if (bytes.length < 6 || ccc.hexFrom(bytes.slice(0, 4)) !== RECOVERY_LIST_MAGIC) throw invalid();
  if (bytes[4] !== RECOVERY_LIST_VERSION) throw new Error(`Unknown recovery list version ${bytes[4]}`);
  const joyId = await client.getKnownScript(ccc.KnownScript.JoyId);
  const entries: RecoveryListEntry[] = [];
  let at = 6;
  for (let index = 0; index < bytes[5]; index++) {
    if (bytes[at] !== OMNILOCK_AUTH_EXEC || at + 1 + PREIMAGE_LENGTH > bytes.length) throw invalid();
    const preimage = ccc.hexFrom(bytes.slice(at + 1, at + 1 + PREIMAGE_LENGTH));
    const codeHash = preimage.slice(0, 66);
    const id = ccc.bytesFrom(preimage).slice(42);
    if (codeHash === EVM_PERSONAL_SIGN_VERIFIER.codeHash) {
      entries.push({ backup: { kind: "evm", address: ccc.hexFrom(id) }, auth: execAuth(preimage), preimage });
    } else if (codeHash === JOYID_WEBAUTHN_VERIFIER.codeHash) {
      const lock = ccc.Script.from({ codeHash: joyId.codeHash, hashType: joyId.hashType, args: ccc.bytesConcat("0x0001", id) });
      entries.push({ backup: { kind: "joyid", address: ccc.Address.fromScript(lock, client).toString() }, auth: execAuth(preimage), preimage });
    } else {
      throw invalid();
    }
    // The verifiers are named by data hash with the whole cell; anything else isn't a record KeyWay wrote.
    if (preimage !== (entries.at(-1)!.backup.kind === "evm" ? evmPreimage(ccc.hexFrom(id)) : joyIdPreimage(id))) throw invalid();
    at += 1 + PREIMAGE_LENGTH;
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
  const entries = await decodeRecoveryList(client, record);
  const { root, proofs } = whitelistTree(entries.map(({ auth }) => auth));
  if (adminListData(root) !== ccc.hexFrom(cell.outputData)) throw new Error("The recorded backups don't match the recovery list on chain");
  return { cell, entries, root, proofs };
}

/** The auths of these backups, in order. */
export async function backupAuths(client: ccc.Client, backups: RecoveryBackup[]): Promise<ccc.Hex[]> {
  return Promise.all(backups.map((backup) => backupAuth(client, backup)));
}
