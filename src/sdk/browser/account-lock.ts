import * as ccc from "@ckb-ccc/core";
import { parseBackup, type RecoveryBackup } from "./recovery-backups.ts";

/**
 * Opt-in account recovery: the account lives at an Omnilock address in administrator mode, owned by the same
 * Lit key, whose AdminList cell lists the user's backup signers. Without it the account keeps the standard
 * secp256k1-blake160 lock of the Lit key.
 */
export type KeyWayRecovery = {
  /** 54 bytes: 0x00 ‖ blake160(Lit public key) ‖ 0x01 (administrator mode) ‖ adminListTypeHash. */
  omnilockArgs: string;
  /** Type ID args of the AdminList cell. */
  adminListTypeArgs: string;
  /** Hash of the AdminList cell's Type ID script. */
  adminListTypeHash: string;
  /** Where the AdminList cell was last seen. It moves when the list changes; the type hash doesn't. */
  adminListOutPoint: { txHash: string; index: number };
  /** The account's secp256k1 address from before recovery was turned on. */
  legacyAddress: string;
  enabledAt: string;
  /** The backups in the AdminList's whitelist, in order. Its root alone can't rebuild their proofs. */
  backups?: RecoveryBackup[];
};

export type KeyWayLockKind = "secp256k1" | "omnilock";

export const SECP256K1_WITNESS_LOCK_LENGTH = 65;
/** OmniLockWitnessLock { signature: Some(65 bytes), omni_identity: None, preimage: None }. */
export const OMNILOCK_OWNER_WITNESS_LOCK_LENGTH = 85;
const OMNILOCK_OWNER_WITNESS_HEADER = "0x55000000100000005500000055000000" + "41000000";
/** Locks a channel can be funded from, so Fiber's funding resolver finds the deps of either account lock. */
export const FUNDING_LOCK_KNOWN_SCRIPTS = [ccc.KnownScript.Secp256k1Blake160, ccc.KnownScript.OmniLock];
const TYPE_ID_CODE_HASH = "0x00000000000000000000000000000000000000000000000000545950455f4944";
const HASH = /^0x[0-9a-fA-F]{64}$/;

export function omnilockArgsFor(publicKey: ccc.HexLike, adminListTypeHash: ccc.HexLike): ccc.Hex {
  return ccc.hexFrom(ccc.bytesConcat([0x00], ccc.hashCkbShort(publicKey), [0x01], adminListTypeHash));
}

export function adminListTypeScript(recovery: Pick<KeyWayRecovery, "adminListTypeArgs">): ccc.Script {
  return ccc.Script.from({ codeHash: TYPE_ID_CODE_HASH, hashType: "type", args: recovery.adminListTypeArgs });
}

/**
 * Reads stored or received recovery settings. Returns undefined when there are none and throws when they are
 * malformed or don't belong to this public key, so a broken record is never mistaken for a plain account.
 */
export function parseRecovery(value: unknown, publicKey: ccc.HexLike): KeyWayRecovery | undefined {
  if (value === undefined || value === null) return undefined;
  const invalid = () => new Error("KeyWay account recovery settings are invalid");
  if (typeof value !== "object") throw invalid();
  const candidate = value as Partial<KeyWayRecovery>;
  const outPoint = candidate.adminListOutPoint;
  if (
    typeof candidate.omnilockArgs !== "string" || !/^0x[0-9a-fA-F]{108}$/.test(candidate.omnilockArgs) ||
    typeof candidate.adminListTypeArgs !== "string" || !/^0x(?:[0-9a-fA-F]{2})*$/.test(candidate.adminListTypeArgs) ||
    typeof candidate.adminListTypeHash !== "string" || !HASH.test(candidate.adminListTypeHash) ||
    !outPoint || typeof outPoint.txHash !== "string" || !HASH.test(outPoint.txHash) ||
    !Number.isSafeInteger(outPoint.index) || outPoint.index < 0 ||
    typeof candidate.legacyAddress !== "string" || typeof candidate.enabledAt !== "string" ||
    (candidate.backups !== undefined && !Array.isArray(candidate.backups))
  ) throw invalid();
  try { candidate.backups?.forEach(parseBackup); } catch { throw invalid(); }
  const typeHash = candidate.adminListTypeHash.toLowerCase();
  if (adminListTypeScript(candidate as KeyWayRecovery).hash() !== typeHash) throw invalid();
  if (candidate.omnilockArgs.toLowerCase() !== omnilockArgsFor(publicKey, typeHash)) throw invalid();
  return candidate as KeyWayRecovery;
}

export async function secp256k1Lock(client: ccc.Client, publicKey: ccc.HexLike): Promise<ccc.Script> {
  return ccc.Script.fromKnownScript(client, ccc.KnownScript.Secp256k1Blake160, ccc.hashCkbShort(publicKey));
}

export async function omnilockLock(client: ccc.Client, recovery: Pick<KeyWayRecovery, "omnilockArgs">): Promise<ccc.Script> {
  return ccc.Script.fromKnownScript(client, ccc.KnownScript.OmniLock, recovery.omnilockArgs);
}

/** The account's locks: the current one first, then the secp256k1 lock it had before recovery, if any. */
export async function accountLocks(
  client: ccc.Client,
  publicKey: ccc.HexLike,
  recovery?: KeyWayRecovery,
): Promise<Array<{ script: ccc.Script; kind: KeyWayLockKind }>> {
  const secp = { script: await secp256k1Lock(client, publicKey), kind: "secp256k1" as const };
  return recovery ? [{ script: await omnilockLock(client, recovery), kind: "omnilock" }, secp] : [secp];
}

export async function currentLock(client: ccc.Client, publicKey: ccc.HexLike, recovery?: KeyWayRecovery): Promise<ccc.Script> {
  return (await accountLocks(client, publicKey, recovery))[0].script;
}

export function witnessLockLength(kind: KeyWayLockKind): number {
  return kind === "omnilock" ? OMNILOCK_OWNER_WITNESS_LOCK_LENGTH : SECP256K1_WITNESS_LOCK_LENGTH;
}

/** The Omnilock owner witness lock around a 65-byte r ‖ s ‖ recid signature. */
export function omnilockOwnerWitnessLock(signature: ccc.HexLike): ccc.Hex {
  const bytes = ccc.bytesFrom(signature);
  if (bytes.length !== SECP256K1_WITNESS_LOCK_LENGTH) throw new Error("An Omnilock signature must be 65 bytes");
  return ccc.hexFrom(ccc.bytesConcat(OMNILOCK_OWNER_WITNESS_HEADER, bytes));
}

/** Whether a cell is the account's AdminList, by its Type ID or by its last known out point. */
export function isAdminListCell(
  cell: { outPoint?: ccc.OutPointLike; cellOutput: { type?: ccc.Script } },
  recovery: KeyWayRecovery | undefined,
): boolean {
  if (!recovery) return false;
  if (cell.cellOutput.type?.hash() === recovery.adminListTypeHash.toLowerCase()) return true;
  return Boolean(cell.outPoint && ccc.OutPoint.from(cell.outPoint).eq(ccc.OutPoint.from(recovery.adminListOutPoint)));
}

/** The AdminList is only ever changed by its own list-update transaction, never by ordinary signing. */
export function refuseAdminListSpend(
  transaction: ccc.Transaction,
  inputCells: Array<{ cellOutput: { type?: ccc.Script } }>,
  recovery: KeyWayRecovery | undefined,
): void {
  if (transaction.inputs.some((input, index) => isAdminListCell({ outPoint: input.previousOutput, cellOutput: inputCells[index].cellOutput }, recovery))) {
    throw new Error("This transaction would spend the account's recovery list, which KeyWay never signs here");
  }
}

/**
 * Funds may only reach an Omnilock of this key when it is the account's own current lock. Any other Omnilock
 * with this key's auth, such as one pointing at an AdminList someone else made, would let that list's
 * members spend what it receives, so a recovery list can only be set up by the recovery flow.
 */
export function refuseForeignOmnilockOutputs(
  transaction: ccc.Transaction,
  omnilock: Pick<ccc.ScriptInfo, "codeHash" | "hashType">,
  publicKey: ccc.HexLike,
  recovery: KeyWayRecovery | undefined,
): void {
  const auth = ccc.hexFrom(ccc.bytesConcat([0x00], ccc.hashCkbShort(publicKey)));
  for (const { lock } of transaction.outputs) {
    if (lock.codeHash !== omnilock.codeHash || lock.hashType !== omnilock.hashType || !lock.args.toLowerCase().startsWith(auth)) continue;
    if (recovery && lock.args.toLowerCase() === recovery.omnilockArgs.toLowerCase()) continue;
    throw new Error("This transaction would send funds to an Omnilock address of this account that isn't its own");
  }
}

/** Capacity held by the AdminList cell when it is live under this lock; it isn't spendable balance. */
export async function adminListCapacity(client: ccc.Client, lock: ccc.Script, recovery: KeyWayRecovery | undefined): Promise<bigint> {
  if (!recovery) return 0n;
  const cell = await client.findSingletonCellByType(adminListTypeScript(recovery));
  return cell && cell.cellOutput.lock.eq(lock) ? cell.cellOutput.capacity : 0n;
}

/**
 * A CCC signer for a KeyWay account's public key that knows its current lock. Without recovery it behaves
 * exactly like CCC's SignerCkbPublicKey. With recovery it reports the Omnilock address first, keeps the old
 * secp256k1 address as the account's too, and prepares 85-byte Omnilock placeholders.
 */
export class KeyWayAccountSigner extends ccc.SignerCkbPublicKey {
  /** Whether prepareTransaction may add cell deps. Off for transactions whose deps are already fixed. */
  protected addsCellDeps = true;

  constructor(client: ccc.Client, publicKey: ccc.HexLike, public readonly recovery?: KeyWayRecovery) {
    super(client, publicKey);
    if (recovery) parseRecovery(recovery, this.publicKey);
  }

  async getRecommendedAddressObj(preference?: unknown): Promise<ccc.Address> {
    if (!this.recovery) return super.getRecommendedAddressObj(preference);
    return ccc.Address.fromScript(await omnilockLock(this.client, this.recovery), this.client);
  }

  async getAddressObjs(): Promise<ccc.Address[]> {
    const addresses = await super.getAddressObjs();
    return this.recovery ? [await this.getRecommendedAddressObj(), ...addresses] : addresses;
  }

  async getRelatedScripts(transactionLike: ccc.TransactionLike): Promise<Array<{ script: ccc.Script; cellDeps: ccc.CellDepInfo[] }>> {
    const related = await super.getRelatedScripts(transactionLike);
    if (!this.recovery) return related;
    const omnilock = await omnilockLock(this.client, this.recovery);
    const transaction = ccc.Transaction.from(transactionLike);
    for (const input of transaction.inputs) {
      if (!(await input.getCell(this.client)).cellOutput.lock.eq(omnilock)) continue;
      related.unshift({ script: omnilock, cellDeps: (await this.client.getKnownScript(ccc.KnownScript.OmniLock)).cellDeps });
      break;
    }
    return related;
  }

  async prepareTransaction(transactionLike: ccc.TransactionLike): Promise<ccc.Transaction> {
    if (!this.recovery && this.addsCellDeps) return super.prepareTransaction(transactionLike);
    const transaction = ccc.Transaction.from(transactionLike);
    const omnilock = this.recovery ? await omnilockLock(this.client, this.recovery) : undefined;
    for (const { script, cellDeps } of await this.getRelatedScripts(transaction)) {
      await transaction.prepareSighashAllWitness(script, witnessLockLength(omnilock && script.eq(omnilock) ? "omnilock" : "secp256k1"), this.client);
      if (this.addsCellDeps) await transaction.addCellDepInfos(this.client, cellDeps);
    }
    return transaction;
  }

  /** CKB under the account's locks, not counting the AdminList cell. */
  async getBalance(): Promise<ccc.Num> {
    const balance = await super.getBalance();
    if (!this.recovery) return balance;
    return balance - await adminListCapacity(this.client, await omnilockLock(this.client, this.recovery), this.recovery);
  }
}
