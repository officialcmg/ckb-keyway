import * as ccc from "@ckb-ccc/core";
import { parseBackup, type RecoveryBackup } from "./recovery-backups";

/**
 * The Omnilock binary a KeyWay recovery account runs, referenced by data hash (hash_type data1) so its code
 * can never change under the account: an upgrade of the official deployment, or a CCC release that points
 * `KnownScript.OmniLock` elsewhere, doesn't touch it. `cellDeps` are the genesis secp256k1 dep group (Omnilock's
 * owner path reads secp256k1_data from it) and the code cell.
 */
export type OmnilockDeployment = { codeHash: ccc.Hex; hashType: "data1"; cellDeps: Array<{ outPoint: { txHash: ccc.Hex; index: number }; depType: "code" | "depGroup" }> };

/**
 * Testnet: KeyWay's own copy of the official testnet Omnilock bytes (139,936 bytes), deployed by
 * research/omnilock/audit-fixes/deploy-omnilock.ts under a lock nobody can unlock, so the cell can't be
 * consumed. Mainnet: the official mainnet cell, by its data hash; it sits under a multisig, so an upgrade there
 * would remove the dep (funds frozen until anyone redeploys the same bytes) but couldn't change the code.
 */
export const KEYWAY_OMNILOCK: Record<"testnet" | "mainnet", OmnilockDeployment> = {
  testnet: {
    codeHash: "0x6b29b6f10346b43c540e53806ba88ba0fe3a0c3a29d7448ef555840c8f8318fa",
    hashType: "data1",
    cellDeps: [
      { outPoint: { txHash: "0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37", index: 0 }, depType: "depGroup" },
      { outPoint: { txHash: "0xf4ce65847089d24bbc8e7d999f396d4227d34376bbfef0f5e3c11967c5a13271", index: 0 }, depType: "code" },
    ],
  },
  mainnet: {
    codeHash: "0x768f306681da232ceb0b94f436c5f813377179762a831c5ad8797bd4fd2d118d",
    hashType: "data1",
    cellDeps: [
      { outPoint: { txHash: "0x71a7ba8fc96349fea0ed3a5c47992e3b4084b031a42264a018e0072e8172e46c", index: 0 }, depType: "depGroup" },
      { outPoint: { txHash: "0xc76edf469816aa22f416503c38d0b533d2a018e253e379f134c3985b3472c842", index: 0 }, depType: "code" },
    ],
  },
};

/** KeyWay's Omnilock on the client's network, for turning recovery on. */
export function keywayOmnilock(client: Pick<ccc.Client, "addressPrefix">): OmnilockDeployment {
  return client.addressPrefix === "ckb" ? KEYWAY_OMNILOCK.mainnet : KEYWAY_OMNILOCK.testnet;
}

/** The deployment with this code hash, if it is one of KeyWay's. */
export function knownOmnilock(codeHash: string, hashType: string): OmnilockDeployment | undefined {
  return Object.values(KEYWAY_OMNILOCK).find((deployment) => deployment.codeHash === codeHash.toLowerCase() && deployment.hashType === hashType);
}

/**
 * Opt-in account recovery: the account lives at an Omnilock address in administrator mode, owned by the same
 * Lit key, whose AdminList cell lists the user's backup signers. Without it the account keeps the standard
 * secp256k1-blake160 lock of the Lit key.
 */
export type KeyWayRecovery = {
  /** 54 bytes: 0x00 ‖ blake160(Lit public key) ‖ 0x01 (administrator mode) ‖ adminListTypeHash. */
  omnilockArgs: string;
  /** The Omnilock the account and its AdminList run, fixed when recovery was turned on. */
  omnilock: OmnilockDeployment;
  /** Type ID args of the AdminList cell. */
  adminListTypeArgs: string;
  /** Hash of the AdminList cell's Type ID script. */
  adminListTypeHash: string;
  /** Where the AdminList cell was last seen. It moves when the list changes; the type hash doesn't. */
  adminListOutPoint: { txHash: string; index: number };
  /**
   * The transaction that turned recovery on. Its input 0 was the account's own secp256k1 cell and fixes the
   * AdminList's Type ID, which ties the list to this account on chain (`verifyRecoveryAnchor`).
   */
  enableTransactionHash: string;
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
/** Locks a channel can be funded from. KeyWay's pinned Omnilock isn't a CCC known script: see `fundingLockCellDeps`. */
export const FUNDING_LOCK_KNOWN_SCRIPTS = [ccc.KnownScript.Secp256k1Blake160];
const TYPE_ID_CODE_HASH = "0x00000000000000000000000000000000000000000000000000545950455f4944";
const HASH = /^0x[0-9a-fA-F]{64}$/;

export function omnilockArgsFor(publicKey: ccc.HexLike, adminListTypeHash: ccc.HexLike): ccc.Hex {
  return ccc.hexFrom(ccc.bytesConcat([0x00], ccc.hashCkbShort(publicKey), [0x01], adminListTypeHash));
}

export function adminListTypeScript(recovery: Pick<KeyWayRecovery, "adminListTypeArgs">): ccc.Script {
  return ccc.Script.from({ codeHash: TYPE_ID_CODE_HASH, hashType: "type", args: recovery.adminListTypeArgs });
}

/** The account's Omnilock script: KeyWay's pinned Omnilock with the account's args. */
export function omnilockScript(recovery: Pick<KeyWayRecovery, "omnilockArgs" | "omnilock">): ccc.Script {
  return ccc.Script.from({ codeHash: recovery.omnilock.codeHash, hashType: recovery.omnilock.hashType, args: recovery.omnilockArgs });
}

/**
 * The AdminList's own lock: the same Omnilock and Lit key without administrator mode (args 0x00 ‖
 * blake160(public key) ‖ 0x00), so only the Lit key can spend or rewrite the list, never a backup. Omnilock finds
 * the list by its type hash alone, so this lock isn't part of the account's address.
 */
export function adminListLock(recovery: Pick<KeyWayRecovery, "omnilockArgs" | "omnilock">): ccc.Script {
  const args = ccc.bytesFrom(recovery.omnilockArgs);
  return ccc.Script.from({ codeHash: recovery.omnilock.codeHash, hashType: recovery.omnilock.hashType, args: ccc.bytesConcat(args.slice(0, 21), [0x00]) });
}

const sameDeps = (a: OmnilockDeployment["cellDeps"], b: OmnilockDeployment["cellDeps"]) =>
  a.length === b.length && a.every((dep, index) => dep.depType === b[index].depType && dep.outPoint.index === b[index].outPoint.index && dep.outPoint.txHash.toLowerCase() === b[index].outPoint.txHash);

/**
 * Reads stored or received recovery settings. Returns undefined when there are none and throws when they are
 * malformed, name an Omnilock deployment that isn't KeyWay's, or don't belong to this public key, so a broken
 * record is never mistaken for a plain account. Whether the chain backs the record is `verifyRecoveryAnchor`.
 */
export function parseRecovery(value: unknown, publicKey: ccc.HexLike): KeyWayRecovery | undefined {
  if (value === undefined || value === null) return undefined;
  const invalid = () => new Error("KeyWay account recovery settings are invalid");
  if (typeof value !== "object") throw invalid();
  const candidate = value as Partial<KeyWayRecovery>;
  const outPoint = candidate.adminListOutPoint;
  const omnilock = candidate.omnilock;
  if (
    typeof candidate.omnilockArgs !== "string" || !/^0x[0-9a-fA-F]{108}$/.test(candidate.omnilockArgs) ||
    typeof candidate.adminListTypeArgs !== "string" || !/^0x(?:[0-9a-fA-F]{2})*$/.test(candidate.adminListTypeArgs) ||
    typeof candidate.adminListTypeHash !== "string" || !HASH.test(candidate.adminListTypeHash) ||
    !outPoint || typeof outPoint.txHash !== "string" || !HASH.test(outPoint.txHash) ||
    !Number.isSafeInteger(outPoint.index) || outPoint.index < 0 ||
    typeof candidate.enableTransactionHash !== "string" || !HASH.test(candidate.enableTransactionHash) ||
    !omnilock || typeof omnilock.codeHash !== "string" || typeof omnilock.hashType !== "string" || !Array.isArray(omnilock.cellDeps) ||
    typeof candidate.legacyAddress !== "string" || typeof candidate.enabledAt !== "string" ||
    (candidate.backups !== undefined && !Array.isArray(candidate.backups))
  ) throw invalid();
  const known = knownOmnilock(omnilock.codeHash, omnilock.hashType);
  if (!known || !sameDeps(omnilock.cellDeps, known.cellDeps)) throw invalid();
  try { candidate.backups?.forEach(parseBackup); } catch { throw invalid(); }
  const typeHash = candidate.adminListTypeHash.toLowerCase();
  if (adminListTypeScript(candidate as KeyWayRecovery).hash() !== typeHash) throw invalid();
  if (candidate.omnilockArgs.toLowerCase() !== omnilockArgsFor(publicKey, typeHash)) throw invalid();
  return candidate as KeyWayRecovery;
}

/**
 * Checks on chain that the AdminList a recovery record names was made by this account: the enabling transaction
 * is committed (and is the one asked for), its input 0 was a cell under the account's own secp256k1 lock (checked
 * against the transaction that created that cell), the list's Type ID comes from that input, and output 0 is the
 * list under its owner-only lock. Nobody but the Lit key can spend the account's cells, so nobody else can make
 * such a list; a record pointing at any other list, or at another Omnilock, is refused. Results are cached per
 * record, so this is one chain lookup per process and record.
 */
export async function verifyRecoveryAnchor(client: ccc.Client, publicKey: ccc.HexLike, recovery: KeyWayRecovery): Promise<void> {
  parseRecovery(recovery, publicKey);
  const key = [ccc.hexFrom(publicKey), recovery.enableTransactionHash, recovery.adminListTypeArgs, recovery.omnilockArgs, recovery.omnilock.codeHash, client.addressPrefix].join(":").toLowerCase();
  let pending = anchors.get(key);
  if (!pending) {
    pending = checkAnchor(client, publicKey, recovery);
    anchors.set(key, pending);
    pending.catch(() => anchors.delete(key));
  }
  return pending;
}

const anchors = new Map<string, Promise<void>>();

async function checkAnchor(client: ccc.Client, publicKey: ccc.HexLike, recovery: KeyWayRecovery): Promise<void> {
  const refuse = (reason: string) => new Error(`This account's recovery record doesn't match the chain: ${reason}`);
  if (knownOmnilock(recovery.omnilock.codeHash, recovery.omnilock.hashType) !== keywayOmnilock(client)) throw refuse("it names another network's Omnilock");
  const enable = await client.getTransaction(recovery.enableTransactionHash);
  if (!enable || enable.status !== "committed") throw refuse("the transaction that turned recovery on isn't committed");
  const transaction = enable.transaction;
  if (transaction.hash() !== recovery.enableTransactionHash.toLowerCase()) throw refuse("the node returned another transaction");
  const input0 = transaction.inputs[0];
  if (!input0) throw refuse("the transaction that turned recovery on has no inputs");
  const previous = await client.getTransaction(input0.previousOutput.txHash);
  if (!previous || previous.transaction.hash() !== input0.previousOutput.txHash) throw refuse("the account's first input can't be read");
  const spent = previous.transaction.outputs[Number(input0.previousOutput.index)];
  if (!spent || !spent.lock.eq(await secp256k1Lock(client, publicKey))) throw refuse("the recovery list wasn't made from this account's own cell");
  if (ccc.hashTypeId(input0, 0) !== recovery.adminListTypeArgs.toLowerCase()) throw refuse("the recovery list's Type ID doesn't come from this account");
  const [adminList] = transaction.outputs;
  if (!adminList?.type?.eq(adminListTypeScript(recovery))) throw refuse("output 0 isn't the recovery list");
  if (!adminList.lock.eq(adminListLock(recovery))) throw refuse("the recovery list isn't locked to this account's key alone");
}

export async function secp256k1Lock(client: ccc.Client, publicKey: ccc.HexLike): Promise<ccc.Script> {
  return ccc.Script.fromKnownScript(client, ccc.KnownScript.Secp256k1Blake160, ccc.hashCkbShort(publicKey));
}

export async function omnilockLock(_client: ccc.Client, recovery: Pick<KeyWayRecovery, "omnilockArgs" | "omnilock">): Promise<ccc.Script> {
  return omnilockScript(recovery);
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

/**
 * The AdminList is only ever changed by KeyWay's own list-update transaction (`checkBackupChangeTransaction`),
 * never by ordinary signing: no input may be the list, by Type ID or out point, or anything under its
 * owner-only lock.
 */
export function refuseAdminListSpend(
  transaction: ccc.Transaction,
  inputCells: Array<{ cellOutput: { type?: ccc.Script; lock?: ccc.Script } }>,
  recovery: KeyWayRecovery | undefined,
): void {
  if (!recovery) return;
  const listLock = adminListLock(recovery);
  if (transaction.inputs.some((input, index) =>
    isAdminListCell({ outPoint: input.previousOutput, cellOutput: inputCells[index].cellOutput }, recovery) || inputCells[index].cellOutput.lock?.eq(listLock))) {
    throw new Error("This transaction would spend the account's recovery list, which KeyWay never signs here");
  }
}

/**
 * Funds may only reach an Omnilock of this key when it is the account's own current lock. Any other Omnilock
 * with this key's auth, such as one pointing at an AdminList someone else made, would let that list's
 * members spend what it receives, so a recovery list can only be set up by the recovery flow. `omnilocks` are
 * CCC's Omnilock deployment; KeyWay's pinned ones are always checked too.
 */
export function refuseForeignOmnilockOutputs(
  transaction: ccc.Transaction,
  omnilocks: Pick<ccc.ScriptInfo, "codeHash" | "hashType"> | Array<Pick<ccc.ScriptInfo, "codeHash" | "hashType">>,
  publicKey: ccc.HexLike,
  recovery: KeyWayRecovery | undefined,
): void {
  const auth = ccc.hexFrom(ccc.bytesConcat([0x00], ccc.hashCkbShort(publicKey)));
  const known = [...(Array.isArray(omnilocks) ? omnilocks : [omnilocks]), ...Object.values(KEYWAY_OMNILOCK)];
  for (const { lock } of transaction.outputs) {
    if (!known.some(({ codeHash, hashType }) => lock.codeHash === codeHash && lock.hashType === hashType) || !lock.args.toLowerCase().startsWith(auth)) continue;
    if (recovery && lock.args.toLowerCase() === recovery.omnilockArgs.toLowerCase()) continue;
    throw new Error("This transaction would send funds to an Omnilock address of this account that isn't its own");
  }
}

/** The Omnilock's cell deps in Fiber's RPC shape, for the external funding resolver. */
export function fundingLockCellDeps(recovery: Pick<KeyWayRecovery, "omnilock">) {
  return recovery.omnilock.cellDeps.map(({ outPoint, depType }) => ({
    out_point: { tx_hash: outPoint.txHash, index: `0x${outPoint.index.toString(16)}` as ccc.Hex },
    dep_type: depType === "depGroup" ? "dep_group" as const : "code" as const,
  }));
}

/**
 * A CCC signer for a KeyWay account's public key that knows its current lock. Without recovery it behaves
 * exactly like CCC's SignerCkbPublicKey. With recovery it reports only the Omnilock address and prepares 85-byte
 * Omnilock placeholders. The old secp256k1 address isn't one of its addresses, so CCC never picks its cells for
 * a transaction: the sign-in sweep owns them (`recovery.legacyAddress` still names it).
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
    return this.recovery ? [await this.getRecommendedAddressObj()] : super.getAddressObjs();
  }

  async getRelatedScripts(transactionLike: ccc.TransactionLike): Promise<Array<{ script: ccc.Script; cellDeps: ccc.CellDepInfo[] }>> {
    const related = await super.getRelatedScripts(transactionLike);
    if (!this.recovery) return related;
    const omnilock = await omnilockLock(this.client, this.recovery);
    const transaction = ccc.Transaction.from(transactionLike);
    for (const input of transaction.inputs) {
      if (!(await input.getCell(this.client)).cellOutput.lock.eq(omnilock)) continue;
      related.unshift({ script: omnilock, cellDeps: this.recovery.omnilock.cellDeps.map((cellDep) => ccc.CellDepInfo.from({ cellDep })) });
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

}
