import * as ccc from "@ckb-ccc/core";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";

/**
 * Backup signers for opt-in account recovery. Each backup is an Omnilock auth, 21 bytes: a flag and a 20-byte
 * id, and the AdminList's whitelist holds one SMT key per backup. A backup is accepted only with a signature
 * over `recoveryBackupChallenge`, proving the user controls it.
 *
 * - EVM wallet, flag 0x12 (EthereumDisplaying): id = the 20-byte address. The wallet personal_signs the text
 *   "CKB transaction: 0x" followed by the sighash in 64 lowercase hex digits (83 bytes, `evmOmnilockMessage`), so
 *   Omnilock recovers the signer from a 65-byte r ‖ s ‖ recid signature over
 *   keccak256("\x19Ethereum Signed Message:\n83" ‖ that text), with recid 0 or 1 (a wallet's v of 27 or 28, minus 27).
 * - JoyID, flag 0xFC (owner lock): id = the first 20 bytes of the JoyID lock script hash. Omnilock needs no
 *   signature then; it only checks that an input of the same transaction has that lock, which JoyID unlocks
 *   with its own passkey signature.
 * - CKB secp256k1 key, flag 0x00: id = blake160(public key). Used in tests; not accepted as a backup.
 */
export type RecoveryBackup = { kind: "evm"; address: string } | { kind: "joyid"; address: string };

/** A backup with its signature over the recovery challenge. */
export type RecoveryBackupProof =
  | { kind: "evm"; address: string; signature: string }
  /** `signature` and `identity` as CCC's JoyID signer returns them from signMessage. */
  | { kind: "joyid"; address: string; signature: string; identity: string };

export const OMNILOCK_AUTH_CKB = 0x00;
/** Omnilock's IdentityFlagsEthereumDisplaying: personal_sign of "CKB transaction: 0x…". */
export const OMNILOCK_AUTH_ETHEREUM_DISPLAYING = 0x12;
export const OMNILOCK_AUTH_OWNER_LOCK = 0xfc;
export const MAX_RECOVERY_BACKUPS = 8;
/** JoyID lock args for a secp256r1 main key: 0x0001 ‖ blake160(64-byte public key). */
const JOYID_MAIN_KEY_ARGS_PREFIX = "0x0001";
const JOYID_ES256 = -7;

const auth = (flag: number, id: ccc.BytesLike): ccc.Hex => {
  const bytes = ccc.bytesFrom(id);
  if (bytes.length !== 20) throw new Error("An Omnilock auth id must be 20 bytes");
  return ccc.hexFrom(ccc.bytesConcat([flag], bytes));
};

export function evmBackupAuth(address: string): ccc.Hex {
  return auth(OMNILOCK_AUTH_ETHEREUM_DISPLAYING, normalizeEvmAddress(address));
}

export function joyIdBackupAuth(lock: ccc.ScriptLike): ccc.Hex {
  return auth(OMNILOCK_AUTH_OWNER_LOCK, ccc.bytesFrom(ccc.Script.from(lock).hash()).slice(0, 20));
}

export function ckbSecp256k1Auth(publicKey: ccc.HexLike): ccc.Hex {
  return auth(OMNILOCK_AUTH_CKB, ccc.hashCkbShort(publicKey));
}

/** The backup's Omnilock auth. JoyID addresses must be JoyID main-key locks on the client's network. */
export async function backupAuth(client: ccc.Client, backup: RecoveryBackup): Promise<ccc.Hex> {
  if (backup.kind === "evm") return evmBackupAuth(backup.address);
  return joyIdBackupAuth(await joyIdLock(client, backup.address));
}

export async function joyIdLock(client: ccc.Client, address: string): Promise<ccc.Script> {
  const invalid = () => new Error("That isn't a JoyID address on this network");
  let script: ccc.Script;
  try {
    script = (await ccc.Address.fromString(address, client)).script;
  } catch {
    throw invalid();
  }
  const joyId = await client.getKnownScript(ccc.KnownScript.JoyId);
  if (script.codeHash !== joyId.codeHash || script.hashType !== joyId.hashType) throw invalid();
  if (!script.args.startsWith(JOYID_MAIN_KEY_ARGS_PREFIX) || ccc.bytesFrom(script.args).length !== 22) {
    throw new Error("Only a JoyID passkey (main key) can be a backup");
  }
  return script;
}

export function normalizeEvmAddress(address: string): ccc.Hex {
  if (typeof address !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(address)) throw new Error("An EVM backup needs a 0x-prefixed 20-byte address");
  return address.toLowerCase() as ccc.Hex;
}

/** Validates a backup from a request or a stored record. */
export function parseBackup(value: unknown): RecoveryBackup {
  if (!value || typeof value !== "object") throw new Error("A backup is invalid");
  const { kind, address } = value as Record<string, unknown>;
  if (kind === "evm" && typeof address === "string") return { kind, address: normalizeEvmAddress(address) };
  if (kind === "joyid" && typeof address === "string" && /^ck[bt]1[0-9a-z]{20,200}$/.test(address)) return { kind, address };
  throw new Error("A backup must be an EVM wallet or a JoyID passkey");
}

export function parseBackups(value: unknown): RecoveryBackup[] {
  if (!Array.isArray(value) || value.length === 0) throw new Error("Add at least one backup");
  if (value.length > MAX_RECOVERY_BACKUPS) throw new Error(`At most ${MAX_RECOVERY_BACKUPS} backups can be added`);
  const backups = value.map(parseBackup);
  if (new Set(backups.map(({ kind, address }) => `${kind}:${address}`)).size !== backups.length) throw new Error("A backup is listed twice");
  return backups;
}

/** How a backup is named in previews, dialogs and emails. */
export function describeBackup(backup: RecoveryBackup): string {
  const short = (value: string) => value.length <= 20 ? value : `${value.slice(0, 10)}…${value.slice(-6)}`;
  return backup.kind === "evm" ? `EVM wallet ${short(backup.address)}` : `JoyID ${short(backup.address)}`;
}

/** The message a backup signs to prove the user controls it. `account` is the account's secp256k1 address. */
export function recoveryBackupChallenge(account: string, backup: RecoveryBackup): string {
  return [
    "KeyWay account recovery",
    "",
    "I control this wallet and approve it as a backup that can recover my KeyWay account.",
    "",
    `Account: ${account}`,
    `Backup: ${backup.kind === "evm" ? `EVM wallet ${normalizeEvmAddress(backup.address)}` : `JoyID ${backup.address}`}`,
  ].join("\n");
}

/** The address an EIP-191 personal_sign signature (r ‖ s ‖ v) recovers to. */
export function evmPersonalSignAddress(message: string | Uint8Array, signature: ccc.HexLike): ccc.Hex {
  const bytes = typeof message === "string" ? new TextEncoder().encode(message) : message;
  return evmAddressFrom(evmPersonalSignDigest(bytes), evmOmnilockSignature(signature));
}

/** A wallet's 65-byte r ‖ s ‖ v signature with v reduced to the 0/1 recovery id Omnilock expects. */
export function evmOmnilockSignature(signature: ccc.HexLike): ccc.Hex {
  const bytes = ccc.bytesFrom(signature).slice();
  if (bytes.length !== 65) throw new Error("An EVM signature must be 65 bytes");
  if (bytes[64] >= 27) bytes[64] -= 27;
  if (bytes[64] > 1) throw new Error("The EVM signature's recovery id is invalid");
  return ccc.hexFrom(bytes);
}

function evmAddressFrom(digest: Uint8Array, signature: ccc.Hex): ccc.Hex {
  const bytes = ccc.bytesFrom(signature);
  const publicKey = secp256k1.recoverPublicKey(Uint8Array.from([bytes[64], ...bytes.slice(0, 64)]), digest, { prehash: false });
  const uncompressed = secp256k1.Point.fromBytes(publicKey).toBytes(false);
  return ccc.hexFrom(keccak_256(uncompressed.slice(1)).slice(12));
}

/**
 * The text an EVM backup (flag 0x12) personal_signs to approve a transaction: "CKB transaction: 0x" and the
 * 32-byte sighash in lowercase hex, as Omnilock's `convert_eth_message_displaying` rebuilds it.
 */
export function evmOmnilockMessage(sighash: ccc.HexLike): string {
  const bytes = ccc.bytesFrom(sighash);
  if (bytes.length !== 32) throw new Error("A sighash must be 32 bytes");
  return `CKB transaction: ${ccc.hexFrom(bytes)}`;
}

/** The digest Omnilock checks a flag-0x12 signature against: personal_sign's hash of `evmOmnilockMessage`. */
export function evmOmnilockDigest(sighash: ccc.HexLike): Uint8Array {
  return evmPersonalSignDigest(new TextEncoder().encode(evmOmnilockMessage(sighash)));
}

const evmPersonalSignDigest = (bytes: Uint8Array) =>
  keccak_256(ccc.bytesConcat(new TextEncoder().encode(`\x19Ethereum Signed Message:\n${bytes.length}`), bytes));

/**
 * Checks a backup's signature over the recovery challenge for this account and returns the backup. EVM:
 * EIP-191 personal_sign by that address. JoyID: a passkey (main key) signature whose public key is the one in
 * the JoyID address's lock args.
 */
export async function verifyBackupOwnership(client: ccc.Client, account: string, value: unknown): Promise<RecoveryBackup> {
  const backup = parseBackup(value);
  const proof = value as Record<string, unknown>;
  const challenge = recoveryBackupChallenge(account, backup);
  const refused = () => new Error(`${describeBackup(backup)} didn't sign the recovery approval`);
  if (typeof proof.signature !== "string") throw refused();
  if (backup.kind === "evm") {
    if (!/^0x[0-9a-fA-F]{130}$/.test(proof.signature)) throw refused();
    let signer: string;
    try { signer = evmPersonalSignAddress(challenge, proof.signature); } catch { throw refused(); }
    if (signer !== normalizeEvmAddress(backup.address)) throw refused();
    return backup;
  }
  const lock = await joyIdLock(client, backup.address);
  if (typeof proof.identity !== "string") throw refused();
  let identity: { publicKey?: unknown; keyType?: unknown };
  let signature: { alg?: unknown };
  try {
    identity = JSON.parse(proof.identity);
    signature = JSON.parse(proof.signature);
  } catch {
    throw refused();
  }
  if (identity.keyType !== "main_key" || signature.alg !== JOYID_ES256 || typeof identity.publicKey !== "string") throw refused();
  const publicKey = identity.publicKey.startsWith("0x") ? identity.publicKey : `0x${identity.publicKey}`;
  if (!/^0x[0-9a-fA-F]{128}$/.test(publicKey)) throw refused();
  if (ccc.hexFrom(ccc.bytesConcat(JOYID_MAIN_KEY_ARGS_PREFIX, ccc.hashCkbShort(publicKey))) !== lock.args) throw refused();
  let valid = false;
  try { valid = await ccc.verifyMessageJoyId(challenge, proof.signature, proof.identity); } catch { valid = false; }
  if (!valid) throw refused();
  return backup;
}

// Molecule, for the two tables the admin witness needs.
const u32 = (value: number) => ccc.numLeToBytes(value, 4);
function table(fields: Uint8Array[]): Uint8Array {
  let offset = 4 + 4 * fields.length;
  const offsets = fields.map((field) => { const at = offset; offset += field.length; return u32(at); });
  return ccc.bytesConcat(u32(offset), ...offsets, ...fields);
}
const fixvec = (bytes: Uint8Array) => ccc.bytesConcat(u32(bytes.length), bytes);

/**
 * OmniLockWitnessLock for the administrator path: { signature, omni_identity: { identity: auth,
 * proofs: [{ mask: 3, proof }] }, preimage: None }. The signature is absent for an owner-lock (0xFC) backup.
 */
export function omnilockAdminWitnessLock(input: { signature?: ccc.HexLike; auth: ccc.HexLike; proof: ccc.HexLike }): ccc.Hex {
  const authBytes = ccc.bytesFrom(input.auth);
  if (authBytes.length !== 21) throw new Error("An Omnilock auth must be 21 bytes");
  const proofs = table([table([Uint8Array.from([3]), fixvec(ccc.bytesFrom(input.proof))])]);
  const identity = table([authBytes, proofs]);
  return ccc.hexFrom(table([input.signature === undefined ? new Uint8Array() : fixvec(ccc.bytesFrom(input.signature)), identity, new Uint8Array()]));
}
