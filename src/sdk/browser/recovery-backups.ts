import * as ccc from "@ckb-ccc/core";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { parseJoyIdSignature, verifyWebAuthn } from "./webauthn";

/**
 * Backup signers for opt-in account recovery. Each backup is an Omnilock exec identity (auth flag 0xFD), 21 bytes:
 * the flag and blake160 of a 62-byte preimage naming one of KeyWay's verifiers (contracts/) by data hash and the
 * backup's 20-byte id salted with the account's: `blake160(id ‖ salt)`, where the salt is the account's AdminList
 * type hash (the last 32 bytes of its Omnilock args, which the verifier reads from the lock it unlocks). The same
 * backup has an unrelated identity in every account, so reading the chain doesn't link one person's accounts in
 * two apps through a shared backup, and no list names its backups. The salt is public, so someone who already
 * knows a backup's address can check whether it is on a given account's list, and a rescue's witness reveals the
 * backup that signed it. The AdminList's whitelist holds one SMT key per backup. A backup is accepted only with a
 * signature over `recoveryBackupChallenge`, proving the user controls it.
 *
 * Both kinds approve a spend by signing the same readable text (`recoveryApprovalText`): where everything goes,
 * how much CKB, how many token cells, the fee and the transaction's sighash. The verifier rebuilds that text from
 * the transaction it runs in and refuses anything that isn't a rescue to one address, so the wallet shows what is
 * approved and a signature for one destination or amount can't move funds anywhere else.
 * - EVM wallet: id = the 20-byte address; contracts/evm-personal-sign checks an EIP-191 personal_sign of the
 *   text by that address.
 * - JoyID passkey: id = blake160 of the passkey's public key, the 20 bytes in the JoyID main key's lock args after
 *   0x0001; contracts/joyid-webauthn checks a WebAuthn assertion whose challenge is the text.
 * - CKB secp256k1 key, flag 0x00: id = blake160(public key). Used in tests; not accepted as a backup.
 */
export type RecoveryBackup = { kind: "evm"; address: string } | { kind: "joyid"; address: string };

/** A backup with its signature over the recovery challenge for `challengeNonce`. */
export type RecoveryBackupProof =
  | { kind: "evm"; address: string; signature: string; challengeNonce: string }
  /** `signature` and `identity` as CCC's JoyID signer returns them from signMessage. */
  | { kind: "joyid"; address: string; signature: string; identity: string; challengeNonce: string };

/** An account's salt: the AdminList type hash, 32 bytes. */
export type RecoverySalt = ccc.HexLike;

export const OMNILOCK_AUTH_CKB = 0x00;
/** Omnilock's IdentityFlagsExec: the identity is blake160 of a preimage naming a binary Omnilock execs. */
export const OMNILOCK_AUTH_EXEC = 0xfd;
export const MAX_RECOVERY_BACKUPS = 8;
/** JoyID lock args for a secp256r1 main key: 0x0001 ‖ blake160(64-byte public key). */
const JOYID_MAIN_KEY_ARGS_PREFIX = "0x0001";
const JOYID_ES256 = -7;
const JOYID_RS256 = -257;

/**
 * KeyWay's verifiers, referenced by data hash (hash_type data1), so the code a backup's identity names can never
 * change; the testnet cells' locks can't be unlocked, and anyone can redeploy the same bytes (contracts/build) if
 * a cell were ever gone. Deployed by research/backup-unlinking/deploy-verifiers.ts (version 3: salted identities).
 */
export const EVM_PERSONAL_SIGN_VERIFIER = {
  codeHash: "0x14715402af1d6cdb6036ac02d10c822e84349c289c938320c2f7e8bb6d54b86f",
  hashType: "data1",
  testnetCellDep: { outPoint: { txHash: "0x1d487850a80c6e75a841e97184d52a6a84bf3405cb8ddc3152b1d03eeed9e089", index: 0 }, depType: "code" },
} as const;
export const JOYID_WEBAUTHN_VERIFIER = {
  codeHash: "0x01ac20c4c1a7e5e073a9369b452382970d7d493ad98169dbfa017df1351e2957",
  hashType: "data1",
  testnetCellDep: { outPoint: { txHash: "0x2b25815f1a4e130878880b079530646887560fcec104fb09e3fdfdec26be58c6", index: 0 }, depType: "code" },
} as const;

/** The verifier a backup of this kind needs as a cell dep. They are deployed on testnet only so far. */
export function verifierCellDep(client: ccc.Client, kind: RecoveryBackup["kind"]): ccc.CellDepLike {
  if (client.addressPrefix !== "ckt") throw new Error("Recovery backups are only available on CKB testnet");
  return (kind === "evm" ? EVM_PERSONAL_SIGN_VERIFIER : JOYID_WEBAUTHN_VERIFIER).testnetCellDep;
}

/**
 * The salt of the account whose Omnilock args these are: `auth (21) ‖ 0x01 (administrator mode) ‖ AdminList type
 * hash (32)`, as the verifiers read it (`keyway_approval::account_salt`). Anything else is refused.
 */
export function accountSalt(omnilockArgs: ccc.HexLike): ccc.Hex {
  const args = ccc.bytesFrom(omnilockArgs);
  if (args.length !== 54 || args[21] !== 0x01) throw new Error("That isn't a KeyWay recovery account's lock");
  return ccc.hexFrom(args.slice(22));
}

/** `blake160(id ‖ salt)`: the 20 bytes an account's identity for a backup commits to. */
export function saltedBackupId(id: ccc.BytesLike, salt: RecoverySalt): ccc.Hex {
  const bytes = ccc.bytesFrom(id);
  const saltBytes = ccc.bytesFrom(salt);
  if (bytes.length !== 20) throw new Error("A backup's id must be 20 bytes");
  if (saltBytes.length !== 32) throw new Error("An account's salt must be 32 bytes");
  return ccc.hexFrom(ccc.hashCkbShort(ccc.bytesConcat(bytes, saltBytes)));
}

/** Exec preimage hash type byte for data1 (Omnilock looks the binary up by data hash for anything but 1). */
const DATA1 = 0x02;

const auth = (flag: number, id: ccc.BytesLike): ccc.Hex => {
  const bytes = ccc.bytesFrom(id);
  if (bytes.length !== 20) throw new Error("An Omnilock auth id must be 20 bytes");
  return ccc.hexFrom(ccc.bytesConcat([flag], bytes));
};

/**
 * An exec identity's preimage, 62 bytes: verifier code hash ‖ hash type (data1) ‖ place 0 (cell dep) ‖ length 0 ‖
 * offset 0 (the whole cell, u32 LE each) ‖ the 20-byte pubkey hash the verifier is given, `saltedBackupId`.
 */
export function execPreimage(codeHash: ccc.HexLike, pubkeyHash: ccc.BytesLike): ccc.Hex {
  const bytes = ccc.bytesFrom(pubkeyHash);
  if (bytes.length !== 20) throw new Error("A backup's id must be 20 bytes");
  return ccc.hexFrom(ccc.bytesConcat(codeHash, [DATA1, 0x00], new Uint8Array(8), bytes));
}

/** The EVM verifier's preimage for an address in the account with this salt. */
export function evmPreimage(address: string, salt: RecoverySalt): ccc.Hex {
  return execPreimage(EVM_PERSONAL_SIGN_VERIFIER.codeHash, saltedBackupId(normalizeEvmAddress(address), salt));
}

/** 0xFD ‖ blake160(preimage) for an EVM address in the account with this salt. */
export function evmBackupAuth(address: string, salt: RecoverySalt): ccc.Hex {
  return execAuth(evmPreimage(address, salt));
}

/** The WebAuthn verifier's preimage for blake160 of a passkey's public key, in the account with this salt. */
export function joyIdPreimage(pubkeyHash: ccc.BytesLike, salt: RecoverySalt, codeHash: ccc.HexLike = JOYID_WEBAUTHN_VERIFIER.codeHash): ccc.Hex {
  return execPreimage(codeHash, saltedBackupId(pubkeyHash, salt));
}

/** 0xFD ‖ blake160(preimage) for a JoyID main-key lock in the account with this salt. */
export function joyIdBackupAuth(lock: ccc.ScriptLike, salt: RecoverySalt): ccc.Hex {
  return execAuth(joyIdPreimage(joyIdPubkeyHash(lock), salt));
}

export function execAuth(preimage: ccc.HexLike): ccc.Hex {
  return auth(OMNILOCK_AUTH_EXEC, ccc.hashCkbShort(preimage));
}

/** blake160 of the passkey's public key, from a JoyID main key's lock args. */
export function joyIdPubkeyHash(lock: ccc.ScriptLike): Uint8Array {
  const args = ccc.bytesFrom(ccc.Script.from(lock).args);
  if (args.length !== 22 || ccc.hexFrom(args.slice(0, 2)) !== JOYID_MAIN_KEY_ARGS_PREFIX) throw new Error("Only a JoyID passkey (main key) can be a backup");
  return args.slice(2);
}

export function ckbSecp256k1Auth(publicKey: ccc.HexLike): ccc.Hex {
  return auth(OMNILOCK_AUTH_CKB, ccc.hashCkbShort(publicKey));
}

/**
 * The backup's Omnilock auth in the account with this salt (its AdminList type hash). JoyID addresses must be
 * JoyID main-key locks on the client's network.
 */
export async function backupAuth(client: ccc.Client, backup: RecoveryBackup, salt: RecoverySalt): Promise<ccc.Hex> {
  return execAuth(await backupPreimage(client, backup, salt));
}

/** The exec preimage of a backup's identity in the account with this salt; the backup's witness carries it. */
export async function backupPreimage(client: ccc.Client, backup: RecoveryBackup, salt: RecoverySalt): Promise<ccc.Hex> {
  if (backup.kind === "evm") return evmPreimage(backup.address, salt);
  return joyIdPreimage(joyIdPubkeyHash(await joyIdLock(client, backup.address)), salt);
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
  joyIdPubkeyHash(script);
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

/** How long a backup has to sign the recovery challenge after KeyWay issues its nonce. */
export const BACKUP_CHALLENGE_TTL_MS = 15 * 60_000;

/** When a challenge nonce (`<expiry in ms>.<random>.<server tag>`, issued by KeyWay's server) stops being accepted. */
export function backupChallengeExpiry(nonce: string): Date {
  const match = /^(\d{13})\.[0-9a-f]{32}\.[0-9a-f]{64}$/.exec(typeof nonce === "string" ? nonce : "");
  if (!match) throw new Error("The backup's approval request is invalid. Start adding the backup again");
  return new Date(Number(match[1]));
}

/**
 * The message a backup signs to prove the user controls it. `account` is the account's secp256k1 address;
 * `nonce` comes from KeyWay's server and expires, so a signature only works for one request, briefly.
 */
export function recoveryBackupChallenge(account: string, backup: RecoveryBackup, nonce: string): string {
  return [
    "KeyWay account recovery",
    "",
    "I control this wallet and approve it as a backup that can recover my KeyWay account.",
    "",
    `Account: ${account}`,
    `Backup: ${backup.kind === "evm" ? `EVM wallet ${normalizeEvmAddress(backup.address)}` : `JoyID ${backup.address}`}`,
    `Request: ${nonce}`,
    `Valid until: ${backupChallengeExpiry(nonce).toISOString()}`,
  ].join("\n");
}

/** The address an EIP-191 personal_sign signature (r ‖ s ‖ v) recovers to. */
export function evmPersonalSignAddress(message: string | Uint8Array, signature: ccc.HexLike): ccc.Hex {
  const bytes = typeof message === "string" ? new TextEncoder().encode(message) : message;
  return evmAddressFrom(evmPersonalSignDigest(bytes), evmSignature(signature));
}

/** A wallet's 65-byte r ‖ s ‖ v signature with v reduced to the 0/1 recovery id. */
export function evmSignature(signature: ccc.HexLike): ccc.Hex {
  const bytes = ccc.bytesFrom(signature).slice();
  if (bytes.length !== 65) throw new Error("An EVM signature must be 65 bytes");
  if (bytes[64] >= 27) bytes[64] -= 27;
  if (bytes[64] > 1) throw new Error("The EVM signature's recovery id is invalid");
  return ccc.hexFrom(bytes);
}

/** The EVM verifier's signature: version 1 ‖ network byte ‖ r ‖ s ‖ v, 67 bytes. */
export function evmApprovalSignature(networkByte: 0 | 1, signature: ccc.HexLike): ccc.Hex {
  return ccc.hexFrom(ccc.bytesConcat([1, networkByte], evmSignature(signature)));
}
export const EVM_APPROVAL_SIGNATURE_LENGTH = 67;

function evmAddressFrom(digest: Uint8Array, signature: ccc.Hex): ccc.Hex {
  const bytes = ccc.bytesFrom(signature);
  const publicKey = secp256k1.recoverPublicKey(Uint8Array.from([bytes[64], ...bytes.slice(0, 64)]), digest, { prehash: false });
  const uncompressed = secp256k1.Point.fromBytes(publicKey).toBytes(false);
  return ccc.hexFrom(keccak_256(uncompressed.slice(1)).slice(12));
}

export const evmPersonalSignDigest = (bytes: Uint8Array) =>
  keccak_256(ccc.bytesConcat(new TextEncoder().encode(`\x19Ethereum Signed Message:\n${bytes.length}`), bytes));

/**
 * Checks a backup's signature over the recovery challenge for this account and its nonce, and returns the backup.
 * EVM: EIP-191 personal_sign by that address. JoyID: a WebAuthn assertion, checked as the on-chain verifier checks
 * spends, by the passkey (main key) whose public key is the one in the JoyID address's lock args. An expired nonce
 * is refused; that the server issued it is the server's own check.
 */
export async function verifyBackupOwnership(client: ccc.Client, account: string, value: unknown, now = new Date()): Promise<RecoveryBackup> {
  const backup = parseBackup(value);
  const proof = value as Record<string, unknown>;
  if (typeof proof.challengeNonce !== "string") throw new Error("The backup's approval request is invalid. Start adding the backup again");
  if (backupChallengeExpiry(proof.challengeNonce) <= now) throw new Error(`${describeBackup(backup)}'s approval expired. Sign with it again`);
  const challenge = recoveryBackupChallenge(account, backup, proof.challengeNonce);
  const refused = () => new Error(`${describeBackup(backup)} didn't sign the recovery approval`);
  const lock = backup.kind === "joyid" ? await joyIdLock(client, backup.address) : undefined;
  if (typeof proof.signature !== "string") throw refused();
  if (backup.kind === "evm" || !lock) {
    if (!/^0x[0-9a-fA-F]{130}$/.test(proof.signature)) throw refused();
    let signer: string;
    try { signer = evmPersonalSignAddress(challenge, proof.signature); } catch { throw refused(); }
    if (signer !== normalizeEvmAddress(backup.address)) throw refused();
    return backup;
  }
  if (typeof proof.identity !== "string") throw refused();
  const publicKey = joyIdMainKey(proof.identity, proof.signature);
  if (!publicKey) throw refused();
  if (ccc.hexFrom(ccc.hashCkbShort(publicKey)) !== ccc.hexFrom(joyIdPubkeyHash(lock))) throw refused();
  let valid = false;
  try { valid = verifyWebAuthn(parseJoyIdSignature(proof.signature, publicKey), challenge); } catch { valid = false; }
  if (!valid) throw refused();
  return backup;
}

/**
 * The 64-byte public key of a JoyID main key from CCC's identity JSON ({ keyType, publicKey }). Session keys
 * (RSA) and sub keys (passkeys added through JoyID later, which only JoyID's CoTA records tie to the address)
 * are refused with a message saying so. Returns undefined when the identity is malformed.
 */
export function joyIdMainKey(identityJson: string, signatureJson?: string): ccc.Hex | undefined {
  let identity: { publicKey?: unknown; keyType?: unknown };
  let alg: unknown = JOYID_ES256;
  try {
    identity = JSON.parse(identityJson);
    if (signatureJson !== undefined) alg = (JSON.parse(signatureJson) as { alg?: unknown }).alg;
  } catch {
    return undefined;
  }
  const keyType = identity.keyType;
  if (alg === JOYID_RS256 || keyType === "main_session_key" || keyType === "sub_session_key") {
    throw new Error("A JoyID session key can't be a backup. Use the JoyID passkey your account was created with");
  }
  if (keyType === "sub_key") {
    throw new Error("A JoyID device added later can't be a backup. Use the JoyID passkey your account was created with");
  }
  if (keyType !== "main_key" || alg !== JOYID_ES256 || typeof identity.publicKey !== "string") return undefined;
  const publicKey = identity.publicKey.startsWith("0x") ? identity.publicKey : `0x${identity.publicKey}`;
  return /^0x[0-9a-fA-F]{128}$/.test(publicKey) ? ccc.hexFrom(publicKey) : undefined;
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
 * proofs: [{ mask: 3, proof }] }, preimage }. Every backup is an exec (0xFD) identity, so the preimage is there.
 */
export function omnilockAdminWitnessLock(input: { signature: ccc.HexLike; auth: ccc.HexLike; proof: ccc.HexLike; preimage?: ccc.HexLike }): ccc.Hex {
  const authBytes = ccc.bytesFrom(input.auth);
  if (authBytes.length !== 21) throw new Error("An Omnilock auth must be 21 bytes");
  const proofs = table([table([Uint8Array.from([3]), fixvec(ccc.bytesFrom(input.proof))])]);
  const identity = table([authBytes, proofs]);
  const preimage = input.preimage === undefined ? new Uint8Array() : fixvec(ccc.bytesFrom(input.preimage));
  return ccc.hexFrom(table([fixvec(ccc.bytesFrom(input.signature)), identity, preimage]));
}
