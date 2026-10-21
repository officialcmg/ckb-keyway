// Shared helpers for the Omnilock opt-in recovery spike (CKB testnet only).
import { ccc } from "@ckb-ccc/core";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync, appendFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const HERE = dirname(fileURLToPath(import.meta.url));
export const KEYS_PATH = join(HERE, "keys.json");
export const STATE_PATH = join(HERE, "state.json");
export const LOG_PATH = join(HERE, "txlog.md");

export const client = new ccc.ClientPublicTestnet({ url: "https://testnet.ckb.dev/" });

export type Keys = { K: string; B1: string; B2: string };

export function loadKeys(): Keys {
  if (!existsSync(KEYS_PATH)) {
    const gen = () => ccc.hexFrom(secp256k1.utils.randomSecretKey());
    writeFileSync(KEYS_PATH, JSON.stringify({ K: gen(), B1: gen(), B2: gen() }, null, 2), { mode: 0o600 });
  }
  return JSON.parse(readFileSync(KEYS_PATH, "utf8"));
}

// Non-secret progress (outpoints, hashes) so steps can run independently.
export function loadState(): Record<string, any> {
  return existsSync(STATE_PATH) ? JSON.parse(readFileSync(STATE_PATH, "utf8")) : {};
}
export function saveState(patch: Record<string, any>) {
  writeFileSync(STATE_PATH, JSON.stringify({ ...loadState(), ...patch }, null, 2));
}
export function logTx(step: string, hash: string, note = "") {
  appendFileSync(LOG_PATH, `- ${step}: \`${hash}\` ${note}\n`);
  console.log(`[${step}] ${hash} ${note}`);
}

export function pubkeyOf(priv: string): ccc.Hex {
  return ccc.hexFrom(secp256k1.getPublicKey(ccc.bytesFrom(priv), true));
}
export function blake160(pub: ccc.HexLike): ccc.Hex {
  return ccc.hexFrom(ccc.bytesFrom(ccc.hashCkb(pub)).slice(0, 20));
}
/** 21-byte Omnilock auth: flag 0x00 (secp256k1/blake160) ‖ blake160(pubkey). */
export function authOf(priv: string): ccc.Hex {
  return ccc.hexFrom(ccc.bytesConcat([0x00], blake160(pubkeyOf(priv))));
}
/** SMT key: auth (21) ‖ 11 zero bytes. */
export function smtKeyOf(priv: string): ccc.Hex {
  return ccc.hexFrom(ccc.bytesConcat(authOf(priv), new Uint8Array(11)));
}

/** Calls the Rust reference tool (sparse-merkle-tree 0.6.1). */
export function smtBuild(keys: string[]): { root: ccc.Hex; proofs: Record<string, ccc.Hex> } {
  const bin = join(HERE, "smt-rs/target/release/smt-ref");
  return JSON.parse(execFileSync(bin, keys, { encoding: "utf8" }));
}

/** RCData union, item 0 = RCRule { smt_root, flags }. flags 0x02 = whitelist. */
export function rcDataRule(root: ccc.HexLike, flags = 0x02): ccc.Hex {
  return ccc.hexFrom(ccc.bytesConcat(ccc.numLeToBytes(0, 4), root, [flags]));
}

export async function omnilockScript(ownerPriv: string, adminListTypeHash: ccc.HexLike): Promise<ccc.Script> {
  const args = ccc.bytesConcat([0x00], blake160(pubkeyOf(ownerPriv)), [0x01], adminListTypeHash);
  if (args.length !== 54) throw new Error(`omnilock args ${args.length} != 54`);
  return ccc.Script.fromKnownScript(client, ccc.KnownScript.OmniLock, args);
}

export async function secpScript(priv: string): Promise<ccc.Script> {
  return ccc.Script.fromKnownScript(client, ccc.KnownScript.Secp256k1Blake160, blake160(pubkeyOf(priv)));
}

// ---- molecule encoding (hand-rolled; tiny and fixed-shape) ----
const u32 = (n: number) => ccc.numLeToBytes(n, 4);
function table(fields: Uint8Array[]): Uint8Array {
  const header = 4 + 4 * fields.length;
  let off = header;
  const offs = fields.map((f) => { const o = off; off += f.length; return u32(o); });
  return ccc.bytesConcat(u32(off), ...offs, ...fields);
}
function fixvec(b: ccc.BytesLike): Uint8Array { const x = ccc.bytesFrom(b); return ccc.bytesConcat(u32(x.length), x); }
function dynvec(items: Uint8Array[]): Uint8Array {
  if (items.length === 0) return u32(4);
  return table(items); // dynvec has the same header layout as a table
}

/** OmniLockWitnessLock { signature: BytesOpt, omni_identity: IdentityOpt, preimage: BytesOpt }. */
export function omniWitnessLock(sig: ccc.BytesLike, identity?: { auth: ccc.HexLike; proofs: { mask: number; proof: ccc.HexLike }[] }): Uint8Array {
  const sigField = fixvec(sig);
  const idField = identity
    ? table([
        ccc.bytesFrom(identity.auth),
        dynvec(identity.proofs.map((p) => table([new Uint8Array([p.mask]), fixvec(p.proof)]))),
      ])
    : new Uint8Array();
  return table([sigField, idField, new Uint8Array()]);
}

export type SignDigest = (digest32: ccc.Hex) => Promise<{ r: ccc.HexLike; s: ccc.HexLike; recoveryParam: number }>;

/** Same shape as lit-actions/sign-ckb-digest.js, but with a local throwaway key. */
export function localSignDigest(priv: string): SignDigest {
  return async (digest) => {
    const sig = secp256k1.sign(ccc.bytesFrom(digest), ccc.bytesFrom(priv), { format: "recovered", prehash: false });
    // noble "recovered" format = recid(1) ‖ r(32) ‖ s(32)
    return { r: ccc.hexFrom(sig.slice(1, 33)), s: ccc.hexFrom(sig.slice(33, 65)), recoveryParam: sig[0] };
  };
}

async function signOmnilockGroup(
  tx: ccc.Transaction,
  lock: ccc.Script,
  signDigest: SignDigest,
  identity?: { auth: ccc.HexLike; proofs: { mask: number; proof: ccc.HexLike }[] },
): Promise<ccc.Transaction> {
  const position = await tx.findInputIndexByLock(lock, client);
  if (position === undefined) throw new Error("no input with this omnilock");
  const finalLen = omniWitnessLock(new Uint8Array(65), identity).length;
  const witness = tx.getWitnessArgsAt(position) ?? ccc.WitnessArgs.from({});
  witness.lock = ccc.hexFrom(new Uint8Array(finalLen)); // whole lock zeroed at its final length
  tx.setWitnessArgsAt(position, witness);
  const info = await tx.getSignHashInfo(lock, client);
  if (!info) throw new Error("no sign hash info");
  const { r, s, recoveryParam } = await signDigest(info.message);
  const sig = ccc.bytesConcat(ccc.bytesFrom(r), ccc.bytesFrom(s), [recoveryParam]);
  if (sig.length !== 65) throw new Error("bad sig length");
  witness.lock = ccc.hexFrom(omniWitnessLock(sig, identity));
  tx.setWitnessArgsAt(position, witness);
  return tx;
}

/** Everyday owner path: 85-byte witness lock, no AdminList dep, no SMT proof. */
export function signOmnilockOwner(tx: ccc.Transaction, lock: ccc.Script, signDigest: SignDigest) {
  return signOmnilockGroup(tx, lock, signDigest);
}

/** Admin (backup) path: identity + one SMT proof (mask 3). Caller adds the AdminList cell dep. */
export function signOmnilockAdmin(tx: ccc.Transaction, lock: ccc.Script, signDigest: SignDigest, auth: ccc.HexLike, proof: ccc.HexLike) {
  return signOmnilockGroup(tx, lock, signDigest, { auth, proofs: [{ mask: 3, proof }] });
}

export function witnessLockLen(admin?: { proof: ccc.HexLike }): number {
  return omniWitnessLock(new Uint8Array(65), admin ? { auth: new Uint8Array(21), proofs: [{ mask: 3, proof: admin.proof }] } : undefined).length;
}

export function txSize(tx: ccc.Transaction): number {
  return tx.toBytes().length + 4; // + offset in block's tx vector
}
export function feeFor(size: number, rate: bigint): bigint {
  return (BigInt(size) * rate + 999n) / 1000n;
}

/** Deduct the fee from output[changeIdx]. Witness placeholders must already be at final length. */
export function payFeeFromOutput(tx: ccc.Transaction, changeIdx: number, rate: bigint): bigint {
  const fee = feeFor(txSize(tx), rate);
  tx.outputs[changeIdx].capacity -= fee;
  return fee;
}

export async function setPlaceholder(tx: ccc.Transaction, lock: ccc.Script, len: number) {
  await tx.prepareSighashAllWitness(lock, len, client);
}

export async function dryRunAndSend(tx: ccc.Transaction, step: string, note = ""): Promise<ccc.Hex> {
  const cycles = await client.sendTransactionDry(tx, "passthrough");
  const inCap = await tx.getInputsCapacity(client);
  console.log(`[${step}] test_tx_pool_accept ok: cycles=${cycles} size=${txSize(tx)} fee=${inCap - tx.getOutputsCapacity()}`);
  const hash = await client.sendTransaction(tx, "passthrough");
  logTx(step, hash, note);
  return hash;
}

export async function waitCommitted(hash: ccc.HexLike, timeoutMs = 300_000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const r = await client.getTransaction(hash);
    if (r?.status === "committed") return r;
    if (r?.status === "rejected") throw new Error(`tx rejected: ${hash}`);
    await new Promise((res) => setTimeout(res, 3000));
  }
  throw new Error(`timeout waiting for ${hash}`);
}

export async function cellsOf(lock: ccc.Script): Promise<ccc.Cell[]> {
  const out: ccc.Cell[] = [];
  for await (const c of client.findCellsByLock(lock, undefined, true)) out.push(c);
  return out;
}

export const FEE_RATE = 1500n;
