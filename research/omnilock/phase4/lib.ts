// Shared helpers for the JoyID verifier and phase 4 testnet proofs (CKB testnet only, throwaway keys in
// keys.json, gitignored, never printed).
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import * as ccc from "@ckb-ccc/core";
import { p256 } from "@noble/curves/nist.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { sha256 } from "@noble/hashes/sha2.js";

export const HERE = dirname(fileURLToPath(import.meta.url));
const KEYS_PATH = join(HERE, "keys.json");
const STATE_PATH = join(HERE, "state.json");
export const client = new ccc.ClientPublicTestnet({ url: "https://testnet.ckb.dev/" });

/**
 * K stands in for the account's Lit key, E1/E2 are EVM backups, J1/J2 are P-256 keys standing in for JoyID
 * passkeys, D1–D4 fund the verifier's deployment. All secp256k1 keys except J1/J2.
 */
const NAMES = ["K", "E1", "E2", "J1", "J2", "D1", "D2", "D3", "D4"] as const;
export type KeyName = (typeof NAMES)[number];
export function loadKeys(): Record<KeyName, string> {
  const keys = existsSync(KEYS_PATH) ? JSON.parse(readFileSync(KEYS_PATH, "utf8")) : {};
  let changed = false;
  for (const name of NAMES) {
    if (keys[name]) continue;
    keys[name] = ccc.hexFrom(name.startsWith("J") ? p256.utils.randomSecretKey() : secp256k1.utils.randomSecretKey());
    changed = true;
  }
  if (changed) writeFileSync(KEYS_PATH, JSON.stringify(keys, null, 2), { mode: 0o600 });
  return keys;
}

export const loadState = (): Record<string, any> => existsSync(STATE_PATH) ? JSON.parse(readFileSync(STATE_PATH, "utf8")) : {};
export const saveState = (patch: Record<string, unknown>) => writeFileSync(STATE_PATH, JSON.stringify({ ...loadState(), ...patch }, null, 2) + "\n");

export const publicKeyOf = (key: string) => ccc.hexFrom(secp256k1.getPublicKey(ccc.bytesFrom(key), true));
export const evmAddressOf = (key: string) => ccc.hexFrom(keccak_256(secp256k1.getPublicKey(ccc.bytesFrom(key), false).slice(1)).slice(12));
export const secpLock = (key: string) => ccc.Script.fromKnownScript(client, ccc.KnownScript.Secp256k1Blake160, ccc.hashCkbShort(publicKeyOf(key)));
export const secpAddress = async (key: string) => ccc.Address.fromScript(await secpLock(key), client).toString();

/** Signs like the Lit action: { r, s, recoveryParam } over a 32-byte digest. */
export function localLitSignature(key: string, digest: ccc.HexLike) {
  const raw = secp256k1.sign(ccc.bytesFrom(digest), ccc.bytesFrom(key), { prehash: false, format: "recovered" });
  return { r: ccc.hexFrom(raw.slice(1, 33)), s: ccc.hexFrom(raw.slice(33, 65)), recoveryParam: raw[0] as 0 | 1 };
}

/** An EVM wallet's personal_sign: r ‖ s ‖ v with v = 27 or 28. */
export function evmPersonalSign(key: string, message: string): ccc.Hex {
  const bytes = new TextEncoder().encode(message);
  const digest = keccak_256(ccc.bytesConcat(new TextEncoder().encode(`\x19Ethereum Signed Message:\n${bytes.length}`), bytes));
  const raw = secp256k1.sign(digest, ccc.bytesFrom(key), { prehash: false, format: "recovered" });
  return ccc.hexFrom(ccc.bytesConcat(raw.slice(1), [raw[0] + 27]));
}

const base64url = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");

/**
 * A P-256 key answering like JoyID's sign-message page: the WebAuthn challenge is the UTF-8 text, authenticatorData
 * is rpIdHash(testnet.joyid.dev) ‖ 0x05 ‖ signCount 0, clientDataJSON has the browser's fields, and the result is
 * what CCC's JoyID signer returns: signMessageRaw's JSON { signature (DER, base64url), alg: -7, message
 * (base64url authenticatorData ‖ clientDataJSON) } and getIdentity's JSON { keyType, publicKey }.
 */
export function joyIdPasskey(key: string) {
  const publicKey = ccc.hexFrom(p256.getPublicKey(ccc.bytesFrom(key), false).slice(1));
  const signMessageRaw = (text: string) => {
    const authData = ccc.bytesConcat(sha256(new TextEncoder().encode("testnet.joyid.dev")), [0x05, 0, 0, 0, 0]);
    const clientData = new TextEncoder().encode(JSON.stringify({
      type: "webauthn.get",
      challenge: base64url(new TextEncoder().encode(text)),
      origin: "https://testnet.joyid.dev",
      crossOrigin: false,
      other_keys_can_be_added_here: "do not compare clientDataJSON against a template. See https://goo.gl/yabPex",
    }));
    const der = p256.sign(ccc.bytesConcat(authData, sha256(clientData)), ccc.bytesFrom(key), { format: "der" });
    return JSON.stringify({ signature: base64url(der), alg: -7, message: base64url(ccc.bytesConcat(authData, clientData)) });
  };
  const identity = JSON.stringify({ keyType: "main_key", publicKey: publicKey.slice(2) });
  return { publicKey, signMessageRaw, identity };
}

export async function waitCommitted(hash: ccc.HexLike, timeoutMs = 300_000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const result = await client.getTransaction(hash);
    if (result?.status === "committed") return result;
    if (result?.status === "rejected") throw new Error(`rejected: ${hash}`);
    await new Promise((resolve) => setTimeout(resolve, 3000));
  }
  throw new Error(`timeout waiting for ${hash}`);
}
