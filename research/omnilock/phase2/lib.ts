// Shared helpers for the phase 2 testnet proof (CKB testnet only, throwaway keys in keys.json, gitignored).
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import * as ccc from "@ckb-ccc/core";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";

export const HERE = dirname(fileURLToPath(import.meta.url));
const KEYS_PATH = join(HERE, "keys.json");
const STATE_PATH = join(HERE, "state.json");
export const client = new ccc.ClientPublicTestnet({ url: "https://testnet.ckb.dev/" });

/** K stands in for the account's Lit key; E is the EVM backup. */
export function loadKeys(): { K: string; E: string } {
  if (!existsSync(KEYS_PATH)) {
    const gen = () => ccc.hexFrom(secp256k1.utils.randomSecretKey());
    writeFileSync(KEYS_PATH, JSON.stringify({ K: gen(), E: gen() }, null, 2), { mode: 0o600 });
  }
  return JSON.parse(readFileSync(KEYS_PATH, "utf8"));
}

export const loadState = (): Record<string, any> => existsSync(STATE_PATH) ? JSON.parse(readFileSync(STATE_PATH, "utf8")) : {};
export const saveState = (patch: Record<string, unknown>) => writeFileSync(STATE_PATH, JSON.stringify({ ...loadState(), ...patch }, null, 2));

export const publicKeyOf = (key: string) => ccc.hexFrom(secp256k1.getPublicKey(ccc.bytesFrom(key), true));
export const evmAddressOf = (key: string) => ccc.hexFrom(keccak_256(secp256k1.getPublicKey(ccc.bytesFrom(key), false).slice(1)).slice(12));

/** Signs like the Lit action: { r, s, recoveryParam } over a 32-byte digest. */
export function localLitSignature(key: string, digest: ccc.HexLike) {
  const raw = secp256k1.sign(ccc.bytesFrom(digest), ccc.bytesFrom(key), { prehash: false, format: "recovered" });
  return { r: ccc.hexFrom(raw.slice(1, 33)), s: ccc.hexFrom(raw.slice(33, 65)), recoveryParam: raw[0] as 0 | 1 };
}

/** An EVM wallet's personal_sign: r ‖ s ‖ v with v = 27 or 28. */
export function evmPersonalSign(key: string, message: Uint8Array): ccc.Hex {
  const digest = keccak_256(ccc.bytesConcat(new TextEncoder().encode(`\x19Ethereum Signed Message:\n${message.length}`), message));
  const raw = secp256k1.sign(digest, ccc.bytesFrom(key), { prehash: false, format: "recovered" });
  return ccc.hexFrom(ccc.bytesConcat(raw.slice(1), [raw[0] + 27]));
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
