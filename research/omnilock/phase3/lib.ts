// Shared helpers for the phase 3 testnet proof (CKB testnet only, throwaway keys in keys.json, gitignored).
// Signing and waiting helpers come from phase 2; this run keeps its own keys and state.
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import * as ccc from "@ckb-ccc/core";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { client } from "../phase2/lib.ts";

export { client, evmAddressOf, evmPersonalSign, localLitSignature, publicKeyOf, waitCommitted } from "../phase2/lib.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const KEYS_PATH = join(HERE, "keys.json");
const STATE_PATH = join(HERE, "state.json");

/** K stands in for the account's Lit key, E is its EVM backup, I issues the test token and sends to K's old address. */
export function loadKeys(): { K: string; E: string; I: string } {
  if (!existsSync(KEYS_PATH)) {
    const gen = () => ccc.hexFrom(secp256k1.utils.randomSecretKey());
    writeFileSync(KEYS_PATH, JSON.stringify({ K: gen(), E: gen(), I: gen() }, null, 2), { mode: 0o600 });
  }
  return JSON.parse(readFileSync(KEYS_PATH, "utf8"));
}

export const loadState = (): Record<string, any> => existsSync(STATE_PATH) ? JSON.parse(readFileSync(STATE_PATH, "utf8")) : {};
export const saveState = (patch: Record<string, unknown>) => writeFileSync(STATE_PATH, JSON.stringify({ ...loadState(), ...patch }, null, 2));

export const secpLockOf = (publicKey: ccc.HexLike) => ccc.Script.fromKnownScript(client, ccc.KnownScript.Secp256k1Blake160, ccc.hashCkbShort(publicKey));
