// Helpers for the audit's testnet dry runs (CKB testnet only, throwaway keys in keys.json, gitignored, never
// printed). K stands in for the account's Lit key, E1 is its EVM backup, D1 is a destination.
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import * as ccc from "@ckb-ccc/core";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { client, evmAddressOf, evmPersonalSign, localLitSignature, publicKeyOf, secpAddress, secpLock, waitCommitted } from "../phase4/lib.ts";

export { client, evmAddressOf, evmPersonalSign, localLitSignature, publicKeyOf, secpAddress, secpLock, waitCommitted };

export const HERE = dirname(fileURLToPath(import.meta.url));
const KEYS_PATH = join(HERE, "keys.json");
const STATE_PATH = join(HERE, "state.json");
const NAMES = ["K", "E1", "D1"] as const;
export type KeyName = (typeof NAMES)[number];

export function loadKeys(): Record<KeyName, string> {
  const keys = existsSync(KEYS_PATH) ? JSON.parse(readFileSync(KEYS_PATH, "utf8")) : {};
  let changed = false;
  for (const name of NAMES) {
    if (keys[name]) continue;
    keys[name] = ccc.hexFrom(secp256k1.utils.randomSecretKey());
    changed = true;
  }
  if (changed) writeFileSync(KEYS_PATH, JSON.stringify(keys, null, 2), { mode: 0o600 });
  return keys;
}

export const loadState = (): Record<string, any> => existsSync(STATE_PATH) ? JSON.parse(readFileSync(STATE_PATH, "utf8")) : {};
export const saveState = (patch: Record<string, unknown>) => writeFileSync(STATE_PATH, JSON.stringify({ ...loadState(), ...patch }, null, 2) + "\n");

/** An EIP-1193 stand-in for an EVM wallet holding `key`, reporting what it is asked to sign. */
export function evmProvider(key: string, onSign?: (text: string) => void) {
  return {
    request: async ({ method, params }: { method: string; params?: unknown[] }) => {
      if (method === "eth_requestAccounts" || method === "eth_accounts") return [evmAddressOf(key)];
      if (method !== "personal_sign") throw new Error(method);
      const text = new TextDecoder().decode(ccc.bytesFrom(params![0] as string));
      onSign?.(text);
      return evmPersonalSign(key, text);
    },
  };
}
