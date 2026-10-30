// Helpers for the audit-fix testnet proofs (CKB testnet only, throwaway keys in keys.json, gitignored, never
// printed). K stands in for the account's Lit key, E1/E2 are EVM backups, J1 a P-256 key standing in for a
// JoyID passkey, D1/D2 are rescue destinations, F1–F40 fund the deployments (one faucet claim each).
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import * as ccc from "@ckb-ccc/core";
import { p256 } from "@noble/curves/nist.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";

export const HERE = dirname(fileURLToPath(import.meta.url));
const KEYS_PATH = join(HERE, "keys.json");
const STATE_PATH = join(HERE, "state.json");
export const client = new ccc.ClientPublicTestnet({ url: "https://testnet.ckb.dev/" });

export const FUNDERS = Array.from({ length: 40 }, (_, index) => `F${index + 1}`);
const NAMES = ["K", "E1", "E2", "J1", "D1", "D2", ...FUNDERS];
export function loadKeys(): Record<string, string> {
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
export const secpLock = (key: string) => ccc.Script.fromKnownScript(client, ccc.KnownScript.Secp256k1Blake160, ccc.hashCkbShort(publicKeyOf(key)));
export const secpAddress = async (key: string) => ccc.Address.fromScript(await secpLock(key), client).toString();

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

export async function plainBalance(lock: ccc.Script): Promise<bigint> {
  let total = 0n;
  for await (const cell of client.findCellsByLock(lock, null, true)) if (!cell.cellOutput.type && cell.outputData === "0x") total += cell.cellOutput.capacity;
  return total;
}
