// Shared helpers for the phase 5 testnet proof of the rescue page (CKB testnet only, throwaway keys in keys.json,
// gitignored, never printed). Signing stand-ins come from phase 4; this run keeps its own keys and state.
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import * as ccc from "@ckb-ccc/core";
import { p256 } from "@noble/curves/nist.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { client, evmAddressOf, evmPersonalSign, joyIdPasskey, localLitSignature, publicKeyOf, waitCommitted } from "../phase4/lib.ts";

export { client, evmAddressOf, evmPersonalSign, publicKeyOf, waitCommitted };

export const HERE = dirname(fileURLToPath(import.meta.url));
const KEYS_PATH = join(HERE, "keys.json");
const STATE_PATH = join(HERE, "state.json");

/**
 * K stands in for the account's Lit key, E1 is its EVM backup, J1 a P-256 key standing in for its JoyID passkey,
 * F funds the account and issues the test token, X is an EVM wallet that isn't a backup, D1/D2 receive the
 * rescues. All secp256k1 keys except J1.
 */
const NAMES = ["K", "E1", "J1", "F", "X", "D1", "D2"] as const;
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

export const secpLock = (key: string) => ccc.Script.fromKnownScript(client, ccc.KnownScript.Secp256k1Blake160, ccc.hashCkbShort(publicKeyOf(key)));
export const secpAddress = async (key: string) => ccc.Address.fromScript(await secpLock(key), client).toString();

export async function joyIdLockOf(key: string) {
  const joyId = await client.getKnownScript(ccc.KnownScript.JoyId);
  return ccc.Script.from({ codeHash: joyId.codeHash, hashType: joyId.hashType, args: ccc.bytesConcat("0x0001", ccc.hashCkbShort(joyIdPasskey(key).publicKey)) });
}

/** A stand-in for CCC's JoyId.CkbSigner, answering from a local P-256 key as JoyID's pages do. */
export async function joyIdSigner(key: string, onSign?: (text: string) => void): Promise<ccc.Signer> {
  const passkey = joyIdPasskey(key);
  const address = ccc.Address.fromScript(await joyIdLockOf(key), client).toString();
  return {
    client,
    signType: ccc.SignerSignType.JoyId,
    isConnected: async () => true,
    connect: async () => undefined,
    getRecommendedAddress: async () => address,
    getIdentity: async () => passkey.identity,
    signMessageRaw: async (text: string) => { onSign?.(text); return passkey.signMessageRaw(text); },
    signMessage: async (text: string) => ({ signature: passkey.signMessageRaw(text), identity: passkey.identity, signType: ccc.SignerSignType.JoyId }),
  } as unknown as ccc.Signer;
}

/** An EIP-1193 stand-in for an EVM wallet holding `key`. */
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

/** A local Postgres user and wallet record for K, created once and kept in state.json. */
export async function accountContext(emails: Array<{ subject: string; plaintext: string }>) {
  const { saveWallet, readWallet } = await import("../../../src/server/user-wallet.ts");
  const { formatCkbSignature } = await import("../../../src/server/funding-transaction.ts");
  const keys = loadKeys();
  const state = loadState();
  const user = { id: state.userId ?? crypto.randomUUID() };
  const publicKey = publicKeyOf(keys.K);
  let wallet = await readWallet(user);
  if (!wallet) {
    wallet = {
      version: 1, status: "ready", litPkpId: "0xphase5-throwaway", litPublicKey: publicKey, ckbAddress: await secpAddress(keys.K),
      encryptedFiberKey: "unused", primaryDeviceIdHash: "0".repeat(64), hasOpenedChannel: false,
      createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
    };
    await saveWallet(user, wallet);
    saveState({ userId: user.id });
  }
  if (wallet.status !== "ready") throw new Error("wallet isn't ready");
  return {
    user, wallet, appName: "KeyWay phase 5 testnet proof", client,
    email: async () => "phase5@example.invalid",
    sendEmail: async (_to: string, message: { subject: string; plaintext: string }) => { emails.push(message); },
    rateLimit: async () => ({ allowed: true, retryAfter: null }),
    recordSigning: async () => undefined,
    signDigest: async (digest: ccc.Hex) => formatCkbSignature(localLitSignature(keys.K, digest)),
    broadcast: async (transaction: ccc.Transaction) => {
      const cycles = await client.sendTransactionDry(transaction, "passthrough");
      console.log("test_tx_pool_accept ok, cycles", cycles.toString(), "size", transaction.toBytes().length + 4);
      return client.sendTransaction(transaction, "passthrough");
    },
  };
}

export const emailCode = (emails: Array<{ plaintext: string }>) => /code is (\d{6})/.exec(emails.findLast(({ plaintext }) => /code is \d{6}/.test(plaintext))!.plaintext)![1];
