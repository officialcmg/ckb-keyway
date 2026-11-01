// Helpers for the real-backup test page (CKB testnet only). K is a throwaway key standing in for the account's Lit
// key and F a throwaway funder for refills, both in keys.json (gitignored, never printed). Postgres is a local test
// database (DATABASE_URL).
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import * as ccc from "@ckb-ccc/core";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { client, localLitSignature, publicKeyOf, secpAddress, waitCommitted } from "../phase4/lib.ts";

export { client, secpAddress, waitCommitted };

const HERE = dirname(fileURLToPath(import.meta.url));
const KEYS_PATH = join(HERE, "keys.json");
const STATE_PATH = join(HERE, "state.json");

function key(name: "K" | "F"): string {
  const keys = existsSync(KEYS_PATH) ? JSON.parse(readFileSync(KEYS_PATH, "utf8")) : {};
  if (!keys[name]) {
    keys[name] = ccc.hexFrom(secp256k1.utils.randomSecretKey());
    writeFileSync(KEYS_PATH, JSON.stringify(keys, null, 2), { mode: 0o600 });
  }
  return keys[name];
}

export const accountKey = () => key("K");
export const funderKey = () => key("F");

export const loadState = (): Record<string, any> => existsSync(STATE_PATH) ? JSON.parse(readFileSync(STATE_PATH, "utf8")) : {};
export const saveState = (patch: Record<string, unknown>) => writeFileSync(STATE_PATH, JSON.stringify({ ...loadState(), ...patch }, null, 2) + "\n");

/** A local wallet record for K and the context the recovery operations run with; K signs where the Lit action would. */
export async function accountContext(emails: Array<{ subject: string; plaintext: string }>) {
  const { saveWallet, readWallet } = await import("../../../src/server/user-wallet.ts");
  const { formatCkbSignature } = await import("../../../src/server/funding-transaction.ts");
  const secret = accountKey();
  const state = loadState();
  const user = { id: state.userId ?? crypto.randomUUID() };
  let wallet = await readWallet(user);
  if (!wallet) {
    wallet = {
      version: 1, status: "ready", litPkpId: "0xbackup-test-throwaway", litPublicKey: publicKeyOf(secret), ckbAddress: await secpAddress(secret),
      encryptedFiberKey: "unused", primaryDeviceIdHash: "0".repeat(64), hasOpenedChannel: false,
      createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
    };
    await saveWallet(user, wallet);
    saveState({ userId: user.id });
  }
  return {
    user, wallet: wallet as Extract<typeof wallet, { status: "ready" }>, appName: "KeyWay backup test", client,
    email: async () => "backup-test@example.invalid",
    sendEmail: async (_to: string, message: { subject: string; plaintext: string }) => { emails.push(message); },
    rateLimit: async () => ({ allowed: true, retryAfter: null }),
    recordSigning: async () => undefined,
    signDigest: async (digest: ccc.Hex) => formatCkbSignature(localLitSignature(secret, digest)),
    broadcast: async (transaction: ccc.Transaction) => {
      await client.sendTransactionDry(transaction, "passthrough");
      return client.sendTransaction(transaction, "passthrough");
    },
  };
}

/** Sends `amount` CKB from F to `address` and waits for it to commit. */
export async function refill(address: string, amount: string): Promise<string> {
  const signer = new ccc.SignerCkbPrivateKey(client, funderKey());
  const transaction = ccc.Transaction.from({ outputs: [{ lock: (await ccc.Address.fromString(address, client)).script, capacity: ccc.fixedPointFrom(amount) }] });
  await transaction.completeInputsByCapacity(signer);
  await transaction.completeFeeBy(signer);
  const hash = await signer.sendTransaction(transaction);
  await waitCommitted(hash);
  return hash;
}

export const claimFaucet = (address: string) => fetch("https://faucet-api.nervos.org/claim_events", {
  method: "POST", headers: { "content-type": "application/json" },
  body: JSON.stringify({ claim_event: { address_hash: address, amount: "10000" } }),
}).then((response) => response.status);

export const emailCode = (emails: Array<{ plaintext: string }>) => /code is (\d{6})/.exec(emails.findLast(({ plaintext }) => /code is \d{6}/.test(plaintext))!.plaintext)![1];
