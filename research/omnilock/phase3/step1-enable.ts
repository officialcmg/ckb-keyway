// Phase 3, step 1: turn recovery on for K with an EVM backup E, exactly as phase 2's step 1 does (preview ->
// request-email-code -> enable through src/server/recovery.ts). Postgres is a local test database
// (DATABASE_URL); K signs where the Lit action would. The user's id and wallet are kept for the later steps.
import * as ccc from "@ckb-ccc/core";
import { formatCkbSignature } from "../../../src/server/funding-transaction.ts";
import { recoverySetup, type RecoveryContext } from "../../../src/server/recovery.ts";
import { saveWallet, type ReadyWallet } from "../../../src/server/user-wallet.ts";
import { recoveryBackupChallenge } from "../../../src/sdk/browser/recovery-backups.ts";
import { client, evmAddressOf, evmPersonalSign, loadKeys, localLitSignature, publicKeyOf, saveState, secpLockOf, waitCommitted } from "./lib.ts";

const keys = loadKeys();
const user = { id: crypto.randomUUID() };
const publicKey = publicKeyOf(keys.K);
const legacyAddress = ccc.Address.fromScript(await secpLockOf(publicKey), client).toString();
const wallet: ReadyWallet = {
  version: 1, status: "ready", litPkpId: "0xphase3-throwaway", litPublicKey: publicKey, ckbAddress: legacyAddress,
  encryptedFiberKey: "unused", primaryDeviceIdHash: "0".repeat(64), hasOpenedChannel: false,
  createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
};
await saveWallet(user, wallet);

const backup = { kind: "evm" as const, address: evmAddressOf(keys.E) };
const proof = { ...backup, signature: evmPersonalSign(keys.E, new TextEncoder().encode(recoveryBackupChallenge(legacyAddress, backup))) };
const emails: string[] = [];
const context: RecoveryContext = {
  user, wallet, appName: "KeyWay phase 3 testnet proof",
  email: async () => "phase3@example.invalid",
  sendEmail: async (_to, message) => { emails.push(message.plaintext); },
  rateLimit: async () => ({ allowed: true, retryAfter: null }),
  recordSigning: async () => undefined,
  signDigest: async (digest) => formatCkbSignature(localLitSignature(keys.K, digest)),
  client,
  broadcast: async (transaction) => {
    await client.sendTransactionDry(transaction, "passthrough");
    return client.sendTransaction(transaction, "passthrough");
  },
};

const preview = await recoverySetup(context, { operation: "preview", backups: [proof] }) as { confirmationNonce: string };
await recoverySetup(context, { operation: "request-email-code", backups: [proof], confirmationNonce: preview.confirmationNonce });
const code = /code is (\d{6})/.exec(emails.at(-1)!)![1];
const result = await recoverySetup(context, { operation: "enable", backups: [proof], confirmationNonce: preview.confirmationNonce, emailCode: code }) as {
  transactionHash: string; recovery: Record<string, unknown>; ckbAddress: string;
};
console.log("enable tx", result.transactionHash);
await waitCommitted(result.transactionHash);
saveState({ userId: user.id, enable: result.transactionHash, recovery: result.recovery, newAddress: result.ckbAddress, legacyAddress, evmBackup: backup.address });
console.log("committed; new address", result.ckbAddress);
process.exit(0);
