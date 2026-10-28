// Phase 2, step 1: turn recovery on with an EVM backup through the server's own flow (src/server/recovery.ts):
// preview -> request-email-code -> enable, against CKB testnet. Postgres is a local test database
// (DATABASE_URL); K signs where the Lit action would, and the emailed code is read from the captured email.
import * as ccc from "@ckb-ccc/core";
import { formatCkbSignature } from "../../../src/server/funding-transaction.ts";
import { recoverySetup, type RecoveryContext } from "../../../src/server/recovery.ts";
import { saveWallet, type ReadyWallet } from "../../../src/server/user-wallet.ts";
import { recoveryBackupChallenge } from "../../../src/sdk/browser/recovery-backups.ts";
import { client, evmAddressOf, evmPersonalSign, loadKeys, localLitSignature, publicKeyOf, saveState, waitCommitted } from "./lib.ts";

const keys = loadKeys();
const user = { id: crypto.randomUUID() };
const publicKey = publicKeyOf(keys.K);
const secp = await ccc.Script.fromKnownScript(client, ccc.KnownScript.Secp256k1Blake160, ccc.hashCkbShort(publicKey));
const legacyAddress = ccc.Address.fromScript(secp, client).toString();
const wallet: ReadyWallet = {
  version: 1, status: "ready", litPkpId: "0xphase2-throwaway", litPublicKey: publicKey, ckbAddress: legacyAddress,
  encryptedFiberKey: "unused", primaryDeviceIdHash: "0".repeat(64), hasOpenedChannel: false,
  createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
};
await saveWallet(user, wallet);

const backup = { kind: "evm" as const, address: evmAddressOf(keys.E) };
const proof = { ...backup, signature: evmPersonalSign(keys.E, new TextEncoder().encode(recoveryBackupChallenge(legacyAddress, backup))) };
const emails: string[] = [];
const context: RecoveryContext = {
  user, wallet, appName: "KeyWay phase 2 testnet proof",
  email: async () => "phase2@example.invalid",
  sendEmail: async (_to, message) => { emails.push(message.plaintext); },
  rateLimit: async () => ({ allowed: true, retryAfter: null }),
  recordSigning: async () => undefined,
  signDigest: async (digest) => formatCkbSignature(localLitSignature(keys.K, digest)),
  client,
  broadcast: async (transaction) => {
    const cycles = await client.sendTransactionDry(transaction, "passthrough");
    console.log("test_tx_pool_accept ok, cycles", cycles.toString(), "size", transaction.toBytes().length + 4);
    return client.sendTransaction(transaction, "passthrough");
  },
};

const preview = await recoverySetup(context, { operation: "preview", backups: [proof] }) as { preview: Record<string, unknown>; confirmationNonce: string };
console.log("preview", JSON.stringify(preview.preview, null, 2));
await recoverySetup(context, { operation: "request-email-code", backups: [proof], confirmationNonce: preview.confirmationNonce });
console.log("email:\n" + emails.at(-1));
const code = /code is (\d{6})/.exec(emails.at(-1)!)![1];
const result = await recoverySetup(context, { operation: "enable", backups: [proof], confirmationNonce: preview.confirmationNonce, emailCode: code }) as {
  transactionHash: string; recovery: Record<string, unknown>; ckbAddress: string;
};
console.log("enable tx", result.transactionHash);
if (result.ckbAddress !== preview.preview.newAddress) throw new Error("address differs from the preview");
await waitCommitted(result.transactionHash);
saveState({ enable: result.transactionHash, recovery: result.recovery, newAddress: result.ckbAddress, legacyAddress, evmBackup: backup.address });
console.log("committed");
process.exit(0);
