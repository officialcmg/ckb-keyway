// JoyID verifier proof, step 1: turn recovery on through src/server/recovery.ts (preview -> request-email-code ->
// enable) with one JoyID-style backup, J1. Its ownership proof is a WebAuthn assertion in JoyID's exact format.
// Postgres is a local test database (DATABASE_URL); K signs where the Lit action would.
import { recoverySetup } from "../../../src/server/recovery.ts";
import { recoveryBackupChallenge } from "../../../src/sdk/browser/recovery-backups.ts";
import { accountContext, emailCode, joyIdSigner, loadKeys, saveState, secpAddress, waitCommitted } from "./lib.ts";

const keys = loadKeys();
const emails: string[] = [];
const context = await accountContext(emails);
const legacyAddress = await secpAddress(keys.K);
const signer = await joyIdSigner(keys.J1);
const address = await signer.getRecommendedAddress();
const signed = await signer.signMessage(recoveryBackupChallenge(legacyAddress, { kind: "joyid", address }));
const proof = { kind: "joyid" as const, address, signature: signed.signature, identity: signed.identity };

const preview = await recoverySetup(context, { operation: "preview", backups: [proof] }) as { preview: Record<string, unknown>; confirmationNonce: string };
console.log("preview", JSON.stringify(preview.preview, null, 2));
await recoverySetup(context, { operation: "request-email-code", backups: [proof], confirmationNonce: preview.confirmationNonce });
console.log("email:\n" + emails.at(-1));
const result = await recoverySetup(context, { operation: "enable", backups: [proof], confirmationNonce: preview.confirmationNonce, emailCode: emailCode(emails) }) as {
  transactionHash: string; recovery: Record<string, unknown>; ckbAddress: string;
};
console.log("enable tx", result.transactionHash);
if (result.ckbAddress !== preview.preview.newAddress) throw new Error("address differs from the preview");
await waitCommitted(result.transactionHash);
saveState({ enable: result.transactionHash, recovery: result.recovery, newAddress: result.ckbAddress, legacyAddress, joyIdBackup: address });
console.log("committed");
process.exit(0);
