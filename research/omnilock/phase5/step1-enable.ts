// Phase 5, step 1: turn recovery on for K through src/server/recovery.ts (preview -> request-email-code -> enable)
// with two backups, the EVM wallet E1 and the JoyID-style passkey J1, then check the notice email that follows.
// Postgres is a local test database (DATABASE_URL); K signs where the Lit action would.
import { recoverySetup } from "../../../src/server/recovery.ts";
import { recoveryBackupChallenge } from "../../../src/sdk/browser/recovery-backups.ts";
import { accountContext, emailCode, evmAddressOf, evmPersonalSign, joyIdSigner, loadKeys, saveState, secpAddress, waitCommitted } from "./lib.ts";

const keys = loadKeys();
const emails: Array<{ subject: string; plaintext: string }> = [];
const context = await accountContext(emails);
const legacyAddress = await secpAddress(keys.K);
const evm = { kind: "evm" as const, address: evmAddressOf(keys.E1) };
const signer = await joyIdSigner(keys.J1);
const joyIdAddress = await signer.getRecommendedAddress();
const signed = await signer.signMessage(recoveryBackupChallenge(legacyAddress, { kind: "joyid", address: joyIdAddress }));
const backups = [
  { ...evm, signature: evmPersonalSign(keys.E1, recoveryBackupChallenge(legacyAddress, evm)) },
  { kind: "joyid" as const, address: joyIdAddress, signature: signed.signature, identity: signed.identity },
];

const preview = await recoverySetup(context, { operation: "preview", backups }) as { preview: Record<string, unknown>; confirmationNonce: string };
console.log("preview", JSON.stringify(preview.preview, null, 2));
await recoverySetup(context, { operation: "request-email-code", backups, confirmationNonce: preview.confirmationNonce });
const result = await recoverySetup(context, { operation: "enable", backups, confirmationNonce: preview.confirmationNonce, emailCode: emailCode(emails) }) as {
  transactionHash: string; recovery: Record<string, unknown>; ckbAddress: string;
};
console.log("enable tx", result.transactionHash);
if (result.ckbAddress !== preview.preview.newAddress) throw new Error("address differs from the preview");
const notice = emails.at(-1)!;
if (!notice.plaintext.includes(result.ckbAddress) || !notice.plaintext.includes("https://ckbkeyway.dev/rescue")) throw new Error("the notice email lacks the address or the rescue page");
console.log(`notice email: ${notice.subject}\n${notice.plaintext}`);
await waitCommitted(result.transactionHash);
saveState({ enable: result.transactionHash, recovery: result.recovery, newAddress: result.ckbAddress, legacyAddress, joyIdBackup: joyIdAddress, evmBackup: evm.address, noticeEmail: notice.plaintext });
console.log("committed");
process.exit(0);
