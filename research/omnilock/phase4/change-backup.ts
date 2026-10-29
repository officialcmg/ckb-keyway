// Phase 4: add or remove a backup through src/server/recovery.ts (preview -> request-email-code -> apply):
//   npx tsx change-backup.ts add E1 | add J2 | remove E1
// Adding signs the recovery challenge with the new backup. Postgres is a local test database (DATABASE_URL).
import { recoveryBackupChange } from "../../../src/server/recovery.ts";
import { readRecoveryList } from "../../../src/sdk/browser/recovery-list.ts";
import { recoveryBackupChallenge } from "../../../src/sdk/browser/recovery-backups.ts";
import { accountContext, client, emailCode, evmAddressOf, evmPersonalSign, joyIdSigner, loadKeys, loadState, saveState, secpAddress, waitCommitted } from "./lib.ts";

const [change, name] = process.argv.slice(2) as ["add" | "remove", "E1" | "E2" | "J1" | "J2"];
const keys = loadKeys();
const emails: string[] = [];
const context = await accountContext(emails);
const account = await secpAddress(keys.K);
let backup: Record<string, unknown>;
if (name.startsWith("E")) {
  const address = evmAddressOf(keys[name]);
  backup = { kind: "evm", address };
  if (change === "add") backup.signature = evmPersonalSign(keys[name], recoveryBackupChallenge(account, { kind: "evm", address }));
} else {
  const signer = await joyIdSigner(keys[name]);
  const address = await signer.getRecommendedAddress();
  backup = { kind: "joyid", address };
  if (change === "add") Object.assign(backup, await signer.signMessage(recoveryBackupChallenge(account, { kind: "joyid", address })));
  delete backup.signType;
}

const body = { change, backup };
const preview = await recoveryBackupChange(context, { ...body, operation: "preview" }) as { preview: Record<string, unknown>; confirmationNonce: string };
console.log("preview", JSON.stringify(preview.preview, null, 2));
await recoveryBackupChange(context, { ...body, operation: "request-email-code", confirmationNonce: preview.confirmationNonce });
console.log("email:\n" + emails.at(-1));
const result = await recoveryBackupChange(context, { ...body, operation: "apply", confirmationNonce: preview.confirmationNonce, emailCode: emailCode(emails) }) as { transactionHash: string; recovery: Record<string, unknown> };
console.log(`${change} ${name} tx`, result.transactionHash);
await waitCommitted(result.transactionHash);
const list = await readRecoveryList(client, result.recovery as never);
console.log("on-chain list now", list.entries.map(({ backup }) => `${backup.kind} ${backup.address}`), "root", list.root);
const state = loadState();
saveState({
  recovery: result.recovery,
  [`${change}${name}`]: result.transactionHash,
  ...(name.startsWith("J") ? { joyIdBackups: { ...state.joyIdBackups, [name]: backup.address } } : {}),
});
console.log("committed");
process.exit(0);
