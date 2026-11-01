// Phase 5, negative checks: rescues the chain must refuse, as dry runs (test_tx_pool_accept) only; nothing is
// sent. Needs funds at the KeyWay address (`step2-fund.ts fundNegative 200`).
//   1. An EVM wallet that isn't a backup (X) signs, with a proof built from the list plus X: Omnilock error 59.
//   2. E1 signs the rescue, then the destination is swapped for X's address: the signature no longer matches.
//   3. A passkey that isn't J1 signs as J1 (J1's identity and preimage): the WebAuthn verifier refuses.
//   4. E1 signs a transaction that also spends the AdminList cell. The rescue page never builds one; this shows
//      what the chain alone does with it (phase 4 noted a backup could spend the list).
import * as ccc from "@ckb-ccc/core";
import { openRescueAccount, planRescue, rescueClient, rescueEntryForEvm, rescueEntryForJoyId, signRescueWithEvm, signRescueWithJoyId, type RescueAccount } from "../../../src/rescue/rescue.ts";
import { evmBackupAuth } from "../../../src/sdk/browser/recovery-backups.ts";
import { signRecoverySpendWithEvm } from "../../../src/sdk/browser/recovery-spend.ts";
import { whitelistTree } from "../../../src/sdk/browser/recovery-smt.ts";
import { evmAddressOf, evmProvider, joyIdSigner, loadKeys, loadState, saveState, secpAddress } from "./lib.ts";

const keys = loadKeys();
const state = loadState();
const client = rescueClient("testnet");
const account = await openRescueAccount(client, state.newAddress);
const destination = await secpAddress(keys.D1);
const results: Record<string, string> = {};

async function dryRun(name: string, transaction: ccc.Transaction) {
  try {
    const cycles = await client.sendTransactionDry(transaction, "passthrough");
    results[name] = `accepted (dry run only, not sent), cycles ${cycles}`;
  } catch (error) {
    const text = String(error instanceof Error ? error.message : error);
    results[name] = `rejected: ${/error code (-?\d+)/.exec(text)?.[0] ?? text.slice(0, 160)} ${/Inputs\[\d+\]\.Lock/.exec(text)?.[0] ?? ""}`.trim();
  }
  console.log(name, "->", results[name]);
}

// 1. Not a backup.
{
  const address = evmAddressOf(keys.X);
  const stranger = { backup: { kind: "evm" as const, address }, auth: evmBackupAuth(address) };
  const forged: RescueAccount = { ...account, entries: [...account.entries, stranger], proofs: whitelistTree([...account.entries, stranger].map(({ auth }) => auth)).proofs };
  const plan = await planRescue(client, forged, stranger, destination);
  await dryRun("1. EVM wallet not on the list", await signRescueWithEvm(client, forged, plan, evmProvider(keys.X)));
}
// 2. Destination swapped after signing.
{
  const plan = await planRescue(client, account, rescueEntryForEvm(account, [evmAddressOf(keys.E1)]), destination);
  const signed = await signRescueWithEvm(client, account, plan, evmProvider(keys.E1));
  const swapped = signed.clone();
  swapped.outputs.forEach((output) => { output.lock = ccc.Script.from(output.lock); });
  const thief = (await ccc.Address.fromString(await secpAddress(keys.X), client)).script;
  swapped.outputs[swapped.outputs.length - 1].lock = thief;
  await dryRun("2. destination swapped after E1 signed", swapped);
}
// 3. Another passkey answering as J1.
{
  const entry = rescueEntryForJoyId(account, state.joyIdBackup);
  const plan = await planRescue(client, account, entry, destination);
  const impostor = await joyIdSigner(keys.D2.replace(/^0x../, "0x11"));
  const genuine = await joyIdSigner(keys.J1);
  const lying = Object.assign(Object.create(null), impostor, { getIdentity: genuine.getIdentity });
  try {
    await dryRun("3. another passkey signing as J1", await signRescueWithJoyId(client, account, plan, lying));
  } catch (error) {
    // CCC-side check: the assertion doesn't verify against J1's key, so it never reaches the chain.
    results["3. another passkey signing as J1"] = `refused before sending: ${error instanceof Error ? error.message : error}`;
    console.log("3 ->", results["3. another passkey signing as J1"]);
  }
}
// 4. A backup spending the AdminList itself.
{
  const entry = rescueEntryForEvm(account, [evmAddressOf(keys.E1)]);
  const plan = await planRescue(client, account, entry, destination);
  const tx = plan.transaction.clone();
  tx.inputs.push(ccc.CellInput.from({ previousOutput: account.adminList.outPoint }));
  tx.outputs[tx.outputs.length - 1].capacity += account.adminList.cellOutput.capacity;
  const signed = await signRecoverySpendWithEvm(tx, { client, lock: account.lock, list: account.entries, entry, adminList: account.adminList.outPoint }, evmProvider(keys.E1));
  await dryRun("4. E1 also spending the AdminList", signed);
}
saveState({ negative: results });
process.exit(0);
