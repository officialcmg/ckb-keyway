// JoyID verifier proof, step 2: spend from the account's Omnilock via the administrator path, signed only by the
// JoyID-style backup J1 through signRecoverySpendWithJoyId. The backup list and proof come from the chain alone
// (readRecoveryList). Sends 1000 CKB to K's legacy address and 100 CKB to J1's own JoyID address (used by the
// owner-lock negative check), change back to the Omnilock.
import * as ccc from "@ckb-ccc/core";
import { omnilockLock } from "../../../src/sdk/browser/account-lock.ts";
import { readRecoveryList } from "../../../src/sdk/browser/recovery-list.ts";
import { signRecoverySpendWithJoyId } from "../../../src/sdk/browser/recovery-spend.ts";
import { client, joyIdLockOf, joyIdSigner, loadKeys, loadState, saveState, secpLock, waitCommitted } from "./lib.ts";

const keys = loadKeys();
const state = loadState();
const name = (process.argv[2] ?? "J1") as "J1" | "J2";
const stateKey = process.argv[3] ?? "joyIdSpend";
const omnilock = await omnilockLock(client, state.recovery);
const list = await readRecoveryList(client, state.recovery);
console.log("on-chain list", list.entries.map(({ backup, auth }) => `${backup.kind} ${backup.address} ${auth}`), "root", list.root);
const signer = await joyIdSigner(keys[name]);
const entry = list.entries.find(({ backup }) => backup.kind === "joyid" && backup.address === state.joyIdBackups?.[name] || backup.address === state.joyIdBackup && name === "J1")!;

let input: ccc.Cell | undefined;
for await (const cell of client.findCellsByLock(omnilock, null, true)) {
  if (!cell.cellOutput.type && cell.outputData === "0x" && (!input || cell.cellOutput.capacity > input.cellOutput.capacity)) input = cell;
}
const outputs = [{ lock: await secpLock(keys.K), capacity: ccc.fixedPointFrom(1000) }];
if (process.argv.includes("--fund-joyid")) outputs.push({ lock: await joyIdLockOf(keys.J1), capacity: ccc.fixedPointFrom(100) });
const tx = ccc.Transaction.from({ inputs: [{ previousOutput: input!.outPoint }], outputs: [...outputs, { lock: omnilock, capacity: 0n }], outputsData: [...outputs.map(() => "0x"), "0x"] });
const spend = { client, lock: omnilock, list: list.entries, entry, adminList: list.cell.outPoint };
// Size the fee with a signed copy, then sign the final transaction.
const sized = await signRecoverySpendWithJoyId(tx, spend, signer);
const fee = (BigInt(sized.toBytes().length + 4) * 1500n + 999n) / 1000n;
tx.outputs[tx.outputs.length - 1].capacity = input!.cellOutput.capacity - outputs.reduce((sum, output) => sum + output.capacity, 0n) - fee;
const signed = await signRecoverySpendWithJoyId(tx, spend, signer);
const cycles = await client.sendTransactionDry(signed, "passthrough");
console.log("test_tx_pool_accept ok, cycles", cycles.toString(), "size", signed.toBytes().length + 4, "fee", fee.toString(), "witness lock", ccc.bytesFrom(signed.getWitnessArgsAt(0)!.lock!).length);
const hash = await client.sendTransaction(signed, "passthrough");
console.log("spend tx", hash);
await waitCommitted(hash);
saveState({ [stateKey]: hash });
console.log("committed");
process.exit(0);
