// Phase 4: spend from the account's Omnilock via the administrator path, signed only by an EVM backup through
// signRecoverySpendWithEvm and an EIP-1193 stand-in. The list and proof come from the chain (readRecoveryList).
// Sends 1000 CKB to K's legacy address. `--dry-run` only runs test_tx_pool_accept.
import * as ccc from "@ckb-ccc/core";
import { omnilockLock } from "../../../src/sdk/browser/account-lock.ts";
import { evmBackupAuth } from "../../../src/sdk/browser/recovery-backups.ts";
import { readRecoveryList, type RecoveryListEntry } from "../../../src/sdk/browser/recovery-list.ts";
import { signRecoverySpendWithEvm } from "../../../src/sdk/browser/recovery-spend.ts";
import { client, evmAddressOf, evmPersonalSign, loadKeys, loadState, saveState, secpLock, waitCommitted } from "./lib.ts";

const name = (process.argv[2] ?? "E1") as "E1" | "E2";
const dryRun = process.argv.includes("--dry-run");
const keys = loadKeys();
const state = loadState();
const omnilock = await omnilockLock(client, state.recovery);
const list = await readRecoveryList(client, state.recovery);
const address = evmAddressOf(keys[name]);
// A removed backup isn't on the list any more; sign anyway with a proof from the list it was last on.
const entry: RecoveryListEntry = list.entries.find(({ backup }) => backup.address === address) ?? { backup: { kind: "evm", address }, auth: evmBackupAuth(address) };
const entries = list.entries.includes(entry) ? list.entries : [...list.entries, entry];
const ethereum = {
  request: async ({ method, params }: { method: string; params?: unknown[] }) => {
    if (method !== "personal_sign") throw new Error(method);
    return evmPersonalSign(keys[name], new TextDecoder().decode(ccc.bytesFrom(params![0] as string)));
  },
};

let input: ccc.Cell | undefined;
for await (const cell of client.findCellsByLock(omnilock, null, true)) {
  if (!cell.cellOutput.type && cell.outputData === "0x" && (!input || cell.cellOutput.capacity > input.cellOutput.capacity)) input = cell;
}
const payout = { lock: await secpLock(keys.K), capacity: ccc.fixedPointFrom(1000) };
const tx = ccc.Transaction.from({ inputs: [{ previousOutput: input!.outPoint }], outputs: [payout, { lock: omnilock, capacity: 0n }], outputsData: ["0x", "0x"] });
const spend = { client, lock: omnilock, list: entries, entry, adminList: list.cell.outPoint };
const sized = await signRecoverySpendWithEvm(tx, spend, ethereum);
const fee = (BigInt(sized.toBytes().length + 4) * 1500n + 999n) / 1000n;
tx.outputs[1].capacity = input!.cellOutput.capacity - payout.capacity - fee;
const signed = await signRecoverySpendWithEvm(tx, spend, ethereum);
try {
  const cycles = await client.sendTransactionDry(signed, "passthrough");
  console.log("test_tx_pool_accept ok, cycles", cycles.toString(), "size", signed.toBytes().length + 4, "fee", fee.toString());
} catch (error) {
  const text = String(error instanceof Error ? error.message : error);
  console.log(`${name} spend: rejected, ${/error code (-?\d+)/.exec(text)?.[0] ?? text.slice(0, 200)} ${/Inputs\[\d+\]\.Lock/.exec(text)?.[0] ?? ""}`);
  process.exit(0);
}
if (dryRun) process.exit(0);
const hash = await client.sendTransaction(signed, "passthrough");
console.log("spend tx", hash);
await waitCommitted(hash);
saveState({ [`spend${name}`]: hash });
console.log("committed");
process.exit(0);
