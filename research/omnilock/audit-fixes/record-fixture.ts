// Records the testnet proof as an offline fixture (tests/fixtures/recovery-audit-fixes.json): the enable
// transaction with the transaction that paid its input 0 (the record's anchor), the add-E2 list update, and both
// backups' rescues, each with its input cells.
import { writeFileSync } from "node:fs";
import * as ccc from "@ckb-ccc/core";
import { evmAddressOf, joyIdPasskey, joyIdSigner } from "../phase4/lib.ts";
import { client, loadKeys, loadState, publicKeyOf } from "./lib.ts";

const state = loadState();
const keys = loadKeys();
const record = async (hash: string) => {
  const transaction = (await client.getTransaction(hash))!.transaction;
  const inputCells = await Promise.all(transaction.inputs.map((input) => input.getCell(client)));
  return { transaction, inputCells: inputCells.map((cell) => ({ outPoint: cell.outPoint, cellOutput: cell.cellOutput, outputData: cell.outputData })) };
};
const enable = await record(state.enable);
writeFileSync(new URL("../../../tests/fixtures/recovery-audit-fixes.json", import.meta.url), JSON.stringify(JSON.parse(ccc.stringify({
  note: "CKB testnet proof (research/omnilock/audit-fixes-results.md): recovery turned on with an EVM and a JoyID-style backup, an EVM backup added, and both original backups' rescues through KeyWay's approval verifiers",
  publicKey: publicKeyOf(keys.K),
  evmBackup: evmAddressOf(keys.E1),
  addedBackup: evmAddressOf(keys.E2),
  joyIdBackup: await (await joyIdSigner(keys.J1)).getRecommendedAddress(),
  joyIdPublicKey: joyIdPasskey(keys.J1).publicKey,
  enable,
  enableFunding: (await client.getTransaction(enable.transaction.inputs[0].previousOutput.txHash))!.transaction,
  add: await record(state.add),
  rescueJoyId: await record(state.rescueJ1),
  rescueEvm: await record(state.rescueE1),
})), null, 2) + "\n");
console.log("recorded");
process.exit(0);
