// Records the JoyID-backup enable transaction, J1's admin-path spend through the verifier, and the add-E1 list
// update, each with its input cells, as an offline test fixture (tests/fixtures/recovery-enable.json).
import { writeFileSync } from "node:fs";
import * as ccc from "@ckb-ccc/core";
import { client, evmAddressOf, joyIdPasskey, loadKeys, loadState, publicKeyOf } from "./lib.ts";

const state = loadState();
const keys = loadKeys();
const record = async (hash: string) => {
  const transaction = (await client.getTransaction(hash))!.transaction;
  const inputCells = await Promise.all(transaction.inputs.map((input) => input.getCell(client)));
  return { transaction, inputCells: inputCells.map((cell) => ({ outPoint: cell.outPoint, cellOutput: cell.cellOutput, outputData: cell.outputData })) };
};
writeFileSync(new URL("../../../tests/fixtures/recovery-enable.json", import.meta.url), JSON.stringify(JSON.parse(ccc.stringify({
  note: "CKB testnet proofs (research/omnilock/joyid-verifier-results.md, phase4-results.md): recovery turned on with one JoyID-style backup, that backup's admin-path spend through the WebAuthn verifier, and adding an EVM backup",
  publicKey: publicKeyOf(keys.K),
  joyIdBackup: state.joyIdBackup,
  joyIdPublicKey: joyIdPasskey(keys.J1).publicKey,
  evmBackup: evmAddressOf(keys.E1),
  enable: await record(state.enable),
  joyIdSpend: await record(state.joyIdSpend),
  addEvm: await record(state.addE1),
})), null, 2) + "\n");
console.log("recorded");
process.exit(0);
