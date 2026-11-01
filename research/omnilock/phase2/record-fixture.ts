// Records the phase 2 enable transaction and the EVM spend (flag 0x12), with their input cells, as an offline test fixture.
import { writeFileSync } from "node:fs";
import * as ccc from "@ckb-ccc/core";
import { client, loadKeys, loadState, publicKeyOf } from "./lib.ts";
const state = loadState();
const tx = (await client.getTransaction(state.enable))!.transaction;
const inputCells = await Promise.all(tx.inputs.map((input) => input.getCell(client)));
const evmSpend = (await client.getTransaction(state.evmSpend))!.transaction;
writeFileSync(new URL("../../../tests/fixtures/recovery-enable.json", import.meta.url), JSON.stringify(JSON.parse(ccc.stringify({
  note: "CKB testnet phase 2 proof (research/omnilock/phase2-results.md): recovery turned on with one EVM backup (flag 0x12), then that backup's admin-path spend",
  publicKey: publicKeyOf(loadKeys().K), evmBackup: state.evmBackup,
  transaction: tx, inputCells: inputCells.map((c) => ({ outPoint: c.outPoint, cellOutput: c.cellOutput, outputData: c.outputData })),
  evmSpend: { transaction: evmSpend, inputCell: (await evmSpend.inputs[0].getCell(client)), adminListCellDep: evmSpend.cellDeps[0] },
})), null, 2) + "\n");
console.log(tx.hash(), inputCells.length);
process.exit(0);
