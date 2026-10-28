// Records the phase 2 enable transaction and the EVM spend, with their input cells, as an offline test fixture.
import { writeFileSync } from "node:fs";
import * as ccc from "@ckb-ccc/core";
import { client, loadKeys, publicKeyOf } from "./lib.ts";
const hash = "0x250e0b50785082de4819b618251aa4c1d6148c36fb5bb1379488edfaa0911af4";
const tx = (await client.getTransaction(hash))!.transaction;
const inputCells = await Promise.all(tx.inputs.map((input) => input.getCell(client)));
const evmSpend = (await client.getTransaction("0x7597ed3d13d4e1a0f7293e67fb02fc16b479d265e634e3d6625fb14b5737ac66"))!.transaction;
writeFileSync(new URL("../../../tests/fixtures/recovery-enable.json", import.meta.url), JSON.stringify(JSON.parse(ccc.stringify({
  note: "CKB testnet phase 2 proof (research/omnilock/phase2-results.md): recovery turned on with one EVM backup, then that backup's admin-path spend",
  publicKey: publicKeyOf(loadKeys().K), evmBackup: "0x2918d5553eec5967e4fcc79a07577f96ee23d3b3",
  transaction: tx, inputCells: inputCells.map((c) => ({ outPoint: c.outPoint, cellOutput: c.cellOutput, outputData: c.outputData })),
  evmSpend: { transaction: evmSpend, inputCell: (await evmSpend.inputs[0].getCell(client)), adminListCellDep: evmSpend.cellDeps[0] },
})), null, 2) + "\n");
console.log(tx.hash(), inputCells.length);
process.exit(0);
