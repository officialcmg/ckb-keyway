// Records the testnet proof as an offline fixture (tests/fixtures/recovery-backup-unlinking.json): both accounts'
// enable transactions with the transactions that paid their input 0, and the two rescues, each with its input
// cells: npx tsx record-fixture.ts
import { writeFileSync } from "node:fs";
import * as ccc from "@ckb-ccc/core";
import { evmAddressOf, joyIdPasskey, joyIdSigner } from "../omnilock/phase4/lib.ts";
import { client, loadKeys, loadState, publicKeyOf } from "./lib.ts";

const state = loadState();
const keys = loadKeys();
const record = async (hash: string) => {
  const transaction = (await client.getTransaction(hash))!.transaction;
  const inputCells = await Promise.all(transaction.inputs.map((input) => input.getCell(client)));
  return { transaction, inputCells: inputCells.map((cell) => ({ outPoint: cell.outPoint, cellOutput: cell.cellOutput, outputData: cell.outputData })) };
};
const enable = async (hash: string) => {
  const recorded = await record(hash);
  return { ...recorded, funding: (await client.getTransaction(recorded.transaction.inputs[0].previousOutput.txHash))!.transaction };
};
writeFileSync(new URL("../../tests/fixtures/recovery-backup-unlinking.json", import.meta.url), JSON.stringify(JSON.parse(ccc.stringify({
  note: "CKB testnet proof (research/backup-unlinking/README.md): accounts A and B turn recovery on with the same EVM backup and JoyID-style backup, whose salted auths differ; E1 rescues A and J1 rescues B through the version 3 verifiers",
  publicKeyA: publicKeyOf(keys.KA),
  publicKeyB: publicKeyOf(keys.KB),
  evmBackup: evmAddressOf(keys.E1),
  joyIdBackup: await (await joyIdSigner(keys.J1)).getRecommendedAddress(),
  joyIdPublicKey: joyIdPasskey(keys.J1).publicKey,
  enableA: await enable(state.enableA),
  enableB: await enable(state.enableB),
  rescueEvmA: await record(state.rescueE1A),
  rescueJoyIdB: await record(state.rescueJ1B),
})), null, 2) + "\n");
console.log("recorded");
process.exit(0);
