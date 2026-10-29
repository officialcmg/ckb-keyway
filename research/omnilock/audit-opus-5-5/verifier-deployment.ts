// Checks the deployed JoyID verifier cell: data hash == SDK code hash == blake2b(build/joyid-webauthn), and its lock.
import * as ccc from "@ckb-ccc/core";
import { readFileSync } from "node:fs";
import { JOYID_WEBAUTHN_VERIFIER } from "../../../src/sdk/browser/recovery-backups.ts";

const client = new ccc.ClientPublicTestnet();
const dep = JOYID_WEBAUTHN_VERIFIER.testnetCellDep.outPoint;
const tx = await client.getTransaction(dep.txHash);
const output = tx!.transaction.outputs[dep.index];
const data = tx!.transaction.outputsData[dep.index];
const live = await client.getCellLive(dep, false);
console.log("sdk code hash      ", JOYID_WEBAUTHN_VERIFIER.codeHash);
console.log("on-chain data hash ", ccc.hashCkb(data));
console.log("build/ data hash   ", ccc.hashCkb(readFileSync("contracts/build/joyid-webauthn")));
console.log("cell live          ", Boolean(live));
console.log("cell lock          ", JSON.stringify(output.lock), "type", JSON.stringify(output.type ?? null));
process.exit(0);
