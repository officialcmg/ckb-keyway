// Prints the CKB and cells at K's old secp256k1 address, at its Omnilock address once recovery is on, and at I's address.
import * as ccc from "@ckb-ccc/core";
import { client, loadKeys, loadState, publicKeyOf, secpLockOf } from "./lib.ts";

const keys = loadKeys();
const show = async (name: string, lock: ccc.Script) => {
  const cells: string[] = [];
  for await (const cell of client.findCellsByLock(lock, null, true)) {
    cells.push(`${ccc.fixedPointToString(cell.cellOutput.capacity)}${cell.cellOutput.type ? ` type ${cell.cellOutput.type.codeHash.slice(0, 10)}… data ${cell.outputData.slice(0, 34)}` : cell.outputData !== "0x" ? ` data ${cell.outputData}` : ""}`);
  }
  console.log(name, ccc.fixedPointToString(await client.getBalanceSingle(lock)), "CKB plain;", cells.length, "cells:", cells.join(" | "));
};
await show("K old", await secpLockOf(publicKeyOf(keys.K)));
const { newAddress } = loadState();
if (newAddress) await show("K new", (await ccc.Address.fromString(newAddress, client)).script);
await show("I", await secpLockOf(publicKeyOf(keys.I)));
process.exit(0);
