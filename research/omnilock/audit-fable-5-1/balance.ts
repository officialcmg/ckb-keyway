// Prints the CKB at the named key's secp256k1 address and, if recovery was enabled, at the Omnilock address.
import * as ccc from "@ckb-ccc/core";
import { client, loadKeys, loadState, secpLock, type KeyName } from "./lib.ts";

const name = (process.argv[2] ?? "K") as KeyName;
const keys = loadKeys();
async function show(label: string, lock: ccc.Script) {
  let total = 0n, n = 0;
  for await (const cell of client.findCellsByLock(lock, null, true)) { total += cell.cellOutput.capacity; n++; }
  console.log(label, "cells", n, "CKB", ccc.fixedPointToString(total));
}
await show(`${name} secp256k1`, await secpLock(keys[name]));
const state = loadState();
if (name === "K" && state.omnilockArgs) await show("K Omnilock", await ccc.Script.fromKnownScript(client, ccc.KnownScript.OmniLock, state.omnilockArgs));
