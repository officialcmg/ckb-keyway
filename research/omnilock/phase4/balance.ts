// Prints the CKB at each named key's secp256k1 address: npx tsx balance.ts K D1 D2
import * as ccc from "@ckb-ccc/core";
import { client, loadKeys, secpLock, type KeyName } from "./lib.ts";

const keys = loadKeys();
for (const name of process.argv.slice(2) as KeyName[]) {
  console.log(name, ccc.fixedPointToString(await client.getBalanceSingle(await secpLock(keys[name]))));
}
