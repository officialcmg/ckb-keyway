// Plain CKB at each named throwaway key's secp256k1 address: npx tsx balance.ts K F1 …
import * as ccc from "@ckb-ccc/core";
import { loadKeys, plainBalance, secpLock } from "./lib.ts";

const keys = loadKeys();
let total = 0n;
for (const name of process.argv.slice(2)) {
  const balance = await plainBalance(await secpLock(keys[name]));
  total += balance;
  console.log(name, ccc.fixedPointToString(balance));
}
console.log("total", ccc.fixedPointToString(total));
process.exit(0);
