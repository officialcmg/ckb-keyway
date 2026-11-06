// Plain CKB of each named throwaway key: npx tsx balance.ts KA F1 …
import * as ccc from "@ckb-ccc/core";
import { loadKeys, plainBalance, secpLock } from "./lib.ts";

const keys = loadKeys();
for (const name of process.argv.slice(2)) console.log(name, ccc.fixedPointToString(await plainBalance(await secpLock(keys[name]))));
process.exit(0);
