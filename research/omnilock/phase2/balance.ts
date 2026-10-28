// Prints the CKB at K's secp256k1 address and, once recovery is on, at its Omnilock address.
import * as ccc from "@ckb-ccc/core";
import { client, loadKeys, loadState, publicKeyOf } from "./lib.ts";

const secp = await ccc.Script.fromKnownScript(client, ccc.KnownScript.Secp256k1Blake160, ccc.hashCkbShort(publicKeyOf(loadKeys().K)));
console.log("secp", ccc.fixedPointToString(await client.getBalanceSingle(secp)));
const { newAddress } = loadState();
if (newAddress) console.log("omnilock", ccc.fixedPointToString(await client.getBalanceSingle((await ccc.Address.fromString(newAddress, client)).script)));
process.exit(0);
