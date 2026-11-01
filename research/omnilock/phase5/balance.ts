// Prints the CKB at each named key's secp256k1 address and, once recovery is on, at the account's KeyWay address.
import { client, loadKeys, loadState, secpLock } from "./lib.ts";
import { openRescueAccount } from "../../../src/rescue/rescue.ts";

const keys = loadKeys();
for (const name of ["K", "F", "D1", "D2"] as const) {
  console.log(name, (await client.getBalance([await secpLock(keys[name])])).toString());
}
const state = loadState();
if (state.newAddress) {
  const account = await openRescueAccount(client, state.newAddress);
  console.log("KeyWay address: ckb", account.ckb.toString(), "token cells", account.tokenCkb.toString(), account.tokens.map(({ amountText }) => amountText), "backups", account.entries.length);
}
process.exit(0);
