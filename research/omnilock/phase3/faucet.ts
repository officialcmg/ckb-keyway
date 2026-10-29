// Claims 10000 testnet CKB to the secp256k1 address of K or I: `faucet.ts K` or `faucet.ts I`.
import * as ccc from "@ckb-ccc/core";
import { client, loadKeys, publicKeyOf, secpLockOf } from "./lib.ts";

const name = process.argv[2] as "K" | "I";
const address = ccc.Address.fromScript(await secpLockOf(publicKeyOf(loadKeys()[name])), client).toString();
console.log(name, "address", address);
const response = await fetch("https://faucet-api.nervos.org/claim_events", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ claim_event: { address_hash: address, amount: "10000" } }),
});
console.log(response.status, (await response.text()).slice(0, 300));
