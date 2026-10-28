// Claims 10000 testnet CKB to K's secp256k1 address.
import * as ccc from "@ckb-ccc/core";
import { client, loadKeys, publicKeyOf } from "./lib.ts";

const lock = await ccc.Script.fromKnownScript(client, ccc.KnownScript.Secp256k1Blake160, ccc.hashCkbShort(publicKeyOf(loadKeys().K)));
const address = ccc.Address.fromScript(lock, client).toString();
console.log("address", address);
const response = await fetch("https://faucet-api.nervos.org/claim_events", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ claim_event: { address_hash: address, amount: "10000" } }),
});
console.log(response.status, (await response.text()).slice(0, 300));
