// Claims 10000 testnet CKB to the named throwaway key's secp256k1 address: npx tsx faucet.ts K
import { loadKeys, secpAddress, type KeyName } from "./lib.ts";

const name = (process.argv[2] ?? "K") as KeyName;
const address = await secpAddress(loadKeys()[name]);
console.log(name, address);
const response = await fetch("https://faucet-api.nervos.org/claim_events", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ claim_event: { address_hash: address, amount: "10000" } }),
});
console.log(response.status, (await response.text()).slice(0, 300));
