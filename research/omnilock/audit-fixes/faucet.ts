// Claims 10000 testnet CKB for each named throwaway key: npx tsx faucet.ts K F1 F2 …
import { loadKeys, secpAddress } from "./lib.ts";

const keys = loadKeys();
for (const name of process.argv.slice(2)) {
  const address = await secpAddress(keys[name]);
  const response = await fetch("https://faucet-api.nervos.org/claim_events", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ claim_event: { address_hash: address, amount: "10000" } }),
  });
  console.log(name, address, response.status, (await response.text()).slice(0, 200));
}
process.exit(0);
