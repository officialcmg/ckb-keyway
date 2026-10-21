// Usage: tsx faucet.ts <who: K|B1|B2|addr> — claims 10000 testnet CKB to that key's secp address.
import { ccc } from "@ckb-ccc/core";
import { client, loadKeys, secpScript } from "./lib.ts";

const who = process.argv[2] ?? "K";
const keys = loadKeys();
const address = who.startsWith("ckt1") ? who : ccc.Address.fromScript(await secpScript((keys as any)[who]), client).toString();
console.log("address", address);
const res = await fetch("https://faucet-api.nervos.org/claim_events", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ claim_event: { address_hash: address, amount: "10000" } }),
});
console.log(res.status, await res.text());
