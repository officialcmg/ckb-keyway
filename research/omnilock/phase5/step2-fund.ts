// Phase 5, step 2: F sends to the account's KeyWay address, so a rescue has CKB and a token to move:
// two plain cells (`ckb` CKB and 300 CKB) and a 176 CKB cell holding 1,000,000 of a test xUDT that F issues
// (owner mode: the type args are F's lock hash). `npx tsx step2-fund.ts <label> [ckb]`
import * as ccc from "@ckb-ccc/core";
import { client, loadKeys, loadState, saveState, waitCommitted } from "./lib.ts";

const label = process.argv[2] ?? "fund";
const CKB = 100_000_000n;
const plain = BigInt(process.argv[3] ?? "1000") * CKB;
const keys = loadKeys();
const state = loadState();
const funder = new ccc.SignerCkbPrivateKey(client, keys.F);
const token = await ccc.Script.fromKnownScript(client, ccc.KnownScript.XUdt, (await funder.getRecommendedAddressObj()).script.hash());
const lock = (await ccc.Address.fromString(state.newAddress, client)).script;
const amount = (value: bigint) => ccc.hexFrom(ccc.numLeToBytes(value, 16));
const tx = ccc.Transaction.from({
  outputs: [{ lock, capacity: plain }, { lock, capacity: 300n * CKB }, { lock, type: token, capacity: 176n * CKB }],
  outputsData: ["0x", "0x", amount(1_000_000n)],
});
await tx.addCellDepsOfKnownScripts(client, ccc.KnownScript.XUdt);
await tx.completeInputsByCapacity(funder);
await tx.completeFeeBy(funder, 1500);
const signed = await funder.signTransaction(tx);
await client.sendTransactionDry(signed, "passthrough");
const hash = await client.sendTransaction(signed, "passthrough");
console.log(label, "tx", hash, "token", token.hash());
await waitCommitted(hash);
saveState({ [label]: hash, tokenTypeHash: token.hash() });
console.log("committed");
process.exit(0);
