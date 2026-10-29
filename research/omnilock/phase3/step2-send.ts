// Phase 3, step 2: I sends to K's old secp256k1 address, after recovery is on.
//   `step2-send.ts mixed`: 300 CKB, 70 CKB (below the 95 CKB Omnilock minimum), 142 CKB holding 1,000,000 of a
//   test xUDT that I issues (owner mode: the type args are I's lock hash), and a 70 CKB cell with data, which
//   the sweep must leave alone.
//   `step2-send.ts lone-token`: one 142 CKB cell holding 500,000 of the same token and nothing else.
import * as ccc from "@ckb-ccc/core";
import { client, loadKeys, publicKeyOf, saveState, secpLockOf, waitCommitted } from "./lib.ts";

const mode = process.argv[2];
if (mode !== "mixed" && mode !== "lone-token") throw new Error("mode: mixed or lone-token");
const keys = loadKeys();
const issuer = new ccc.SignerCkbPrivateKey(client, keys.I);
const issuerLock = (await issuer.getRecommendedAddressObj()).script;
const token = await ccc.Script.fromKnownScript(client, ccc.KnownScript.XUdt, issuerLock.hash());
const old = await secpLockOf(publicKeyOf(keys.K));
const CKB = 100_000_000n;
const amount = (value: bigint) => ccc.hexFrom(ccc.numLeToBytes(value, 16));

const outputs = mode === "mixed"
  ? [
    { output: { lock: old, capacity: 300n * CKB }, data: "0x" },
    { output: { lock: old, capacity: 70n * CKB }, data: "0x" },
    { output: { lock: old, type: token, capacity: 142n * CKB }, data: amount(1_000_000n) },
    { output: { lock: old, capacity: 70n * CKB }, data: "0x1234" },
  ]
  : [{ output: { lock: old, type: token, capacity: 142n * CKB }, data: amount(500_000n) }];
const tx = ccc.Transaction.from({ outputs: outputs.map(({ output }) => output), outputsData: outputs.map(({ data }) => data) });
await tx.addCellDepsOfKnownScripts(client, ccc.KnownScript.XUdt);
await tx.completeInputsByCapacity(issuer);
await tx.completeFeeBy(issuer, 1500);
const signed = await issuer.signTransaction(tx);
await client.sendTransactionDry(signed, "passthrough");
const hash = await client.sendTransaction(signed, "passthrough");
console.log(mode, "send tx", hash, "token", token.hash());
await waitCommitted(hash);
saveState({ [`send-${mode}`]: hash, tokenTypeHash: token.hash(), tokenArgs: token.args });
console.log("committed");
process.exit(0);
