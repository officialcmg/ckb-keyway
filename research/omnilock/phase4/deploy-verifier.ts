// Deploys contracts/build/joyid-webauthn to CKB testnet as a plain data cell, referenced by its data hash
// (hash_type data1). The cell's lock is secp256k1 with 20 zero-byte args, which no key can unlock, so the
// cell can't be consumed. Funded from D1–D4 (one faucet claim each); change returns to D1.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import * as ccc from "@ckb-ccc/core";
import { client, HERE, loadKeys, saveState, secpLock, waitCommitted } from "./lib.ts";

const FEE_RATE = 1500n;
const binary = readFileSync(join(HERE, "../../../contracts/build/joyid-webauthn"));
const keys = loadKeys();
const funders = (["D1", "D2", "D3", "D4"] as const).map((name) => new ccc.SignerCkbPrivateKey(client, keys[name]));
const dead = await ccc.Script.fromKnownScript(client, ccc.KnownScript.Secp256k1Blake160, new Uint8Array(20));
const change = await secpLock(keys.D1);

const verifier = ccc.CellOutput.from({ lock: dead, capacity: 0n });
verifier.capacity = ccc.fixedPointFrom(verifier.occupiedSize + binary.length);
const tx = ccc.Transaction.from({ outputs: [verifier, { lock: change, capacity: 0n }], outputsData: [ccc.hexFrom(binary), "0x"] });
let total = 0n;
for (const signer of funders) {
  for await (const cell of client.findCellsByLock((await signer.getRecommendedAddressObj()).script, null, true)) {
    if (cell.cellOutput.type || cell.outputData !== "0x") continue;
    tx.inputs.push(ccc.CellInput.from({ previousOutput: cell.outPoint }));
    total += cell.cellOutput.capacity;
  }
}
for (const signer of funders) await signer.prepareTransaction(tx);
const fee = (BigInt(tx.toBytes().length + 4) * FEE_RATE + 999n) / 1000n;
if (total < verifier.capacity + fee + ccc.fixedPointFrom(61)) throw new Error(`not enough: ${ccc.fixedPointToString(total)} CKB`);
tx.outputs[1].capacity = total - verifier.capacity - fee;
let signed = tx;
for (const signer of funders) signed = await signer.signOnlyTransaction(signed);
const cycles = await client.sendTransactionDry(signed, "passthrough");
console.log("dry run ok, cycles", cycles.toString(), "size", signed.toBytes().length + 4, "verifier CKB", ccc.fixedPointToString(verifier.capacity));
const hash = await client.sendTransaction(signed, "passthrough");
console.log("deploy tx", hash);
await waitCommitted(hash);
saveState({ verifier: { outPoint: { txHash: hash, index: 0 }, codeHash: ccc.hashCkb(binary), hashType: "data1", size: binary.length, capacity: ccc.fixedPointToString(verifier.capacity) } });
console.log("committed; code hash", ccc.hashCkb(binary));
