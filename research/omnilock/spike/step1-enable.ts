// Step 1: turn recovery on. One tx signed only by K's secp key:
//   input 0 = a K secp cell; out 0 = AdminList (Type ID, RCRule root{B1}); out 1 = all the rest -> K's Omnilock.
import { ccc } from "@ckb-ccc/core";
import { client, loadKeys, secpScript, omnilockScript, smtKeyOf, smtBuild, rcDataRule, cellsOf, dryRunAndSend, waitCommitted, saveState, FEE_RATE } from "./lib.ts";

const keys = loadKeys();
const signerK = new ccc.SignerCkbPrivateKey(client, keys.K);
const secpK = await secpScript(keys.K);
const cells = await cellsOf(secpK);
if (!cells.length) throw new Error("K has no cells; claim from faucet first");

const input0 = ccc.CellInput.from({ previousOutput: cells[0].outPoint });
const typeIdScript = await ccc.Script.fromKnownScript(client, ccc.KnownScript.TypeId, ccc.hashTypeId(input0, 0));
const adminTypeHash = typeIdScript.hash();
const omni = await omnilockScript(keys.K, adminTypeHash);
const precomputedAddress = ccc.Address.fromScript(omni, client).toString();

const smt = smtBuild([smtKeyOf(keys.B1)]);
const adminData = rcDataRule(smt.root);

const tx = ccc.Transaction.from({
  inputs: [input0],
  outputs: [{ lock: omni, type: typeIdScript }, { lock: omni }],
  outputsData: [adminData, "0x"],
});
// Size the AdminList at its exact occupied capacity.
tx.outputs[0].capacity = ccc.fixedPointFrom(tx.outputs[0].occupiedSize + ccc.bytesFrom(adminData).length);
await tx.addCellDepsOfKnownScripts(client, ccc.KnownScript.TypeId);
// Only one of K's cells is needed; everything else in it goes to output 1.
await tx.completeInputsByCapacity(signerK);
await tx.completeFeeChangeToOutput(signerK, 1, FEE_RATE);
const signed = await signerK.signTransaction(tx);
if (!signed.inputs[0].previousOutput.eq(input0.previousOutput)) throw new Error("input 0 moved");

const outAddr = ccc.Address.fromScript(signed.outputs[1].lock, client).toString();
console.log("omnilock args", omni.args, "len", ccc.bytesFrom(omni.args).length);
console.log("adminList typeHash", adminTypeHash, "data", adminData);
console.log("precomputed address", precomputedAddress);
console.log("output address     ", outAddr, outAddr === precomputedAddress ? "MATCH" : "MISMATCH");
if (outAddr !== precomputedAddress) throw new Error("address mismatch");

const hash = await dryRunAndSend(signed, "step1", "enable recovery (AdminList + Omnilock)");
await waitCommitted(hash);
saveState({
  omniArgs: omni.args, omniAddress: precomputedAddress, adminTypeArgs: typeIdScript.args, adminTypeHash,
  adminListOutPoint: { txHash: hash, index: 0 }, smtRoot1: smt.root, step1: hash,
});
console.log("committed");
