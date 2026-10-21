// Step 4a: K spends and recreates the AdminList (same Type ID) with root {B1, B2}. The Omnilock args don't change.
import { ccc } from "@ckb-ccc/core";
import { client, loadKeys, loadState, smtKeyOf, smtBuild, rcDataRule, localSignDigest, signOmnilockOwner, setPlaceholder, witnessLockLen, payFeeFromOutput, dryRunAndSend, waitCommitted, saveState, FEE_RATE } from "./lib.ts";
import { omniLock, plainOmniCells, adminListCell } from "./common-omni.ts";

const keys = loadKeys();
const st = loadState();
const lock = await omniLock();
const admin = await adminListCell();
const [fund] = await plainOmniCells(lock); // largest plain cell pays the fee
const smt = smtBuild([smtKeyOf(keys.B1), smtKeyOf(keys.B2)]);
const newData = rcDataRule(smt.root);

const tx = ccc.Transaction.from({
  inputs: [{ previousOutput: admin.outPoint }, { previousOutput: fund.outPoint }],
  outputs: [admin.cellOutput, { lock, capacity: fund.cellOutput.capacity }],
  outputsData: [newData, "0x"],
});
await tx.addCellDepsOfKnownScripts(client, ccc.KnownScript.OmniLock, ccc.KnownScript.TypeId);
await setPlaceholder(tx, lock, witnessLockLen());
payFeeFromOutput(tx, 1, FEE_RATE);
await signOmnilockOwner(tx, lock, localSignDigest(keys.K));

if (tx.outputs[0].type?.hash() !== st.adminTypeHash) throw new Error("type id changed");
if (tx.outputs[0].lock.args !== st.omniArgs || tx.outputs[1].lock.args !== st.omniArgs) throw new Error("args changed");
console.log("old root", ccc.hexFrom(ccc.bytesFrom(admin.outputData).slice(4, 36)), "new root", smt.root);
const hash = await dryRunAndSend(tx, "step4a", "AdminList rotate {B1} -> {B1,B2}, same Type ID");
await waitCommitted(hash);
const after = await adminListCell();
console.log("AdminList now at", after.outPoint.txHash, after.outPoint.index, "lock args unchanged:", after.cellOutput.lock.args === st.omniArgs,
  "address:", ccc.Address.fromScript(after.cellOutput.lock, client).toString() === st.omniAddress ? "UNCHANGED" : "CHANGED");
saveState({ step4a: hash, smtRoot2: smt.root });
console.log("committed");
