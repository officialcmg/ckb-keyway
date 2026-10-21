// Step 3 (and 4b): backup spend through the admin path: identity + SMT proof, AdminList as a cell dep.
// Usage: tsx step3-backup.ts B1   (or B2 after step 4). Spends a 1500 CKB Omnilock cell to the backup's secp address.
import { ccc } from "@ckb-ccc/core";
import { client, loadKeys, loadState, authOf, smtKeyOf, smtBuild, secpScript, localSignDigest, signOmnilockAdmin, setPlaceholder, witnessLockLen, payFeeFromOutput, dryRunAndSend, waitCommitted, saveState, FEE_RATE } from "./lib.ts";
import { omniLock, plainOmniCells, adminListCell } from "./common-omni.ts";

const who = (process.argv[2] ?? "B1") as "B1" | "B2";
const keys = loadKeys();
const st = loadState();
const lock = await omniLock();
const admin = await adminListCell();
// Rebuild the tree with the members the on-chain root claims, and check it matches.
const members = st.smtRoot2 ? [keys.B1, keys.B2] : [keys.B1];
const smt = smtBuild(members.map(smtKeyOf));
const onchainRoot = ccc.hexFrom(ccc.bytesFrom(admin.outputData).slice(4, 36));
if (smt.root !== onchainRoot) throw new Error(`root mismatch ${smt.root} vs ${onchainRoot}`);
const proof = smt.proofs[smtKeyOf(keys[who])];
console.log(who, "auth", authOf(keys[who]), "proof", proof, "AdminList", admin.outPoint.txHash, admin.outPoint.index);

const cell = (await plainOmniCells(lock)).find((c) => c.cellOutput.capacity === ccc.fixedPointFrom(1500));
if (!cell) throw new Error("no 1500 CKB omnilock cell");
const to = await secpScript(keys[who]);
const tx = ccc.Transaction.from({
  inputs: [{ previousOutput: cell.outPoint }],
  outputs: [{ lock: to, capacity: cell.cellOutput.capacity }],
  outputsData: ["0x"],
  cellDeps: [{ outPoint: admin.outPoint, depType: "code" }],
});
await tx.addCellDepsOfKnownScripts(client, ccc.KnownScript.OmniLock);
const len = witnessLockLen({ proof });
console.log("admin witness lock length", len);
await setPlaceholder(tx, lock, len);
payFeeFromOutput(tx, 0, FEE_RATE);
await signOmnilockAdmin(tx, lock, localSignDigest(keys[who]), authOf(keys[who]), proof);
console.log("witness[0]", tx.witnesses[0]);
const step = who === "B1" ? "step3" : "step4b";
const hash = await dryRunAndSend(tx, step, `backup ${who} admin-path spend`);
await waitCommitted(hash);
saveState({ [step]: hash });
console.log("committed");
