// Step 2: everyday owner spend from the Omnilock with K (85-byte witness lock, no AdminList dep).
// Splits the big Omnilock cell into: 1500 CKB (for step 3), 1500 CKB (for step 4b), rest change.
import { ccc } from "@ckb-ccc/core";
import { client, loadKeys, localSignDigest, signOmnilockOwner, setPlaceholder, witnessLockLen, payFeeFromOutput, dryRunAndSend, waitCommitted, saveState, FEE_RATE } from "./lib.ts";
import { omniLock, plainOmniCells } from "./common-omni.ts";

const keys = loadKeys();
const lock = await omniLock();
const [cell] = await plainOmniCells(lock);
const amt = ccc.fixedPointFrom(1500);
const tx = ccc.Transaction.from({
  inputs: [{ previousOutput: cell.outPoint }],
  outputs: [{ lock, capacity: amt }, { lock, capacity: amt }, { lock, capacity: cell.cellOutput.capacity - 2n * amt }],
  outputsData: ["0x", "0x", "0x"],
});
await tx.addCellDepsOfKnownScripts(client, ccc.KnownScript.OmniLock);
const len = witnessLockLen();
console.log("owner witness lock length", len);
await setPlaceholder(tx, lock, len);
payFeeFromOutput(tx, 2, FEE_RATE);
await signOmnilockOwner(tx, lock, localSignDigest(keys.K));
console.log("witness[0]", tx.witnesses[0]);
const hash = await dryRunAndSend(tx, "step2", "owner spend (K, 85-byte lock)");
await waitCommitted(hash);
saveState({ step2: hash });
console.log("committed");
