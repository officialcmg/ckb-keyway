// Step 5: after the switch, CKB still lands on K's old secp address. Send some there (from the Omnilock, owner
// path), then sweepOldAddress(K, omniLock) moves everything on the old address to the Omnilock.
import { ccc } from "@ckb-ccc/core";
import { client, loadKeys, secpScript, cellsOf, localSignDigest, signOmnilockOwner, setPlaceholder, witnessLockLen, payFeeFromOutput, dryRunAndSend, waitCommitted, saveState, FEE_RATE } from "./lib.ts";
import { omniLock, plainOmniCells } from "./common-omni.ts";

/** Moves every cell on K's old secp256k1-blake160 address to the Omnilock, signed with K's normal secp signature. */
export async function sweepOldAddress(privK: string, newOmnilockLock: ccc.Script): Promise<ccc.Hex | undefined> {
  const signer = new ccc.SignerCkbPrivateKey(client, privK);
  const old = await secpScript(privK);
  const cells = (await cellsOf(old)).filter((c) => !c.cellOutput.type && c.outputData === "0x");
  if (!cells.length) return undefined;
  const total = cells.reduce((a, c) => a + c.cellOutput.capacity, 0n);
  const tx = ccc.Transaction.from({
    inputs: cells.map((c) => ({ previousOutput: c.outPoint })),
    outputs: [{ lock: newOmnilockLock, capacity: total }],
    outputsData: ["0x"],
  });
  await tx.addCellDepsOfKnownScripts(client, ccc.KnownScript.Secp256k1Blake160);
  await tx.prepareSighashAllWitness(old, 65, client);
  payFeeFromOutput(tx, 0, FEE_RATE);
  const signed = await signer.signTransaction(tx);
  return dryRunAndSend(signed, "step5b", `sweep ${cells.length} cell(s) old secp -> Omnilock`);
}

const keys = loadKeys();
const lock = await omniLock();
const old = await secpScript(keys.K);

// 5a: deposit 500 CKB to the old address.
const [fund] = await plainOmniCells(lock);
const dep = ccc.Transaction.from({
  inputs: [{ previousOutput: fund.outPoint }],
  outputs: [{ lock: old, capacity: ccc.fixedPointFrom(500) }, { lock, capacity: fund.cellOutput.capacity - ccc.fixedPointFrom(500) }],
  outputsData: ["0x", "0x"],
});
await dep.addCellDepsOfKnownScripts(client, ccc.KnownScript.OmniLock);
await setPlaceholder(dep, lock, witnessLockLen());
payFeeFromOutput(dep, 1, FEE_RATE);
await signOmnilockOwner(dep, lock, localSignDigest(keys.K));
const h1 = await dryRunAndSend(dep, "step5a", "deposit 500 CKB to K's old secp address");
await waitCommitted(h1);

// 5b: sweep.
const h2 = await sweepOldAddress(keys.K, lock);
if (!h2) throw new Error("nothing to sweep");
await waitCommitted(h2);
const left = await cellsOf(old);
console.log("old address cells left:", left.length);
saveState({ step5a: h1, step5b: h2 });
