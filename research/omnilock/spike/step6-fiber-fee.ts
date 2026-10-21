// Step 6 (stretch): does a Fiber v0.9.1 external-funding tx, balanced the way funding_tx.rs does it, clear the
// node's min fee rate once the funding source is an Omnilock? Dry runs only (test_tx_pool_accept), nothing sent.
//
// Fiber's balancer (ckb-sdk 5.1.0 CapacityBalancer) sizes the tx with WitnessArgs{lock: 65 zero bytes} and sets
// fee = floor(size_in_block * rate / 1000). Only the FIRST funding_source_lock_script_cell_deps entry is resolved
// during balancing; the rest are appended afterwards by with_extra_cell_deps (funding_tx.rs:658, :701).
import { ccc } from "@ckb-ccc/core";
import { client, loadKeys, secpScript, localSignDigest, signOmnilockOwner, setPlaceholder, witnessLockLen, txSize } from "./lib.ts";
import { omniLock, plainOmniCells } from "./common-omni.ts";

const keys = loadKeys();
const lock = await omniLock();
const [cell] = await plainOmniCells(lock);
const known = await client.getKnownScript(ccc.KnownScript.OmniLock);
// Resolve the type-id code cell dep to its live outpoint.
const resolvedDeps: ccc.CellDep[] = [];
for (const info of known.cellDeps) {
  if (info.type) {
    const c = await client.findSingletonCellByType(info.type, true);
    resolvedDeps.push(ccc.CellDep.from({ outPoint: c!.outPoint, depType: info.cellDep.depType }));
  } else resolvedDeps.push(ccc.CellDep.from(info.cellDep));
}
const fundingStandIn = await secpScript(keys.B1); // stand-in for the channel funding lock (outputs aren't executed)
const FUND = ccc.fixedPointFrom(1000);
const floorFee = (size: number, rate: bigint) => (BigInt(size) * rate) / 1000n;

async function trial(rate: bigint, depsDuringBalance: ccc.CellDep[], depsAfter: ccc.CellDep[]) {
  const tx = ccc.Transaction.from({
    inputs: [{ previousOutput: cell.outPoint }],
    outputs: [{ lock: fundingStandIn, capacity: FUND }, { lock, capacity: cell.cellOutput.capacity - FUND }],
    outputsData: ["0x", "0x"],
    cellDeps: depsDuringBalance,
  });
  await setPlaceholder(tx, lock, 65); // Fiber's secp placeholder
  const est = txSize(tx);
  const fee = floorFee(est, rate);
  tx.outputs[1].capacity -= fee;
  tx.cellDeps.push(...depsAfter);
  await setPlaceholder(tx, lock, witnessLockLen()); // real Omnilock owner lock is 85 bytes
  await signOmnilockOwner(tx, lock, localSignDigest(keys.K));
  const actual = txSize(tx);
  const minFee = floorFee(actual, 1000n);
  let verdict: string;
  try {
    const cycles = await client.sendTransactionDry(tx, "passthrough");
    verdict = `ACCEPTED (cycles ${cycles})`;
  } catch (e: any) {
    const m = String(e.message ?? e);
    verdict = "REJECTED: " + (m.match(/PoolRejected\w+[^"]{0,160}/)?.[0] ?? m.slice(0, 200));
  }
  console.log(`rate=${rate} deps(balance/after)=${depsDuringBalance.length}/${depsAfter.length} estSize=${est} actualSize=${actual} fee=${fee} nodeMinFee@1000=${minFee} -> ${verdict}`);
}

console.log("Omnilock cell deps (CCC KnownScript):", resolvedDeps.map((d) => `${d.outPoint.txHash}:${d.outPoint.index} ${d.depType}`));
// A: realistic — user passes both Omnilock deps; Fiber resolves the first during balancing, appends the second.
await trial(1000n, [resolvedDeps[0]], [resolvedDeps[1]]);
await trial(1500n, [resolvedDeps[0]], [resolvedDeps[1]]);
// B: witness delta alone (both deps present while balancing), isolating the 85-vs-65-byte lock.
await trial(1000n, resolvedDeps, []);
await trial(1500n, resolvedDeps, []);
