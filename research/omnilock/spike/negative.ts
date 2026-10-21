// Dry-run-only negative checks (nothing is broadcast). Each should be REJECTED by test_tx_pool_accept.
import { ccc } from "@ckb-ccc/core";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { client, loadKeys, authOf, smtKeyOf, smtBuild, localSignDigest, signOmnilockAdmin, signOmnilockOwner, omniWitnessLock, setPlaceholder, witnessLockLen, payFeeFromOutput, FEE_RATE } from "./lib.ts";
import { omniLock, plainOmniCells, adminListCell } from "./common-omni.ts";

const keys = loadKeys();
const lock = await omniLock();
const admin = await adminListCell();
const [cell] = await plainOmniCells(lock);

function base(withDep: boolean) {
  const tx = ccc.Transaction.from({
    inputs: [{ previousOutput: cell.outPoint }],
    outputs: [{ lock, capacity: cell.cellOutput.capacity }],
    outputsData: ["0x"],
    cellDeps: withDep ? [{ outPoint: admin.outPoint, depType: "code" }] : [],
  });
  return tx;
}
async function expectReject(name: string, tx: ccc.Transaction) {
  try {
    await client.sendTransactionDry(tx, "passthrough");
    console.log(`UNEXPECTED ACCEPT: ${name}`);
  } catch (e: any) {
    console.log(`rejected as expected: ${name}\n   ${String(e.message ?? e).slice(0, 220)}`);
  }
}
async function adminTx(signerPriv: string, auth: string, proof: string, withDep = true) {
  const tx = base(withDep);
  await tx.addCellDepsOfKnownScripts(client, ccc.KnownScript.OmniLock);
  await setPlaceholder(tx, lock, witnessLockLen({ proof }));
  payFeeFromOutput(tx, 0, FEE_RATE);
  return signOmnilockAdmin(tx, lock, localSignDigest(signerPriv), auth, proof);
}

// 1. stale proof: B1's proof from the old {B1} root against the current {B1,B2} root.
const oldProof = smtBuild([smtKeyOf(keys.B1)]).proofs[smtKeyOf(keys.B1)];
await expectReject("B1 with stale single-member proof", await adminTx(keys.B1, authOf(keys.B1), oldProof));
// 2. outsider claiming to be B1 (B1's auth + valid proof, but signed by someone else).
const cur = smtBuild([smtKeyOf(keys.B1), smtKeyOf(keys.B2)]);
const outsider = ccc.hexFrom(secp256k1.utils.randomSecretKey());
await expectReject("outsider signing with B1's identity+proof", await adminTx(outsider, authOf(keys.B1), cur.proofs[smtKeyOf(keys.B1)]));
// 3. valid B1 admin witness but AdminList missing from cell deps.
await expectReject("B1 admin path without AdminList dep", await adminTx(keys.B1, authOf(keys.B1), cur.proofs[smtKeyOf(keys.B1)], false));
// 4. owner path signed over a 65-byte zero placeholder, then an 85-byte lock written in.
{
  const tx = base(false);
  await tx.addCellDepsOfKnownScripts(client, ccc.KnownScript.OmniLock);
  await setPlaceholder(tx, lock, witnessLockLen());
  payFeeFromOutput(tx, 0, FEE_RATE);
  await setPlaceholder(tx, lock, 65);
  const info = (await tx.getSignHashInfo(lock, client))!;
  const { r, s, recoveryParam } = await localSignDigest(keys.K)(info.message);
  const w = tx.getWitnessArgsAt(0)!;
  w.lock = ccc.hexFrom(omniWitnessLock(ccc.bytesConcat(ccc.bytesFrom(r), ccc.bytesFrom(s), [recoveryParam])));
  tx.setWitnessArgsAt(0, w);
  await expectReject("owner sig over 65-byte placeholder", tx);
}
// 5. owner path with a bare 65-byte signature as the witness lock (plain secp style).
{
  const tx = base(false);
  await tx.addCellDepsOfKnownScripts(client, ccc.KnownScript.OmniLock);
  await setPlaceholder(tx, lock, 65);
  payFeeFromOutput(tx, 0, FEE_RATE);
  const info = (await tx.getSignHashInfo(lock, client))!;
  const { r, s, recoveryParam } = await localSignDigest(keys.K)(info.message);
  const w = tx.getWitnessArgsAt(0)!;
  w.lock = ccc.hexFrom(ccc.bytesConcat(ccc.bytesFrom(r), ccc.bytesFrom(s), [recoveryParam]));
  tx.setWitnessArgsAt(0, w);
  await expectReject("bare 65-byte secp signature as Omnilock witness lock", tx);
}
// Control: the same tx built correctly through signOmnilockOwner is accepted.
{
  const tx = base(false);
  await tx.addCellDepsOfKnownScripts(client, ccc.KnownScript.OmniLock);
  await setPlaceholder(tx, lock, witnessLockLen());
  payFeeFromOutput(tx, 0, FEE_RATE);
  await signOmnilockOwner(tx, lock, localSignDigest(keys.K));
  console.log("control owner tx dry-run cycles:", await client.sendTransactionDry(tx, "passthrough"));
}
