// Checks the in-page watchtower's claim against a live commitment before its delay has passed: builds the claim from
// the watchtower data in the page's IndexedDB exactly as settleChannel does (minus the fee cell, which the lock does
// not look at), signs it with the channel's settlement key and asks CKB to run the scripts (estimate_cycles, which
// does not wait for `since`). Nothing is sent, and only public facts are returned.
//
// Built into one script and handed to a running browser-settlement.mjs through its eval.js:
//   node research/e2e/claim-dry-run.mjs <evidence folder>
import * as ccc from "@ckb-ccc/core";
import { commitmentLockCellDeps, parseCommitmentArgs, planClaim, signSettlement, XUDT_COMPATIBLE_WITNESS } from "../../src/sdk/browser/watchtower-settle";
import type { WatchedChannel } from "../../src/sdk/browser/watchtower-store";

async function claimDryRun(channelId: string, commitment: string, payTo: string) {
  const name = (await indexedDB.databases()).map((d) => d.name).find((n) => n?.endsWith("-keyway-watchtower"));
  if (!name) return { error: "no watchtower database in this page" };
  const db = await new Promise<IDBDatabase>((resolve, reject) => { const r = indexedDB.open(name); r.onsuccess = () => resolve(r.result); r.onerror = () => reject(r.error); });
  const rows = await new Promise<WatchedChannel[]>((resolve) => { const r = db.transaction("channels").objectStore("channels").getAll(); r.onsuccess = () => resolve(r.result); });
  db.close();
  const channel = rows.find((row) => row.channelId === channelId);
  if (!channel) return { error: "the watchtower holds no data for the channel" };

  const client = new ccc.ClientPublicTestnet();
  const outPoint = ccc.OutPoint.from({ txHash: commitment, index: 0 });
  const cell = await client.getCellLive(outPoint, false);
  if (!cell) return { error: "the commitment cell is not live" };
  const args = parseCommitmentArgs(cell.cellOutput.lock.args);
  const decision = planClaim({ channel, cell: { capacity: cell.cellOutput.capacity, args: cell.cellOutput.lock.args }, now: Date.now() });
  const facts = { commitmentNumber: args.commitmentNumber.toString(), delaySince: `0x${args.delaySince.toString(16)}`, channelFeatures: args.channelFeatures };
  if ("skip" in decision) return { ...facts, skip: decision.skip };
  const plan = decision.claim;
  if (plan.preimage || plan.feeSince !== undefined) return { ...facts, error: "the claim is for a pending payment, which this check does not build" };

  const lock = (await ccc.Address.fromString(payTo, client)).script;
  const unlock = ccc.bytesConcat(new Uint8Array([plan.unlockType, 0]), new Uint8Array(65));
  const tx = ccc.Transaction.from({
    cellDeps: await commitmentLockCellDeps(client, "testnet"),
    inputs: [{ previousOutput: outPoint, since: plan.since }],
    outputs: [
      ...(plan.successor ? [{ capacity: plan.successor.capacity, lock: { ...cell.cellOutput.lock, args: plan.successor.args } }] : []),
      { capacity: cell.cellOutput.capacity - (plan.successor?.capacity ?? 0n), lock },
    ],
    outputsData: plan.successor ? ["0x", "0x"] : ["0x"],
    witnesses: [ccc.hexFrom(ccc.bytesConcat(XUDT_COMPATIBLE_WITNESS, new Uint8Array([1]), plan.witnessState, unlock))],
  });
  signSettlement(tx, plan.signingKey);
  const claim = {
    ...facts, unlockType: `0x${plan.unlockType.toString(16)}`, since: `0x${plan.since.toString(16)}`,
    toTheUser: (cell.cellOutput.capacity - (plan.successor?.capacity ?? 0n)).toString(), leftForThePeer: (plan.successor?.capacity ?? 0n).toString(),
  };
  try {
    return { ...claim, accepted: true, cycles: (await client.estimateCycles(tx)).toString() };
  } catch (error) {
    return { ...claim, accepted: false, error: String((error as Error)?.message ?? error).slice(0, 1500) };
  }
}
Object.assign(window, { claimDryRun });
