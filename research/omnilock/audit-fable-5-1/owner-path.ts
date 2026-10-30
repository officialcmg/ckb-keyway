// Testnet dry run: with recovery on, does the account's own key (Omnilock owner path) still spend when the
// transaction carries no AdminList cell dep at all, i.e. would funds stay reachable if the AdminList were destroyed?
import * as ccc from "@ckb-ccc/core";
import { OMNILOCK_OWNER_WITNESS_LOCK_LENGTH } from "../../../src/sdk/browser/account-lock.ts";
import { formatCkbSignature, signAccountGroups } from "../../../src/server/funding-transaction.ts";
import { client, loadKeys, loadState, localLitSignature, secpLock } from "./lib.ts";

const keys = loadKeys();
const state = loadState();
const omnilock = await ccc.Script.fromKnownScript(client, ccc.KnownScript.OmniLock, state.omnilockArgs);
let plain: ccc.Cell | undefined;
for await (const cell of client.findCellsByLock(omnilock, null, true)) if (!cell.cellOutput.type && cell.outputData === "0x") plain = cell;
if (!plain) throw new Error("no plain Omnilock cell");
const transaction = ccc.Transaction.from({
  inputs: [{ previousOutput: plain.outPoint }],
  outputs: [{ lock: await secpLock(keys.K), capacity: plain.cellOutput.capacity - 100_000n }],
  outputsData: ["0x"],
});
await transaction.addCellDepsOfKnownScripts(client, ccc.KnownScript.OmniLock);
transaction.witnesses = [ccc.hexFrom(ccc.WitnessArgs.from({ lock: ccc.hexFrom(new Uint8Array(OMNILOCK_OWNER_WITNESS_LOCK_LENGTH)) }).toBytes())];
const signed = await signAccountGroups(transaction, [{ script: omnilock, kind: "omnilock" }], client, async (digest) => formatCkbSignature(localLitSignature(keys.K, digest)));
console.log("cell deps", signed.cellDeps.map((dep) => `${dep.outPoint.txHash.slice(0, 10)}:${dep.outPoint.index}`), "(Omnilock only, no AdminList)");
console.log("owner path, no AdminList dep: test_tx_pool_accept OK, cycles", (await client.sendTransactionDry(signed, "passthrough")).toString(), "(not sent)");
