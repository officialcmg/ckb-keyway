// Phase 2, step 2: spend from the account's Omnilock address through the administrator path, signed only by
// the EVM backup E (Omnilock auth flag 0x01): identity = 0x01 ‖ E's address, one SMT proof (mask 3), the
// AdminList as a cell dep, and E's personal_sign of the raw 32-byte sighash.
import * as ccc from "@ckb-ccc/core";
import { adminListTypeScript, parseRecovery } from "../../../src/sdk/browser/account-lock.ts";
import { evmBackupAuth, evmOmnilockSignature, omnilockAdminWitnessLock } from "../../../src/sdk/browser/recovery-backups.ts";
import { adminListData, whitelistTree } from "../../../src/sdk/browser/recovery-smt.ts";
import { client, evmPersonalSign, loadKeys, loadState, publicKeyOf, saveState, waitCommitted } from "./lib.ts";

const keys = loadKeys();
const state = loadState();
const recovery = parseRecovery(state.recovery, publicKeyOf(keys.K))!;
const omnilock = await ccc.Script.fromKnownScript(client, ccc.KnownScript.OmniLock, recovery.omnilockArgs);
const adminList = await client.findSingletonCellByType(adminListTypeScript(recovery), true);
if (!adminList) throw new Error("AdminList not found");

// The full member list rebuilds the tree; it must hash to the on-chain root.
const auth = evmBackupAuth(state.evmBackup);
const { root, proofs } = whitelistTree([auth]);
if (adminList.outputData !== adminListData(root)) throw new Error("member list doesn't match the on-chain root");
const proof = proofs[auth];

let funds: ccc.Cell | undefined;
for await (const cell of client.findCellsByLock(omnilock, null, true)) {
  if (!cell.cellOutput.type && cell.outputData === "0x") funds = cell;
}
if (!funds) throw new Error("no plain Omnilock cell");
const legacy = (await ccc.Address.fromString(state.legacyAddress, client)).script;
const tx = ccc.Transaction.from({
  inputs: [{ previousOutput: funds.outPoint }],
  outputs: [{ lock: legacy, capacity: ccc.fixedPointFrom(1000) }, { lock: omnilock, capacity: 0n }],
  outputsData: ["0x", "0x"],
  cellDeps: [{ outPoint: adminList.outPoint, depType: "code" }],
});
await tx.addCellDepsOfKnownScripts(client, ccc.KnownScript.OmniLock);
// The whole witness lock is zeroed at its final length before hashing.
const placeholder = omnilockAdminWitnessLock({ signature: new Uint8Array(65), auth, proof });
tx.setWitnessArgsAt(0, ccc.WitnessArgs.from({ lock: ccc.hexFrom(new Uint8Array(ccc.bytesFrom(placeholder).length)) }));
const fee = (BigInt(tx.toBytes().length + 4) * 1500n + 999n) / 1000n;
tx.outputs[1].capacity = funds.cellOutput.capacity - tx.outputs[0].capacity - fee;
const info = await tx.getSignHashInfo(omnilock, client);
if (!info) throw new Error("no sign hash info");
// What a wallet's personal_sign does with the 32 raw bytes of the sighash.
const signature = evmOmnilockSignature(evmPersonalSign(keys.E, ccc.bytesFrom(info.message)));
tx.setWitnessArgsAt(0, ccc.WitnessArgs.from({ lock: omnilockAdminWitnessLock({ signature, auth, proof }) }));

const cycles = await client.sendTransactionDry(tx, "passthrough");
console.log("test_tx_pool_accept ok, cycles", cycles.toString(), "size", tx.toBytes().length + 4, "fee", fee.toString(), "witness lock", ccc.bytesFrom(placeholder).length);
const hash = await client.sendTransaction(tx, "passthrough");
console.log("EVM admin spend", hash);
await waitCommitted(hash);
saveState({ evmSpend: hash });
console.log("committed");
process.exit(0);
