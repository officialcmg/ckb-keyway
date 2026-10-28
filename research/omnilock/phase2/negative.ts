// Dry runs only: the admin path must refuse a signature from an EVM key that isn't the listed backup, and a
// backup that isn't in the AdminList.
import * as ccc from "@ckb-ccc/core";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { adminListTypeScript, parseRecovery } from "../../../src/sdk/browser/account-lock.ts";
import { evmBackupAuth, evmOmnilockSignature, omnilockAdminWitnessLock } from "../../../src/sdk/browser/recovery-backups.ts";
import { whitelistTree } from "../../../src/sdk/browser/recovery-smt.ts";
import { client, evmAddressOf, evmPersonalSign, loadKeys, loadState, publicKeyOf } from "./lib.ts";

const keys = loadKeys();
const state = loadState();
const recovery = parseRecovery(state.recovery, publicKeyOf(keys.K))!;
const omnilock = await ccc.Script.fromKnownScript(client, ccc.KnownScript.OmniLock, recovery.omnilockArgs);
const adminList = (await client.findSingletonCellByType(adminListTypeScript(recovery), true))!;
let funds: ccc.Cell | undefined;
for await (const cell of client.findCellsByLock(omnilock, null, true)) if (!cell.cellOutput.type && cell.outputData === "0x") funds = cell;

async function attempt(name: string, auth: ccc.Hex, proof: ccc.Hex, signingKey: string) {
  const tx = ccc.Transaction.from({
    inputs: [{ previousOutput: funds!.outPoint }],
    outputs: [{ lock: omnilock, capacity: funds!.cellOutput.capacity - 2000n }],
    outputsData: ["0x"],
    cellDeps: [{ outPoint: adminList.outPoint, depType: "code" }],
  });
  await tx.addCellDepsOfKnownScripts(client, ccc.KnownScript.OmniLock);
  const length = ccc.bytesFrom(omnilockAdminWitnessLock({ signature: new Uint8Array(65), auth, proof })).length;
  tx.setWitnessArgsAt(0, ccc.WitnessArgs.from({ lock: ccc.hexFrom(new Uint8Array(length)) }));
  const info = (await tx.getSignHashInfo(omnilock, client))!;
  const signature = evmOmnilockSignature(evmPersonalSign(signingKey, ccc.bytesFrom(info.message)));
  tx.setWitnessArgsAt(0, ccc.WitnessArgs.from({ lock: omnilockAdminWitnessLock({ signature, auth, proof }) }));
  try {
    await client.sendTransactionDry(tx, "passthrough");
    console.log(`${name}: accepted`);
  } catch (error) {
    console.log(`${name}: rejected, ${String((error as Error).message).match(/error code (-?\d+)/)?.[0] ?? (error as Error).message.slice(0, 160)}`);
  }
}

const outsider = ccc.hexFrom(secp256k1.utils.randomSecretKey());
const listed = evmBackupAuth(state.evmBackup);
await attempt("control: E signs as E", listed, whitelistTree([listed]).proofs[listed], keys.E);
await attempt("outsider signs with E's identity and proof", listed, whitelistTree([listed]).proofs[listed], outsider);
const unlisted = evmBackupAuth(evmAddressOf(outsider));
await attempt("outsider with its own identity, proof from its own tree", unlisted, whitelistTree([unlisted]).proofs[unlisted], outsider);
process.exit(0);
