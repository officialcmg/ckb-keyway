// JoyID verifier proof: negative dry runs (test_tx_pool_accept only, nothing is sent). Each builds the same
// admin-path spend as joyid-spend.ts and changes one thing. Output in joyid-negative.out.
import * as ccc from "@ckb-ccc/core";
import { omnilockLock } from "../../../src/sdk/browser/account-lock.ts";
import { execAuth, joyIdPreimage, joyIdVerifierCellDep, omnilockAdminWitnessLock } from "../../../src/sdk/browser/recovery-backups.ts";
import { readRecoveryList } from "../../../src/sdk/browser/recovery-list.ts";
import { whitelistTree } from "../../../src/sdk/browser/recovery-smt.ts";
import { parseJoyIdSignature, webAuthnSignatureBlob } from "../../../src/sdk/browser/webauthn.ts";
import { client, joyIdLockOf, joyIdPasskey, loadKeys, loadState, secpLock } from "./lib.ts";

const keys = loadKeys();
const state = loadState();
const omnilock = await omnilockLock(client, state.recovery);
const list = await readRecoveryList(client, state.recovery);
const j1 = list.entries.find(({ backup }) => backup.kind === "joyid")!;
const SLOT = 768;

let input: ccc.Cell | undefined;
for await (const cell of client.findCellsByLock(omnilock, null, true)) {
  if (!cell.cellOutput.type && cell.outputData === "0x" && (!input || cell.cellOutput.capacity > input.cellOutput.capacity)) input = cell;
}

type Case = {
  auth?: ccc.Hex; preimage?: ccc.Hex; proofAuths?: ccc.Hex[]; signer?: string; publicKeyOf?: string;
  signOther?: boolean; noVerifierDep?: boolean; noSignature?: boolean; joyIdInput?: boolean;
};

async function attempt(label: string, options: Case) {
  const auth = options.auth ?? j1.auth;
  const preimage = options.noSignature ? undefined : options.preimage ?? j1.preimage;
  const proof = whitelistTree(options.proofAuths ?? list.entries.map((entry) => entry.auth)).proofs[auth];
  const tx = ccc.Transaction.from({
    inputs: [{ previousOutput: input!.outPoint }],
    outputs: [{ lock: await secpLock(keys.K), capacity: ccc.fixedPointFrom(1000) }, { lock: omnilock, capacity: input!.cellOutput.capacity - ccc.fixedPointFrom(1000) - 5000n }],
    outputsData: ["0x", "0x"],
  });
  await tx.addCellDepsOfKnownScripts(client, ccc.KnownScript.OmniLock);
  tx.addCellDeps({ outPoint: list.cell.outPoint, depType: "code" });
  if (!options.noVerifierDep) tx.addCellDeps(joyIdVerifierCellDep(client));
  if (options.joyIdInput) {
    const joyLock = await joyIdLockOf(keys.J1);
    for await (const cell of client.findCellsByLock(joyLock, null, true)) { tx.inputs.push(ccc.CellInput.from({ previousOutput: cell.outPoint })); tx.outputs[1].capacity += cell.cellOutput.capacity; break; }
    await tx.addCellDepsOfKnownScripts(client, ccc.KnownScript.JoyId);
  }
  const signature = options.noSignature ? new Uint8Array() : new Uint8Array(SLOT);
  const lockOf = (sig: ccc.HexLike) => options.noSignature
    ? ccc.hexFrom(ccc.bytesFrom(omnilockAdminWitnessLock({ signature: "0x", auth, proof })).slice())
    : omnilockAdminWitnessLock({ signature: sig, auth, proof, preimage });
  tx.setWitnessArgsAt(0, ccc.WitnessArgs.from({ lock: ccc.hexFrom(new Uint8Array(ccc.bytesFrom(lockOf(signature)).length)) }));
  if (!options.noSignature) {
    let message = (await tx.getSignHashInfo(omnilock, client))!.message;
    if (options.signOther) message = ccc.hexFrom(ccc.hashCkb(message));
    const passkey = joyIdPasskey(keys[(options.signer ?? "J1") as "J1"]);
    const assertion = parseJoyIdSignature(passkey.signMessageRaw(`CKB transaction: ${message}`), joyIdPasskey(keys[(options.publicKeyOf ?? options.signer ?? "J1") as "J1"]).publicKey);
    tx.setWitnessArgsAt(0, ccc.WitnessArgs.from({ lock: lockOf(webAuthnSignatureBlob(assertion, SLOT)) }));
  } else {
    tx.setWitnessArgsAt(0, ccc.WitnessArgs.from({ lock: lockOf("0x") }));
  }
  try {
    const cycles = await client.sendTransactionDry(tx, "passthrough");
    console.log(`${label}: accepted (${cycles} cycles)`);
  } catch (error) {
    const text = String(error instanceof Error ? error.message : error);
    console.log(`${label}: rejected, ${/error code (-?\d+)/.exec(text)?.[0] ?? text.slice(0, 200)} ${/Inputs\[\d+\]\.Lock/.exec(text)?.[0] ?? ""}`);
  }
}

const j2Preimage = joyIdPreimage(ccc.hashCkbShort(joyIdPasskey(keys.J2).publicKey));
const joyLock = await joyIdLockOf(keys.J1);
await attempt("Control: J1 signs this transaction", {});
await attempt("J1 signs another transaction's sighash", { signOther: true });
await attempt("J2 signs with its own key under J1's identity and proof", { signer: "J2" });
await attempt("J2's signature with J1's public key in the blob", { signer: "J2", publicKeyOf: "J1" });
await attempt("J2 with its own identity and a proof from a tree that contains it", { signer: "J2", auth: execAuth(j2Preimage), preimage: j2Preimage, proofAuths: [j1.auth, execAuth(j2Preimage)] });
await attempt("J1 signs, but the verifier isn't a cell dep", { noVerifierDep: true });
await attempt("Owner-lock style (0xFC, J1's JoyID lock hash), J1's JoyID cell as an input, no signature", {
  auth: ccc.hexFrom(ccc.bytesConcat([0xfc], ccc.bytesFrom(joyLock.hash()).slice(0, 20))), noSignature: true, joyIdInput: true, proofAuths: [j1.auth, ccc.hexFrom(ccc.bytesConcat([0xfc], ccc.bytesFrom(joyLock.hash()).slice(0, 20)))],
});
await attempt("J1's identity with no signature and a JoyID input", { noSignature: true, joyIdInput: true });
process.exit(0);
