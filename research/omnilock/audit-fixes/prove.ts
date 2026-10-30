// Testnet proof of the audit fixes, with throwaway keys (keys.json, gitignored, never printed) and a local
// Postgres for KeyWay's own records. Each step runs KeyWay's real code: the server's recovery flow (challenge,
// preview, emailed code, enable/apply, settle once committed), then the rescue page's library for the backups'
// spends. Run step by step: npx tsx prove.ts enable | add | remove | negative | joyid | refund | evm
// Needs DATABASE_URL (a local Postgres with KeyWay's tables) and KEYWAY_RATE_LIMIT_SECRET.
import * as ccc from "@ckb-ccc/core";
import { adminListLock, omnilockScript, secp256k1Lock } from "../../../src/sdk/browser/account-lock.ts";
import { evmApprovalSignature, omnilockAdminWitnessLock, recoveryBackupChallenge, type RecoveryBackup } from "../../../src/sdk/browser/recovery-backups.ts";
import { prepareRecoverySpend } from "../../../src/sdk/browser/recovery-spend.ts";
import { parseJoyIdSignature, webAuthnSignatureBlob, MAX_WEBAUTHN_SIGNATURE } from "../../../src/sdk/browser/webauthn.ts";
import { openRescueAccount, planRescue, rescueEntryForEvm, rescueEntryForJoyId, sendRescue, signRescueWithEvm, signRescueWithJoyId } from "../../../src/rescue/rescue.ts";
import { formatCkbSignature } from "../../../src/server/funding-transaction.ts";
import { issueBackupChallenge, recoveryBackupChange, recoverySetup, settleRecoveryChange, type RecoveryContext } from "../../../src/server/recovery.ts";
import { readWallet, saveWallet, type ReadyWallet } from "../../../src/server/user-wallet.ts";
import { evmAddressOf, evmPersonalSign, joyIdPasskey, joyIdSigner, localLitSignature } from "../phase4/lib.ts";
import { client, loadKeys, loadState, publicKeyOf, saveState, secpAddress, waitCommitted } from "./lib.ts";

const keys = loadKeys();
const state = loadState();
const emails: string[] = [];
const code = () => /code is (\d{6})/.exec(emails.findLast((text) => /code is \d{6}/.test(text))!)![1];
const user = { id: state.userId ?? crypto.randomUUID() };
if (!state.userId) saveState({ userId: user.id });

async function wallet(): Promise<ReadyWallet> {
  let current = await readWallet(user);
  if (!current) {
    current = {
      version: 1, status: "ready", litPkpId: "0xaudit-fixes-throwaway", litPublicKey: publicKeyOf(keys.K), ckbAddress: await secpAddress(keys.K),
      encryptedFiberKey: "unused", primaryDeviceIdHash: "0".repeat(64), hasOpenedChannel: false,
      createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
    };
    await saveWallet(user, current);
  }
  if (current.status !== "ready") throw new Error("wallet isn't ready");
  return current;
}

const context = (current: ReadyWallet): RecoveryContext => ({
  user, wallet: current, appName: "KeyWay audit-fix testnet proof", client,
  email: async () => "audit-fixes@example.invalid",
  sendEmail: async (_to: string, message: { plaintext: string }) => { emails.push(message.plaintext); },
  rateLimit: async () => ({ allowed: true, retryAfter: null }),
  recordSigning: async () => undefined,
  signDigest: async (digest: ccc.Hex) => formatCkbSignature(localLitSignature(keys.K, digest)),
  broadcast: async (transaction: ccc.Transaction) => {
    const cycles = await client.sendTransactionDry(transaction, "passthrough");
    console.log("test_tx_pool_accept ok, cycles", cycles.toString(), "size", transaction.toBytes().length + 4);
    return client.sendTransaction(transaction, "passthrough");
  },
});

const account = async () => ccc.Address.fromScript(await secp256k1Lock(client, publicKeyOf(keys.K)), client).toString();

/** A backup's ownership proof over a fresh nonce, as the SDK's createEvmBackup / createJoyIdBackup make it. */
async function proof(name: "E1" | "E2" | "J1") {
  const { challengeNonce } = issueBackupChallenge(user);
  if (name === "J1") {
    const signer = await joyIdSigner(keys.J1);
    const address = await signer.getRecommendedAddress();
    const signed = await signer.signMessage(recoveryBackupChallenge(await account(), { kind: "joyid", address }, challengeNonce));
    return { kind: "joyid" as const, address, signature: signed.signature, identity: signed.identity, challengeNonce };
  }
  const backup: RecoveryBackup = { kind: "evm", address: evmAddressOf(keys[name]) };
  return { ...backup, challengeNonce, signature: evmPersonalSign(keys[name], recoveryBackupChallenge(await account(), backup, challengeNonce)) };
}

async function settle(hash: string) {
  await waitCommitted(hash);
  const settled = await settleRecoveryChange(context(await wallet()));
  console.log("settled; notice email:", emails.at(-1)!.split("\n")[0]);
  return settled;
}

async function enable() {
  const backups = [await proof("E1"), await proof("J1")];
  const current = await wallet();
  const shown = await recoverySetup(context(current), { operation: "preview", backups }) as { preview: Record<string, unknown>; confirmationNonce: string };
  console.log("preview", JSON.stringify({ newAddress: shown.preview.newAddress, adminListCkb: shown.preview.adminListCkb, feeCkb: shown.preview.feeCkb }));
  await recoverySetup(context(current), { operation: "request-email-code", backups, confirmationNonce: shown.confirmationNonce });
  const result = await recoverySetup(context(current), { operation: "enable", backups, confirmationNonce: shown.confirmationNonce, emailCode: code() }) as { transactionHash: string; pending: boolean };
  console.log("enable tx", result.transactionHash, "pending", result.pending);
  const settled = await settle(result.transactionHash);
  saveState({ enable: result.transactionHash, address: settled.ckbAddress, recovery: settled.recovery });
  console.log("account address", settled.ckbAddress);
}

async function change(kind: "add" | "remove") {
  const backup = kind === "add" ? await proof("E2") : { kind: "evm" as const, address: evmAddressOf(keys.E2) };
  const current = await wallet();
  const body = { change: kind, backup };
  const shown = await recoveryBackupChange(context(current), { ...body, operation: "preview" }) as { preview: Record<string, unknown>; confirmationNonce: string };
  await recoveryBackupChange(context(current), { ...body, operation: "request-email-code", confirmationNonce: shown.confirmationNonce });
  const result = await recoveryBackupChange(context(current), { ...body, operation: "apply", confirmationNonce: shown.confirmationNonce, emailCode: code() }) as { transactionHash: string };
  console.log(`${kind} tx`, result.transactionHash);
  const settled = await settle(result.transactionHash);
  console.log("backups", JSON.stringify(settled.recovery?.backups), "address unchanged", settled.ckbAddress === state.address);
  saveState({ [kind]: result.transactionHash, recovery: settled.recovery });
}

async function rescueFor(name: "E1" | "J1", destination: string) {
  const rescue = await openRescueAccount(client, state.address);
  const entry = name === "E1" ? rescueEntryForEvm(rescue, [evmAddressOf(keys.E1)]) : rescueEntryForJoyId(rescue, await (await joyIdSigner(keys.J1)).getRecommendedAddress());
  const plan = await planRescue(client, rescue, entry, destination);
  return { rescue, entry, plan };
}

/** Puts `signature` (made over whatever text) into the backup's admin witness of the prepared transaction. */
async function withSignature(name: "E1" | "J1", destination: string, text: (approval: string, sighash: ccc.Hex) => string) {
  const { rescue, entry, plan } = await rescueFor(name, destination);
  const spend = { client, lock: rescue.lock, omnilock: rescue.omnilock, list: rescue.entries, entry, adminList: rescue.adminList.outPoint, inputCapacity: rescue.ckb + rescue.tokenCkb };
  const prepared = await prepareRecoverySpend(plan.transaction, spend);
  const signed = text(prepared.text, prepared.sighash);
  const signature = name === "E1"
    ? evmApprovalSignature(0, evmPersonalSign(keys.E1, signed))
    : ccc.hexFrom(webAuthnSignatureBlob(parseJoyIdSignature(joyIdPasskey(keys.J1).signMessageRaw(signed), joyIdPasskey(keys.J1).publicKey), MAX_WEBAUTHN_SIGNATURE, 0));
  const transaction = prepared.transaction;
  const witness = transaction.getWitnessArgsAt(prepared.position)!;
  witness.lock = omnilockAdminWitnessLock({ signature, auth: entry.auth, proof: rescue.proofs[entry.auth], preimage: entry.preimage });
  transaction.setWitnessArgsAt(prepared.position, witness);
  return { transaction, approval: prepared.text, rescue, entry, spend };
}

async function dryRun(label: string, transaction: ccc.Transaction) {
  try {
    const cycles = await client.sendTransactionDry(transaction, "passthrough");
    console.log(`UNEXPECTED ACCEPT: ${label} (${cycles} cycles)`);
    process.exitCode = 1;
  } catch (error) {
    const text = error instanceof Error ? error.message : String(error);
    const reason = /source: ([^,]+), cause: ([^}]+?)(?: \}|$)/.exec(text);
    console.log(`rejected as expected: ${label}: ${reason ? `${reason[1]} ${reason[2].trim()}` : text.slice(0, 160)}`);
  }
}

async function negative() {
  const d1 = await secpAddress(keys.D1);
  const d2 = await secpAddress(keys.D2);
  // The accepted versions first (dry run only), so each refusal below differs from an accepted spend in one thing.
  for (const name of ["E1", "J1"] as const) {
    const { transaction } = await withSignature(name, d1, (approval) => approval);
    console.log(`${name} correct approval, dry run accepted, cycles`, (await client.sendTransactionDry(transaction, "passthrough")).toString());
  }
  for (const name of ["E1", "J1"] as const) {
    // A signature over the correct text, replayed on a transaction to another destination.
    const good = await withSignature(name, d1, (approval) => approval);
    const replayed = await withSignature(name, d2, () => good.approval);
    await dryRun(`${name}: correct text for D1 replayed on a transaction to D2`, replayed.transaction);
    // The same destination, one shannon less arriving (one more to the fee).
    const fewer = good.transaction.clone();
    fewer.outputs[fewer.outputs.length - 1].capacity -= 1n;
    const lockAt = good.transaction.getWitnessArgsAt(0)!.lock!;
    const witness = fewer.getWitnessArgsAt(0)!;
    witness.lock = lockAt;
    fewer.setWitnessArgsAt(0, witness);
    await dryRun(`${name}: correct text, transaction with a different amount`, fewer);
    // The right sighash under a wrong destination line.
    const wrongLine = await withSignature(name, d1, (approval) => approval.replace(d1, d2));
    await dryRun(`${name}: right sighash, wrong destination line`, wrongLine.transaction);
    // The old opaque format.
    const old = await withSignature(name, d1, (_approval, sighash) => `CKB transaction: ${sighash}`);
    await dryRun(`${name}: old "CKB transaction: 0x…" format`, old.transaction);
  }
  // A backup trying to spend or move the AdminList, which sits under the Lit key's owner-only lock.
  const rescue = await openRescueAccount(client, state.address);
  const entry = rescueEntryForEvm(rescue, [evmAddressOf(keys.E1)]);
  const listLock = adminListLock(state.recovery);
  const thief = await secp256k1Lock(client, publicKeyOf(keys.D2));
  const attempts: Array<[string, ccc.CellOutputLike[]]> = [
    ["E1 spends the AdminList to its own address", [{ lock: thief, capacity: rescue.adminList.cellOutput.capacity - 100_000n }]],
    ["E1 moves the AdminList under a lock of its own", [{ lock: thief, type: rescue.adminList.cellOutput.type, capacity: rescue.adminList.cellOutput.capacity - 100_000n }]],
  ];
  for (const [label, outputs] of attempts) {
    const transaction = ccc.Transaction.from({ inputs: [{ previousOutput: rescue.adminList.outPoint }], outputs, outputsData: outputs.map((output) => output.type ? rescue.adminList.outputData : "0x") });
    const spend = { client, lock: listLock, omnilock: rescue.omnilock, list: rescue.entries, entry, adminList: rescue.adminList.outPoint, inputCapacity: rescue.adminList.cellOutput.capacity };
    // The text a backup would sign can't even be built for the moving one (data without a type is fine, a type
    // isn't refused by the shape), so sign the readable text the verifier would rebuild where it can, and the
    // old format otherwise.
    const prepared = await prepareRecoverySpend(transaction, spend).catch(() => undefined);
    const base = prepared ?? { transaction, text: "", sighash: ccc.hexFrom(new Uint8Array(32)), position: 0 };
    const signature = evmApprovalSignature(0, evmPersonalSign(keys.E1, base.text || `CKB transaction: ${base.sighash}`));
    const witness = base.transaction.getWitnessArgsAt(base.position) ?? ccc.WitnessArgs.from({});
    witness.lock = omnilockAdminWitnessLock({ signature, auth: entry.auth, proof: rescue.proofs[entry.auth], preimage: entry.preimage });
    base.transaction.setWitnessArgsAt(base.position, witness);
    await dryRun(label, base.transaction);
  }
}

async function rescue(name: "E1" | "J1", destinationKey: "D1" | "D2") {
  const destination = await secpAddress(keys[destinationKey]);
  const { rescue: opened, plan } = await rescueFor(name, destination);
  console.log(`${name} rescue: balance ${ccc.fixedPointToString(opened.ckb)} CKB from the node, ${opened.movable.length} cells`);
  console.log("approval text:\n" + plan.approvalText);
  const signed = name === "E1"
    ? await signRescueWithEvm(client, opened, plan, { request: async ({ method, params }) => {
      if (method !== "personal_sign") throw new Error(method);
      const text = new TextDecoder().decode(ccc.bytesFrom(params![0] as string));
      if (text !== plan.approvalText) throw new Error("asked to sign something else");
      return evmPersonalSign(keys.E1, text);
    } })
    : await signRescueWithJoyId(client, opened, plan, await joyIdSigner(keys.J1));
  const hash = await sendRescue(client, signed);
  console.log(`${name} rescue tx`, hash);
  await waitCommitted(hash);
  saveState({ [`rescue${name}`]: hash });
}

/** Sends CKB from the funders back to the account's address, so the second backup has something to move. */
async function refund() {
  const lock = omnilockScript(state.recovery);
  const signer = new ccc.SignerCkbPrivateKey(client, keys.F12);
  const tx = ccc.Transaction.from({ outputs: [{ lock, capacity: 9_000n * 100_000_000n }], outputsData: ["0x"] });
  await tx.completeInputsByCapacity(signer);
  await tx.completeFeeBy(signer);
  const signed = await signer.signOnlyTransaction(tx);
  const hash = await client.sendTransaction(signed, "passthrough");
  console.log("refund tx", hash);
  await waitCommitted(hash);
  saveState({ refund: hash });
}

const step = process.argv[2];
if (step === "enable") await enable();
else if (step === "add") await change("add");
else if (step === "remove") await change("remove");
else if (step === "negative") await negative();
else if (step === "joyid") await rescue("J1", "D1");
else if (step === "refund") await refund();
else if (step === "evm") await rescue("E1", "D2");
else throw new Error("step: enable | add | remove | negative | joyid | refund | evm");
process.exit(process.exitCode ?? 0);
