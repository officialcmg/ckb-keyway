// Testnet proof of salted backup identities, with throwaway keys (keys.json, gitignored, never printed) and a
// local Postgres for KeyWay's own records. Accounts A (KA) and B (KB) are the same person in two apps; both turn
// recovery on through the server's real flow with the same two backups, E1 (EVM wallet) and J1 (a P-256 key
// answering like JoyID). Account C (KC) is an attacker's list that copies A's salted auths. Run step by step:
//   npx tsx prove.ts enable A | enable B | copy | compare | negative | rescue E1 A D1 | rescue J1 B D2
// Needs DATABASE_URL (a local Postgres with KeyWay's tables) and KEYWAY_RATE_LIMIT_SECRET.
import * as ccc from "@ckb-ccc/core";
import { secp256k1Lock } from "../../src/sdk/browser/account-lock.ts";
import {
  evmApprovalSignature, evmBackupAuth, evmPreimage, joyIdPreimage, omnilockAdminWitnessLock, recoveryBackupChallenge, type RecoveryBackup,
} from "../../src/sdk/browser/recovery-backups.ts";
import { readRecoveryList, recoveryListEntry, recoveryListRecord, recoveryListRecordOf, setRecoveryListRecord, type RecoveryListEntry } from "../../src/sdk/browser/recovery-list.ts";
import { adminListData, whitelistTree } from "../../src/sdk/browser/recovery-smt.ts";
import { prepareRecoverySpend } from "../../src/sdk/browser/recovery-spend.ts";
import { MAX_WEBAUTHN_SIGNATURE, parseJoyIdSignature, webAuthnSignatureBlob } from "../../src/sdk/browser/webauthn.ts";
import { openRescueAccount, planRescue, rescueEntryForEvm, rescueEntryForJoyId, sendRescue, signRescueWithEvm, signRescueWithJoyId, type RescueAccount } from "../../src/rescue/rescue.ts";
import { formatCkbSignature } from "../../src/server/funding-transaction.ts";
import { issueBackupChallenge, planRecovery, recoverySetup, settleRecoveryChange, type RecoveryContext } from "../../src/server/recovery.ts";
import { readWallet, saveWallet, type ReadyWallet } from "../../src/server/user-wallet.ts";
import { evmAddressOf, evmPersonalSign, joyIdPasskey, joyIdSigner, localLitSignature } from "../omnilock/phase4/lib.ts";
import { client, loadKeys, loadState, publicKeyOf, saveState, secpAddress, waitCommitted } from "./lib.ts";

type Account = "A" | "B";
const keys = loadKeys();
const emails: string[] = [];
const code = () => /code is (\d{6})/.exec(emails.findLast((text) => /code is \d{6}/.test(text))!)![1];
const ownerKey = (account: Account | "C") => keys[`K${account}`];

function userOf(account: Account) {
  const state = loadState();
  const users = state.users ?? {};
  if (!users[account]) saveState({ users: { ...users, [account]: crypto.randomUUID() } });
  return { id: loadState().users[account] as string };
}

async function wallet(account: Account): Promise<ReadyWallet> {
  const user = userOf(account);
  let current = await readWallet(user);
  if (!current) {
    current = {
      version: 1, status: "ready", litPkpId: `0xbackup-unlinking-${account}`, litPublicKey: publicKeyOf(ownerKey(account)), ckbAddress: await secpAddress(ownerKey(account)),
      encryptedFiberKey: "unused", primaryDeviceIdHash: "0".repeat(64), hasOpenedChannel: false,
      createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
    };
    await saveWallet(user, current);
  }
  if (current.status !== "ready") throw new Error("wallet isn't ready");
  return current;
}

const context = (account: Account, current: ReadyWallet): RecoveryContext => ({
  user: userOf(account), wallet: current, appName: `KeyWay backup-unlinking proof, app ${account}`, client,
  email: async () => "backup-unlinking@example.invalid",
  sendEmail: async (_to: string, message: { plaintext: string }) => { emails.push(message.plaintext); },
  rateLimit: async () => ({ allowed: true, retryAfter: null }),
  recordSigning: async () => undefined,
  signDigest: async (digest: ccc.Hex) => formatCkbSignature(localLitSignature(ownerKey(account), digest)),
  broadcast: async (transaction: ccc.Transaction) => {
    const cycles = await client.sendTransactionDry(transaction, "passthrough");
    console.log("test_tx_pool_accept ok, cycles", cycles.toString(), "size", transaction.toBytes().length + 4);
    return client.sendTransaction(transaction, "passthrough");
  },
});

const legacyAddress = async (account: Account) => ccc.Address.fromScript(await secp256k1Lock(client, publicKeyOf(ownerKey(account))), client).toString();
const joyIdAddress = async () => (await joyIdSigner(keys.J1)).getRecommendedAddress();

/** A backup's ownership proof for this account over a fresh nonce, as createEvmBackup / createJoyIdBackup make it. */
async function proof(account: Account, name: "E1" | "J1") {
  const { challengeNonce } = issueBackupChallenge(userOf(account));
  if (name === "J1") {
    const signer = await joyIdSigner(keys.J1);
    const address = await signer.getRecommendedAddress();
    const signed = await signer.signMessage(recoveryBackupChallenge(await legacyAddress(account), { kind: "joyid", address }, challengeNonce));
    return { kind: "joyid" as const, address, signature: signed.signature, identity: signed.identity, challengeNonce };
  }
  const backup: RecoveryBackup = { kind: "evm", address: evmAddressOf(keys.E1) };
  return { ...backup, challengeNonce, signature: evmPersonalSign(keys.E1, recoveryBackupChallenge(await legacyAddress(account), backup, challengeNonce)) };
}

async function enable(account: Account) {
  if (loadState()[`enable${account}`]) throw new Error(`account ${account} already enabled`);
  const backups = [await proof(account, "E1"), await proof(account, "J1")];
  const current = await wallet(account);
  const shown = await recoverySetup(context(account, current), { operation: "preview", backups }) as { preview: Record<string, unknown>; confirmationNonce: string };
  console.log("preview", JSON.stringify({ newAddress: shown.preview.newAddress, adminListCkb: shown.preview.adminListCkb, feeCkb: shown.preview.feeCkb }));
  await recoverySetup(context(account, current), { operation: "request-email-code", backups, confirmationNonce: shown.confirmationNonce });
  const result = await recoverySetup(context(account, current), { operation: "enable", backups, confirmationNonce: shown.confirmationNonce, emailCode: code() }) as { transactionHash: string };
  console.log(`enable ${account} tx`, result.transactionHash);
  await waitCommitted(result.transactionHash);
  const settled = await settleRecoveryChange(context(account, await wallet(account)));
  console.log("settled; notice email:", emails.at(-1)!.split("\n")[0]);
  saveState({ [`enable${account}`]: result.transactionHash, [`address${account}`]: settled.ckbAddress, [`recovery${account}`]: settled.recovery });
  console.log(`account ${account} address`, settled.ckbAddress);
}

/**
 * Account C turns recovery on from KC's own cells with a list that copies A's salted auths (its root and record),
 * as anyone reading A's enable transaction could. Built like KeyWay's enable, then the list swapped; KC signs.
 */
async function copy() {
  const state = loadState();
  if (state.enableC) throw new Error("account C already enabled");
  const authsA = (await readRecoveryList(client, state.recoveryA)).auths;
  const current: ReadyWallet = {
    version: 1, status: "ready", litPkpId: "0xbackup-unlinking-C", litPublicKey: publicKeyOf(keys.KC), ckbAddress: await secpAddress(keys.KC),
    encryptedFiberKey: "unused", primaryDeviceIdHash: "0".repeat(64), hasOpenedChannel: false, createdAt: "", updatedAt: "",
  };
  // Two backups, so the record has A's length and the planned fee still covers the transaction.
  const plan = await planRecovery(client, current, [{ kind: "evm", address: evmAddressOf(keys.E1) }, { kind: "joyid", address: await joyIdAddress() }]);
  const transaction = plan.transaction;
  transaction.outputsData[0] = adminListData(whitelistTree(authsA).root);
  setRecoveryListRecord(transaction, 0, recoveryListRecord(authsA));
  const signed = await new ccc.SignerCkbPrivateKey(client, keys.KC).signOnlyTransaction(transaction);
  console.log("test_tx_pool_accept ok, cycles", (await client.sendTransactionDry(signed, "passthrough")).toString());
  const hash = await client.sendTransaction(signed, "passthrough");
  console.log("enable C (A's auths copied) tx", hash);
  await waitCommitted(hash);
  const address = ccc.Address.fromScript(plan.omnilock, client).toString();
  saveState({ enableC: hash, addressC: address, saltC: plan.adminListType.hash() });
  console.log("account C address", address);
}

/** The three lists as the chain records them, and what each backup's auth is in each account. */
async function compare() {
  const state = loadState();
  const evm = evmAddressOf(keys.E1);
  const joyIdHash = ccc.hashCkbShort(joyIdPasskey(keys.J1).publicKey);
  const out: Record<string, unknown> = {};
  for (const account of ["A", "B"] as const) {
    const recovery = state[`recovery${account}`];
    const list = await readRecoveryList(client, recovery);
    const enableTx = (await client.getTransaction(state[`enable${account}`]))!.transaction;
    const record = recoveryListRecordOf(enableTx, 0)!;
    const e1 = await recoveryListEntry(client, list, { kind: "evm", address: evm });
    const j1 = await recoveryListEntry(client, list, { kind: "joyid", address: await joyIdAddress() });
    out[account] = {
      address: state[`address${account}`], salt: list.salt, record, auths: list.auths, E1: e1?.auth, J1: j1?.auth,
      E1preimage: e1?.preimage, J1preimage: j1?.preimage,
      recordNamesE1: record.includes(evm.slice(2)), recordNamesJ1: record.includes(ccc.hexFrom(joyIdHash).slice(2)),
    };
    console.log(`${account}: salt ${list.salt}\n  E1 auth ${e1?.auth}\n  J1 auth ${j1?.auth}\n  record ${record}\n  record names E1's address: ${record.includes(evm.slice(2))}, J1's key hash: ${record.includes(ccc.hexFrom(joyIdHash).slice(2))}`);
  }
  const [a, b] = [out.A as Record<string, string>, out.B as Record<string, string>];
  console.log("E1's auths differ between A and B:", a.E1 !== b.E1, "J1's:", a.J1 !== b.J1, "no auth shared:", !(a.auths as unknown as string[]).some((auth) => (b.auths as unknown as string[]).includes(auth)));
  const c = await readRecoveryList(client, { adminListTypeArgs: (await openRescueAccount(client, state.addressC)).adminList.cellOutput.type!.args });
  console.log("C copies A's auths:", JSON.stringify(c.auths) === JSON.stringify(a.auths), "C's own salt for E1:", evmBackupAuth(evm, c.salt), "on C's list:", c.auths.includes(evmBackupAuth(evm, c.salt)));
  saveState({ compare: out });
}

type Name = "E1" | "J1";

/** Signs `text` as the backup does and writes the admin witness for `entry` into the prepared rescue. */
async function signedRescue(rescue: RescueAccount, name: Name, entry: RecoveryListEntry, destination: string, text?: (approval: string) => string) {
  const plan = await planRescue(client, rescue, entry, destination);
  const spend = { client, lock: rescue.lock, omnilock: rescue.omnilock, auths: rescue.auths, entry, adminList: rescue.adminList.outPoint, inputCells: rescue.movable };
  const prepared = await prepareRecoverySpend(plan.transaction, spend);
  const message = text ? text(prepared.text) : prepared.text;
  const signature = name === "E1"
    ? evmApprovalSignature(0, evmPersonalSign(keys.E1, message))
    : ccc.hexFrom(webAuthnSignatureBlob(parseJoyIdSignature(joyIdPasskey(keys.J1).signMessageRaw(message), joyIdPasskey(keys.J1).publicKey), MAX_WEBAUTHN_SIGNATURE, 0));
  const witness = prepared.transaction.getWitnessArgsAt(prepared.position)!;
  witness.lock = omnilockAdminWitnessLock({ signature, auth: entry.auth, proof: rescue.proofs[entry.auth] ?? whitelistTree(rescue.auths).proofs[entry.auth] ?? "0x", preimage: entry.preimage });
  prepared.transaction.setWitnessArgsAt(prepared.position, witness);
  return { transaction: prepared.transaction, approval: prepared.text, signature, position: prepared.position };
}

const entryOf = async (rescue: RescueAccount, name: Name) => name === "E1"
  ? rescueEntryForEvm(client, rescue, [evmAddressOf(keys.E1)])
  : rescueEntryForJoyId(client, rescue, await joyIdAddress());

const results: Array<{ label: string; accepted: boolean; detail: string }> = [];
async function dryRun(label: string, transaction: ccc.Transaction, expectAccept: boolean) {
  try {
    const cycles = await client.sendTransactionDry(transaction, "passthrough");
    console.log(`${expectAccept ? "accepted as expected" : "UNEXPECTED ACCEPT"}: ${label} (${cycles} cycles)`);
    results.push({ label, accepted: true, detail: `${cycles} cycles` });
    if (!expectAccept) process.exitCode = 1;
  } catch (error) {
    const text = error instanceof Error ? error.message : String(error);
    const reason = /source: ([^,]+), cause: ([^}]+?)(?: \}|$)/.exec(text);
    const detail = reason ? `${reason[1]} ${reason[2].trim()}` : text.slice(0, 200);
    console.log(`${expectAccept ? "UNEXPECTED REFUSAL" : "refused as expected"}: ${label}: ${detail}`);
    results.push({ label, accepted: false, detail });
    if (expectAccept) process.exitCode = 1;
  }
}

async function negative() {
  const state = loadState();
  const [d1, d2] = [await secpAddress(keys.D1), await secpAddress(keys.D2)];
  const A = await openRescueAccount(client, state.addressA);
  const B = await openRescueAccount(client, state.addressB);
  const C = await openRescueAccount(client, state.addressC);
  const evm = evmAddressOf(keys.E1);
  const joyIdHash = ccc.hashCkbShort(joyIdPasskey(keys.J1).publicKey);
  // Each backup through each of its own accounts: dry runs accepted.
  for (const [label, account] of [["A", A], ["B", B]] as const) {
    for (const name of ["E1", "J1"] as const) {
      const entry = await entryOf(account, name);
      await dryRun(`${name} spends account ${label} with its own salted identity`, (await signedRescue(account, name, entry, d1)).transaction, true);
    }
  }
  for (const name of ["E1", "J1"] as const) {
    const entryA = await entryOf(A, name);
    const entryB = await entryOf(B, name);
    // 1. A's identity (auth, proof, preimage) in a spend of B: not on B's list, Omnilock refuses before the verifier.
    const intoB = await signedRescue(B, name, entryB, d1);
    const witness = intoB.transaction.getWitnessArgsAt(intoB.position)!;
    witness.lock = omnilockAdminWitnessLock({ signature: intoB.signature, auth: entryA.auth, proof: A.proofs[entryA.auth], preimage: entryA.preimage });
    intoB.transaction.setWitnessArgsAt(intoB.position, witness);
    await dryRun(`${name}: account A's auth and proof in a spend of account B`, intoB.transaction, false);
    // 2. B's auth with A's preimage: blake160(preimage) isn't the auth.
    const mixed = await signedRescue(B, name, entryB, d1);
    const mixedWitness = mixed.transaction.getWitnessArgsAt(mixed.position)!;
    mixedWitness.lock = omnilockAdminWitnessLock({ signature: mixed.signature, auth: entryB.auth, proof: B.proofs[entryB.auth], preimage: entryA.preimage });
    mixed.transaction.setWitnessArgsAt(mixed.position, mixedWitness);
    await dryRun(`${name}: account B's auth with account A's preimage`, mixed.transaction, false);
    // 3. A signature A's spend got, replayed in B's spend with B's own identity.
    const fromA = await signedRescue(A, name, entryA, d1);
    const replay = await signedRescue(B, name, entryB, d1);
    const replayWitness = replay.transaction.getWitnessArgsAt(replay.position)!;
    replayWitness.lock = omnilockAdminWitnessLock({ signature: fromA.signature, auth: entryB.auth, proof: B.proofs[entryB.auth], preimage: entryB.preimage });
    replay.transaction.setWitnessArgsAt(replay.position, replayWitness);
    await dryRun(`${name}: the signature from a spend of account A replayed in a spend of account B`, replay.transaction, false);
    // 4. Account C lists A's auths, so Omnilock accepts A's identity and proof there and execs the verifier,
    // which salts the backup with C's AdminList type hash and refuses (101): the identity only works in A.
    const copied: RecoveryListEntry = name === "E1"
      ? { backup: { kind: "evm", address: evm }, auth: entryA.auth, preimage: evmPreimage(evm, A.adminListTypeHash) }
      : { backup: { kind: "joyid", address: await joyIdAddress() }, auth: entryA.auth, preimage: joyIdPreimage(joyIdHash, A.adminListTypeHash) };
    await dryRun(`${name}: account A's identity on account C, whose list copies A's auths, signed over C's own readable text`, (await signedRescue(C, name, copied, d2)).transaction, false);
  }
  saveState({ negative: results });
}

async function rescue(name: Name, account: Account, destinationKey: "D1" | "D2") {
  const state = loadState();
  const destination = await secpAddress(keys[destinationKey]);
  const opened = await openRescueAccount(client, state[`address${account}`]);
  const entry = await entryOf(opened, name);
  const plan = await planRescue(client, opened, entry, destination);
  console.log(`${name} rescue of ${account}: ${ccc.fixedPointToString(opened.ckb)} CKB, ${opened.movable.length} cells`);
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
  console.log(`${name} rescue of ${account} tx`, hash);
  await waitCommitted(hash);
  saveState({ [`rescue${name}${account}`]: hash });
}

const [step, ...rest] = process.argv.slice(2);
if (step === "enable") await enable(rest[0] as Account);
else if (step === "copy") await copy();
else if (step === "compare") await compare();
else if (step === "negative") await negative();
else if (step === "rescue") await rescue(rest[0] as Name, rest[1] as Account, rest[2] as "D1" | "D2");
else throw new Error("step: enable A | enable B | copy | compare | negative | rescue E1 A D1 | rescue J1 B D2");
process.exit(process.exitCode ?? 0);
