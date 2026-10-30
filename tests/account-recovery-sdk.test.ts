import assert from "node:assert/strict";
import test from "node:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import * as ccc from "@ckb-ccc/core";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { KEYWAY_OMNILOCK, omnilockScript } from "../src/sdk/browser/account-lock.ts";
import { changeRecoveryBackup, createEvmBackup, createJoyIdBackup, enableRecovery, recoveryAccountAddress, requestBackupChallenge, type BackupChangePreview, type RecoveryPreview } from "../src/sdk/browser/account-recovery.ts";
import { KeyWayApiClient } from "../src/sdk/browser/api-client.ts";
import { evmBackupAuth, evmPersonalSignAddress, evmPreimage, EVM_PERSONAL_SIGN_VERIFIER, joyIdBackupAuth, joyIdPreimage, JOYID_WEBAUTHN_VERIFIER, recoveryBackupChallenge, verifyBackupOwnership } from "../src/sdk/browser/recovery-backups.ts";
import { whitelistTree } from "../src/sdk/browser/recovery-smt.ts";
import { prepareRecoverySpend, signRecoverySpendWithEvm, signRecoverySpendWithJoyId } from "../src/sdk/browser/recovery-spend.ts";
import { MAX_WEBAUTHN_SIGNATURE, verifyWebAuthn } from "../src/sdk/browser/webauthn.ts";
import { KeyWayBackupChangeModal, KeyWayEmailCodeModal, KeyWayRecoveryModal } from "../src/sdk/react/signing-modals.tsx";

const client = new ccc.ClientPublicTestnet({ url: "https://testnet.ckb.dev/" });
const publicKey = ccc.hexFrom(secp256k1.getPublicKey(secp256k1.utils.randomSecretKey(), true));
const NONCE = `${Date.now() + 600_000}.${"ab".repeat(16)}.${"cd".repeat(32)}`;
const noWait = async () => undefined;

/** An EIP-1193 wallet that signs personal_sign as EVM wallets do: the hex message's bytes, v = 27 or 28. */
function injectedWallet() {
  const key = secp256k1.utils.randomSecretKey();
  const address = ccc.hexFrom(keccak_256(secp256k1.getPublicKey(key, false).slice(1)).slice(12));
  const calls: Array<{ method: string; params?: unknown[] }> = [];
  const provider = {
    request: async (args: { method: string; params?: unknown[] }) => {
      calls.push(args);
      if (args.method === "eth_requestAccounts") return [ccc.hexFrom(address).replace(/[a-f]/g, (c) => c.toUpperCase()).replace("0X", "0x")];
      if (args.method !== "personal_sign") throw new Error("unsupported");
      const message = ccc.bytesFrom(args.params![0] as string);
      const digest = keccak_256(ccc.bytesConcat(new TextEncoder().encode(`\x19Ethereum Signed Message:\n${message.length}`), message));
      const raw = secp256k1.sign(digest, key, { prehash: false, format: "recovered" });
      return ccc.hexFrom(ccc.bytesConcat(raw.slice(1), [raw[0] + 27]));
    },
  };
  return { address, provider, calls };
}

test("creates an EVM backup the server accepts, from an injected wallet", async () => {
  const account = await recoveryAccountAddress(publicKey, client);
  assert.match(account, /^ckt1q/);
  const wallet = injectedWallet();
  const proof = await createEvmBackup(account, NONCE, wallet.provider);
  assert.equal(proof.kind, "evm");
  assert.equal(proof.address, wallet.address);
  assert.equal(proof.challengeNonce, NONCE);
  assert.deepEqual(wallet.calls.map(({ method }) => method), ["eth_requestAccounts", "personal_sign"]);
  // The wallet is asked to sign the readable challenge text, with KeyWay's nonce and its expiry.
  assert.equal(new TextDecoder().decode(ccc.bytesFrom(wallet.calls[1].params![0] as string)), recoveryBackupChallenge(account, proof, NONCE));
  assert.deepEqual(await verifyBackupOwnership(client, account, proof), { kind: "evm", address: wallet.address });
  await assert.rejects(createEvmBackup(account, NONCE, undefined), /No EVM wallet/);
  // The nonce comes from KeyWay's server.
  const api = new KeyWayApiClient({ fetch: async (_input, init) => {
    assert.deepEqual(JSON.parse(String(init!.body)), { operation: "challenge" });
    return Response.json({ challengeNonce: NONCE, expiresAt: new Date(Date.now() + 600_000).toISOString() });
  } });
  assert.equal(await requestBackupChallenge("session", api), NONCE);
});

test("creates a JoyID backup from a CCC JoyID signer", async () => {
  const signed: string[] = [];
  const signer = {
    signType: ccc.SignerSignType.JoyId,
    isConnected: async () => false,
    connect: async () => { signed.push("connect"); },
    getRecommendedAddress: async () => "ckt1qrfrwcdnvssswdwpn3s9v8fp87emat306ctjwsm3nmlkjg8qyza2cqgqq8n3thvttqfasgrql80e3s5l66lcneyxrsuglhh2",
    signMessage: async (message: string) => { signed.push(message); return { signature: "{\"alg\":-7}", identity: "{\"keyType\":\"main_key\"}", signType: ccc.SignerSignType.JoyId }; },
  } as unknown as ccc.Signer;
  const proof = await createJoyIdBackup("ckt1account", NONCE, signer);
  assert.deepEqual(proof, { kind: "joyid", address: await signer.getRecommendedAddress(), signature: "{\"alg\":-7}", identity: "{\"keyType\":\"main_key\"}", challengeNonce: NONCE });
  assert.equal(signed[0], "connect");
  assert.equal(signed[1], recoveryBackupChallenge("ckt1account", { kind: "joyid", address: proof.address }, NONCE));
  await assert.rejects(createJoyIdBackup("ckt1account", NONCE, { ...signer, signType: ccc.SignerSignType.EvmPersonal, isConnected: async () => true } as unknown as ccc.Signer), /JoyID signer/);
});

const preview: RecoveryPreview = {
  network: "CKB testnet", newAddress: "ckt1qrejnmlar3r452tcg57gvq8patctcgy8acync0hxfnyka35ywafvkqgqnewaddress", legacyAddress: "ckt1qzda0old",
  backups: [{ kind: "evm", address: `0x${"ab".repeat(20)}`, label: "EVM wallet 0xabababab…ababab" }],
  adminListCkb: "165", minimumCellCkb: "95", tokenCellsExtraCkb: "0", lockedCkb: "165", feeCkb: "0.00000981", movedCkb: "9802.99999019",
  tokens: [], cellsLeft: 0, transactionHash: `0x${"12".repeat(32)}`,
};

test("turns recovery on: preview, the user's approval, then the emailed code until it's right", async () => {
  const requests: Array<{ url: string; body: Record<string, unknown>; idempotency: string | null }> = [];
  const api = new KeyWayApiClient({
    fetch: async (input, init) => {
      const body = JSON.parse(String(init!.body));
      requests.push({ url: String(input), body, idempotency: new Headers(init!.headers).get("idempotency-key") });
      if (body.operation === "preview") return Response.json({ preview, confirmationNonce: "00000000-0000-4000-8000-000000000000", requiresEmailCode: true });
      if (body.operation === "request-email-code") return Response.json({ sent: true });
      if (body.emailCode === "111111") return Response.json({ error: "That email code isn't right" }, { status: 400 });
      // The change takes effect once its transaction is committed; the SDK waits for that.
      if (body.operation === "status") {
        return Response.json(++statusChecks < 3
          ? { pending: true, transactionHash: preview.transactionHash, ckbAddress: preview.legacyAddress }
          : { pending: false, ckbAddress: preview.newAddress, recovery: { legacyAddress: "ckt1qzda0old", adminListOutPoint: { txHash: preview.transactionHash, index: 0 } } });
      }
      return Response.json({ transactionHash: preview.transactionHash, pending: true, ckbAddress: preview.newAddress, recovery: { legacyAddress: "ckt1qzda0old" } });
    },
  });
  let statusChecks = 0;
  const backups = [{ kind: "evm" as const, address: preview.backups[0].address, signature: `0x${"00".repeat(65)}`, challengeNonce: NONCE }];
  const approvals: RecoveryPreview[] = [];
  const codes = ["111111", "222222"];
  const prompts: Array<{ reason: string; error?: string }> = [];
  const result = await enableRecovery({
    authToken: "session", backups, api, wait: noWait,
    approve: (shown) => { approvals.push(shown); return true; },
    requestEmailCode: async (request) => { prompts.push({ reason: request.reason, error: request.error }); return codes.shift(); },
  });
  assert.equal(result.ckbAddress, preview.newAddress);
  assert.deepEqual(approvals, [preview]);
  assert.deepEqual(requests.map(({ body }) => body.operation), ["preview", "request-email-code", "enable", "enable", "status", "status", "status"]);
  assert.ok(requests.every(({ url }) => url.endsWith("/api/v1/keyway/recovery")));
  assert.ok(requests.filter(({ body }) => body.operation !== "status").every(({ body }) => JSON.stringify(body.backups) === JSON.stringify(backups)));
  assert.ok(requests.filter(({ body }) => body.operation === "enable").every(({ idempotency }) => idempotency));
  assert.deepEqual(prompts, [{ reason: "recovery", error: undefined }, { reason: "recovery", error: "That email code isn't right" }]);

  requests.length = 0;
  await assert.rejects(enableRecovery({ authToken: "session", backups, api, approve: () => false, requestEmailCode: async () => "222222" }), /cancelled/);
  assert.deepEqual(requests.map(({ body }) => body.operation), ["preview"], "nothing is emailed or signed when the user cancels");
});

test("a recovery change the network drops is reported, not taken as done", async () => {
  const api = new KeyWayApiClient({
    fetch: async (_input, init) => {
      const body = JSON.parse(String(init!.body));
      if (body.operation === "preview") return Response.json({ preview, confirmationNonce: "00000000-0000-4000-8000-000000000000", requiresEmailCode: true });
      if (body.operation === "request-email-code") return Response.json({ sent: true });
      if (body.operation === "status") return Response.json({ pending: false, ckbAddress: preview.legacyAddress });
      return Response.json({ transactionHash: preview.transactionHash, pending: true });
    },
  });
  const backups = [{ kind: "evm" as const, address: preview.backups[0].address, signature: `0x${"00".repeat(65)}`, challengeNonce: NONCE }];
  await assert.rejects(enableRecovery({ authToken: "session", backups, api, wait: noWait, approve: () => true, requestEmailCode: async () => "123456" }), /didn't confirm on chain\. Nothing changed/);
});

test("the built-in dialog shows the backups, the CKB locked, the fee and the new address", () => {
  const html = renderToStaticMarkup(createElement(KeyWayRecoveryModal, { theme: "light", appName: "Acme Pay", preview, answer: () => undefined }));
  assert.match(html, /Turn on recovery\?/);
  assert.match(html, /EVM wallet 0xabababab…ababab/);
  assert.match(html, /165 CKB/);
  assert.match(html, /0\.00000981 CKB/);
  assert.match(html, /ckt1qrejnmla…ddress/);
  assert.match(html, new RegExp(preview.newAddress));
  assert.match(html, /Your address will change because you&#x27;re turning on recovery\./);
  const code = renderToStaticMarkup(createElement(KeyWayEmailCodeModal, { theme: "light", reason: "recovery", resend: async () => undefined, answer: () => undefined }));
  assert.match(code, /confirm turning on recovery/);
});

const changePreview: BackupChangePreview = {
  network: "CKB testnet", change: "add",
  backup: { kind: "evm", address: `0x${"cd".repeat(20)}`, label: "EVM wallet 0xcdcdcdcd…cdcdcd" },
  backups: [preview.backups[0], { kind: "evm", address: `0x${"cd".repeat(20)}`, label: "EVM wallet 0xcdcdcdcd…cdcdcd" }],
  feeCkb: "0.00001274", transactionHash: `0x${"34".repeat(32)}`,
};

test("adds and removes a backup: preview, the user's approval, then the emailed code, always", async () => {
  const requests: Array<{ url: string; body: Record<string, unknown>; idempotency: string | null }> = [];
  const api = new KeyWayApiClient({
    fetch: async (input, init) => {
      const body = JSON.parse(String(init!.body));
      requests.push({ url: String(input), body, idempotency: new Headers(init!.headers).get("idempotency-key") });
      if (body.operation === "preview") return Response.json({ preview: { ...changePreview, change: body.change }, confirmationNonce: "00000000-0000-4000-8000-000000000000", requiresEmailCode: true });
      if (body.operation === "request-email-code") return Response.json({ sent: true });
      if (body.operation === "status") return Response.json({ pending: false, ckbAddress: preview.newAddress, recovery: { legacyAddress: "ckt1qzda0old", adminListOutPoint: { txHash: changePreview.transactionHash, index: 0 } } });
      return Response.json({ transactionHash: changePreview.transactionHash, pending: true, recovery: { legacyAddress: "ckt1qzda0old" } });
    },
  });
  const proof = { kind: "evm" as const, address: changePreview.backup.address, signature: `0x${"00".repeat(65)}`, challengeNonce: NONCE };
  const prompts: string[] = [];
  const shown: BackupChangePreview[] = [];
  const result = await changeRecoveryBackup({
    authToken: "session", change: "add", backup: proof, api, wait: noWait,
    approve: (preview) => { shown.push(preview); return true; },
    requestEmailCode: async (request) => { prompts.push(request.reason); return "123456"; },
  });
  assert.equal(result.transactionHash, changePreview.transactionHash);
  assert.deepEqual(shown, [changePreview]);
  assert.deepEqual(prompts, ["recovery-backup"]);
  assert.deepEqual(requests.map(({ body }) => body.operation), ["preview", "request-email-code", "apply", "status"]);
  assert.ok(requests.every(({ url }) => url.endsWith("/api/v1/keyway/recovery-backups")));
  assert.ok(requests.slice(0, 3).every(({ body }) => body.change === "add" && JSON.stringify(body.backup) === JSON.stringify(proof)));
  assert.ok(requests[2].idempotency);

  // Removing sends only the backup, not a signature, and still needs the code.
  requests.length = 0;
  prompts.length = 0;
  await changeRecoveryBackup({ authToken: "session", change: "remove", backup: proof, api, wait: noWait, approve: () => true, requestEmailCode: async (request) => { prompts.push(request.reason); return "123456"; } });
  assert.deepEqual(requests.slice(0, 3).map(({ body }) => body.backup), Array(3).fill({ kind: "evm", address: proof.address }));
  assert.deepEqual(prompts, ["recovery-backup"]);
  requests.length = 0;
  await assert.rejects(changeRecoveryBackup({ authToken: "session", change: "remove", backup: proof, api, approve: () => false, requestEmailCode: async () => "123456" }), /Removing the backup was cancelled/);
  assert.deepEqual(requests.map(({ body }) => body.operation), ["preview"]);
});

test("the built-in backup dialog names the backup, what it can do, and the fee", () => {
  const html = renderToStaticMarkup(createElement(KeyWayBackupChangeModal, { theme: "light", appName: "Acme Pay", preview: changePreview, answer: () => undefined }));
  assert.match(html, /Add this backup\?/);
  assert.match(html, /EVM wallet 0xcdcdcdcd…cdcdcd/);
  assert.match(html, /move everything in your account without KeyWay/);
  assert.match(html, /0\.00001274 CKB/);
  assert.match(html, /Your address doesn&#x27;t change/);
  const removal = renderToStaticMarkup(createElement(KeyWayBackupChangeModal, { theme: "light", appName: "Acme Pay", preview: { ...changePreview, change: "remove" }, answer: () => undefined }));
  assert.match(removal, /Remove this backup\?/);
  assert.match(removal, /no longer be able to recover your account/);
  const code = renderToStaticMarkup(createElement(KeyWayEmailCodeModal, { theme: "light", reason: "recovery-backup", resend: async () => undefined, answer: () => undefined }));
  assert.match(code, /confirm this backup change/);
});

/** A recovery account's Omnilock cell, a rescue of it, and a two-member list with an EVM wallet and a JoyID passkey. */
async function recoveryFixture() {
  const joyKey = p256.utils.randomSecretKey();
  const joyPublicKey = ccc.hexFrom(p256.getPublicKey(joyKey, false).slice(1));
  const joyId = await client.getKnownScript(ccc.KnownScript.JoyId);
  const joyLock = ccc.Script.from({ codeHash: joyId.codeHash, hashType: joyId.hashType, args: ccc.bytesConcat("0x0001", ccc.hashCkbShort(joyPublicKey)) });
  const evm = injectedWallet();
  const list = [
    { backup: { kind: "evm" as const, address: evm.address }, auth: evmBackupAuth(evm.address), preimage: evmPreimage(evm.address) },
    { backup: { kind: "joyid" as const, address: ccc.Address.fromScript(joyLock, client).toString() }, auth: joyIdBackupAuth(joyLock), preimage: joyIdPreimage(ccc.hashCkbShort(joyPublicKey)) },
  ];
  const lock = omnilockScript({ omnilock: KEYWAY_OMNILOCK.testnet, omnilockArgs: ccc.hexFrom(ccc.bytesConcat([0], new Uint8Array(20).fill(1), [1], new Uint8Array(32).fill(2))) });
  const destination = await ccc.Script.fromKnownScript(client, ccc.KnownScript.Secp256k1Blake160, `0x${"77".repeat(20)}`);
  const input = { outPoint: { txHash: `0x${"51".repeat(32)}`, index: 0 }, cellOutput: { lock, capacity: 1000n * 100_000_000n }, outputData: "0x" };
  await client.cache.recordCells([input]);
  const tx = ccc.Transaction.from({ inputs: [{ previousOutput: input.outPoint }], outputs: [{ lock: destination, capacity: 999n * 100_000_000n }], outputsData: ["0x"] });
  const signs: string[] = [];
  const joySigner = {
    signType: ccc.SignerSignType.JoyId,
    isConnected: async () => true,
    connect: async () => undefined,
    getIdentity: async () => JSON.stringify({ keyType: "main_key", publicKey: joyPublicKey.slice(2) }),
    signMessageRaw: async (text: string) => {
      signs.push(text);
      const authData = ccc.bytesConcat(sha256(new TextEncoder().encode("testnet.joyid.dev")), [0x05, 0, 0, 0, 0]);
      const clientData = new TextEncoder().encode(JSON.stringify({ type: "webauthn.get", challenge: Buffer.from(text).toString("base64url"), origin: "https://testnet.joyid.dev", crossOrigin: false }));
      const der = p256.sign(ccc.bytesConcat(authData, sha256(clientData)), joyKey, { format: "der" });
      return JSON.stringify({ alg: -7, signature: Buffer.from(der).toString("base64url"), message: Buffer.from(ccc.bytesConcat(authData, clientData)).toString("base64url") });
    },
  } as unknown as ccc.Signer;
  const spend = (entry: (typeof list)[number]) => ({ client, lock, omnilock: KEYWAY_OMNILOCK.testnet, list, entry, adminList: { txHash: `0x${"ad".repeat(32)}`, index: 0 }, inputCapacity: 1000n * 100_000_000n });
  return { tx, lock, destination, list, evm, joySigner, signs, spend };
}

const hasDep = (transaction: ccc.Transaction, dep: { outPoint: { txHash: string } }) => transaction.cellDeps.some(({ outPoint }) => outPoint.txHash === dep.outPoint.txHash);

test("signs a recovery spend with a JoyID backup: the verifier's blob over the readable approval", async () => {
  const { tx, list, joySigner, signs, spend, destination } = await recoveryFixture();
  const { text } = await prepareRecoverySpend(tx, spend(list[1]));
  const signed = await signRecoverySpendWithJoyId(tx, spend(list[1]), joySigner);
  const witness = ccc.bytesFrom(signed.getWitnessArgsAt(0)!.lock!);
  const blob = witness.slice(20, 20 + MAX_WEBAUTHN_SIGNATURE);
  assert.equal(ccc.hexFrom(witness.slice(-62)), list[1].preimage, "the preimage rides in the witness");
  assert.ok(hasDep(signed, JOYID_WEBAUTHN_VERIFIER.testnetCellDep), "the verifier is a cell dep");
  assert.ok(!hasDep(signed, EVM_PERSONAL_SIGN_VERIFIER.testnetCellDep));
  assert.ok(KEYWAY_OMNILOCK.testnet.cellDeps.every((dep) => hasDep(signed, dep)), "KeyWay's pinned Omnilock is a cell dep");
  assert.ok(signed.cellDeps.some(({ outPoint }) => outPoint.txHash === `0x${"ad".repeat(32)}`), "the AdminList is a cell dep");
  // The passkey signed the readable text naming the destination, the CKB, the tokens, the fee and the sighash.
  assert.deepEqual(signs, [text]);
  assert.equal(text, `KeyWay recovery\nMove everything to ${ccc.Address.fromScript(destination, client).toString()}\nCKB: 999\nTokens: none\nFee: 1 CKB\nTransaction: ${(await prepareRecoverySpend(tx, spend(list[1]))).sighash}`);
  assert.deepEqual([blob[0], blob[1]], [2, 0]);
  const clientAt = 132 + 37;
  const assertion = { publicKey: blob.slice(2, 66), rs: blob.slice(66, 130), authData: blob.slice(132, clientAt), clientDataJson: blob.slice(clientAt + 2, clientAt + 2 + (blob[clientAt] | (blob[clientAt + 1] << 8))) };
  assert.ok(verifyWebAuthn(assertion, text));
  // The proof is against the whole list.
  assert.ok(ccc.hexFrom(witness).includes(whitelistTree(list.map(({ auth }) => auth)).proofs[list[1].auth].slice(2)));
  // Another passkey, or the EVM entry, is refused before anything is signed.
  await assert.rejects(signRecoverySpendWithJoyId(tx, { ...spend(list[1]), entry: { ...list[1], preimage: joyIdPreimage(new Uint8Array(20)) } }, joySigner), /isn't the backup on the recovery list/);
  await assert.rejects(signRecoverySpendWithJoyId(tx, spend(list[0]), joySigner), /isn't a JoyID passkey/);
});

test("signs a recovery spend with an EVM backup: personal_sign of the readable approval", async () => {
  const { tx, lock, list, evm, spend } = await recoveryFixture();
  const { text } = await prepareRecoverySpend(tx, spend(list[0]));
  const signed = await signRecoverySpendWithEvm(tx, spend(list[0]), evm.provider);
  const witness = ccc.bytesFrom(signed.getWitnessArgsAt(0)!.lock!);
  assert.equal(new TextDecoder().decode(ccc.bytesFrom(evm.calls.at(-1)!.params![0] as string)), text);
  // version 1 ‖ network 0 (testnet) ‖ r ‖ s ‖ v
  assert.deepEqual([witness[20], witness[21]], [1, 0]);
  assert.equal(evmPersonalSignAddress(text, witness.slice(22, 87)), evm.address);
  assert.equal(ccc.hexFrom(witness.slice(-62)), list[0].preimage);
  assert.ok(hasDep(signed, EVM_PERSONAL_SIGN_VERIFIER.testnetCellDep), "the EVM verifier is a cell dep");
  assert.ok(!hasDep(signed, JOYID_WEBAUTHN_VERIFIER.testnetCellDep), "no WebAuthn verifier for an EVM backup");
  await assert.rejects(signRecoverySpendWithEvm(tx, { ...spend(list[0]), list: [list[1]] }, evm.provider), /isn't on the recovery list/);
  // A transaction that isn't a rescue to one address has no approval text, so nothing is signed.
  const split = tx.clone();
  split.outputs.push(ccc.CellOutput.from({ lock, capacity: 100n * 100_000_000n }));
  split.outputs[0].capacity -= 100n * 100_000_000n;
  split.outputsData.push("0x");
  const before = evm.calls.length;
  await assert.rejects(signRecoverySpendWithEvm(split, spend(list[0]), evm.provider), /can't be approved by a backup/);
  assert.equal(evm.calls.length, before);
});
