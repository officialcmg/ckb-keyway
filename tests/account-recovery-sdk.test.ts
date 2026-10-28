import assert from "node:assert/strict";
import test from "node:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import * as ccc from "@ckb-ccc/core";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { createEvmBackup, createJoyIdBackup, enableRecovery, recoveryAccountAddress, type RecoveryPreview } from "../src/sdk/browser/account-recovery.ts";
import { KeyWayApiClient } from "../src/sdk/browser/api-client.ts";
import { recoveryBackupChallenge, verifyBackupOwnership } from "../src/sdk/browser/recovery-backups.ts";
import { KeyWayEmailCodeModal, KeyWayRecoveryModal } from "../src/sdk/react/signing-modals.tsx";

const client = new ccc.ClientPublicTestnet({ url: "https://testnet.ckb.dev/" });
const publicKey = ccc.hexFrom(secp256k1.getPublicKey(secp256k1.utils.randomSecretKey(), true));

/** An EIP-1193 wallet that signs personal_sign like MetaMask: the hex message's bytes, v = 27 or 28. */
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
  const proof = await createEvmBackup(account, wallet.provider);
  assert.equal(proof.kind, "evm");
  assert.equal(proof.address, wallet.address);
  assert.deepEqual(wallet.calls.map(({ method }) => method), ["eth_requestAccounts", "personal_sign"]);
  // The wallet is asked to sign the readable challenge text.
  assert.equal(new TextDecoder().decode(ccc.bytesFrom(wallet.calls[1].params![0] as string)), recoveryBackupChallenge(account, proof));
  assert.deepEqual(await verifyBackupOwnership(client, account, proof), { kind: "evm", address: wallet.address });
  await assert.rejects(createEvmBackup(account, undefined), /No EVM wallet/);
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
  const proof = await createJoyIdBackup("ckt1account", signer);
  assert.deepEqual(proof, { kind: "joyid", address: await signer.getRecommendedAddress(), signature: "{\"alg\":-7}", identity: "{\"keyType\":\"main_key\"}" });
  assert.equal(signed[0], "connect");
  assert.equal(signed[1], recoveryBackupChallenge("ckt1account", { kind: "joyid", address: proof.address }));
  await assert.rejects(createJoyIdBackup("ckt1account", { ...signer, signType: ccc.SignerSignType.EvmPersonal, isConnected: async () => true } as unknown as ccc.Signer), /JoyID signer/);
});

const preview: RecoveryPreview = {
  network: "CKB testnet", newAddress: "ckt1qrejnmlar3r452tcg57gvq8patctcgy8acync0hxfnyka35ywafvkqgqnewaddress", legacyAddress: "ckt1qzda0old",
  backups: [{ kind: "evm", address: `0x${"ab".repeat(20)}`, label: "EVM wallet 0xabababab…ababab" }],
  adminListCkb: "197", minimumCellCkb: "95", tokenCellsExtraCkb: "0", lockedCkb: "197", feeCkb: "0.00000981", movedCkb: "9802.99999019",
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
      return Response.json({ transactionHash: preview.transactionHash, ckbAddress: preview.newAddress, recovery: { legacyAddress: "ckt1qzda0old" } });
    },
  });
  const backups = [{ kind: "evm" as const, address: preview.backups[0].address, signature: `0x${"00".repeat(65)}` }];
  const approvals: RecoveryPreview[] = [];
  const codes = ["111111", "222222"];
  const prompts: Array<{ reason: string; error?: string }> = [];
  const result = await enableRecovery({
    authToken: "session", backups, api,
    approve: (shown) => { approvals.push(shown); return true; },
    requestEmailCode: async (request) => { prompts.push({ reason: request.reason, error: request.error }); return codes.shift(); },
  });
  assert.equal(result.ckbAddress, preview.newAddress);
  assert.deepEqual(approvals, [preview]);
  assert.deepEqual(requests.map(({ body }) => body.operation), ["preview", "request-email-code", "enable", "enable"]);
  assert.ok(requests.every(({ url }) => url.endsWith("/api/v1/keyway/recovery")));
  assert.ok(requests.every(({ body }) => JSON.stringify(body.backups) === JSON.stringify(backups)));
  assert.ok(requests.filter(({ body }) => body.operation === "enable").every(({ idempotency }) => idempotency));
  assert.deepEqual(prompts, [{ reason: "recovery", error: undefined }, { reason: "recovery", error: "That email code isn't right" }]);

  requests.length = 0;
  await assert.rejects(enableRecovery({ authToken: "session", backups, api, approve: () => false, requestEmailCode: async () => "222222" }), /cancelled/);
  assert.deepEqual(requests.map(({ body }) => body.operation), ["preview"], "nothing is emailed or signed when the user cancels");
});

test("the built-in dialog shows the backups, the CKB locked, the fee and the new address", () => {
  const html = renderToStaticMarkup(createElement(KeyWayRecoveryModal, { theme: "light", appName: "Acme Pay", preview, answer: () => undefined }));
  assert.match(html, /Turn on recovery\?/);
  assert.match(html, /EVM wallet 0xabababab…ababab/);
  assert.match(html, /197 CKB/);
  assert.match(html, /0\.00000981 CKB/);
  assert.match(html, /ckt1qrejnmla…ddress/);
  assert.match(html, new RegExp(preview.newAddress));
  assert.match(html, /Your address will change because you&#x27;re turning on recovery\./);
  const code = renderToStaticMarkup(createElement(KeyWayEmailCodeModal, { theme: "light", reason: "recovery", resend: async () => undefined, answer: () => undefined }));
  assert.match(code, /confirm turning on recovery/);
});
