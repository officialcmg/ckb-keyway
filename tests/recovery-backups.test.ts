import assert from "node:assert/strict";
import test from "node:test";
import * as ccc from "@ckb-ccc/core";
import { p256 } from "@noble/curves/nist.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  backupAuth,
  ckbSecp256k1Auth,
  describeBackup,
  evmBackupAuth,
  evmOmnilockDigest,
  evmOmnilockMessage,
  evmOmnilockSignature,
  evmPersonalSignAddress,
  execAuth,
  JOYID_WEBAUTHN_VERIFIER,
  joyIdBackupAuth,
  joyIdPreimage,
  omnilockAdminWitnessLock,
  parseBackups,
  recoveryBackupChallenge,
  verifyBackupOwnership,
} from "../src/sdk/browser/recovery-backups.ts";

const client = new ccc.ClientPublicTestnet({ url: "https://testnet.ckb.dev/" });
const ACCOUNT = "ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqv82scyl0ywuurakhc80ha0agm5x8ye8kca6zq0u";

/** A throwaway EVM key, signing like a wallet's personal_sign (r ‖ s ‖ v with v = 27 or 28). */
function evmWallet() {
  const privateKey = secp256k1.utils.randomSecretKey();
  const address = ccc.hexFrom(keccak_256(secp256k1.getPublicKey(privateKey, false).slice(1)).slice(12));
  const signDigest = (digest: Uint8Array) => {
    const raw = secp256k1.sign(digest, privateKey, { prehash: false, format: "recovered" });
    return ccc.hexFrom(ccc.bytesConcat(raw.slice(1), [raw[0] + 27]));
  };
  const personalSign = (message: string) => {
    const bytes = new TextEncoder().encode(message);
    return signDigest(keccak_256(ccc.bytesConcat(new TextEncoder().encode(`\x19Ethereum Signed Message:\n${bytes.length}`), bytes)));
  };
  return { address, personalSign, signDigest };
}

const base64url = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");

/** A JoyID passkey stand-in: a P-256 key whose WebAuthn assertion has the shape JoyID's signMessage returns. */
async function joyIdWallet() {
  const privateKey = p256.utils.randomSecretKey();
  const publicKey = ccc.hexFrom(p256.getPublicKey(privateKey, false).slice(1));
  const joyId = await client.getKnownScript(ccc.KnownScript.JoyId);
  const lock = ccc.Script.from({ codeHash: joyId.codeHash, hashType: joyId.hashType, args: ccc.bytesConcat("0x0001", ccc.hashCkbShort(publicKey)) });
  const address = ccc.Address.fromScript(lock, client).toString();
  const sign = (challenge: string) => {
    const authData = new Uint8Array(37).fill(7);
    const clientData = new TextEncoder().encode(JSON.stringify({ type: "webauthn.get", challenge: base64url(new TextEncoder().encode(challenge)), origin: "https://testnet.joyid.dev" }));
    const der = p256.sign(ccc.bytesConcat(authData, sha256(clientData)), privateKey, { format: "der" });
    return {
      signature: JSON.stringify({ alg: -7, signature: base64url(der), message: base64url(ccc.bytesConcat(authData, clientData)) }),
      identity: JSON.stringify({ keyType: "main_key", publicKey: publicKey.slice(2) }),
    };
  };
  return { address, lock, sign, publicKey };
}

test("encodes each backup as its 21-byte Omnilock auth", async () => {
  const evm = evmWallet();
  assert.equal(evmBackupAuth(evm.address.toUpperCase().replace("0X", "0x")), `0x12${evm.address.slice(2)}`);
  const joy = await joyIdWallet();
  // 0xFD (exec) ‖ blake160 of the 62-byte preimage naming the verifier and the passkey's key hash.
  const preimage = joyIdPreimage(ccc.hashCkbShort(joy.publicKey));
  assert.equal(preimage, ccc.hexFrom(ccc.bytesConcat(JOYID_WEBAUTHN_VERIFIER.codeHash, [0x02, 0x00], new Uint8Array(8), ccc.hashCkbShort(joy.publicKey))));
  assert.equal(ccc.bytesFrom(preimage).length, 62);
  assert.equal(joyIdBackupAuth(joy.lock), `0xfd${ccc.hashCkbShort(preimage).slice(2)}`);
  assert.equal(execAuth(preimage), joyIdBackupAuth(joy.lock));
  assert.equal(await backupAuth(client, { kind: "joyid", address: joy.address }), joyIdBackupAuth(joy.lock));
  assert.equal(await backupAuth(client, { kind: "evm", address: evm.address }), evmBackupAuth(evm.address));
  const publicKey = ccc.hexFrom(secp256k1.getPublicKey(secp256k1.utils.randomSecretKey(), true));
  assert.equal(ckbSecp256k1Auth(publicKey), `0x00${ccc.hashCkbShort(publicKey).slice(2)}`);
  // Not JoyID: a secp256k1 address, and a JoyID lock that isn't a main key.
  await assert.rejects(() => backupAuth(client, { kind: "joyid", address: ACCOUNT }), /isn't a JoyID address/);
  const subKey = ccc.Address.fromScript(ccc.Script.from({ ...joy.lock, args: `0x0002${joy.lock.args.slice(6)}` }), client).toString();
  await assert.rejects(() => backupAuth(client, { kind: "joyid", address: subKey }), /main key/);
});

test("matches JoyID's own main-key lock args for a known public key", () => {
  // From @joyid/ckb's test data: this 64-byte secp256r1 key owns lock args 0x0001fd87…3a4e.
  const publicKey = "0xdb3152525a3586af64b0cf87c1cf6bf3a8af8dc9a23e87a5aa6ad1d0c6e0447f51f147c608a81a5f8450962fb8648dee9acd548cb48bd0ed88642b75e079cace";
  assert.equal(ccc.hexFrom(ccc.bytesConcat("0x0001", ccc.hashCkbShort(publicKey))), "0x0001fd879d61c8187b4fa1e87296bb00371bfebc3a4e");
});

test("parses backup lists", () => {
  const address = evmWallet().address;
  assert.deepEqual(parseBackups([{ kind: "evm", address: address.toUpperCase().replace("0X", "0x") }]), [{ kind: "evm", address }]);
  assert.throws(() => parseBackups([]), /at least one/);
  assert.throws(() => parseBackups([{ kind: "evm", address }, { kind: "evm", address }]), /twice/);
  assert.throws(() => parseBackups([{ kind: "ckb", address }]), /EVM wallet or a JoyID/);
  assert.throws(() => parseBackups([{ kind: "evm", address: "0x1234" }]), /20-byte/);
  assert.throws(() => parseBackups(Array.from({ length: 9 }, () => ({ kind: "evm", address: evmWallet().address }))), /At most 8/);
  assert.match(describeBackup({ kind: "evm", address }), /^EVM wallet 0x[0-9a-f]{8}…[0-9a-f]{6}$/);
});

test("accepts an EVM backup only with its EIP-191 signature over this account's challenge", async () => {
  const evm = evmWallet();
  const backup = { kind: "evm" as const, address: evm.address };
  const challenge = recoveryBackupChallenge(ACCOUNT, backup);
  assert.match(challenge, new RegExp(`Account: ${ACCOUNT}`));
  const signature = evm.personalSign(challenge);
  assert.equal(evmPersonalSignAddress(challenge, signature), evm.address);
  assert.ok(ccc.verifyMessageEvmPersonal(challenge, signature, evm.address), "CCC's EVM verifier agrees");
  assert.deepEqual(await verifyBackupOwnership(client, ACCOUNT, { ...backup, signature }), backup);

  await assert.rejects(() => verifyBackupOwnership(client, "ckt1other", { ...backup, signature }), /didn't sign/);
  await assert.rejects(() => verifyBackupOwnership(client, ACCOUNT, { ...backup, signature: evmWallet().personalSign(challenge) }), /didn't sign/);
  await assert.rejects(() => verifyBackupOwnership(client, ACCOUNT, { ...backup, signature: "0x1234" }), /didn't sign/);
  await assert.rejects(() => verifyBackupOwnership(client, ACCOUNT, backup), /didn't sign/);
});

test("accepts a JoyID backup only with its passkey signature and matching lock", async () => {
  const joy = await joyIdWallet();
  const backup = { kind: "joyid" as const, address: joy.address };
  const challenge = recoveryBackupChallenge(ACCOUNT, backup);
  const signed = joy.sign(challenge);
  assert.ok(await ccc.verifyMessageJoyId(challenge, signed.signature, signed.identity));
  assert.deepEqual(await verifyBackupOwnership(client, ACCOUNT, { ...backup, ...signed }), backup);

  await assert.rejects(() => verifyBackupOwnership(client, ACCOUNT, { ...backup, ...joy.sign("something else") }), /didn't sign/);
  const other = await joyIdWallet();
  await assert.rejects(() => verifyBackupOwnership(client, ACCOUNT, { ...backup, ...other.sign(challenge) }), /didn't sign/, "another passkey's signature");
  // Sub keys and session keys are refused with a reason.
  const subKey = { ...signed, identity: JSON.stringify({ ...JSON.parse(signed.identity), keyType: "sub_key" }) };
  await assert.rejects(() => verifyBackupOwnership(client, ACCOUNT, { ...backup, ...subKey }), /device added later can't be a backup\. Use the JoyID passkey your account was created with/);
  const session = { ...signed, identity: JSON.stringify({ ...JSON.parse(signed.identity), keyType: "main_session_key" }) };
  await assert.rejects(() => verifyBackupOwnership(client, ACCOUNT, { ...backup, ...session }), /session key can't be a backup/);
  const rsa = { ...signed, signature: JSON.stringify({ ...JSON.parse(signed.signature), alg: -257 }) };
  await assert.rejects(() => verifyBackupOwnership(client, ACCOUNT, { ...backup, ...rsa }), /session key can't be a backup/);
});

test("builds the admin witness lock the spike used on chain", () => {
  // Step 3 of the spike: B1's admin-path spend (0x1c24c8af…8186), whose witness lock is 146 bytes.
  const signature = "0xd72796f113b21471000cb19cf7345e4d1f8f5f3fd88a9ea81548a35248e4110b33c1f31320a13ca87daa969bc2c2780e0adc4472840ab3a169e55662ebdb39c801";
  const lock = omnilockAdminWitnessLock({ signature, auth: "0x0079af2d8dbb19362ec15a4acc3c026c2386e0ffa2", proof: "0x4c4f00" });
  assert.equal(lock, `0x9200000010000000550000009200000041000000${signature.slice(2)}3d0000000c000000210000000079af2d8dbb19362ec15a4acc3c026c2386e0ffa21c00000008000000140000000c0000000d00000003030000004c4f00`);
  // An exec (JoyID) backup also carries its 62-byte preimage, as Bytes, in the third field.
  const preimage = joyIdPreimage(new Uint8Array(20).fill(0x11));
  const exec = ccc.bytesFrom(omnilockAdminWitnessLock({ signature: new Uint8Array(768), auth: execAuth(preimage), proof: "0x4c4f00", preimage }));
  assert.equal(exec.length, 146 + 768 - 65 + 4 + 62);
  assert.equal(ccc.hexFrom(exec.slice(-62)), preimage);
});

test("signs an Omnilock sighash the way flag 0x12 verifies it", () => {
  const evm = evmWallet();
  const sighash = `0x${"0a".repeat(16)}${"FF".repeat(16)}`;
  // Omnilock's convert_eth_message_displaying: "CKB transaction: 0x" and 64 lowercase hex digits, 83 bytes.
  const message = evmOmnilockMessage(sighash);
  assert.equal(message, `CKB transaction: 0x${"0a".repeat(16)}${"ff".repeat(16)}`);
  assert.equal(new TextEncoder().encode(message).length, 83);
  assert.deepEqual(evmOmnilockDigest(sighash), keccak_256(new TextEncoder().encode(`\x19Ethereum Signed Message:\n83${message}`)));
  // A wallet's personal_sign of that text is the signature Omnilock recovers E's address from.
  const signature = evmOmnilockSignature(evm.personalSign(message));
  assert.ok(ccc.bytesFrom(signature)[64] <= 1);
  assert.equal(evmPersonalSignAddress(message, signature), evm.address);
  // A personal_sign of the raw 32 bytes (the flag 0x01 rule) recovers someone else under 0x12.
  const raw = evmOmnilockSignature(evm.signDigest(keccak_256(ccc.bytesConcat(new TextEncoder().encode("\x19Ethereum Signed Message:\n32"), ccc.bytesFrom(sighash)))));
  assert.notEqual(evmPersonalSignAddress(message, raw), evm.address);
  assert.throws(() => evmOmnilockMessage("0x00"), /32 bytes/);
  assert.throws(() => evmOmnilockSignature("0x00"), /65 bytes/);
});

test("signs the same text as CCC's EVM signer does for its 0x12 Omnilock address", async () => {
  const evm = evmWallet();
  const signed: string[] = [];
  class Wallet extends ccc.SignerEvm {
    async connect() {}
    async isConnected() { return true; }
    async getEvmAccount() { return evm.address; }
    async signMessageRaw(message: string | ccc.BytesLike) {
      if (typeof message !== "string") throw new Error("expected text");
      signed.push(message);
      return evm.personalSign(message);
    }
  }
  const signer = new Wallet(client);
  const lock = await ccc.Script.fromKnownScript(client, ccc.KnownScript.OmniLock, ccc.hexFrom(ccc.bytesConcat(evmBackupAuth(evm.address), [0x00])));
  const input = { outPoint: { txHash: `0x${"31".repeat(32)}`, index: 0 }, cellOutput: { lock, capacity: 1000n * 100_000_000n }, outputData: "0x" };
  await client.cache.recordCells([input]);
  const tx = ccc.Transaction.from({ inputs: [{ previousOutput: input.outPoint }], outputs: [{ lock, capacity: 999n * 100_000_000n }], outputsData: ["0x"] });
  tx.setWitnessArgsAt(0, ccc.WitnessArgs.from({ lock: ccc.hexFrom(new Uint8Array(85)) }));
  const sighash = (await tx.getSignHashInfo(lock, client))!.message;
  const signedTx = await signer.signOnlyTransaction(tx);
  assert.deepEqual(signed, [evmOmnilockMessage(sighash)]);
  // CCC writes the same 0/1 recovery id signature Omnilock checks.
  const witness = ccc.bytesFrom(signedTx.getWitnessArgsAt(0)!.lock!);
  assert.equal(ccc.hexFrom(witness.slice(20)), evmOmnilockSignature(evm.personalSign(evmOmnilockMessage(sighash))));
});