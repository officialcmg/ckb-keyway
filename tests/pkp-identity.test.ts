import assert from "node:assert/strict";
import test from "node:test";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { recoverPkpPublicKey } from "../src/server/pkp-identity.ts";

test("recovers the compressed public key from Lit signature components", () => {
  const privateKey = new Uint8Array(32);
  privateKey[31] = 1;
  const digest = new Uint8Array(32).fill(3);
  const recovered = secp256k1.sign(digest, privateKey, { prehash: false, format: "recovered" });
  const signature = {
    r: `0x${Buffer.from(recovered.slice(1, 33)).toString("hex")}` as const,
    s: `0x${Buffer.from(recovered.slice(33)).toString("hex")}` as const,
    recoveryParam: recovered[0] as 0 | 1,
  };

  assert.deepEqual(recoverPkpPublicKey(digest, signature), secp256k1.getPublicKey(privateKey, true));
});

test("an identity signature counts only if it is this PKP's, as verify:lit and account creation check", async () => {
  const { derivePkpIdentity } = await import("../src/server/pkp-identity.ts");
  const { keccak_256 } = await import("@noble/hashes/sha3.js");
  const { sha256 } = await import("@noble/hashes/sha2.js");
  const digest = sha256(new TextEncoder().encode("CKB KeyWay identity v1"));
  const keyOf = (seed: number) => { const key = new Uint8Array(32); key[31] = seed; return key; };
  const pkpIdOf = (key: Uint8Array) => `0x${Buffer.from(keccak_256(secp256k1.getPublicKey(key, false).slice(1)).slice(-20)).toString("hex")}`;
  const signer = (key: Uint8Array) => async () => {
    const recovered = secp256k1.sign(digest, key, { prehash: false, format: "recovered" });
    return { r: `0x${Buffer.from(recovered.slice(1, 33)).toString("hex")}` as const, s: `0x${Buffer.from(recovered.slice(33)).toString("hex")}` as const, recoveryParam: recovered[0] as 0 | 1 };
  };
  // A well-formed signature by another key is refused.
  await assert.rejects(derivePkpIdentity(pkpIdOf(keyOf(7)), signer(keyOf(8))), /does not match the Lit PKP/);
  const identity = await derivePkpIdentity(pkpIdOf(keyOf(7)), signer(keyOf(7)));
  assert.equal(identity.publicKey, `0x${Buffer.from(secp256k1.getPublicKey(keyOf(7), true)).toString("hex")}`);
});
