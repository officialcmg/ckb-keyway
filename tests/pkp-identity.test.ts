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
