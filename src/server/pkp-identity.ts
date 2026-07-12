import * as ccc from "@ckb-ccc/core";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { loadLitAction } from "./lit-actions.ts";
import { signCkbDigest, type LitRuntimeConfig, type LitSignature } from "./lit.ts";

const IDENTITY_DIGEST = sha256(new TextEncoder().encode("CKB KeyWay identity v1"));

export type PkpIdentity = {
  litPkpId: string;
  publicKey: `0x${string}`;
  ckbAddress: string;
};

export async function derivePkpIdentity(
  litPkpId: string,
  config: LitRuntimeConfig,
): Promise<PkpIdentity> {
  const digest = toHex(IDENTITY_DIGEST);
  const signature = await signCkbDigest(digest, litPkpId, {
    ...config,
    actionCode: await loadLitAction("sign-ckb-digest"),
  });
  const publicKeyBytes = recoverPkpPublicKey(IDENTITY_DIGEST, signature);
  const recoveredPkpId = `0x${toBareHex(keccak_256(secp256k1.Point.fromBytes(publicKeyBytes).toBytes(false).slice(1)).slice(-20))}`;

  if (recoveredPkpId.toLowerCase() !== litPkpId.toLowerCase()) {
    throw new Error("Recovered public key does not match the Lit PKP");
  }

  const publicKey = toHex(publicKeyBytes);
  const signer = new ccc.SignerCkbPublicKey(new ccc.ClientPublicTestnet(), publicKey);
  const ckbAddress = (await signer.getRecommendedAddressObj()).toString();
  return { litPkpId, publicKey, ckbAddress };
}

export function recoverPkpPublicKey(digest: Uint8Array, signature: LitSignature): Uint8Array {
  const recoveredSignature = Uint8Array.from([
    signature.recoveryParam,
    ...fromHex(signature.r),
    ...fromHex(signature.s),
  ]);
  const publicKey = secp256k1.recoverPublicKey(recoveredSignature, digest, { prehash: false });
  if (!secp256k1.verify(recoveredSignature.slice(1), digest, publicKey, { prehash: false })) {
    throw new Error("Recovered Lit signature is invalid");
  }
  return publicKey;
}

function fromHex(value: string): Uint8Array {
  return Uint8Array.from(Buffer.from(value.slice(2), "hex"));
}

function toHex(value: Uint8Array): `0x${string}` {
  return `0x${toBareHex(value)}`;
}

function toBareHex(value: Uint8Array): string {
  return Buffer.from(value).toString("hex");
}
