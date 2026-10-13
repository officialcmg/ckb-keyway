import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";

const INFO = "ckb-keyway:settlement-key:v1";

/**
 * The CKB key a browser node settles force-closed channels to. Fiber 0.9.1 pays a force close to the
 * node's own CKB key rather than the channel's close address, and without a key it makes a throwaway one,
 * which loses the funds. Deriving it from the user's Fiber key means only someone who can run the user's
 * node can re-create it, and the SDK sweeps anything there to the user's own address.
 */
export function deriveSettlementKey(fiberKey: Uint8Array): Uint8Array {
  if (fiberKey.length !== 32) throw new Error("Fiber key must be exactly 32 bytes");
  for (let counter = 0; counter < 256; counter++) {
    const candidate = hkdf(sha256, fiberKey, undefined, new TextEncoder().encode(`${INFO}:${counter}`), 32);
    if (secp256k1.utils.isValidSecretKey(candidate)) return candidate;
    candidate.fill(0);
  }
  throw new Error("Could not derive a settlement key");
}
