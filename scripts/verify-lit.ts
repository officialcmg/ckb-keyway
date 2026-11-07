import * as ccc from "@ckb-ccc/core";
import { signCkbDigest } from "../src/server/lit.ts";
import { loadLitAction } from "../src/server/lit-actions.ts";
import { litPolicyEnabled, policyIdentitySignature } from "../src/server/lit-policy.ts";
import { derivePkpIdentity, recoverPkpPublicKey } from "../src/server/pkp-identity.ts";

const apiKey = process.env.LIT_USAGE_API_KEY ?? "";
const actionCid = process.env.LIT_SIGN_ACTION_CID ?? "";
const pkpId = process.env.LIT_PKP_ID ?? "";
const policy = litPolicyEnabled();

// A well-formed signature isn't enough: the identity digest's signer must be this PKP. With KEYWAY_LIT_SIGNER=policy
// this checks the policy Action's identity mode; otherwise the digest signer.
const identity = await derivePkpIdentity(pkpId, { apiKey, actionCid }, policy ? policyIdentitySignature : undefined);
if (!policy) {
  // The digest signer must also sign an arbitrary digest as the same key.
  const digest = `0x${"00".repeat(32)}` as const;
  const signature = await signCkbDigest(digest, pkpId, { apiKey, actionCid, actionCode: await loadLitAction("sign-ckb-digest") });
  if (ccc.hexFrom(recoverPkpPublicKey(ccc.bytesFrom(digest), signature)) !== identity.publicKey.toLowerCase()) {
    throw new Error("The digest signer's signature isn't from this PKP");
  }
}
console.log(`Lit PKP ${identity.litPkpId} signs as ${identity.publicKey} (${identity.ckbAddress})`);
console.log(`Lit signature verified (${policy ? "policy Action" : "digest Action"})`);
