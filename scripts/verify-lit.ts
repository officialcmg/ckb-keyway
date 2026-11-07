import * as ccc from "@ckb-ccc/core";
import { signCkbDigest } from "../src/server/lit.ts";
import { loadLitAction } from "../src/server/lit-actions.ts";
import { LIT_ACTION_CIDS, litSignerOverride } from "../src/server/lit-config.ts";
import { litPolicyEnabled, policyIdentitySignature } from "../src/server/lit-policy.ts";
import { derivePkpIdentity, recoverPkpPublicKey } from "../src/server/pkp-identity.ts";

// `npm run verify:lit -- --policy` checks the policy Action before LIT_SIGNER is switched in lit-config.ts.
if (process.argv.includes("--policy")) litSignerOverride.mode = "policy";
const apiKey = process.env.LIT_USAGE_API_KEY ?? "";
const actionCid = LIT_ACTION_CIDS["sign-ckb-digest"];
const pkpId = process.env.LIT_PKP_ID ?? "";
const policy = litPolicyEnabled();

// A well-formed signature isn't enough: the identity digest's signer must be this PKP.
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
