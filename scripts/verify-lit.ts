import { signCkbDigest } from "../src/server/lit.ts";
import { loadLitAction } from "../src/server/lit-actions.ts";
import { litPolicyEnabled, policyIdentitySignature } from "../src/server/lit-policy.ts";
import { derivePkpIdentity } from "../src/server/pkp-identity.ts";

const apiKey = process.env.LIT_USAGE_API_KEY ?? "";
const actionCid = process.env.LIT_SIGN_ACTION_CID ?? "";
const pkpId = process.env.LIT_PKP_ID ?? "";
const digest = `0x${"00".repeat(32)}`;

// With KEYWAY_LIT_SIGNER=policy this checks the policy Action's identity mode; otherwise the digest signer.
const signature = litPolicyEnabled()
  ? await policyIdentitySignature(pkpId)
  : await signCkbDigest(digest, pkpId, { apiKey, actionCid, actionCode: await loadLitAction("sign-ckb-digest") });
// A well-formed signature isn't enough: the identity digest's signer must be this PKP.
const identity = await derivePkpIdentity(pkpId, { apiKey, actionCid }, litPolicyEnabled() ? policyIdentitySignature : undefined);
console.log(`Lit PKP ${identity.litPkpId} signs as ${identity.publicKey} (${identity.ckbAddress})`);
console.log(`Lit signature verified (${litPolicyEnabled() ? "policy Action" : "digest Action"}): r=32 bytes, s=32 bytes, recovery=${signature.recoveryParam}`);
