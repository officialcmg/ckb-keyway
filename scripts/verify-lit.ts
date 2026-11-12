import { policyIdentitySignature } from "../src/server/lit-policy.ts";
import { derivePkpIdentity } from "../src/server/pkp-identity.ts";

// Checks that the pinned policy Action signs as LIT_PKP_ID: the identity digest's signer must be this PKP.
const pkpId = process.env.LIT_PKP_ID ?? "";
const identity = await derivePkpIdentity(pkpId, policyIdentitySignature);
console.log(`Lit PKP ${identity.litPkpId} signs as ${identity.publicKey} (${identity.ckbAddress})`);
console.log("Lit signature verified (policy Action)");
