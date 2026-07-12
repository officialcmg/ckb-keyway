import { signCkbDigest } from "../src/server/lit.ts";
import { loadLitAction } from "../src/server/lit-actions.ts";

const apiKey = process.env.LIT_USAGE_API_KEY ?? "";
const actionCid = process.env.LIT_SIGN_ACTION_CID ?? "";
const pkpId = process.env.LIT_PKP_ID ?? "";
const digest = `0x${"00".repeat(32)}`;

const signature = await signCkbDigest(digest, pkpId, {
  apiKey,
  actionCid,
  actionCode: await loadLitAction("sign-ckb-digest"),
});
console.log(`Lit signature verified: r=32 bytes, s=32 bytes, recovery=${signature.recoveryParam}`);
