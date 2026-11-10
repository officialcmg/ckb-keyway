/**
 * KeyWay's Lit settings. Only secrets (API keys) come from the environment; everything else is fixed here, so a
 * deploy can't run a different Action or signer than this code says.
 *
 * Each CID is the IPFS hash of the Action's source in `lit-actions/` (tests/lit-action-packaging.test.ts checks
 * them), and each must be registered in the "CKB Keyway" Lit group before code that uses it is deployed.
 */
export const LIT_ACTION_CIDS = {
  "sign-ckb-digest": "QmXJAW3CKLUuKa9RjEZKCMzEmLYcT7z4tmrzxZvGGfm6Q3",
  "sign-ckb-transaction": "QmZ2sYky6JNvaPjREfhZza4zQYfKVSCQqbVsL4ej2CpRzj",
  "generate-fiber-key": "QmNZDRCHGW1Y8hAy9zVnWay1ob1ybsR62AjNBPr1ecLFQL",
  "wrap-fiber-key": "QmP52L3EYKPAagzsjDQJEXZSMH3X9rZ9NsGdMR4fxNXQ1B",
} as const;

export type LitSignerMode = "digest" | "policy";

/**
 * Which Action signs for users. "digest" is `sign-ckb-digest`, which signs any digest the server hands it.
 * "policy" is `sign-ckb-transaction`, which checks every transaction itself. Switch to "policy" in a commit once
 * its CID is in the Lit group.
 */
export const LIT_SIGNER: LitSignerMode = "policy";

/** Tests run both signers; production code never writes this. */
export const litSignerOverride: { mode?: LitSignerMode } = {};

export function litSignerMode(): LitSignerMode {
  return litSignerOverride.mode ?? LIT_SIGNER;
}
