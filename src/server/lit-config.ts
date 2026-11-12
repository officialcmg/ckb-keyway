/**
 * KeyWay's Lit settings. Only secrets (API keys) come from the environment; everything else is fixed here, so a
 * deploy can't run a different Action or signer than this code says.
 *
 * Each CID is the IPFS hash of the Action's source in `lit-actions/` (tests/lit-action-packaging.test.ts checks
 * them), and each must be registered in the "CKB Keyway" Lit group before code that uses it is deployed.
 */
export const LIT_ACTION_CIDS = {
  "sign-ckb-transaction": "QmQdQwLVK49DgQBp7RMGM2WH8sjPpkiYGDUXt1N1j2CKED",
  "generate-fiber-key": "QmNZDRCHGW1Y8hAy9zVnWay1ob1ybsR62AjNBPr1ecLFQL",
  "wrap-fiber-key": "QmP52L3EYKPAagzsjDQJEXZSMH3X9rZ9NsGdMR4fxNXQ1B",
} as const;
