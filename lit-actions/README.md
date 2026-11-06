# Lit Actions

## `sign-ckb-digest.js`

Signs one raw 32-byte CKB transaction digest with a permitted Lit PKP. It does not apply an Ethereum message prefix or hash the digest again.

To publish it with the Chipotle dashboard:

1. Paste the file exactly into **Action Runner > Lit Action code**.
2. Click **Get Lit Action IPFS CID**.
3. Register that CID under **IPFS Actions** as `keyway-ckb-signer`.
4. Add the CID and the intended PKP wallet to the `CKB Keyway` group.

Any source change creates a different CID and must be reviewed and registered again.

## `sign-ckb-transaction.js` (policy signer)

Replaces `sign-ckb-digest.js`. It never signs a digest it is handed:

- **transaction:** it fetches every input from CKB testnet, checks each against its transaction hash, derives the
  account's locks from the PKP's own key and computes each sighash itself. It refuses any change to the recovery
  list except creating it when recovery is turned on, or adding or removing exactly one backup with the same lock,
  Type ID and capacity. Lists use version 3 records of salted auths; the server passes each backup's kind and
  id, and the Action rebuilds every listed auth with the account's salt and KeyWay's verifiers.
- **Recovery list changes:** each one needs a code the Action makes, emails and checks itself. The address is bound
  on chain when recovery is turned on.
- **identity:** signs only the fixed identity digest.
- **message:** hashes a CKB "Nervos Message:" itself.

The server uses it once `KEYWAY_LIT_SIGNER=policy`. Its CID is pinned in `src/server/lit-policy.ts` and
`.env.example`. Register it the same way as above, as `keyway-ckb-policy-signer`, then remove the
`sign-ckb-digest` CID from the group. The full steps, the design and what stays trusted are in
`research/lit-policy/README.md`.

## Fiber key protection

`generate-fiber-key.js` creates a browser node's 32-byte Fiber identity key inside Lit and returns only its ciphertext, encrypted to the permitted PKP. `wrap-fiber-key.js` decrypts it inside Lit and re-encrypts it to a one-time key the signed-in browser made, so KeyWay's backend only ever relays ciphertext.

Both Actions must be published immutably and added to the same Lit group as the intended PKP before use.
