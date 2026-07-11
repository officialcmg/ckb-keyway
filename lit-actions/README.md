# Lit Actions

## `sign-ckb-digest.js`

Signs one raw 32-byte CKB transaction digest with a permitted Lit PKP. It does not apply an Ethereum message prefix or hash the digest again.

To publish it with the Chipotle dashboard:

1. Paste the file exactly into **Action Runner > Lit Action code**.
2. Click **Get Lit Action IPFS CID**.
3. Register that CID under **IPFS Actions** as `keyway-ckb-signer`.
4. Add the CID and the intended PKP wallet to the `CKB Keyway` group.

Any source change creates a different CID and must be reviewed and registered again.

## Fiber key protection

`encrypt-fiber-key.js` encrypts a browser-generated 32-byte Fiber identity key using the permitted PKP. `decrypt-fiber-key.js` recovers it only inside the permitted Lit Action so the authenticated backend can start the same browser identity again.

Both Actions must be published immutably and added to the same Lit group as the intended PKP before use.
