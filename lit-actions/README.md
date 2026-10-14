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

`generate-fiber-key.js` creates a browser node's 32-byte Fiber identity key inside Lit and returns only its ciphertext, encrypted to the permitted PKP. `wrap-fiber-key.js` decrypts it inside Lit and re-encrypts it to a one-time key the signed-in browser made, so KeyWay's backend only ever relays ciphertext.

Both Actions must be published immutably and added to the same Lit group as the intended PKP before use.
