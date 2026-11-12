# Lit Actions

Every Action's CID is pinned in `src/server/lit-config.ts`. To publish one with the Chipotle dashboard:

1. Paste the file exactly into **Action Runner > Lit Action code**.
2. Click **Get Lit Action IPFS CID** and check it matches `src/server/lit-config.ts`.
3. Register that CID under **IPFS Actions**.
4. Add the CID to the `CKB Keyway` group.

Any source change creates a different CID and must be reviewed and registered again. The group should hold only
the CIDs in `lit-config.ts`.

## `sign-ckb-transaction.js` (policy signer)

KeyWay's only signer. It never signs a digest it is handed (the earlier `sign-ckb-digest` signer, which did, is
retired: removed from the Lit group and from this repository):

- **transaction:** it fetches every input from CKB testnet, checks each against its transaction hash, derives the
  account's locks from the PKP's own key and computes each sighash itself. It refuses any change to the recovery
  list except creating it when recovery is turned on, or adding or removing exactly one backup with the same lock,
  Type ID and capacity. Lists use version 3 records of salted auths; the server passes each backup's kind and
  id, and the Action rebuilds every listed auth with the account's salt and KeyWay's verifiers.
- **Recovery list changes:** each one needs a code the Action makes, emails and checks itself. The address is bound
  on chain when recovery is turned on.
- **Send limits:** for an account with a send-limit cell, every send must chain on it; the Action sums the last
  24 hours from that chain and asks for its own emailed code once the daily amount is reached. Sends that can't
  chain (Fiber channel funding) always need the code. See `research/send-limits/README.md`.
- **plan:** the same rules without a key, which the server runs locally to know whether a code is needed.
- **identity:** signs only the fixed identity digest.
- **message:** hashes a CKB "Nervos Message:" itself.

Register it as `keyway-ckb-policy-signer`. The design and what stays trusted are in
`research/lit-policy/README.md`.

## Fiber key protection

`generate-fiber-key.js` creates a browser node's 32-byte Fiber identity key inside Lit and returns only its ciphertext, encrypted to the permitted PKP. `wrap-fiber-key.js` decrypts it inside Lit and re-encrypts it to a one-time key the signed-in browser made, so KeyWay's backend only ever relays ciphertext.

Both Actions must be published immutably and added to the same Lit group as the intended PKP before use.
