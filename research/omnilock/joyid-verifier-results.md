# JoyID backups with a WebAuthn verifier: testnet results

Phase 2 made JoyID backups Omnilock owner-lock identities (flag 0xFC), which let any JoyID transaction the user
approved also carry their KeyWay funds out. That mode is gone. A JoyID backup is now an Omnilock **exec
identity (flag 0xFD)** that names KeyWay's WebAuthn verifier (`contracts/joyid-webauthn`) and the JoyID main
key's public key, so a backup spend needs a passkey signature made for that exact transaction, as an EVM backup
does.

Run on CKB testnet on 2026-10-29 with throwaway keys (`phase4/keys.json`, gitignored, never printed): **K**
stands in for the account's Lit key, **J1** is a P-256 key standing in for a JoyID passkey, answering in JoyID's
exact format (below). Funding: five faucet claims of 10000 CKB (D1–D4 for the deployment, K for the account).

| Step | Result | Transaction |
|---|---|---|
| Deploy the verifier (37,024 bytes, `data1`, unspendable lock) | **PASS** | `0x333fa2abd90d32133cd3aca9be68a2042f0bdf3d191c384d6bc77b3cd6ae387b` |
| Turn recovery on through `src/server/recovery.ts` (preview → request-email-code → enable) with J1 as the only backup | **PASS** | `0x749adad0d67555b18816d419c79c662f5d6bc68655abf6cafcd713329e3861cc` |
| Spend from the Omnilock via the administrator path, signed only by J1 through the verifier | **PASS** | `0x7e0bc4816afc6e8fbd3f49961b3330ed798165e7314b5e00d5f65ea59788b445` |
| Negative dry runs (`phase4/joyid-negative.ts`, output in `phase4/joyid-negative.out`) | as expected | dry runs only |

Every transaction was dry-run with `test_tx_pool_accept` first and waited on until committed.

- K legacy secp256k1: `ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsq2rvh7a8hprzkkqumltyahmhr939afydesksjnwu`
- K Omnilock: `ckt1qrejnmlar3r452tcg57gvq8patctcgy8acync0hxfnyka35ywafvkqgqgdjlm57uyv26crn0avnklwuvkyh4y3hxqxez38x39zseegcgl6l6e8wjn8ygq9js4v73sqkdyvdg0s203azz27kznm9`
- J1's JoyID address (main key): `ckt1qrfrwcdnvssswdwpn3s9v8fp87emat306ctjwsm3nmlkjg8qyza2cqgqqy9f7lknjuzw75jjpqy5seak7qqt4xln3uhkpv2y`

## Design

**Identity.** `auth = 0xFD ‖ blake160(preimage)`, `preimage (62 bytes) = verifier code hash ‖ 0x02 (data1) ‖
0x00 (cell dep) ‖ length 0 ‖ offset 0 (u32 LE each, the whole cell) ‖ blake160(64-byte P-256 public key)`. The last
20 bytes are exactly the JoyID main key's lock args after `0x0001`, so the auth is computed from the JoyID address
alone. Checked in nervosnetwork/omnilock `c/ckb_identity.h`: `verify_via_exec` requires a 62-byte preimage
(`32 + 1 + 1 + 8 + 20`), checks `blake160(preimage)` against the identity, computes the group's sighash and
`ckb_exec_cell(code_hash, hash_type, offset, length, 1, argv)` with argv = hex of
`code_hash:hash_type:pubkey_hash:msg:sig`. The administrator path (`omni_identity` + SMT proofs) reaches it
through the same `ckb_verify_identity` after the whitelist check, and nothing in Omnilock runs after it. Its
bundled ckb-c-stdlib looks the binary up by data hash for any hash type but 1, so hash type `0x02` finds the
deployed bytes by data hash and nobody can swap them.

**Exec, not dl.** The verifier is a plain Rust `no_std` program on ckb-std; dl would need a position-independent
shared object with ckb-auth's entry point. Omnilock does nothing after the identity check, so losing its VM to
exec costs nothing, and the extra program load is small next to P-256.

**Verifier.** No ckb-auth `auth_libecc` deployment is listed for testnet, and ckb-auth's P-256 algorithms
(15, 17) don't understand WebAuthn anyway, so P-256 is bundled (RustCrypto `p256` 0.13, verify only). Binary
37,024 bytes (37,085 CKB cell), reproducible from `contracts/`. It checks: the argument shape; blake160(public
key) against the identity; authenticatorData ≥ 37 bytes with user presence; clientDataJSON strictly (UTF-8, one
JSON object, unique top-level keys after unescaping, top-level `"type"` = `"webauthn.get"`, top-level
`"challenge"` = base64url of `CKB transaction: 0x<sighash>`); then P-256 over
`sha256(authenticatorData ‖ sha256(clientDataJSON))`, high `s` allowed. It doesn't require user verification or
check rpIdHash/origin; `contracts/README.md` gives the reasons. 11 tests run the real binary in CKB-VM
(ckb-debugger 1.1.1), including ckb-auth#31's JoyID vector through the P-256 core and a full real JoyID testnet
assertion (iany.me) that parses and passes every check up to its challenge.

**Signature blob** (in the witness's `signature`, ≤ 1024 bytes, Omnilock's limit): `0x01 ‖ public key (64) ‖ r ‖ s
(64) ‖ u16 LE length ‖ authenticatorData ‖ u16 LE length ‖ clientDataJSON ‖ zero padding`. The sighash covers the
witness lock zeroed at its final length, so the length must be fixed before the passkey signs: the SDK reserves 768
bytes and pads with zeros (signing again at 1024 if JoyID's assertion doesn't fit; JoyID-shaped assertions with
Chrome's extra key come to 485 bytes). Padding must be all zero.

**What JoyID signs and shows.** `@joyid/ckb` 1.1.4 `signChallenge(challenge)` with a string opens JoyID's
`/sign-message` page with `isData: false`; CCC's `JoyId.CkbSigner.signMessageRaw(string)` does the same and
returns `{ signature: base64url(DER), alg: -7, message: base64url(authenticatorData (37) ‖ clientDataJSON) }`.
`@joyid/ckb`'s own `verifySignature` → `ensureChallenge` checks `clientData.challenge ===
base64url(utf8(challenge))`, so the WebAuthn challenge is the UTF-8 bytes of the text, nothing added. KeyWay's
text is `CKB transaction: 0x<sighash in 64 lowercase hex digits>` (83 bytes, 111 base64url characters), the same
text an EVM backup signs. The JoyID page shows the message text; what exactly it renders for this text has to be
confirmed with a real JoyID (step 3 below).

**Ownership proof at setup** stays a JoyID `signMessage` of the KeyWay challenge. The server now checks it with
`verifyWebAuthn` (`src/sdk/browser/webauthn.ts`), the verifier's rules in TypeScript, instead of
`ccc.verifyMessageJoyId` (which takes `JSON.parse`'s last duplicate key), and checks that the identity is a
`main_key` with ES256 whose public key hashes to the JoyID address's args.

**Key types** (`@joyid/ckb` `verifySignature`/`verifyCredential`, CCC's identity JSON `{ keyType, publicKey }`):

- `main_key`: the passkey the account was created with, lock args `0x0001 ‖ blake160(pubkey)`. Accepted. A passkey
  synced by Google Password Manager or iCloud Keychain is the same key on every device, so one backup works on
  all of them.
- `sub_key`: a passkey added through JoyID's "add device". It only belongs to the address through JoyID's CoTA
  records; the address args don't commit to it, and checking the CoTA SMT on chain would need JoyID's aggregator
  to supply the proof and a CoTA SMT verifier here. Refused: "A JoyID device added later can't be a backup. Use the
  JoyID passkey your account was created with".
- `main_session_key` / `sub_session_key` (RSA, `alg` -257): refused: "A JoyID session key can't be a backup. Use
  the JoyID passkey your account was created with".

**Helpers.** `signRecoverySpendWithJoyId(tx, spend, joyIdSigner)` and `signRecoverySpendWithEvm(tx, spend,
ethereum)` (`src/sdk/browser/recovery-spend.ts`) write the zeroed admin witness, take the sighash, have the
backup sign `CKB transaction: 0x…`, check the result locally and write the witness lock (signature, identity with
the SMT proof against the whole list, and for JoyID the preimage). They add the Omnilock deps, the AdminList and,
for JoyID, the verifier as cell deps. `spend.list` comes from `readRecoveryList`, which rebuilds the list from chain
data alone (see `phase4-results.md`).

## Testnet proof

**JoyID's byte format, reproduced.** `phase4/lib.ts` `joyIdPasskey`: authenticatorData = `sha256("testnet.joyid.dev")
‖ 0x05 ‖ 00000000` (what JoyID testnet returns: user present and verified, sign count 0); clientDataJSON =
`{"type":"webauthn.get","challenge":"…","origin":"https://testnet.joyid.dev","crossOrigin":false,"other_keys_can_be_added_here":"do not compare clientDataJSON against a template. See https://goo.gl/yabPex"}`,
the real testnet assertion's shape including Chrome's extra key; the result is CCC's JSON above, DER signature
and all. The scripts drive it through a stand-in with CCC's JoyID signer interface (`signType` JoyId,
`getIdentity`, `signMessage`, `signMessageRaw`).

**Enable** (`phase4/joyid-enable.ts`): one 10000 CKB input; AdminList 197 CKB; 727 bytes (73 more than phase 2:
witness 0's `output_type` holds the 69-byte list record `4b57524c 01 01 fd ‖ preimage`); fee 0.00001091 CKB;
2,608,797 cycles. The email named the backup ("Backup: JoyID ckt1qrfrwc…hkpv2y"). AdminList type args
`hashTypeId(input0, 0)`; the SMT member is `0xfd6ca6d6f62c7b2c9abd1fe8e78d8c35beadbb5805`.

**Spend** (`phase4/joyid-spend.ts J1 joyIdSpend --fund-joyid`): the list and proof were read from the chain with
`readRecoveryList` (root `0x06dcf467…62c6` matched the cell). 1000 CKB to K's legacy address, 100 CKB to J1's JoyID
address (for the owner-lock negative below), change to the Omnilock. Witness lock 915 bytes (768-byte blob,
62-byte preimage, 3-byte proof). **6,796,168 cycles**, 1,570 bytes, fee 2,355 shannons.

**Negative dry runs** (same transaction, one thing changed):

| Case | Result |
|---|---|
| Control: J1 signs this transaction | accepted, 6,799,126 cycles |
| J1 signs another transaction's sighash | rejected, verifier exit 107 (challenge) |
| J2 signs with its own public key under J1's identity and proof | rejected, 101 (public key hash) |
| J2's signature with J1's public key in the blob | rejected, 109 (signature) |
| J2 with its own identity and a proof from a tree that contains it | rejected, Omnilock 59 (`ERROR_NOT_ON_WHITE_LIST`) |
| J1 signs, but the verifier isn't a cell dep | rejected, 1 (binary not found among cell deps) |
| Owner-lock style: identity `0xFC ‖ lockHash(J1's JoyID lock)[0..20]`, J1's JoyID cell as an input, no signature | rejected, 59 |
| J1's identity, J1's JoyID cell as an input, no signature or preimage | rejected, 72 (`ERROR_INVALID_PREIMAGE`) |

So a JoyID transaction the user approves elsewhere can't move KeyWay funds any more: only a signature over this
transaction's sighash counts. Off-chain coverage: `tests/webauthn.test.ts`, `tests/recovery-backups.test.ts`,
`tests/account-recovery-sdk.test.ts` (the helper's witness, refusals), `tests/recovery-flow.test.ts` (rebuilds the
enable transaction offline with the same hash and verifies the spend's assertion over its recomputed sighash from
`tests/fixtures/recovery-enable.json`).

## Manual steps with a real JoyID

The cloud can't use a passkey. To repeat with one (testnet.joyid.dev, an account created with a passkey):

1. Run this branch's reference app locally against a local API and testnet. Connect CCC's JoyID signer
   (`new JoyId.CkbSigner(client, name, icon)` from `@ckb-ccc/joy-id`) and call
   `useCkbWallet().recovery.createJoyIdBackup(signer)`. Check: the JoyID page shows the KeyWay challenge text; the
   proof is accepted at preview; `JSON.parse(proof.identity)` is `{ keyType: "main_key", publicKey }` (64 bytes)
   and the signature JSON has `alg: -7`. Note the authenticatorData flags (expect `0x05`) and the clientDataJSON
   keys (Chrome adds `other_keys_can_be_added_here` at random; Android may add `androidPackageName`).
2. Turn recovery on with it, or `recovery.addBackup(proof)` on an account that has recovery. Check the email names
   the JoyID backup, and that `readRecoveryList(client, recovery)` lists it with auth
   `0xfd ‖ blake160(preimage)` whose last 20 preimage bytes are the JoyID address args after `0x0001`.
3. Build a transaction spending one of the account's Omnilock cells (any output) and call
   `signRecoverySpendWithJoyId(tx, { client, lock, list: list.entries, entry, adminList: list.cell.outPoint }, signer)`.
   **Record exactly what JoyID shows** for `CKB transaction: 0x…` (whole text, truncated, or a hex blob), and on
   which devices. Check there is one passkey prompt (a second one means the assertion exceeded 768 bytes; note its
   length). Dry-run with `client.sendTransactionDry(tx)` and send it.
4. If a real assertion is rejected, the dry run's error code says why: 104 (no user presence), 105 (clientDataJSON
   shape), 106 (type), 107 (challenge), 109 (signature). Keep the assertion (it has no secret) for a test vector.
5. Negative: a JoyID account's device added through "add device" must be refused with the sub-key message; a
   session key, if JoyID offers one, with the session-key message.
6. Mainnet needs its own deployment of `contracts/build/joyid-webauthn` (same bytes, same code hash) and its
   cell dep in `joyIdVerifierCellDep`.

## Open points

- What JoyID's sign-message page shows for the 83-byte text is unconfirmed (manual step 3). If it doesn't show
  the text, the user signs blind, as with an EVM wallet showing the same text; the protection is that a signature
  works for that one transaction only.
- User verification isn't required on chain; JoyID's own page asks for it and the real assertions seen have it.
  Requiring it would be a one-line change to the verifier and a redeploy (a new code hash, so new backup auths).
- Sub keys are refused. Supporting them would mean verifying JoyID's CoTA SMT proof for the key against the CoTA
  cell on chain at setup.
