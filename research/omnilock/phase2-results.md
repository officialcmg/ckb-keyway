# Omnilock opt-in recovery, phase 2: turning recovery on — testnet results

**EVM backups now use Omnilock auth flag 0x12 (EthereumDisplaying)**, not 0x01; see "EVM backups use flag 0x12"
below for the rule and its testnet proof. The first run below used flag 0x01 and is kept as a record; its
transactions and keys are superseded (the fixture and `phase2/state.json` now hold the 0x12 run).

First run (flag 0x01), on CKB testnet on 2026-10-28 with throwaway keys (`phase2/keys.json`, gitignored, never printed): **K** stands in
for the account's Lit key, **E** is an EVM backup. Funded by one faucet claim of 10000 CKB to K's secp256k1 address.

| Step | Result | Transaction |
|---|---|---|
| 1. Turn recovery on through the server's own flow (`recoverySetup`: preview → request-email-code → enable) | **PASS** | `0x250e0b50785082de4819b618251aa4c1d6148c36fb5bb1379488edfaa0911af4` |
| 2. Spend from the new Omnilock address via the admin path, signed only by the EVM backup E (flag 0x01) | **PASS** | `0x7597ed3d13d4e1a0f7293e67fb02fc16b479d265e634e3d6625fb14b5737ac66` |
| Negative dry runs (`phase2/negative.ts`, output in `phase2/negative.out`) | as expected | dry runs only |

Both transactions were dry-run with `test_tx_pool_accept` before `send_transaction` and waited on until committed.

Addresses:

- K legacy secp256k1: `ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsq2lhgcyrjawzpyxt207tadtec4s25v5qws2m4yxa`
  (holds the 1000 CKB the EVM spend sent back)
- K Omnilock: `ckt1qrejnmlar3r452tcg57gvq8patctcgy8acync0hxfnyka35ywafvkqgqt7arqswt4cgysedfle04408zkp23jsp6q9m6ce882njzytzc2y4u6jxfh8zlz5zwuw8zu96tplhqg9zsgal0w0dq5n9`
- EVM backup E: `0x2918d5553eec5967e4fcc79a07577f96ee23d3b3`

## Step 1: what the server built and checked

`step1-enable.ts` runs `src/server/recovery.ts` unchanged, with a local Postgres for the approval and email-code
tables, K's local key in place of the Lit action, and the emailed code read from the captured email.

- Preview: input 0 = K's only cell (10000 CKB). AdminList Type ID args `0x322bb9f6…2d49` = `hashTypeId(input0, 0)`, type
  hash `0x77ac64e7…7ef7`; Omnilock args `0x00 ‖ 5fba3041…4074 ‖ 0x01 ‖ 77ac64e7…7ef7` (54 bytes). Locks 197 CKB
  (AdminList), minimum plain cell 95 CKB, fee 0.00000981 CKB (654 bytes at 1500 shannons/KB), 9802.99999019 CKB moved.
- The email named the backup ("Backup: EVM wallet 0x2918d555…23d3b3"), the new address, the CKB locked, the fee and
  "Your address will change because you're turning on recovery."
- E's ownership proof: EIP-191 personal_sign of `recoveryBackupChallenge(legacyAddress, backup)`, verified server-side.
- Enable rebuilt the transaction from the chain, matched it to the previewed digest, verified the code, ran
  `checkRecoveryTransaction`, signed the secp256k1 group (65-byte witness lock), broadcast, and stored
  `wallet.recovery` (with `legacyAddress` and `backups`) and the new `ckbAddress`. The broadcast address equals the
  previewed one. 2,658,116 cycles.
- `tests/fixtures/recovery-enable.json` recorded this transaction and its input; `tests/recovery-flow.test.ts`
  rebuilt it offline with `planRecovery` and got the same hash. (It now records the 0x12 run instead.)

## Step 2: EVM backup spend (admin path, auth flag 0x01, superseded by 0x12)

- Input: the 9802.99999019 CKB Omnilock cell. Outputs: 1000 CKB to K's legacy address, change to the Omnilock.
  Cell deps: the AdminList (`code`) and CCC's `KnownScript.OmniLock` deps. 1,580,046 cycles, 653 bytes, fee 980.
- Witness lock (146 bytes) = `OmniLockWitnessLock { signature: Some(65), omni_identity: { identity: 0x01 ‖ E's
  address, proofs: [{ mask: 3, proof: 0x4c4f00 }] }, preimage: None }` (`omnilockAdminWitnessLock`).
- Signing rule (cryptape/omnilock `c/ckb_identity.h`, `IdentityFlagsEthereum` → `convert_eth_message` +
  `validate_signature_eth`): the sighash (whole witness lock zeroed at its final length, as for the owner path) is
  wrapped as `keccak256("\x19Ethereum Signed Message:\n32" ‖ sighash)`, i.e. a wallet's `personal_sign` of the raw 32
  bytes; the signer is recovered from an uncompressed key and must equal `keccak256(pubkey)[12..32]`. The 65-byte
  signature is `r ‖ s ‖ recid` with recid 0/1 (`secp256k1_ecdsa_recoverable_signature_parse_compact`), so a wallet's
  v of 27/28 has 27 subtracted (`evmOmnilockSignature`). This is what CCC's `SignerEvm` does for its old 0x01 address.
- The member list ({E}) was rebuilt with the TypeScript SMT and checked against the on-chain AdminList data.

## Negative dry runs

| Case | Result |
|---|---|
| Control: E signs as E | accepted |
| Outsider EVM key signs with E's identity and E's valid proof | rejected, error -31 (`ERROR_IDENTITY_PUBKEY_BLAKE160_HASH`) |
| Outsider with its own identity and a proof from a tree that contains it | rejected, error 59 (`ERROR_NOT_ON_WHITE_LIST`) |

## EVM backups use flag 0x12

Re-run on CKB testnet on 2026-10-28 with fresh throwaway keys (`phase2/keys.json`, gitignored, never printed), one
faucet claim of 10000 CKB to K, the same scripts (`step1-enable.ts`, `step2-evm-spend.ts`, `negative.ts`).

| Step | Result | Transaction |
|---|---|---|
| 1. Turn recovery on through `src/server/recovery.ts` (preview → request-email-code → enable) with an EVM backup | **PASS** | `0xe1536bd605120ed82d8fd811e9607f71e2622a77b6ebd154cfb2222c4599b4c1` |
| 2. Spend from the new Omnilock address via the admin path, signed only by E with personal_sign of the 0x12 display text | **PASS** | `0x5ec745a9a9d14e1450b05d77aecc67972afa2fa6e33dd453dfb6ad4babc5c70c` |
| Negative dry runs (`phase2/negative.out`) | as expected | dry runs only |

Both were dry-run with `test_tx_pool_accept` first and waited on until committed.

- K legacy secp256k1: `ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqwzph0p9nqy43vlug730xutjwsj76zmevqvwumzl`
- K Omnilock: `ckt1qrejnmlar3r452tcg57gvq8patctcgy8acync0hxfnyka35ywafvkqgqcgxauykvqjk9nl3r69um3wf6ztmgt09sqx58nlayt44pn68wkxy59mqavl8clfwdkp2pfuzyvgmgnvks9y3877jr09f`
- EVM backup E: `0x9da2a006d667e6d4c15c909ba9f93b64d7dc31d5`; its auth / SMT member is `0x12 ‖ E`.
- Enable: same shape as the 0x01 run (input 10000 CKB, 197 CKB AdminList, fee 0.00000981 CKB, 9802.99999019 CKB
  moved, 654 bytes), 2,639,487 cycles. AdminList Type ID args `0x937f0505…7a61`, type hash `0xa879ffa4…227f`.
- Spend: 1000 CKB back to K's legacy address, change to the Omnilock; 1,562,167 cycles, 653 bytes, fee 980, witness
  lock 146 bytes (same layout as 0x01; only the identity flag and the signed message differ). E signed
  `CKB transaction: 0x8abcd5c249972e8c3b1dedf9e1b4d99ff410620bb6d7d01fee816c42d222a89d`.

**Signing rule** (cryptape/omnilock `c/ckb_identity.h`: `IdentityFlagsEthereumDisplaying = 18` →
`verify_sighash_all(…, validate_signature_eth, convert_eth_message_displaying)`):

- The sighash is computed as for every other flag (whole witness lock zeroed at its final length).
- `convert_eth_message_displaying` hex-encodes the 32-byte sighash with a lowercase table (`bin_to_hex`) and hashes
  `keccak256("\x19Ethereum Signed Message:\n83" ‖ "CKB transaction: 0x" ‖ 64 hex digits)`. So the wallet
  personal_signs the UTF-8 text `CKB transaction: 0x<sighash in lowercase hex>`, 83 bytes, **with** the `0x`. (The
  header comment `COMMON_PREFIX_LEN = 17` is wrong; the prefix is 19 bytes and the code uses 83.)
- `validate_signature_eth`: recover the uncompressed public key from the 65-byte `r ‖ s ‖ recid` signature (recid
  0/1, so a wallet's v of 27/28 has 27 subtracted, `evmOmnilockSignature`), take `keccak256(pubkey)[12..32]` and
  compare it with the identity's 20 bytes; a mismatch is `ERROR_IDENTITY_PUBKEY_BLAKE160_HASH` (-31).
- CCC 1.16.1 `SignerEvm` agrees: its 0x12 Omnilock address (`0x12 ‖ account ‖ 0x00`) is signed with
  ``signMessageRaw(`CKB transaction: ${info.message}`)`` (`info.message` is CCC's lowercase 0x hex), v reduced
  by 27. `tests/recovery-backups.test.ts` checks that CCC's signer signs exactly `evmOmnilockMessage(sighash)` and
  writes the same signature.
- Code: `evmBackupAuth` uses `OMNILOCK_AUTH_ETHEREUM_DISPLAYING = 0x12`; `evmOmnilockMessage(sighash)` gives the text
  to personal_sign; `evmOmnilockDigest` is its personal_sign hash. The ownership proof is unchanged: EIP-191
  personal_sign of `recoveryBackupChallenge`.

Negative dry runs:

| Case | Result |
|---|---|
| Control: E signs the 0x12 display text | accepted |
| E personal_signs the raw 32-byte sighash (the 0x01 rule) under 0x12 | rejected, error -31 (`ERROR_IDENTITY_PUBKEY_BLAKE160_HASH`) |
| Outsider EVM key signs with E's identity and E's valid proof | rejected, error -31 |
| Outsider with its own identity and a proof from a tree that contains it | rejected, error 59 (`ERROR_NOT_ON_WHITE_LIST`) |

`tests/fixtures/recovery-enable.json` now records these two transactions; `tests/recovery-flow.test.ts` rebuilds the
enable transaction offline (hash `0xe1536bd6…b4c1`) and recovers E from the spend's signature over the display text.

## TypeScript SMT

`src/sdk/browser/recovery-smt.ts` ports nervosnetwork/sparse-merkle-tree 0.6.1 (no "trie" feature): `update`, the
compiled proof (opcodes 0x4C/0x50/0x51/0x48/0x4F) and its root computation. Checked against the spike's Rust tool
(`spike/smt-rs`) on 72 random trees of 1–12 keys, single- and multi-key proofs, and against the spike's on-chain roots
(smtRoot1 `0x0c88ee78…4486` for {B1}, smtRoot2 `0x0f299f4a…aa11` for {B1,B2}; B1's and B2's auths read from their
on-chain witnesses) and B2's on-chain 71-byte proof. Vectors: `tests/fixtures/recovery-smt-vectors.json`.

## JoyID backups

Encoding: **owner-lock mode, auth flag 0xFC, id = the first 20 bytes of the JoyID lock script hash** (not blake160 of
it: the lock hash is already a blake2b hash, and `is_lock_script_hash_present` compares its first 20 bytes). Unlock
rule (`c/omni_lock.c` + `ckb_identity.h`): Omnilock takes the identity from the witness, checks its SMT proof against
the AdminList, then for flag 0xFC only checks that **some input of the same transaction has that lock script hash**. No
signature is needed in the Omnilock witness (`signature: None`); the JoyID input's own lock (passkey signature over its
sighash) is what authorizes. Only JoyID main keys (lock args `0x0001 ‖ blake160(64-byte secp256r1 public key)`,
confirmed against @joyid/ckb's own test data) are accepted; sub keys need JoyID's CoTA cells to resolve and are
refused. Ownership proof: CCC's JoyID signer `signMessage(challenge)`; the server checks `ccc.verifyMessageJoyId`, that
the key type is `main_key` with ES256, and that the signing public key is the one in the address's lock args. Unit
tests use a P-256 key producing JoyID's WebAuthn assertion shape. A headless on-chain proof isn't possible (it needs a
passkey), so it was not run.

### What a manual JoyID test must check

1. With a testnet JoyID passkey (testnet.joyid.dev) and CCC's `JoyId.CkbSigner` from `@ckb-ccc/joy-id`,
   `useCkbWallet().recovery.createJoyIdBackup(signer)` returns a proof the server accepts at preview. Check the
   identity JSON CCC returns really has `{ keyType: "main_key", publicKey }` with the 64-byte key (with or without
   0x) and the signature JSON has `alg: -7`; a sub-key session must be refused.
2. Turning recovery on with that backup puts SMT key `0xfc ‖ lockHash(JoyID lock)[0..20] ‖ 00×11` in the AdminList.
3. A recovery spend: inputs = the account's Omnilock cell(s) **plus at least one cell locked by the JoyID address**
   (≥ 63 CKB; fund one first); cell deps = Omnilock deps, the AdminList (`code`), JoyID's deps. Write the Omnilock
   group's witness lock first, `omnilockAdminWitnessLock({ auth: 0xfc‖id, proof })` (no signature, 77 bytes for a
   1-member tree), then let the JoyID signer sign its own group. Check the JoyID signer's `prepareTransaction` doesn't
   overwrite the Omnilock witness or reorder inputs, and that the transaction is accepted.
4. Negative: the same transaction without the JoyID input is rejected (`ERROR_IDENTITY_LOCK_SCRIPT_HASH_NOT_FOUND`),
   and a JoyID address that isn't in the list is rejected with error 59.
5. Threat model note for later phases: because the 0xFC rule only needs the JoyID input to be present, anyone who can
   get the JoyID holder to sign *any* transaction containing their JoyID cell alongside the account's Omnilock cell can
   spend the account's cell. The JoyID signing UI shows the whole transaction, but this is weaker than a signature
   bound to the Omnilock's own sighash.

## Gotchas and open points

- The plan is deterministic (cells sorted by out point, input 0 = the largest plain cell), so enable rebuilds it from
  the chain and must hash to the previewed digest; any change in the account's cells since the preview refuses it.
- Token cells move one-to-one with their data. At the 54-byte Omnilock lock a standard xUDT cell needs 176 CKB (was
  142 at secp256k1), so its capacity is raised from the CKB pool. RUSD moves were tested offline only (the faucet
  gives no RUSD); its contract dep is resolved on chain as the settlement sweep does.
- Cells the flow can't move (Nervos DAO, NFTs, unknown types, plain cells with data) stay at the legacy address,
  which remains the account's lock; the preview counts them. More than 60 movable cells is refused.
- General signing and channel funding now refuse any output to an Omnilock with this key's auth other than the
  account's own, so neither can create a recovery list or send funds into an Omnilock someone else's AdminList
  controls.
- EVM flag 0x01 made wallets show the raw 32-byte sighash as hex when signing a recovery spend. Decided and done:
  EVM backups use flag 0x12 (`EthereumDisplaying`, "CKB transaction: 0x…"), the flag CCC's current EVM address
  uses. It changes the auth (so the SMT key and the AdminList root); no backups were in use, so 0x01 was replaced
  outright with no compatibility path. An AdminList built with 0x01 auths isn't recognised by the current code.
- A browser Fiber node started before recovery was turned on keeps funding from the old lock until it restarts.
- Migration 16 only widens a check constraint, so running API processes keep working; as with every earlier
  migration, an old process that *restarts* after it fails `verifySchema` until the new version is deployed.
