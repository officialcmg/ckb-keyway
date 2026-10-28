# Omnilock opt-in recovery, phase 2: turning recovery on — testnet results

Run on CKB testnet on 2026-10-28 with throwaway keys (`phase2/keys.json`, gitignored, never printed): **K** stands in
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
- `tests/fixtures/recovery-enable.json` records this transaction and its input; `tests/recovery-flow.test.ts`
  rebuilds it offline with `planRecovery` and gets the same hash.

## Step 2: EVM backup spend (admin path, auth flag 0x01)

- Input: the 9802.99999019 CKB Omnilock cell. Outputs: 1000 CKB to K's legacy address, change to the Omnilock.
  Cell deps: the AdminList (`code`) and CCC's `KnownScript.OmniLock` deps. 1,580,046 cycles, 653 bytes, fee 980.
- Witness lock (146 bytes) = `OmniLockWitnessLock { signature: Some(65), omni_identity: { identity: 0x01 ‖ E's
  address, proofs: [{ mask: 3, proof: 0x4c4f00 }] }, preimage: None }` (`omnilockAdminWitnessLock`).
- Signing rule (cryptape/omnilock `c/ckb_identity.h`, `IdentityFlagsEthereum` → `convert_eth_message` +
  `validate_signature_eth`): the sighash (whole witness lock zeroed at its final length, as for the owner path) is
  wrapped as `keccak256("\x19Ethereum Signed Message:\n32" ‖ sighash)`, i.e. a wallet's `personal_sign` of the raw 32
  bytes; the signer is recovered from an uncompressed key and must equal `keccak256(pubkey)[12..32]`. The 65-byte
  signature is `r ‖ s ‖ recid` with recid 0/1 (`secp256k1_ecdsa_recoverable_signature_parse_compact`), so a wallet's
  v of 27/28 has 27 subtracted (`evmOmnilockSignature`). This is what CCC's `SignerEvm` does for its 0x01 address.
- The member list ({E}) was rebuilt with the TypeScript SMT and checked against the on-chain AdminList data.

## Negative dry runs

| Case | Result |
|---|---|
| Control: E signs as E | accepted |
| Outsider EVM key signs with E's identity and E's valid proof | rejected, error -31 (`ERROR_IDENTITY_PUBKEY_BLAKE160_HASH`) |
| Outsider with its own identity and a proof from a tree that contains it | rejected, error 59 (`ERROR_NOT_ON_WHITE_LIST`) |

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
- EVM flag 0x01 makes wallets show the raw 32-byte sighash as hex when signing a recovery spend. Flag 0x12
  (`EthereumDisplaying`, "CKB transaction: 0x…") reads better and is what CCC's current EVM address uses; switching
  changes the auth (and so the SMT key) and should be decided before backups are used in production.
- A browser Fiber node started before recovery was turned on keeps funding from the old lock until it restarts.
- Migration 16 only widens a check constraint, so running API processes keep working; as with every earlier
  migration, an old process that *restarts* after it fails `verifySchema` until the new version is deployed.
