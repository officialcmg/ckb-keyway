# Omnilock opt-in recovery: testnet spike

Research for an optional account-recovery mode. By default a KeyWay account keeps today's
secp256k1-blake160 lock. A user who turns recovery on moves, in one transaction paid from their own
funds, to an Omnilock address in administrator mode whose AdminList holds their backup signers. After
that, adding or removing a backup only rewrites the AdminList, so the address never changes again.

This folder is a spike, not product code. It proves the on-chain mechanics on **CKB testnet** with
throwaway keys before anything is built into the SDK or the API.

## Recipe

**Omnilock lock** (testnet): `code_hash` and cell deps from CCC `KnownScript.OmniLock`
(`0xf329effd…52cb`, `hash_type: type`; code cell `0xec18bf0d…5d4602:0`, resolve it at run time).

**Args, 54 bytes, fixed when recovery is turned on:**

| Offset | Bytes | Value |
|---|---|---|
| 0 | 1 | `0x00` (auth: secp256k1 / blake160) |
| 1 | 20 | blake160(owner compressed public key), the same 20 bytes as today's secp lock args |
| 21 | 1 | `0x01` (Omnilock flags: administrator mode only) |
| 22 | 32 | AdminList cell **type script hash** (Type ID script, args `hashTypeId(input0, outputIndex)`) |

With flags `0x01`, `parse_args` (`c/omni_lock.c` in cryptape/omnilock) requires exactly 54 bytes.

**AdminList cell:** `type` = Type ID, `lock` = the owner's new Omnilock, `data` = `RCData` holding
`RCRule { smt_root: Byte32, flags: 0x02 (whitelist) }` (`c/xudt_rce.mol`). Adding a backup spends the
cell and recreates it with the same Type ID and a new `smt_root`, so the address doesn't change.

**SMT:** key = `auth flag (1) ‖ 20-byte id ‖ 11 zero bytes`, value = `0x01 ‖ 31 zero bytes`,
blake2b personalised `ckb-default-hash`, compiled proof format of nervosnetwork/sparse-merkle-tree;
proof mask is 3, with one proof per RC rule. `spike/smt-rs` is a reference tool (Rust crate
`sparse-merkle-tree` 0.6.1): `cargo build --release`, then `target/release/smt-ref <key32hex>...` prints
`{root, proofs}` and self-verifies each proof. There is no maintained JS/TS CKB-SMT library on npm.

**Owner path (every day):** witness lock = `OmniLockWitnessLock { signature: Some(65 bytes),
omni_identity: None, preimage: None }`, exactly 85 bytes (`55000000 10000000 55000000 55000000 41000000 ‖
sig`). The digest is the usual sighash-all with the **whole witness `lock` zeroed at its final length**
(`generate_sighash_all`, `c/ckb_identity.h`), so the placeholder must be 85 zero bytes, not 65. No
AdminList cell dep and no SMT proof. KeyWay signs a 32-byte digest and gets `{r, s, recoveryParam}`
back (see `lit-actions/sign-ckb-digest.js`); the signature is `r ‖ s ‖ recid` (65 bytes).

**Backup path:** witness lock = `{ signature, omni_identity: { identity: 21-byte auth of the backup,
proofs: [{ mask: 3, proof }] }, preimage: None }`. The AdminList goes in cell deps (or inputs when the
same transaction updates it). The placeholder must be as long as this whole final lock, zeroed.

## Steps to prove (record every transaction hash)

1. **Turn recovery on.** From a normal secp address (key K, standing in for the account's Lit key), in
   ONE transaction signed only with K's normal secp signature: input 0 is one of K's cells; outputs are
   the AdminList (SMT root already containing backup B1, auth `0x00` with a second throwaway key) and
   all remaining CKB to K's new Omnilock address. Check the address computed before broadcast matches.
2. **Everyday owner spend.** Spend from the Omnilock address with K through the digest path above,
   written as a reusable `signOmnilockOwner(tx, signDigest)` where `signDigest(digest32)` returns
   `{r, s, recoveryParam}`. No AdminList dep.
3. **Backup spend.** Spend an Omnilock cell with B1 via the admin path (identity + SMT proof, AdminList as
   a cell dep).
4. **Add a second backup without changing the address.** K spends and recreates the AdminList with B1
   and B2 in the root (same Type ID). Confirm the args/address are unchanged, then spend with B2.
5. **Old-address sign-in check.** Send CKB to K's old secp address after the switch, then run
   `sweepOldAddress(K, newOmnilockLock)` to move everything there to the Omnilock address.
6. **Stretch: Fiber funding fee.** In Fiber v0.9.1 (`nervosnetwork/fiber`, tag `v0.9.1`,
   `crates/fiber-lib/src/ckb/funding/funding_tx.rs`), the external-funding balancer sizes the transaction
   with a 65-byte secp placeholder at a default fee rate of 1000 shannons/KB (the node minimum).
   Show by size math (or a `test_tx_pool_accept` dry run of a funding-shaped transaction) whether the
   85-byte Omnilock witness falls under the minimum at 1000 and clears it at 1500.

## Rules

- Testnet only. Generate throwaway keys K, B1 and B2 into `spike/keys.json` (gitignored, never printed,
  never committed). They hold only faucet CKB.
- Faucet: `POST https://faucet-api.nervos.org/claim_events` with
  `{"claim_event":{"address_hash":"<ckt1 address>","amount":"10000"}}` (only `"10000"` works; it takes a
  minute or two; at most about three claims). Public RPC via CCC `ClientPublicTestnet`. Explorer:
  `https://testnet-api.explorer.nervos.org/api/v1/transactions/<hash>` with Accept and Content-Type
  `application/vnd.api+json`. Dry-run with `test_tx_pool_accept` before each `send_transaction`.
- Spike code goes in `spike/` (TypeScript or `.mjs`, using `@ckb-ccc/core` and `@noble/*` from the repo's
  dependencies). Don't change `src/`, `server/`, `app/` or anything outside `research/omnilock/`.
- If a step fails after a reasonable effort, record why and continue with the next independent step.

## Results

Write `results.md` here: PASS or FAIL per step, transaction hashes, exact byte layouts used, gotchas,
which SMT implementation you used, and anything in this README that turned out wrong.
