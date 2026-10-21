# Omnilock opt-in recovery: testnet spike results

Run on CKB testnet on 2026-10-21 with throwaway keys K, B1 and B2 (`spike/keys.json`, gitignored). Funded by a
single faucet claim of 10000 CKB to K's secp address. Every transaction below was dry-run with
`test_tx_pool_accept` before `send_transaction`, and the script waited for `committed` before moving on.

| Step | Result | Transaction(s) |
|---|---|---|
| 1. Turn recovery on | **PASS** | `0x20347d6b23628eaa485ab1203ef1094f0a787a0c2361b63349705077167aab5d` |
| 2. Everyday owner spend | **PASS** | `0x6aeb4ddb970b5a35016e56296fc615ab230134c41b0935a0f5515f108783b326` |
| 3. Backup spend (B1) | **PASS** | `0x1c24c8af49d55f3b82937ae869ab175c45d5e56a7a26950074014bda94028186` |
| 4. Add B2, same address, spend with B2 | **PASS** | rotate `0x8826e6ea56a2505e01b7a6e2ad4a4de5616d14772490c0b0949e3f7ec90e89db`, B2 spend `0x8d1652c59ee4f7c91587e10c190fb444ef96f8ecc510bd4bf2f890352c24a821` |
| 5. Old-address deposit + sweep | **PASS** | deposit `0x6358edd00f9a050d3334228111d729d58ed0fc3b7bde51b1e0b97c42683eba76`, sweep `0xd768a68bac9bb11819f9ef2e1ac72df49f9b3d479dca3d462b4c50fd38c33562` |
| 6. Fiber funding fee (stretch) | **PASS (confirmed: short at 1000, clears at 1500)** | dry runs only, see below |
| Negative checks | all rejected as expected | dry runs only, see below |

Addresses:

- K old secp: `ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqv82scyl0ywuurakhc80ha0agm5x8ye8kca6zq0u`
  (empty after step 5)
- K Omnilock: `ckt1qrejnmlar3r452tcg57gvq8patctcgy8acync0hxfnyka35ywafvkqgqsa2rqnau3mns0k6lqa7l4l4rwscuny7mqyr9qu7g4e55p4pqqmx6x7clx8kny2yg2hujjvykrlnc3vvkhvmdx0k2zdy`
  (about 7000 CKB left in 3 cells, including the AdminList)

## How to rerun

```sh
npm ci                                       # repo root
(cd research/omnilock/spike/smt-rs && cargo build --release)
npx tsx research/omnilock/spike/faucet.ts K  # creates keys.json on first run, then claims 10000 CKB
npx tsx research/omnilock/spike/step1-enable.ts
npx tsx research/omnilock/spike/step2-owner.ts
npx tsx research/omnilock/spike/step3-backup.ts B1
npx tsx research/omnilock/spike/step4-add-backup.ts
npx tsx research/omnilock/spike/step3-backup.ts B2
npx tsx research/omnilock/spike/step5-sweep.ts
npx tsx research/omnilock/spike/negative.ts       # dry runs only
npx tsx research/omnilock/spike/step6-fiber-fee.ts # dry runs only
```

`spike/state.json` holds non-secret progress (Omnilock args, AdminList Type ID args, SMT roots, hashes) so steps
can run separately. `spike/txlog.md` is the raw transaction log. `spike/lib.ts` has the reusable pieces
(`signOmnilockOwner`, `signOmnilockAdmin`, witness encoding, SMT wrapper). `sweepOldAddress` is in
`spike/step5-sweep.ts`.

## SMT implementation

The Rust reference tool in `spike/smt-rs` (crate `sparse-merkle-tree` 0.6.1, blake2b with personalisation
`ckb-default-hash`, compiled proofs). Rust was available, so I did not write a TypeScript port. The TS code calls
the binary via `execFileSync` (`smtBuild` in `lib.ts`). The proofs it produced were accepted on-chain for a
1-member tree (step 3) and a 2-member tree (step 4b). A stale proof from the old 1-member root was rejected
against the new root (negative check 1).

## Exact byte layouts used

**Omnilock lock script:** `code_hash 0xf329effd1c475a2978453c8600e1eaf0bc2087ee093c3ee64cc96ec6847752cb`,
`hash_type type`. Args (54 bytes):

```
00                                         auth flag: secp256k1/blake160
8754304fbc8ee707db5f077dfafea37431c993db   blake160(K compressed pubkey), same as K's secp args
01                                         omnilock flags: administrator mode only
065073c8ae6940d42006cda37b1f31ed32288855f92930961fe788b196bb36d3   AdminList type script hash
```

**Cell deps for an Omnilock input** (from CCC `KnownScript.OmniLock`, testnet). There are **two**:

- `0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37:0` `dep_group`. Its 76-byte data lists the
  genesis outpoints `0x8f8c79eb…635c9f:3` and `:1` (secp256k1 data and sighash code).
- `0xec18bf0d857c981c3d1f4e17999b9b90c484b303378e94de1a57b0872f5d4602:0` `code`. This is the Omnilock binary,
  located through its Type ID (args `0x761f51fc…a89144`). `addCellDepsOfKnownScripts` resolves it at run time.

**AdminList cell** (output 0 of step 1, recreated at output 0 of step 4a):

- `type` = Type ID (`0x00…545950455f4944`, `type`), args `0x3e4768432d91e76c3774ce0d9f23986f78e12d692aa92a4ed1712f593395ac95`
  = `hashTypeId(input0, 0)`. Its script hash is the 32 bytes in the Omnilock args.
- `lock` = K's Omnilock (the same address, so changing the AdminList is an owner-path spend).
- `data` = `RCData` union, item 0 (`RCRule`), 37 bytes: `00000000 ‖ smt_root(32) ‖ 02`.
  - step 1, {B1}: `0x00000000 0c88ee78ec4fa257f90022c7a770030bf58e4e97973921c2f2372b5029fc4486 02`
  - step 4a, {B1,B2}: root `0x0f299f4a8f333225116cbf1688f9a609c2139f31019bd0c5e7fce76abee1aa11`
- capacity: exactly the occupied size, 8 + 87 (lock) + 65 (type) + 37 (data) = **197 CKB**.
- Step 4a added `KnownScript.TypeId` cell deps (the list is empty because Type ID is built in) and kept the same
  `cellOutput` (lock, type, capacity), changing only the data. The fee came from a second Omnilock input in the
  same lock group, so there is one witness and one signature.

**SMT leaf:** key = `00 ‖ blake160(backup pubkey) ‖ 00×11`, value = `01 ‖ 00×31`. This matches
`smt_verify_identity` in `c/omni_lock.c`, which builds `key[0] = id->flags; memcpy(key+1, id->id, 20)`.

**Owner witness lock (85 bytes)**, `OmniLockWitnessLock { signature: Some(65), omni_identity: None, preimage: None }`:

```
55000000 10000000 55000000 55000000 | 41000000 <r(32) s(32) recid(1)>
```

The full witness (WitnessArgs with only `lock`) is 105 bytes: `69000000 10000000 69000000 69000000 55000000 <85-byte lock>`.

**Admin witness lock**, `{ signature: Some(65), omni_identity: Some(Identity{ identity: Auth(21), proofs: [SmtProofEntry{mask:3, proof}] }), preimage: None }`.
Step 3 (B1, 1-member tree, proof `0x4c4f00`, 3 bytes) gave **146 bytes**:

```
92000000 10000000 55000000 92000000          table header: total, 3 offsets
41000000 <65-byte sig>                        signature: Bytes
3d000000 0c000000 21000000                    Identity table header
  00 79af2d8dbb19362ec15a4acc3c026c2386e0ffa2 identity: Auth(21) = 00 ‖ blake160(B1)
  1c000000 08000000                           SmtProofEntryVec (dynvec, 1 item)
    14000000 0c000000 0d000000 03             SmtProofEntry: mask = 3
    03000000 4c4f00                           proof: SmtProof (fixvec)
                                              preimage: None (0 bytes)
```

Step 4b (B2, 2-member tree, proof 71 bytes) gave 214 bytes. The proof length depends on the tree, so the
admin placeholder has to be built from the real proof.

**Signing digest:** CCC's `tx.getSignHashInfo(lock, client)` matches Omnilock's `generate_sighash_all`
(blake2b-256 ckb personalisation over tx_hash, then for each group witness and each extra witness the u64-LE
length followed by the bytes, with the first group witness's `lock` zeroed). The placeholder written before
hashing is the whole final lock length of zeros (85 for owner, 146 or 214 here for admin). The signature is
`r ‖ s ‖ recid`. `localSignDigest` returns `{r, s, recoveryParam}` in the same shape as
`lit-actions/sign-ckb-digest.js`, so `signOmnilockOwner(tx, lock, signDigest)` can take the Lit action as is.
(The function also takes `lock`, because a transaction may contain more than one lock group.)

## Measured sizes and cycles (fee rate 1500 shannons/KB)

| Tx | Size (bytes, in block) | Fee (shannons) | Cycles (dry run) |
|---|---|---|---|
| step 1, secp in, AdminList + Omnilock out | 654 | 981 | 2,638,457 |
| step 2, owner, 1 in 3 out | 732 | 1,098 | 1,425,911 |
| step 3, admin B1 | 510 | 765 | 1,503,566 |
| step 4a, AdminList rotate | 755 | 1,133 | 2,393,827 |
| step 4b, admin B2 | 578 | 867 | 1,548,150 |
| step 5a, owner deposit to old address | 555 | 833 | 1,416,022 |
| step 5b, secp sweep | 389 | 584 | 1,629,328 |

## Negative checks (dry run only, `spike/negative.ts`, output in `spike/negative.out`)

| Case | Result |
|---|---|
| B1 with the stale proof for the old {B1} root, against the {B1,B2} AdminList | rejected, Omnilock error 59 (`ERROR_NOT_ON_WHITE_LIST`) |
| Outsider key signing with B1's identity and a valid proof | rejected, error -31 (`ERROR_IDENTITY_PUBKEY_BLAKE160_HASH`) |
| Valid B1 admin witness with no AdminList cell dep | rejected, error 1 (RC cell not found in deps or inputs) |
| Owner signature computed over a 65-byte zero placeholder, then sent with the 85-byte lock | rejected, error -31 |
| Bare 65-byte secp signature as the witness lock (plain secp style) | rejected, error 5 (witness lock is not a valid `OmniLockWitnessLock`) |
| Control: the same transaction signed correctly with `signOmnilockOwner` | accepted |

## Step 6: Fiber v0.9.1 funding fee

Source: `crates/fiber-lib/src/ckb/funding/funding_tx.rs` at tag v0.9.1, which uses ckb-sdk 5.1.0.

- `build_and_balance_tx` (around line 571) uses `CapacityBalancer::new_simple(sender, secp_sighash_placeholder_witness(), funding_fee_rate)`.
  That placeholder is `WitnessArgs { lock: Some(65 zero bytes) }`, an 85-byte witness.
- ckb-sdk's balancer sets `fee = FeeRate(rate).fee(serialized_size_in_block)`, which is `size * rate / 1000`
  rounded down. The pool requires `fee >= 1000 * weight / 1000`, where the weight here is the size.
- **There is a second shortfall the README doesn't mention.** `ExternalFundingCellDepResolver` resolves only the
  **first** entry of `funding_source_lock_script_cell_deps` while balancing. `with_extra_cell_deps` appends the
  rest **after** balancing (`build`, line 701). Omnilock needs two cell deps (dep group + code), so the
  transaction grows by another 37 bytes after the fee has been fixed.
- Total growth after balancing: +20 bytes for the witness (105-byte Omnilock witness against the 85-byte secp
  placeholder) plus +37 bytes for the second cell dep, so +57 bytes.

Dry run of a funding-shaped transaction (1 Omnilock input, a 1000 CKB stand-in funding output, Omnilock
change), balanced exactly as above (`spike/step6-fiber-fee.ts`, output in `spike/step6.out`):

| Rate | Deps during balancing / added after | Estimated size | Actual size | Fee | Node minimum | Result |
|---|---|---|---|---|---|---|
| 1000 | 1 / 1 (what Fiber does) | 498 | 555 | 498 | 555 | **REJECTED** `PoolRejectedTransactionByMinFeeRate` |
| 1500 | 1 / 1 | 498 | 555 | 747 | 555 | **ACCEPTED** |
| 1000 | 2 / 0 (witness gap only) | 535 | 555 | 535 | 555 | **REJECTED** |
| 1500 | 2 / 0 | 535 | 555 | 802 | 555 | **ACCEPTED** |

Conclusion: at Fiber's default 1000 shannons/KB, an Omnilock-funded external funding transaction is always below
the minimum. The shortfall is 57 shannons (20 if both deps were present while balancing). At 1500 it clears
whenever the estimated size is at least 114 bytes, which every real transaction is. Any rate of at least
`1000 × (est + 57) / est` works. So KeyWay should pass `funding_fee_rate >= 1500` (or pad the fee) for Omnilock
funding sources. Another option is a single dep-group cell dep containing secp data, secp code and the Omnilock
code, which would leave only the 20-byte witness gap.

## Gotchas

1. **The 85-byte placeholder is required.** A signature over a 65-byte zero placeholder fails with -31, and so
   does every other length. The digest covers the witness length and its zeroed bytes.
2. **Admin placeholders depend on the proof.** Build the real `Identity` (auth and proof) first, then zero the
   whole serialized lock. Proof size grows with the tree (3 bytes for 1 member, 71 bytes for 2).
3. **Proofs go stale when the AdminList changes.** After step 4a, B1's old proof fails with
   `ERROR_NOT_ON_WHITE_LIST`. Whoever builds a backup transaction needs the **full current member list** to
   rebuild the tree and generate a fresh proof. The root alone isn't enough. Keep the member list off-chain
   (API or DB) and check that it hashes to the on-chain root, as `step3-backup.ts` does. Alternatively, put the
   key list in the AdminList cell data alongside the RCRule.
4. **Find the AdminList by Type ID, not by outpoint.** Its outpoint changes on every rotation.
   `client.findSingletonCellByType(typeIdScript)` works.
5. **The AdminList is locked by the Omnilock**, so changing it is an owner-path spend. Because
   `rcrules_in_input_cell = true`, a backup could also spend (and rewrite) the AdminList through the admin path,
   where the RC cell is found among the inputs. That wasn't exercised here. It matters for the threat model,
   because a backup can replace the backup list. Lock the AdminList differently if that isn't wanted.
6. **The Type ID depends on input 0.** Pick the input before computing the Omnilock args, and check that input 0
   didn't move after `completeInputsByCapacity`. `step1-enable.ts` checks both this and the address.
7. **CCC's `ClientPublicTestnet()` defaults to `wss://testnet.ckb.dev/ws`, which keeps Node running after the
   script finishes.** Using `{ url: "https://testnet.ckb.dev/" }` lets scripts exit.
8. **CCC's `findCellsByLock` returns the AdminList as well**, because it has the same lock. Filter it out (no
   type, empty data) before using Omnilock cells as plain capacity, or a spend would consume the AdminList.
9. **The pool's error message says "shannons/KW"** (weight), not KB. Weight is the larger of size and
   cycles × bytes-per-cycle. At about 1.4–2.6M cycles that's well under the size, so size is what counts here.

## What in the README was wrong or incomplete

- **Step 6 understates the gap.** The witness gap is real (20 bytes: a 105-byte witness against Fiber's 85-byte
  secp placeholder witness), but Fiber also appends every funding-source cell dep after the first one *after*
  balancing. Omnilock needs two deps, so that adds another 37 bytes. The headline conclusion still holds:
  short at 1000, clears at 1500.
- **Recipe, cell deps:** it's worth saying explicitly that Omnilock needs two cell deps: the
  `0xf8de3bb4…ee5d37:0` dep group (secp256k1 data) as well as the `0xec18bf0d…5d4602:0` code cell. The README
  mentions only the code cell. Using the full `KnownScript.OmniLock` dep list works.
- **"85-byte Omnilock witness" (step 6)** means the witness *lock*. The serialized witness is 105 bytes.
- **Step 2's `signOmnilockOwner(tx, signDigest)` signature:** the helper also needs the lock script (or has to
  find it), because transactions can mix lock groups. The spike's helper is `signOmnilockOwner(tx, lock, signDigest)`.
- Everything else in the recipe was correct as written: the 54-byte args layout, the Type ID args from
  `hashTypeId(input0, outputIndex)`, `RCRule` flags `0x02`, the SMT key and value layout, `mask = 3` with one
  proof per rule, the 85-byte owner lock header bytes, and zeroing the lock at its final length.
