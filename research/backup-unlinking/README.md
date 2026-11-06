# Salted backup identities: unlinking a person's accounts across apps

Run on CKB testnet on 2026-11-06 with throwaway keys (`keys.json`, gitignored, never printed). Scripts in this
folder; their output in `*.out`, transaction hashes in `state.json`.

## The problem

Each app gives the same email its own KeyWay account, each with its own Omnilock backup list. A backup's identity
used to be the same in every account: the exec auth `0xFD ‖ blake160(preimage)` whose last 20 bytes (`pubkey_hash`)
were the EVM address or blake160 of the JoyID passkey's public key, and the list record (version 2, in the
enable/change transaction's witness) listed those preimages in clear. Anyone reading the chain could link one
person's accounts in two apps through a shared backup. Hashing the address alone wouldn't help: the hash is the same
in every app.

## Design

**Salt.** `pubkey_hash = blake160(backup ID ‖ salt)`, where the salt is the account's AdminList type hash. It is
unique per account (a Type ID) and sits in the Omnilock args of the lock being unlocked:
`0x00 ‖ blake160(Lit key) ‖ 0x01 ‖ AdminList type hash`.

**The verifier can read it without extra witness data.** Checked in cryptape/omnilock at
`280dd97ac0930ea1ed766a18d49478229347c832`:

- `c/omni_lock.c` `parse_args` loads the running script's args: auth flag (1), id (20), omni-lock flags (1) and,
  with `OMNI_ROOT_MASK`, the 32-byte `omni_root`, that is args[22..54]. On the administrator path
  (`witness_lock.has_identity`) it gathers the RC rules from `args.omni_root` (`rce_gather_rcrules_recursively`) and
  checks the identity's SMT proof against that whitelist (`smt_verify_identity`), then calls
  `ckb_verify_identity`.
- `c/ckb_identity.h` `verify_via_exec` checks the 62-byte preimage's blake160 against the identity, computes the
  group's sighash_all and calls `ckb_exec_cell(code_hash, hash_type, offset, length, 1, argv)` with argv
  `code_hash:hash_type:pubkey_hash:msg:sig`. Nothing runs after it.
- CKB's exec syscall ([RFC 0034](https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0034-vm-syscalls-2/0034-vm-syscalls-2.md))
  replaces the running program but keeps the transaction and script group, so `load_script` in the verifier returns
  the same Omnilock lock, and args[22..54] are exactly the root Omnilock just checked the proof against. The
  verifiers already relied on this for `load_script_hash` (refusing outputs to the account itself).

`keyway_approval::chain::running_account_salt` loads the script into a 107-byte buffer (53 bytes of molecule header,
code hash and hash type, plus 54 bytes of args; `LengthNotEnough` exits 114), parses it with the bounds-checked
`parse_script`, and `account_salt` requires exactly 54 bytes of args with flags `0x01` (administrator mode alone;
supply mode `0x08` also has 54 bytes and is refused), else exit 114. `salted_id(id, salt) = blake160(id ‖ salt)`.

- EVM verifier: `blake160(recovered address ‖ salt) == pubkey_hash`, else 101.
- WebAuthn verifier: `blake160(blake160(public key) ‖ salt) == pubkey_hash`, else 101.

The readable approval text, the sighash binding and every other check are unchanged.

**Record, version 3.** `"KWRL" ‖ 0x03 ‖ count ‖ the members' 21-byte auths`. No address, key hash or verifier.
The rescue page and the SDK compute a connected backup's auth with the account's salt and look for it in the list
(`recoveryListEntry`). The page shows "N backups" and, after connecting, "This wallet is on the list". KeyWay's
server still stores the real backups (its ownership proofs and the DB list) for the UI and emails, and checks that
they give exactly the recorded auths before a list change.

**What it doesn't hide.** The salt is public. Someone who already knows a backup's ID (an EVM address is public on
its own chain; a JoyID address shows its key hash) can compute its auth for any account and check whether it's on
that account's list. Scanning every KeyWay account for a known address this way is cheap. Hiding membership from
that would need a secret salt, which the rescue page couldn't rebuild without KeyWay. A rescue also reveals the
backup that signed it: an EVM signature recovers to the address, and the WebAuthn blob carries the public key.
What the salt stops is passive linking: two lists that share a backup no longer share anything visible.

## Deployments (contracts/build, reproducible from contracts/)

Both verifiers sit under secp256k1 with 20 zero-byte args, which no key can unlock, and are referenced by data hash
(`data1`). They were funded by 15 faucet claims.

| Binary | Code hash | Deploy transaction | Size |
|---|---|---|---|
| `evm-personal-sign` | `0x14715402af1d6cdb6036ac02d10c822e84349c289c938320c2f7e8bb6d54b86f` | `0x1d487850a80c6e75a841e97184d52a6a84bf3405cb8ddc3152b1d03eeed9e089` | 99,072 bytes (99,133 CKB) |
| `joyid-webauthn` | `0x01ac20c4c1a7e5e073a9369b452382970d7d493ad98169dbfa017df1351e2957` | `0x2b25815f1a4e130878880b079530646887560fcec104fb09e3fdfdec26be58c6` | 41,392 bytes (41,453 CKB) |

The EVM binary grew by 9 KB (blake2b, which the WebAuthn verifier already had). A fresh copy of `contracts/` built
in another directory gave the same bytes, and editing comments afterwards didn't change them.

## Testnet proof (`prove.ts`)

KA and KB stand in for two accounts' Lit keys: the same person in two apps. Both accounts turn recovery on through
the server's real flow (`recoverySetup`: preview, emailed code, enable, settle) with the same two backups: E1, an
EVM key, and J1, a P-256 key answering like JoyID's sign-message page. KC is a third account whose list copies A's
salted auths, as anyone reading A's enable transaction could.

| Step | Transaction |
|---|---|
| Account A turns recovery on (E1, J1) | `0xf709012a4e22b078bf6217aa73b8890d3c31b6dafab35805b352137ca38cb295` |
| Account B turns recovery on (E1, J1) | `0x6807abfa7a21fa5f7ce58f852ff6a6885544605119dd4fd158f7495ac89d206f` |
| Account C turns recovery on with A's auths copied | `0xb027fdd3bc42088d85352e981568b85583a06dfaf074bb4c9a07c29612a714a8` |
| E1 rescues A through the new EVM verifier | `0xfd7674dd90339f559e678456d0aaff25973b1f3df488de48cfe1b6a156dc6d12` |
| J1 rescues B through the new WebAuthn verifier | `0xe4634e3f51c94eb3a1fa67ba97177f207f3f0144e4c44fcf862419cdb256b757` |

**Different auths (`compare.out`).**

| | Account A (salt `0x5f92bd4e…35b9`) | Account B (salt `0xe7548568…fac5`) |
|---|---|---|
| E1 | `0xfd74d929da39f79d3c15d7f6f28a25d463cda20110` | `0xfd15266353601f62504ee1e69daf00c27dc2fc716c` |
| J1 | `0xfd6e8472fcfb4109ce447fcc144074615e4734f06e` | `0xfd0ec3ac3669295e06bd2e19e48ee900a4078297bb` |

Neither record contains E1's address or J1's key hash, and the two lists share no auth.

**Dry runs (`negative.out`, `test_tx_pool_accept` only).** Omnilock's error codes are on
[its page](https://nervosnetwork.github.io/ckb-script-error-codes/by-data-hash/6b29b6f10346b43c540e53806ba88ba0fe3a0c3a29d7448ef555840c8f8318fa.html).

| Case | E1 | J1 |
|---|---|---|
| Spends A with its own salted identity | accepted, 8.05M cycles | accepted, 7.32M |
| Spends B with its own salted identity | accepted, 8.04M | accepted, 7.34M |
| A's auth and proof in a spend of B | refused, Omnilock 59 (not on B's list) | refused, 59 |
| B's auth with A's preimage | refused, Omnilock 72 (preimage hash) | refused, 72 |
| The signature from a spend of A, replayed in a spend of B with B's identity | refused, verifier 101 | refused, verifier 107 (challenge) |
| A's identity on C, whose list copies A's auths, signed over C's own readable text | refused, verifier 101 | refused, verifier 101 |

The last row is the salt doing its job on chain. Omnilock accepts A's identity and proof against C's root and execs
the verifier, which salts the signer with C's AdminList type hash and refuses. An identity only works in the
account it was made for.

**Real rescues (`rescue.out`).** E1 moved A's 9,834.99997964 CKB to D1 and J1 moved B's 9,834.99996529 CKB to D2,
each signing the readable text the verifier rebuilds. `tests/fixtures/recovery-backup-unlinking.json`
(`record-fixture.ts`) holds both enables and both rescues; `tests/recovery-flow.test.ts` rebuilds both enable
transactions from KeyWay's code to the same hashes and checks the records, signatures and salted preimages offline.

## Tests

- `contracts/tests/tests/approval.rs` `identities_are_salted_per_account`: in CKB-VM, E1's and J1's identities
  differ between two accounts; each works in its own account and is refused (101) in the other; the bare unsalted ID
  is refused; flags `0x00/0x03/0x09/0x81`, and args of 53, 55, 22, 0 and 354 bytes, exit 114. The random-transaction
  tests, the 40,000-mutation test and the Fable 5.1 parity fuzz run with salted identities (fixture accounts now
  have administrator-mode args); `verifier.rs` uses rescue.json's account salt.
- TypeScript: salted preimages and auths, `accountSalt`, the version 3 record (encode, decode, malformed, duplicate,
  versions 1 and 2 refused), `recoveryListEntry`, an entry with another account's salt refused before signing, the
  rescue page's lookup by salted auth, the server refusing a list salted for another account, and a test that the
  SDK's verifier code hashes are the data hashes of `contracts/build`.

## Review

An independent review (Fable 5.1) of the diff and the contracts found the salt binding sound. `load_script` in the
exec'd verifier is the account's Omnilock, args[22..54] are what Omnilock checked the proof against, and the exact
`0x01` check keeps out the other 54-byte shape. It found no memory-safety issue (buffer, `parse_script` bounds, no
overflow) and the Rust and SDK sides in parity. Its findings, and what was done:

1. The SDK still named the old verifier hashes, because the deploy was pending at review time. Fixed by the deploy
   above. A new test ties the constants to `contracts/build`.
2. Accounts with version 2 lists can't be read or changed by the new code. Intended: there are no users and no
   migration (release notes).
3. The wording overstated unlinkability. Fixed in the rescue page, SDK and contract docs, which now say what the
   public salt doesn't hide (above).
4. A doc comment credited the salt with stopping signature replay across accounts. Fixed: the sighash in the text
   does that. The salt stops an identity from one account working in another.
5. `rescueEntryForJoyId` reported every error as "not a JoyID passkey". Fixed: node failures are reported as `rpc`.
6. Two old research scripts didn't type-check. Updated to the new API, with a note that they no longer reproduce
   their transactions.

## Files

`lib.ts` (keys, client, deployment), `faucet.ts`, `balance.ts`, `deploy-verifiers.ts`, `prove.ts`,
`record-fixture.ts`, `release-notes.md` (draft for the next SDK release).
