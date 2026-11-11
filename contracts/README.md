# KeyWay on-chain scripts

Two Omnilock exec verifiers for recovery backups and the library they share. A backup is an Omnilock **exec
identity** (auth flag `0xFD`). When a backup spends through Omnilock's administrator path, Omnilock checks the
identity's SMT proof against the account's AdminList, checks `blake160(preimage)` against the identity, computes
the lock group's sighash_all and execs the verifier the preimage names. The verifier's exit code becomes the
lock's result.

| Crate | What it is |
|---|---|
| `keyway-approval` | The readable text a backup signs, and the code that rebuilds it from the transaction (`chain`) |
| `evm-personal-sign` | EVM wallets: EIP-191 `personal_sign` of that text, recovered with secp256k1 and checked against the salted address |
| `joyid-webauthn` | JoyID passkeys: a WebAuthn (P-256) assertion whose challenge is that text |

## Salted identities

A backup's identity never holds its own 20-byte ID (EVM address, or blake160 of the passkey's public key). It
holds `blake160(id ‖ salt)`, where the salt is the account's AdminList type hash:

```
account lock args (54) = 0x00 ‖ blake160(Lit key) (20) ‖ 0x01 (administrator mode) ‖ AdminList type hash (32)
salt                   = args[22..54]
pubkey_hash            = blake160(id ‖ salt)        (the last 20 bytes of the exec preimage)
```

Omnilock execs the verifier with `ckb_exec_cell` (`c/ckb_identity.h`, `verify_via_exec`), which replaces the
program but keeps the script group, so `load_script` in the verifier is the account's Omnilock lock, and args[22..54]
is the `omni_root` Omnilock's `parse_args` (`c/omni_lock.c`) just used to find the AdminList and check the backup's
SMT proof. `keyway_approval::chain::running_account_salt` reads it; anything but 54 bytes with flags exactly `0x01`
exits 114. Both verifiers then check `blake160(recovered ID ‖ salt) == pubkey_hash`.

The same backup in two accounts therefore has two unrelated identities, and an identity listed in one account is
refused (101) in another, even by a list that copies it. The salt is public: whoever already knows a backup's ID
can test it against an account's list, and a rescue's witness reveals the backup that signed it.

## The approval text (`keyway-approval`)

```
KeyWay recovery
Move everything to ckt1…
CKB: 12,345.678
Tokens: 2 token cells
Fee: 0.00001234 CKB
Transaction: 0x<sighash in 64 lowercase hex digits>
```

Lines are joined by `\n`, with no trailing newline.

- **Move everything to**: the outputs' lock in CKB's full address format (bech32m over `0x00 ‖ code_hash ‖
  hash_type ‖ args`, no 90-character limit), prefix `ckt` on testnet and `ckb` on mainnet.
- **CKB**: the total capacity of the outputs, which is everything the destination receives.
- **Tokens**: how many outputs have a type script: `none`, `1 token cell` or `N token cells`. The count stands
  for the account's own token cells, moved unchanged (see below), so it can't hide a changed or burned one.
- **Fee**: the inputs' capacity less the outputs', read by the verifier from the real input cells.
- Amounts use thousands separators and up to 8 decimals, trailing zeros dropped.
- **Transaction**: the sighash from Omnilock's argument. It binds the signature to one transaction.

The verifier builds this from the transaction it runs in (`load_script_hash`, then capacity, lock hash, type hash,
data hash and data length of every output, and capacity, lock hash, type hash and data hash of every input). It
refuses, with exit code 111, any transaction that isn't a rescue:

- no outputs;
- outputs to more than one lock;
- outputs to the account itself (the running script, which is the account's Omnilock in exec);
- an output with data but no type script;
- token cells that aren't exactly the account's own, moved unchanged: each output with a type script must have the
  type script hash and data hash of a distinct input of the account, each of the account's inputs with a type
  script must be one of them, and the outputs of each kind (same type script hash and data hash) may hold no more
  CKB than the account's inputs of that kind did. A token cell changed (tokens burned), left out (burned), moved
  twice, taken from someone else's input, made under a type script the account didn't hold, or given more CKB
  than it held, is refused. The last one matters because anyone can send the account a cell under their own type
  script, and that script could keep any CKB put in it: the rescued CKB beyond what token cells held must arrive
  in plain cells;
- more than 256 token cells (`MAX_TOKEN_CELLS`; the rescue page moves at most 100 cells at a time);
- outputs above inputs.

The text is at most 480 bytes (exit code 112 beyond). A JoyID assertion carries it base64url-encoded in
clientDataJSON, which must fit Omnilock's 1024-byte signature with the rest of the assertion. With Chrome's extra
clientDataJSON key and the testnet origin, 480 bytes of text make a 1,015-byte blob. That limit is why the text
doesn't name the account's own address: with it, an Omnilock destination alone overflowed 1024 bytes. Destination
addresses up to about 300 characters fit (lock args up to about 150 bytes).

The network byte in each signature picks the prefix. It is display only: the lock bytes are what the text names
and what the chain checks.

`tests/fixtures/approval-text-cases.json` (400 cases) and `approval-transaction-cases.json` (160 random
transactions) are written by `scripts/approval-fixtures.ts` from the SDK's builder (`src/sdk/browser/recovery-approval.ts`)
and CCC's address encoder. `tests/tests/approval.rs` checks the Rust builder and the bech32m encoder against them,
and runs both verifiers in CKB-VM on every transaction.

## `evm-personal-sign`

```
preimage (62 bytes) = verifier code hash (32) ‖ 0x02 (data1) ‖ 0x00 (cell dep) ‖ u32 LE 0 ‖ u32 LE 0 ‖ blake160(EVM address ‖ salt) (20)
auth                = 0xFD ‖ blake160(preimage)
signature (67)      = version 0x01 ‖ network (0 testnet, 1 mainnet) ‖ r ‖ s ‖ v
```

`v` may be 27/28 or 0/1; a high `s` is accepted (normalised before recovery, as `ecrecover` does). The binary
checks that keccak256(`"\x19Ethereum Signed Message:\n"` ‖ decimal length ‖ text) recovers to an address whose salted hash is `pubkey_hash`
(RustCrypto `k256` 0.13 without precomputed tables, `sha3` keccak).

Exit codes: 0 success, 100 argument, 101 recovered address salted isn't the identity's, 102 signature encoding, 109
signature out of range, 110–114 from the approval (network byte, shape, too long, syscall, not a KeyWay account's lock).

## `joyid-webauthn`

```
preimage (62 bytes) = verifier code hash (32) ‖ 0x02 (data1) ‖ 0x00 (cell dep) ‖ u32 LE 0 ‖ u32 LE 0 ‖ pubkey_hash (20)
pubkey_hash         = blake160(id ‖ salt)
id                  = blake160(64-byte uncompressed P-256 public key X ‖ Y)
                    = the JoyID main key's lock args without the 0x0001 prefix
```

The signature blob, at most 1024 bytes:

| Bytes | Field |
|---|---|
| 1 | version, `0x02` |
| 1 | network, `0x00` testnet or `0x01` mainnet |
| 64 | P-256 public key X ‖ Y |
| 64 | r ‖ s, big-endian |
| 2 | authenticatorData length, u16 LE |
| n | authenticatorData |
| 2 | clientDataJSON length, u16 LE |
| m | clientDataJSON |
| rest | zero padding |

The SDK always fills the full 1024 bytes (zero-padded), so the transaction's size and sighash are fixed before
the passkey signs, and the backup is asked once.

What it checks:

1. Five argument fields of 32, 1, 20, 32 and at most 1024 bytes, nothing else.
2. The blob's version, lengths and zero padding.
3. `blake160(blake160(public key) ‖ salt) == pubkey_hash`, the salt read from the running Omnilock's args.
4. authenticatorData is at least 37 bytes and has the user-present flag (`0x01`).
5. clientDataJSON is valid UTF-8 (a leading byte-order mark is refused) and exactly one JSON object (RFC 8259,
   nothing before or after it, nesting at most 8 deep, at most 32 top-level keys); top-level keys are unique after
   unescaping; the top-level `"type"` is `"webauthn.get"`; the top-level `"challenge"` is exactly the base64url (no
   padding) of the approval text rebuilt from this transaction. A challenge anywhere else doesn't count.
6. ECDSA P-256 over `sha256(authenticatorData ‖ sha256(clientDataJSON))` with RustCrypto `p256` 0.13. High `s`
   is accepted: WebAuthn signatures aren't normalised.

Exit codes: 0 success, 100 argument, 101 public key hash, 102 blob encoding, 103 authenticatorData too short,
104 no user presence, 105 malformed clientDataJSON, 106 wrong type, 107 wrong challenge, 108 public key not on
P-256, 109 signature, 110–114 from the approval.

Not checked, on purpose: user verification (JoyID's page decides whether to ask for it) and rpIdHash/origin (a
passkey only signs for its own relying party, so the key binding already ties the signature to JoyID).

JoyID's sign-message page (`@joyid/ckb` `signChallenge`, CCC's `JoyId.CkbSigner.signMessageRaw` with a string)
uses the UTF-8 bytes of the text as the WebAuthn challenge and shows the text to the user.

### Why exec, not dynamic linking

Omnilock supports both (`IdentityFlagsExec = 0xFD`, `IdentityFlagsDl = 0xFE`). Exec runs an ordinary RISC-V
program, so it can be a plain Rust `no_std` binary on ckb-std, and the exec'd program keeps the script group, so
it can read the transaction itself. Omnilock does nothing after the identity check, so replacing its VM loses
nothing.

## Testnet deployments

Each cell's lock is secp256k1-blake160 with 20 zero-byte args, which no key can unlock, so the cells can't be
spent. Each is referenced by data hash (`data1`), so the code can't change; anyone can redeploy the same bytes.
Deployed by `research/backup-unlinking/deploy-verifiers.ts` (version 3, salted identities).

| Binary | Code hash (`data1`) | Out point | Size |
|---|---|---|---|
| `build/evm-personal-sign` | `0x14715402af1d6cdb6036ac02d10c822e84349c289c938320c2f7e8bb6d54b86f` | `0x1d487850a80c6e75a841e97184d52a6a84bf3405cb8ddc3152b1d03eeed9e089:0` | 99,072 bytes |
| `build/joyid-webauthn` | `0x01ac20c4c1a7e5e073a9369b452382970d7d493ad98169dbfa017df1351e2957` | `0x2b25815f1a4e130878880b079530646887560fcec104fb09e3fdfdec26be58c6:0` | 41,392 bytes |

The source here is version 4, which also checks that the token cells are the account's own, moved unchanged
(audit run 3, M19). Built from it, `evm-personal-sign` is 100,976 bytes with code hash
`0x17c0015351a676c893110dab13dfbf5e7db1bd80678a7cd6934d593e969cc863` and `joyid-webauthn` is 42,456 bytes with code
hash `0x82ac814afad69575b760902a3bd6b56ee432181d9efc67cf83bce6246f472866`. They aren't deployed yet: a backup's
identity names its verifier's code hash, which the policy Lit Action pins too, so switching to them takes the
deployment, a new Action CID and new pins in the SDK together. Until then `build/` holds the version 3 binaries
above, which the SDK and the Action use, and which don't make that check. An account's recovery list names its
backups' identities, so an account whose list was written before the switch keeps version 3 identities, and the
old check, until its list is written again.

The version 2 verifiers (unsalted: `0x33bd1c69…3c88` EVM, `0xf1185da2…cd89` WebAuthn) and the version 1 WebAuthn
verifier (`0x24306cbe…9720`) are still on chain but no longer used.

KeyWay also deployed its own copy of the official testnet Omnilock binary (139,936 bytes, data hash
`0x6b29b6f10346b43c540e53806ba88ba0fe3a0c3a29d7448ef555840c8f8318fa`) at
`0xf4ce65847089d24bbc8e7d999f396d4227d34376bbfef0f5e3c11967c5a13271:0`, under the same unspendable lock.

## Build and test

```sh
rustup target add riscv64imac-unknown-none-elf     # toolchain pinned in rust-toolchain.toml (1.97.0)
cargo build -p joyid-webauthn -p evm-personal-sign --release --target riscv64imac-unknown-none-elf
cmp target/riscv64imac-unknown-none-elf/release/joyid-webauthn build/joyid-webauthn      # differs until version 4 is deployed
cmp target/riscv64imac-unknown-none-elf/release/evm-personal-sign build/evm-personal-sign  # (see Testnet deployments)
cargo install ckb-debugger --version 1.1.1 --locked  # needs protoc
cargo test --release -- --nocapture                # runs the binaries in CKB-VM through ckb-debugger
```

The builds are reproducible: a fresh copy of `contracts/` built in another directory gives the same bytes.
`tests/tests/verifier.rs` runs the WebAuthn verifier against `tests/tests/rescue.json` (a mock rescue transaction
for ckb-debugger); `approval.rs` runs both verifiers on the random transactions and 40,000 signature mutations, and checks the salt (an identity from one account refused in another, 114 for a lock that isn't a KeyWay account's);
`approval.rs` also runs both verifiers on the token-cell attempts above, and the EVM verifier on 100, 256 and 257
token cells;
`audit_fable51_parity.rs` checks the clientDataJSON rules against the server's. `p256-check` is a test-only binary
that runs the P-256 code on `public_key:rs:message`.

### Cycles (ckb-debugger 1.1.1)

| Case | Cycles |
|---|---|
| EVM verifier, random rescue transactions | up to 7.9M |
| WebAuthn verifier, random rescue transactions | up to 7.2M |
| EVM verifier, 100 token cells (the most the rescue page moves at once) | 9.3M |
| EVM verifier, 256 token cells (the most it accepts) | 13.2M |
| Whole administrator-path spend on testnet, EVM backup | 8.05M |
| Whole administrator-path spend on testnet, JoyID-style backup | 7.34M |
