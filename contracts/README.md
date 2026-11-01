# KeyWay on-chain scripts

Two Omnilock exec verifiers for recovery backups and the library they share. A backup is an Omnilock **exec
identity** (auth flag `0xFD`). When a backup spends through Omnilock's administrator path, Omnilock checks the
identity's SMT proof against the account's AdminList, checks `blake160(preimage)` against the identity, computes
the lock group's sighash_all and execs the verifier the preimage names. The verifier's exit code becomes the
lock's result.

| Crate | What it is |
|---|---|
| `keyway-approval` | The readable text a backup signs, and the code that rebuilds it from the transaction (`chain`) |
| `evm-personal-sign` | EVM wallets: EIP-191 `personal_sign` of that text, recovered with secp256k1 against the 20-byte address |
| `joyid-webauthn` | JoyID passkeys: a WebAuthn (P-256) assertion whose challenge is that text |

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
- **Tokens**: how many outputs have a type script: `none`, `1 token cell` or `N token cells`.
- **Fee**: the inputs' capacity less the outputs', read by the verifier from the real input cells.
- Amounts use thousands separators and up to 8 decimals, trailing zeros dropped.
- **Transaction**: the sighash from Omnilock's argument. It binds the signature to one transaction.

The verifier builds this from the transaction it runs in (`load_script_hash`, then capacity, lock hash, type hash
and data length of every output, and capacity of every input). It refuses, with exit code 111, any transaction
that isn't a rescue:

- no outputs;
- outputs to more than one lock;
- outputs to the account itself (the running script, which is the account's Omnilock in exec);
- an output with data but no type script;
- outputs above inputs.

The text is at most 480 bytes (exit code 112 beyond). A JoyID assertion carries it base64url-encoded in
clientDataJSON, which must fit Omnilock's 1024-byte signature with the rest of the assertion. With Chrome's extra
clientDataJSON key and the testnet origin, 480 bytes of text make a 1,015-byte blob. That limit is why the text
doesn't name the account's own address: with it, an Omnilock destination alone overflowed 1024 bytes. Destination
addresses up to about 300 characters fit (lock args up to about 150 bytes).

The network byte in each signature picks the prefix. It is display only: the lock bytes are what the text names
and what the chain checks.

`tests/fixtures/approval-text-cases.json` (400 cases) and `approval-transaction-cases.json` (120 random
transactions) are written by `scripts/approval-fixtures.ts` from the SDK's builder (`src/sdk/browser/recovery-approval.ts`)
and CCC's address encoder. `tests/tests/approval.rs` checks the Rust builder and the bech32m encoder against them,
and runs both verifiers in CKB-VM on every transaction.

## `evm-personal-sign`

```
preimage (62 bytes) = verifier code hash (32) ‖ 0x02 (data1) ‖ 0x00 (cell dep) ‖ u32 LE 0 ‖ u32 LE 0 ‖ EVM address (20)
auth                = 0xFD ‖ blake160(preimage)
signature (67)      = version 0x01 ‖ network (0 testnet, 1 mainnet) ‖ r ‖ s ‖ v
```

`v` may be 27/28 or 0/1; a high `s` is accepted (normalised before recovery, as `ecrecover` does). The binary
checks keccak256(`"\x19Ethereum Signed Message:\n"` ‖ decimal length ‖ text) recovers to the address
(RustCrypto `k256` 0.13 without precomputed tables, `sha3` keccak).

Exit codes: 0 success, 100 argument, 101 recovered address isn't the backup's, 102 signature encoding, 109
signature out of range, 110–113 from the approval (network byte, shape, too long, syscall).

## `joyid-webauthn`

```
preimage (62 bytes) = verifier code hash (32) ‖ 0x02 (data1) ‖ 0x00 (cell dep) ‖ u32 LE 0 ‖ u32 LE 0 ‖ pubkey_hash (20)
pubkey_hash         = blake160(64-byte uncompressed P-256 public key X ‖ Y)
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
3. `blake160(public key) == pubkey_hash`.
4. authenticatorData is at least 37 bytes and has the user-present flag (`0x01`).
5. clientDataJSON is valid UTF-8 (a leading byte-order mark is refused) and exactly one JSON object (RFC 8259,
   nothing before or after it, nesting at most 8 deep, at most 32 top-level keys); top-level keys are unique after
   unescaping; the top-level `"type"` is `"webauthn.get"`; the top-level `"challenge"` is exactly the base64url (no
   padding) of the approval text rebuilt from this transaction. A challenge anywhere else doesn't count.
6. ECDSA P-256 over `sha256(authenticatorData ‖ sha256(clientDataJSON))` with RustCrypto `p256` 0.13. High `s`
   is accepted: WebAuthn signatures aren't normalised.

Exit codes: 0 success, 100 argument, 101 public key hash, 102 blob encoding, 103 authenticatorData too short,
104 no user presence, 105 malformed clientDataJSON, 106 wrong type, 107 wrong challenge, 108 public key not on
P-256, 109 signature, 110–113 from the approval.

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
Deployed by `research/omnilock/audit-fixes/deploy-verifiers.ts`.

| Binary | Code hash (`data1`) | Out point | Size |
|---|---|---|---|
| `build/evm-personal-sign` | `0x33bd1c699b633d685a6f60f6b0ca16fe8bb896f81323926ca6e0671bf8ab3c88` | `0xff16f2aa117ba8e67aeb8946a8d3cb0c5f4627eab4fd8d7d5ecd938d7fa9014f:0` | 89,768 bytes |
| `build/joyid-webauthn` | `0xf1185da23bf04b638010038b40ec64b587654db5cb98eb39f0373ad8919bcd89` | `0xb99678308cde0a54f856a00ec1e2ec46a318cdf05ef375cc381933dc00c7fb17:0` | 41,200 bytes |

The earlier version 1 WebAuthn verifier (`0x24306cbe…9720`, challenge `CKB transaction: 0x…`) is still on chain
but no longer used.

KeyWay also deployed its own copy of the official testnet Omnilock binary (139,936 bytes, data hash
`0x6b29b6f10346b43c540e53806ba88ba0fe3a0c3a29d7448ef555840c8f8318fa`) at
`0xf4ce65847089d24bbc8e7d999f396d4227d34376bbfef0f5e3c11967c5a13271:0`, under the same unspendable lock.

## Build and test

```sh
rustup target add riscv64imac-unknown-none-elf     # toolchain pinned in rust-toolchain.toml (1.97.0)
cargo build -p joyid-webauthn -p evm-personal-sign --release --target riscv64imac-unknown-none-elf
cmp target/riscv64imac-unknown-none-elf/release/joyid-webauthn build/joyid-webauthn
cmp target/riscv64imac-unknown-none-elf/release/evm-personal-sign build/evm-personal-sign
cargo install ckb-debugger --version 1.1.1 --locked  # needs protoc
cargo test --release -- --nocapture                # runs the binaries in CKB-VM through ckb-debugger
```

The builds are reproducible: a fresh copy of `contracts/` built in another directory gives the same bytes.
`tests/tests/verifier.rs` runs the WebAuthn verifier against `tests/tests/rescue.json` (a mock rescue transaction
for ckb-debugger); `approval.rs` runs both verifiers on the random transactions and 40,000 signature mutations;
`audit_fable51_parity.rs` checks the clientDataJSON rules against the server's. `p256-check` is a test-only binary
that runs the P-256 code on `public_key:rs:message`.

### Cycles (ckb-debugger 1.1.1)

| Case | Cycles |
|---|---|
| EVM verifier, random rescue transactions | up to 7.9M |
| WebAuthn verifier, random rescue transactions | up to 7.1M |
| Whole administrator-path spend on testnet, EVM backup | 8.03M |
| Whole administrator-path spend on testnet, JoyID-style backup | 7.33M |
