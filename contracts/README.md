# KeyWay on-chain scripts

## `joyid-webauthn`: WebAuthn (P-256) verifier for JoyID recovery backups

A JoyID backup is an Omnilock **exec identity** (auth flag `0xFD`) bound to the JoyID passkey's public key. When a
backup spends through Omnilock's administrator path, Omnilock checks the identity's SMT proof against the
account's AdminList, checks `blake160(preimage)` against the identity, computes the lock group's sighash_all and
execs this binary. Its exit code becomes the lock's result, so the backup needs a passkey signature made for that
exact transaction.

### Why exec, not dynamic linking

Omnilock supports both (`IdentityFlagsExec = 0xFD`, `IdentityFlagsDl = 0xFE`, `c/ckb_identity.h`). Exec runs an
ordinary RISC-V program with one argument, so it can be a plain Rust `no_std` binary on ckb-std. Dynamic linking
needs a position-independent shared object exporting the ckb-auth `ckb_auth_validate` entry and the
swappable-signature ABI, which Rust doesn't produce without a custom toolchain setup. Exec costs one extra
program load (about 0.1M cycles here) and Omnilock does nothing after the identity check, so replacing its VM
loses nothing.

### Identity

```
preimage (74 bytes) = verifier code hash (32) ‖ hash_type 0x02 (data1) ‖ place 0x00 (cell dep)
                      ‖ length u32 LE 0 ‖ offset u32 LE 0 (the whole cell) ‖ pubkey_hash (20)
pubkey_hash         = blake160(64-byte uncompressed P-256 public key X ‖ Y)
                    = the JoyID main key's lock args without the 0x0001 prefix
auth                = 0xFD ‖ blake160(preimage)
```

The witness lock carries the preimage in `OmniLockWitnessLock.preimage`. The identity commits to the
verifier's code hash, so nobody can swap the verifier: Omnilock finds it among the cell deps by data hash
(ckb-c-stdlib's `ckb_look_for_dep_with_hash2` matches the data hash for every hash type except 1), and anyone
can redeploy the identical bytes if the cell ever disappears.

### Exec argument and signature blob

Omnilock passes one argument, lowercase hex fields joined by `:` (ckb-auth's exec convention):
`code_hash:hash_type:pubkey_hash:msg:signature`. `msg` is the 32-byte sighash. The signature is at most 1024
bytes (Omnilock's `MAX_SIGNATURE_SIZE`):

| Bytes | Field |
|---|---|
| 1 | version, `0x01` |
| 64 | P-256 public key X ‖ Y |
| 64 | r ‖ s, big-endian |
| 2 | authenticatorData length, u16 LE |
| n | authenticatorData |
| 2 | clientDataJSON length, u16 LE |
| m | clientDataJSON |
| rest | zero padding |

The sighash covers the witness lock zeroed at its final length, so the signer has to fix the length before the
passkey signs. The SDK reserves a 768-byte slot (1024 if the assertion doesn't fit) and pads with zeros; any
non-zero byte after clientDataJSON is rejected.

### What it checks

1. Five argument fields of 32, 1, 20, 32 and at most 1024 bytes, nothing else.
2. The blob's version, lengths and zero padding.
3. `blake160(public key) == pubkey_hash`.
4. authenticatorData is at least 37 bytes and has the user-present flag (`0x01`).
5. clientDataJSON is valid UTF-8 and exactly one JSON object (RFC 8259, nothing before or after it, nesting at
   most 8 deep, at most 32 top-level keys); top-level keys are unique after unescaping; the top-level `"type"`
   is the string `"webauthn.get"`; the top-level `"challenge"` is exactly the base64url (no padding) of the
   83-byte text `CKB transaction: 0x<msg in 64 lowercase hex digits>`. A challenge anywhere else (another
   key, a nested object, inside the origin string) doesn't count.
6. ECDSA P-256 over `sha256(authenticatorData ‖ sha256(clientDataJSON))` with RustCrypto `p256` 0.13. High `s`
   is accepted: WebAuthn signatures aren't normalised (the real JoyID assertion in the tests has a high `s`).

Exit codes: 0 success, 100 argument, 101 public key hash, 102 blob encoding, 103 authenticatorData too short,
104 no user presence, 105 malformed clientDataJSON, 106 wrong type, 107 wrong challenge, 108 public key not on
P-256, 109 signature.

**Not checked, on purpose:**

- **User verification (`0x04`).** JoyID's own page decides whether to ask for it, not the dapp, and the real
  JoyID assertions seen so far have it set. Requiring it would only lock out authenticators that can't do it.
- **rpIdHash and origin.** A passkey only ever signs for the relying party it was created for, so the key
  binding already ties the signature to JoyID. Checking them would also tie the binary to one JoyID network.

### The challenge and what the user sees

JoyID's sign-message page (`@joyid/ckb` `signChallenge`, CCC's `JoyId.CkbSigner.signMessageRaw` with a string)
uses the UTF-8 bytes of the text as the WebAuthn challenge, so clientDataJSON's `challenge` is
`base64url(utf8(text))`; `@joyid/ckb`'s `ensureChallenge` checks exactly this. The JoyID popup shows the text,
`CKB transaction: 0x…`, the same text an EVM backup (Omnilock flag 0x12) signs. JoyID returns the assertion as
`{ signature: base64url(DER r,s), alg: -7, message: base64url(authenticatorData (37) ‖ clientDataJSON) }`, and
the SDK turns that into the blob above.

As with the EVM backup, the user can't read a sighash: whoever shows them the prompt decides what they sign.
The binding is that a signature works for one transaction only.

### Testnet deployment

| | |
|---|---|
| Code hash (`data1`) | `0x24306cbe18769a05ca453722a53628ebb2453b72d1d6e6ed7a12b878b1ce9720` |
| Out point | `0x333fa2abd90d32133cd3aca9be68a2042f0bdf3d191c384d6bc77b3cd6ae387b:0` |
| Size | 37,024 bytes (cell: 37,085 CKB) |

The cell's lock is secp256k1-blake160 with 20 zero-byte args, which no key can unlock, so it can't be spent.
`build/joyid-webauthn` is the deployed binary. Mainnet needs its own deployment of the same bytes.

### Build and test

```sh
rustup target add riscv64imac-unknown-none-elf     # toolchain pinned in rust-toolchain.toml (1.97.0)
cargo build -p joyid-webauthn --release --target riscv64imac-unknown-none-elf
cmp target/riscv64imac-unknown-none-elf/release/joyid-webauthn build/joyid-webauthn
cargo install ckb-debugger --version 1.1.1 --locked  # needs protoc
cargo test --release -- --nocapture                # runs both binaries in CKB-VM through ckb-debugger
```

The build is reproducible (same bytes from a different directory). `p256-check` is a test-only binary that runs
the same P-256 code on `public_key:rs:message`, used for ckb-auth issue #31's JoyID vector, which comes as
authenticatorData ‖ sha256(clientDataJSON) without the JSON.

### Cycles (ckb-debugger 1.1.1)

| Case | Cycles |
|---|---|
| Valid JoyID-shaped assertion | 6,488,191 |
| Same, in a 640-byte zero-padded blob | 6,502,372 |
| ckb-auth#31 vector, P-256 core only | 6,346,468 |

Almost all of it is the P-256 verification. Omnilock's own part (sighash, SMT proof, exec) comes on top; see
`research/omnilock/joyid-verifier-results.md` for whole transactions.
