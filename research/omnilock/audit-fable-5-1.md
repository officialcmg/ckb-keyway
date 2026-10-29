# Independent security audit: Omnilock account recovery in KeyWay

Branch audited: `omnilock-recovery` at `5ecfca1dcf2ba7a0cf14081e520d15f6e3f34cca` (diff against `main`), on 2026-10-29.
Audit branch: `audit/omnilock-fable-5-1`. Nothing in product code was changed; the proofs of concept are tests and
scripts listed under each finding. Testnet runs used throwaway keys (`research/omnilock/audit-fable-5-1/keys.json`,
gitignored, never printed) and one faucet claim; every chain check was a `test_tx_pool_accept` dry run except the
one transaction that turned recovery on for the throwaway account
(`0x97ce2a646994c11f0d7c2eb9b77c160299bc9c57d6740d2fc61784f782c38405`).

## Summary

The on-chain design holds. I found no way for anyone other than the account's Lit key or a listed backup to move
funds on chain: Omnilock's administrator mode behaves as the design assumes (read from the Omnilock source, commit
`280dd97`), every signature is bound to one lock group of one transaction, the sparse Merkle tree port matches what
Omnilock accepted in the builders' testnet runs, and the deployed WebAuthn verifier is byte-identical to the
committed binary, reproduces from source with the pinned toolchain, hashes to the code hash the SDK names and sits
under a lock nobody can unlock. The verifier's parser agrees with the server's TypeScript rules on 73 adversarial
clientDataJSON cases (one harmless divergence, below) and survives 20,000 random blob mutations without a panic or
a false accept.

The findings are about trust placed off chain:

| Severity | Finding |
|---|---|
| Medium | The rescue page trusts the CKB node it is pointed at for the capacity, data and identity of the cells it spends. A malicious node makes a backup sign a rescue that burns most of the balance as fee, burns tokens, or destroys the AdminList. Confirmed with a testnet dry run: the network accepts a rescue paying 9,312 of 9,803 CKB to the miner. |
| Medium | Nothing ties a stored recovery record to the user except the database row. Whoever can write that row can point an account at an AdminList they minted, after which the sign-in sweep moves the user's old-address funds there with the user's own Lit signature and no dialog, change outputs follow, and the attacker's backup spends it all. No Lit API key is needed, which lowers the bar from "server compromise" to "database write". |
| Medium | A backup approves a spend by signing the opaque text `CKB transaction: 0x…`, which names no destination or amount, and every backup's EVM address is public in the on-chain list record. A phishing page a backup wallet visits for any reason can drain the KeyWay account with one `personal_sign`. Inherent to Omnilock flag 0x12 and to the exec verifier's challenge; the design document's "a signature works for one transaction only" does not help when the attacker builds the transaction. |
| Low | The server's clientDataJSON check strips a leading byte-order mark that the on-chain verifier rejects. |
| Low | There is no way to turn recovery off, rebuild a destroyed or rewritten AdminList, or move to a fresh list after a backup is compromised. Funds stay reachable by the Lit key (confirmed by dry run), but only outside KeyWay's flows. |
| Low | The Omnilock deployment is resolved from CCC's known-script table at runtime and is not pinned in the stored record or the rescue page, so a CCC upgrade that changes the deployment would silently change every recovery account's address. |
| Low | The sign-in sweep and the SDK's own transactions can spend the same old-address cells at the same time. |
| Info | The KeyWay server alone can already sign anything for any account (the Lit action signs any digest for any PKP with the server's API key); this predates the branch, and the sweep adds an unattended use of it. Plus notes on JoyID, the AdminList, the verifier's deliberate omissions and the approval props. |

Counts: 0 critical, 0 high, 3 medium, 4 low, several informational.

## Findings

### M1. The rescue page can be made to burn funds or destroy the list by the node it talks to (Medium)

**Where.** `src/rescue/rescue.ts`: `openRescueAccount` (cells from `findCellsByLock`, AdminList from
`findSingletonCellByType`, record from `getTransaction`), `planRescue`, `checkRescueTransaction`, `sendRescue`.

**What goes wrong.** A CKB transaction commits to its inputs by out point only. The backup's signature covers the
sighash, which depends on the out points, the outputs and the witness layout, never on what the input cells
contain. The page builds outputs from what the node reports, so a node that under-reports an input's capacity
produces a transaction whose real fee is the difference, a node that under-reports an xUDT amount produces a
transaction that burns the rest (xUDT only requires outputs ≤ inputs), and a node that reports the AdminList's out
point as a plain cell while answering `findSingletonCellByType` with a decoy out point produces a transaction that
spends the real AdminList (Omnilock still finds the RC cell among the inputs; the Type ID cell has no successor).
The dry run in `sendRescue` goes to the same node. The page's review step shows the lie as the balance.

The preconditions are a malicious node URL entered in the page's "CKB node" field, a compromised public node, or
anyone who can answer for one (the default is `https://testnet.ckb.dev/` over HTTPS). People use this page when
KeyWay is gone and will take node URLs from wherever they can find them.

**Repro.**
- `tests/audit-fable51-rescue-rpc.test.ts`, three tests: a 10,000 CKB cell reported as 200 CKB gives a signed rescue
  whose real fee is above 9,799 CKB while the page showed a fee under 0.001 CKB; a 2,500-token cell reported as
  holding 1 token gives outputs that burn 2,499; a decoy AdminList out point gives a rescue whose input is the real
  AdminList with no output recreating it.
- Testnet: `research/omnilock/audit-fable-5-1/rpc-burn.ts`, output in `rpc-burn.out`. With a wrapper that reports
  the account's plain cell at 5% of its capacity, the page showed a balance of 490.15 CKB and a fee of 0.00000765
  CKB; the real network accepted the signed transaction (`test_tx_pool_accept`, 1,560,566 cycles) with real inputs
  of 9,802.99998972 CKB and a real fee of 9,312.84999789 CKB. The honest control run showed 9,802.99998972 CKB and
  the same small fee. Nothing was sent.

**Fix.**
1. Cross-check every input with a second source before signing: fetch each input with `get_live_cell` from a
   second node (ship two or three defaults and let the user add one) and refuse the rescue if capacity, type, lock or
   data differ. A light-client proof would be better still.
2. Take the AdminList from one place. Use the cell found by `findCellsByLock` (the one whose Type ID the address
   names) as `account.adminList`, require that `readRecoveryList`'s cell has the same out point, and in
   `checkRescueTransaction` refuse any input whose out point equals it.
3. Print the balance and fee the user is about to sign for and say plainly that they come from the node; a user who
   knows their balance can catch the first variant.

### M2. A forged recovery record redirects the account to an attacker's list (Medium)

**Where.** `src/sdk/browser/account-lock.ts` `parseRecovery` (the only validation of a stored record; it checks
internal consistency against the public key and nothing about who made the AdminList); `src/server/user-wallet.ts`
`readWallet`; `src/server/legacy-sweep.ts` `planLegacySweep` and `checkLegacySweepTransaction` (destination computed
from `recovery.adminListTypeHash`); `refuseForeignOmnilockOutputs` (allows `recovery.omnilockArgs`); the SDK's
`KeyWayAccountSigner` (address from `recovery`).

**What goes wrong.** The AdminList's Type ID is derived from whatever cell was input 0 of the transaction that made
it, and the Omnilock args are derived from the victim's public key plus that type hash. An attacker can therefore
mint, from their own cell, an AdminList whose lock is the victim's Omnilock in administrator mode and whose
whitelist holds the attacker's backup, write the matching record in its witness, and build a `KeyWayRecovery`
object that passes `parseRecovery`, `readRecoveryList` and every policy check. Written into the victim's wallet
row, it makes the next sign-in sweep move everything at the old address to that Omnilock, signed by the victim's
Lit key with no approval, makes the SDK show that address as the account's (so new deposits go there), makes every
change output go there, and lets the attacker's backup spend it all through the administrator path. The attacker
needs database write access, not the Lit API key. Before this branch, database write access alone could not move
funds.

**Repro.** `tests/audit-fable51-forged-recovery.test.ts`, three tests: the forged record passes `parseRecovery`,
`readRecoveryList` names the attacker as the only backup and the SDK reports the forged address; the sweep plans,
passes `checkLegacySweepTransaction`, signs with the victim's key and pays 5,000 CKB to the forged Omnilock, after
which the attacker's EVM wallet produces an administrator-path witness for a drain over that group's sighash;
ordinary signing treats change to the forged address as the user's own.

**Fix.** Anchor the AdminList to the user with chain data. Store the enabling transaction's hash, and before a
record is used (in `readWallet`, or at least in the sweep and in `/bootstrap`'s response) fetch that transaction,
check it is committed, that `hashTypeId(tx.inputs[0], 0)` equals `adminListTypeArgs`, that output 0 carries that
Type ID, and that input 0's previous output was locked by the user's own secp256k1 lock. An attacker cannot spend the
user's cells, so they cannot satisfy that. Alternatively have Lit sign `blake160(pubkey) ‖ adminListTypeHash` once at
enable time, store the signature, and check it in `parseRecovery`. The SDK can run the same chain check on what
`/bootstrap` returns, which also removes the server from the list of parties who can change the user's address.

### M3. One opaque signature from a backup wallet drains the account, and backups are easy to find (Medium)

**Where.** `src/sdk/browser/recovery-backups.ts` (`evmOmnilockMessage`, the exec verifier's challenge),
`src/sdk/browser/recovery-list.ts` (the list record in the witness of every enable and change transaction),
`docs-site/content/docs/account-recovery.mdx` ("The wallet's network doesn't matter: it only signs a message").

**What goes wrong.** Omnilock flag 0x12 and the verifier both accept a signature over `CKB transaction: 0x<sighash>`.
The text names no destination, amount, account or app. Everything else an attacker needs (the AdminList, the full
list with each backup's address, the SMT proofs) is public: the list record is in plain sight in the witness of
every enable and change transaction, so a crawler can map EVM addresses to KeyWay accounts and balances. A page the
backup wallet visits for an unrelated reason asks for one `personal_sign` and the account is empty. This is the
Omnilock model, and the builders note that "the user can't read a sighash"; what the design document does not say
is that the attacker chooses the transaction, so "one transaction only" is no protection in this scenario.

**Repro.** `tests/audit-fable51-backup-phishing.test.ts`: from the enable transaction's record the backup's EVM
address is recovered; from chain data alone the list and proof are rebuilt; a drain to the thief's lock is signed
with exactly one `personal_sign` request matching `/^CKB transaction: 0x[0-9a-f]{64}$/`; the signature recovers
to the backup over that text, which is the group's sighash, so Omnilock accepts it.

**Fix.** Omnilock offers no typed-data identity, so this cannot be closed in the SDK alone. Options, in rising
order of effort: tell users in the dialog, the emails and the docs that the backup wallet should be one they use
for nothing else; prefer JoyID backups in the UI (the passkey prompt is JoyID's own and shows the text, and a
passkey cannot be asked to sign by an arbitrary dapp without the JoyID page); and, since an exec verifier already
exists for JoyID, consider an EVM exec verifier of the same shape whose signed message is EIP-712 typed data naming
the destination lock and amounts, so the wallet shows what is approved. Also consider not writing EVM addresses
in clear in the record (a blake160 would do for rebuilding the SMT key; the rescue page already matches by auth).

### L1. Server-side clientDataJSON check accepts a leading BOM the chain rejects (Low)

**Where.** `src/sdk/browser/webauthn.ts` `clientDataMatches`: `new TextDecoder("utf-8", { fatal: true })` has
`ignoreBOM: false`, which strips a leading U+FEFF before parsing. `contracts/joyid-webauthn/src/lib.rs`
`check_client_data` uses `core::str::from_utf8`, which keeps the three bytes, so `expect(b'{')` fails.

**What goes wrong.** An ownership proof whose clientDataJSON starts with a BOM is accepted at setup but could never
spend on chain. No browser emits one, so no loss follows; it is the one divergence between the two parsers.

**Repro.** `tests/audit-fable51-clientdata-parity.test.ts` (case "leading BOM", recorded with `expectedTs: true`)
and `contracts/tests/tests/audit_fable51_parity.rs` (the Rust side rejects it). Run the TypeScript test first; it
writes `tests/fixtures/audit-fable51-clientdata-cases.json`, then `cargo test --release --test audit_fable51_parity`
in `contracts/`.

**Fix.** `new TextDecoder("utf-8", { fatal: true, ignoreBOM: true })`.

### L2. No way out once the AdminList is gone or hostile (Low)

**Where.** `src/server/recovery.ts`: `recoverySetup` refuses when `wallet.recovery` is set; `planBackupChange` needs
the live AdminList and a record or stored list that hashes to its root; nothing turns recovery off.

**What goes wrong.** A backup can spend the AdminList through the administrator path (Omnilock looks for the RC cell
among the inputs when it is not a cell dep: `rce_state.rcrules_in_input_cell = true` in `omni_lock.c`). If a backup
destroys it, or rewrites it to a root KeyWay does not know, every KeyWay recovery flow fails ("The recovery list
isn't on chain", "KeyWay's copy of your backups doesn't match the recovery list on chain"), the rescue page fails
("list-missing"), and the user cannot re-enable, rotate or disable recovery. The Lit key still spends: the owner
path does not read the RC cell at all, confirmed on testnet (`research/omnilock/audit-fable-5-1/owner-path.ts`,
output in `owner-path.out`: an Omnilock owner-path spend with only the Omnilock deps, no AdminList dep, accepted by
`test_tx_pool_accept`, 1,409,884 cycles). So funds are safe but stuck under KeyWay's own flows, and a user with a
compromised backup has no in-product way to evict it if the attacker rewrites the list first.

**Fix.** Add a "turn recovery off / start over" flow: sweep the Omnilock address back to the secp256k1 lock (or to a
fresh AdminList) with the Lit key, clear or replace the record, and let `recoverySetup` run again.

### L3. The Omnilock deployment is not pinned (Low)

**Where.** `omnilockLock` and `accountLocks` in `account-lock.ts`, `parseKeyWayAddress` and `prepareAdminWitness` in
`rescue.ts`, `planLegacySweep`: all resolve `ccc.KnownScript.OmniLock` from CCC's table at runtime. The stored
`KeyWayRecovery` holds only `omnilockArgs`.

**What goes wrong.** CCC's testnet Omnilock is referenced by type (`hash_type: type`, code hash `0xf329ef…`), so its
deployer can change the code (known limit, documented). Separately, a CCC release that points `KnownScript.OmniLock`
at a different deployment would make every recovery account's computed lock, address and policy checks change at
once: funds under the old lock would disappear from balances and could not be spent through KeyWay until the SDK
was pinned back. The rescue page would likewise refuse the old addresses as "not a KeyWay address".

**Fix.** Store `codeHash`, `hashType` and the cell dep in `KeyWayRecovery` at enable time, use them instead of the
table, and in the rescue page accept the known Omnilock code hashes by value (as `fiber-methods.ts` already does
for the funding fee rate).

### L4. The sign-in sweep races the SDK's own input selection (Low)

**Where.** `src/server/http.ts` starts `sweepLegacyAfterSignIn` on every bootstrap; `KeyWayAccountSigner.getAddressObjs`
still lists the old secp256k1 address, so CCC's `completeInputsByCapacity` in the app can pick old-address cells for
a user transaction at the same time.

**What goes wrong.** Both transactions spend the same cell; whichever reaches the pool second is rejected. For the
user that means a transaction they approved and confirmed by email fails with a dead-cell error. No funds are at
risk.

**Fix.** Once recovery is on, keep the old address out of the SDK's input selection (report it only as
`legacyAddress`) and let the sweep own those cells, or have the sweep skip cells the pool already sees as spent.

### Informational

- **I1. The server alone can sign for any account.** `lit-actions/sign-ckb-digest.js` signs any 32-byte digest for
  any `pkpId`; the only gate is `LIT_USAGE_API_KEY`. This predates the branch and is outside its scope, but it means
  the premise "the server alone must not be able to steal" does not hold today. The branch adds an unattended use
  of that power (the sweep signs with no user interaction and its outflow is not counted toward daily amounts). The
  recovery design itself does not make it worse, and M2 shows what a weaker attacker (database write) gains.
- **I2. JoyID backups have not been exercised with a real passkey.** The builders say so; I confirm from
  `@joyid/ckb` 1.1.4 that `signChallenge(string)` opens the sign-message page with `isData: false` and that
  `ensureChallenge` compares against `base64url(utf8(challenge))`, which matches both the SDK and the verifier. If a
  real JoyID popup ever transformed the text, setup would fail at `verifyBackupOwnership` before anything was
  written, so the failure mode is "cannot add", not "added but useless". Still, a real run is needed before relying
  on JoyID backups.
- **I3. A backup can spend or rewrite the AdminList** (known, listed by the builders). Confirmed from the Omnilock
  source: the RC cell is looked up in cell deps, then inputs. Locking the list under something other than the
  account's own Omnilock would need a different args scheme, as the builders note.
- **I4. Verifier omissions are deliberate and I found no exploit in them.** High `s` is accepted (WebAuthn
  signatures are not normalised; a malleated signature authorises the same transaction, and witnesses are not in
  the transaction hash). rpIdHash, origin and user verification are not checked; a passkey only signs for its own
  relying party, so the key binding already ties the signature to JoyID.
- **I5. Apps can auto-approve.** `approveRecovery` and `approveBackupChange` are app-replaceable, so with a malicious
  app page the emailed code is the only user-facing gate. The code email names the backup and the consequence
  ("will be able to move everything in your account without KeyWay"), the request and the code are bound to one
  exact transaction digest, and five wrong codes burn the request. This is the same model as transactions; it holds
  as long as the email is read.
- **I6. The ownership challenge has no nonce.** A backup's proof over `recoveryBackupChallenge(account, backup)`
  stays valid forever for that account and backup. It can only be replayed by someone who also holds the user's
  session and reads their email, so it buys nothing extra today; a timestamp or server nonce would be cheap.
- **I7. The rescue page leaves the AdminList's 197 CKB and anything that is not plain CKB or a standard token.**
  Documented; the page says so. There is no way to retrieve the 197 CKB without other software.
- **I8. The rescue page's hosting.** `ckbkeyway.dev/rescue` is served by KeyWay's own Next app with
  `Cross-Origin-Opener-Policy: same-origin-allow-popups`. If the KeyWay deployment is hostile the page is too; the
  docs explain self-hosting, and the notice email links only the hosted page.

## What I checked and found sound

- **Omnilock administrator mode** (source read at commit `280dd97`): args `0x00 ‖ blake160(pk) ‖ 0x01 ‖ type hash`
  parse as auth, admin flag and `omni_root`; with no `omni_identity` in the witness the owner path runs and never
  reads the RC cell; with one, Omnilock requires the admin flag, gathers RCRules from the cell found by type hash
  (cell deps, then inputs), requires at least one whitelist rule and no emergency halt, checks the identity's SMT
  membership with mask 3, then verifies the identity by its own flag (0x12: keccak of the EIP-191 prefix, `83`,
  `CKB transaction: 0x` and the sighash in lowercase hex, recovered against the 20-byte id; 0xFD: 62-byte preimage,
  blake160 check, exec with `code_hash:hash_type:pubkey_hash:msg:sig`). KeyWay's `adminListData` (RCData union 0,
  RCRule, flags 0x02 = whitelist), `omnilockAdminWitnessLock` and `omnilockOwnerWitnessLock` match the molecule
  layouts.
- **Signature binding.** Every group is signed over its own sighash_all (CCC's `getSignHashInfo` and Omnilock's
  `generate_sighash_all` agree: transaction hash, first witness with the lock zeroed at its final length, the group's
  other witnesses, witnesses beyond the inputs). Two groups of one key (old secp256k1 and Omnilock) have different
  first witnesses and so different digests; one signature cannot satisfy both. Cross-network replay is impossible
  (cell deps and out points differ). Witness index alignment is correct for every builder in the branch.
- **The list record** lives in witness 0's `output_type`, which Omnilock and Type ID ignore and the owner signature
  covers; `readRecoveryList` refuses a record that does not hash to the cell's root. Witness 0 is always the signing
  group's first witness in KeyWay's own transactions.
- **Type ID derivation** (`hashTypeId(input0, 0)`), the AdminList's exact occupied capacity (197 CKB), the Omnilock
  minimums (95 CKB plain, 176 CKB xUDT) and the fee rate (1,500 shannons/KB; Fiber funding from Omnilock also 1,500)
  are right.
- **Policy checkers** `checkRecoveryTransaction`, `checkBackupChangeTransaction`, `checkLegacySweepTransaction`,
  `refuseAdminListSpend`, `refuseForeignOmnilockOutputs` and `checkRescueTransaction` do what their comments say
  against honest chain data; I could not find an output, input or fee shape they let through that they should not.
  Every output of the enable transaction, the list update and the sweep is the account's own lock; tokens move
  whole; the AdminList is never an input of ordinary signing or funding.
- **Approval gating.** Turning on, adding and removing always issue a `recovery` request with `requiresEmailCode`
  true, bound to the exact transaction digest and the backups; adding re-checks the ownership proof at apply;
  removal keeps at least one backup; the user lock serialises enable/apply; idempotent mutations prevent double
  sends. (Read, not executed: the Postgres suite needs a database I did not have.)
- **The SMT port** reproduces the crate's vectors in `tests/fixtures/recovery-smt-vectors.json` (1, 2 and 7 members)
  and the roots Omnilock accepted on testnet.
- **The verifier.** `contracts/build/joyid-webauthn` is byte-identical (sha256 `245458d7…2d48`) to the live cell at
  `0x333fa2ab…387b:0` on testnet, whose data hashes to `0x24306cbe…9720` as the SDK pins (`data1`, so it cannot
  change), and whose lock is secp256k1-blake160 with 20 zero-byte args. `cargo build` with the pinned 1.97.0
  toolchain reproduces the same bytes. Blob parsing bounds every length; the argument decoder refuses odd or oversized
  hex; exit codes fit `i8`; `overflow-checks` and `panic = "abort"` make any surprise a lock failure. Parity with the
  server's rules on 73 cases (duplicate and escaped keys, nesting and key-count limits, numbers, literals,
  surrogates, invalid UTF-8, challenge padding and case) with the one BOM divergence; 20,000 random blob mutations
  produce no panic and no false accept. Cycles about 6.5M per spend (builders' measurement), far below limits.
- **JoyID challenge encoding** per `@joyid/ckb` 1.1.4 source (`signChallenge`, `ensureChallenge`).
- **Fiber.** Channels opened after recovery close to the current lock (hosted: `ownLockScript` reads the wallet;
  browser: the funding signer's recommended address); settlement sweeps and the returned fee reserve go to the same
  address; older channels and nodes land at the old address and the sign-in sweep moves it. `refuseAdminListSpend`
  and `refuseForeignOmnilockOutputs` run on funding transactions too. A malicious Fiber peer gets nothing new from
  the branch.
- **Rescue page with an honest node.** Builds one transaction, every output to the destination, tokens one to one,
  refuses the account's own address, refuses the AdminList as input when the node is honest, signs once, checks the
  signed hash equals the reviewed one, dry-runs before sending. Confirmed against testnet in the control run.

## What I could not check

- The JoyID popup with a real passkey (needs a browser and a JoyID account); see I2.
- The Postgres-backed flows (`recovery-postgres.test.ts`, `legacy-sweep-postgres.test.ts`): no database here. I read
  them and the code paths they cover.
- The verifier under ckb-debugger: the download was refused by this environment and `cargo install ckb-debugger`
  needs `protoc` and did not finish. The library tests run on the host; the builders' VM runs and the testnet spends
  through the verifier stand for the VM path.
- The Lit action at runtime (no API key); its code was read.
- Mainnet: the rescue page's mainnet switch is untested by the builders and by me.
- The React dialogs in a browser; I reviewed the code and the builders' screenshots.

## Files added by this audit

- `tests/audit-fable51-rescue-rpc.test.ts`, `tests/audit-fable51-forged-recovery.test.ts`,
  `tests/audit-fable51-backup-phishing.test.ts`, `tests/audit-fable51-clientdata-parity.test.ts` and
  `tests/fixtures/audit-fable51-clientdata-cases.json` (all run by `npm test`; 214 tests, 197 pass, 17 Postgres-only
  skipped, 0 fail at the audit head). The PoC tests pass: each asserts that the weakness is present.
- `contracts/tests/tests/audit_fable51_parity.rs` (plus `serde`/`serde_json` dev-dependencies):
  `cargo test --release --test audit_fable51_parity`, 3 pass.
- `research/omnilock/audit-fable-5-1/`: `lib.ts`, `faucet.ts`, `balance.ts`, `enable.ts`, `rpc-burn.ts`,
  `owner-path.ts`, their outputs and `state.json` (addresses and hashes only).
