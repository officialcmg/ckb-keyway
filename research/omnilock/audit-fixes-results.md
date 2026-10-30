# Omnilock recovery: fixes for both audits

Branch `omnilock-audit-fixes`, from `omnilock-recovery` at `5ecfca1` with both audit branches merged
(`audit/omnilock-opus-5-5`, `audit/omnilock-fable-5-1`). Every proof-of-concept test from the audits now runs the
same scenario and asserts the fix. CKB testnet only, throwaway keys in `research/omnilock/audit-fixes/keys.json`
(gitignored, never printed). Scripts and their output are in `research/omnilock/audit-fixes/`.

## What changed, in short

- **The backup list has its own lock.** The AdminList is locked by the Lit key's Omnilock *without*
  administrator mode (`0x00 ‖ blake160(Lit key) ‖ 0x00`). Backups can't spend, move or rewrite it. The account's
  address is unchanged by this: Omnilock finds the list by type hash only.
- **Backups sign a readable text.** EVM and JoyID backups both sign:

  ```
  KeyWay recovery
  Move everything to ckt1…
  CKB: 9,834.99993392
  Tokens: none
  Fee: 0.0000246 CKB
  Transaction: 0x<sighash>
  ```

  Two new KeyWay exec verifiers rebuild it from the transaction on chain and accept nothing else. Flag 0x12 is
  gone.
- **Omnilock is pinned by data hash.** On testnet it runs from KeyWay's own copy of the official binary.
- **The rescue page doesn't trust its node** for cell contents.
- **Recovery records are anchored on chain**, by the server and by the SDK.
- **Recovery changes take effect only once committed.**
- **The audits' smaller findings are fixed** (sweep sizing, BOM, nonce, destination check, token extensions,
  input-selection race, docs).

## Findings

Line numbers are at the final commit. "Test" names a test in `tests/` (run by `npm test`; the `-postgres` files
by `npm run test:auth:postgres`) or in `contracts/tests/tests/`.

### Part 1: the backup list is locked to the Lit key (Opus M3, the precondition of Fable L2)

| | |
|---|---|
| Change | `adminListLock` `src/sdk/browser/account-lock.ts:104`. The enable transaction puts the list under it: `planRecovery`, and `checkRecoveryTransaction` refuses anything else (`src/server/recovery.ts:349`). The list update spends the list on that lock and the fee cells on the account's lock, so the Lit key signs both groups on the owner path (`recovery.ts:463`, `planBackupChange` :504, `checkBackupChangeTransaction` :572). `refuseAdminListSpend` (`account-lock.ts:233`) refuses the list by Type ID, by out point, and anything under its lock, everywhere except that list update. Readers find the list by Type ID (`readRecoveryList`, `recoveryListFrom` in `recovery-list.ts`); the rescue page looks under the owner-only lock (`src/rescue/rescue.ts:143`). |
| Tests | `audit-opus-5-5.test.ts` "M3 fixed: the AdminList is locked to the account's key alone…"; `recovery-flow.test.ts` (list lock, two owner witnesses, moving the list refused); `omnilock-recovery.test.ts` (nothing under the list lock is spent or paid by ordinary signing); `recovery-postgres.test.ts` (two 85-byte owner witnesses) |
| Testnet | Enable `0xe44afcb8ae5c43c28c555fce402297122b51f8e12fa7d41812adc03a94d2b7c0`. Add E2 `0x5042f4295d96cdc3a31f5a72c200eccc23b8a4598bbb6c87b4d4a0e8e3d1b8bc`. Remove E2 `0x40a93da31989304a170dab4ca5651dc87f3e10c1141c2e3bbe4e0d5d0b22dbc9` (address unchanged). Spends with each backup: see Part 3. Rejected dry runs: "E1 spends the AdminList to its own address" and "E1 moves the AdminList under a lock of its own", both Omnilock code 47 (`omni_lock.c:417`: an identity in the witness on args without administrator mode). |

The AdminList now holds 165 CKB (its lock args are 32 bytes shorter), down from 197.

### Part 2

**1. The rescue page trusts its node (Opus M2, Fable M1).**

| | |
|---|---|
| Change | `verifiedCell` (`rescue.ts:124`) reads every input and the AdminList from the transaction that created it, after checking that transaction's hash against the out point. Capacity, lock, type and data all come from there; a cell the node lists under the account but the chain locks otherwise is dropped. The AdminList comes from one place, under its owner-only lock, and `checkRescueTransaction` refuses it as an input by out point and by type hash (`rescue.ts:379`). The fee is checked against the verified totals. The page says plainly that the balance comes from the node (`app/rescue/rescue-view.tsx`). |
| Fable's proposed fix | It proposed a second node to cross-check against. Rather than that, the page uses the creating transaction checked by hash: one node is enough, and a lying node can then only leave cells out. |
| Further binding | The readable approval (Part 3) also names the fee, which the verifier computes from the real inputs, so a lie the page missed would make the backup's signature fail on chain. |
| Tests | `audit-opus-5-5.test.ts` "M2 fixed…" (CKB and tokens; a swapped transaction is refused); `audit-fable51-rescue-rpc.test.ts`, all three ("M1 fixed…") |

**2. Forged recovery record (Fable M2).**

| | |
|---|---|
| Change | `KeyWayRecovery.enableTransactionHash`. `verifyRecoveryAnchor` (`account-lock.ts:152`) checks four things: the enable transaction is committed and is the one asked for; its input 0 was locked by the user's secp256k1 lock (read from the transaction that created that cell, hash-checked); `hashTypeId(input0, 0)` equals the list's Type ID args; output 0 is the list under the owner-only lock. Results are cached per record and process. |
| Server | The server runs it before the sign-in sweep (`legacy-sweep.ts:60`), in `/bootstrap` (`http.ts:200`), before general signing (`transaction-policy.ts:115`), before channel funding (`funding-transaction.ts:50`), for the hosted node's lock (`http.ts:142`) and before backup changes (`recovery.ts`, `planBackupChange`). |
| SDK | `bootstrapKeyWay` runs the same check on what `/bootstrap` returns (`checkWalletRecovery`, `src/sdk/browser/bootstrap.ts:44`). |
| Tests | `audit-fable51-forged-recovery.test.ts`, all three; `legacy-sweep-postgres.test.ts` "signs nothing for a recovery record the chain doesn't back" |

**3. Settlement sweep breaks once recovery is on (Opus M1).**

| | |
|---|---|
| Change | `sweepSettlement` (`src/sdk/browser/settlement-sweep.ts:73`) sizes each token output as `max(capacity, occupied at the destination)` and takes the difference from the plain CKB. Token cells the plain CKB can't cover stay on the key for a later sweep. A remainder too small for a plain cell at the destination (95 CKB at an Omnilock) joins the reserve, rides in a token cell, or waits. |
| Test | `audit-opus-5-5.test.ts` "M1 fixed…", with an Omnilock destination: 142 → 176 CKB from 5,000 CKB plain; 90 CKB tops up one cell; 61 CKB tops up one of two |

**4. Recovery state saved on broadcast (Opus L1).**

| | |
|---|---|
| Change | Enable and apply store `wallet.recoveryPending` (`recovery.ts:118`, :468) before sending; a refused send clears it. `settleRecoveryChange` (`recovery.ts:153`) applies the change and sends the notice email only once the transaction is committed, and drops it if rejected or unknown 10 minutes after sending. It runs on every sign-in (`http.ts`) and on the new `status` operation, which the SDK polls until the change settles (`waitForCommit`, `src/sdk/browser/account-recovery.ts:84`). New changes are refused while one is pending. |
| Tests | `recovery-postgres.test.ts` (pending until committed, no notice before; a rejected change is dropped and can be retried); `account-recovery-sdk.test.ts` (waits for commit; a dropped change is reported) |

**5. BOM divergence (Fable L1).**

| | |
|---|---|
| Change | `new TextDecoder("utf-8", { fatal: true, ignoreBOM: true })` (`src/sdk/browser/webauthn.ts:102`) |
| Test | `audit-fable51-clientdata-parity.test.ts`: the BOM case no longer records a divergence, and a new test asserts that no case does. `contracts/tests/tests/audit_fable51_parity.rs` agrees on all 73 cases. |

**6. Ownership proof has no nonce or expiry (Opus I1, Fable I6).**

| | |
|---|---|
| Change | The challenge text adds `Request: <nonce>` and `Valid until: <time>` (`recovery-backups.ts:177`). The nonce is `<expiry ms>.<random>.<HMAC(user, expiry, random)>` (`issueBackupChallenge` / `checkBackupChallenge`, `recovery.ts:187`/:193), valid for 15 minutes and bound to the user. It is checked before the signature. The SDK fetches it (`requestBackupChallenge`, operation `challenge`). |
| Tests | `audit-opus-5-5.test.ts` "I1 fixed…"; `recovery-flow.test.ts` (another user's, expired and forged nonces refused); `recovery-backups.test.ts` |

**7. Rescue destination may be unspendable (Opus L3).**

| | |
|---|---|
| Change | `checkDestinationLock` (`rescue.ts:337`) accepts only the network's known locks (CCC's table: secp256k1, the multisigs, ACP, JoyID, Omnilock, PW, Nostr) and KeyWay's pinned Omnilock. Anything else is refused with a plain explanation. |
| Why not "a live cell's code or type hash" | The node's RPC can't look a script up by its hash, so the page can't check that. |
| Test | `rescue.test.ts` "refuses a bad destination" |

**8. Third-party token cells block sweeps and rescues (Opus L4).**

| | |
|---|---|
| Change | `hasPlainTokenArgs` (`src/sdk/browser/tokens.ts:26`) treats xUDT args other than the 32-byte owner hash (optionally with zero flags) as "other", in the legacy sweep, the enable plan, the settlement sweep and the rescue page. When a dry run blames one input's type script, the cell is left out and the transaction rebuilt: in the sign-in sweep automatically (`blamedTokenCell`, `legacy-sweep.ts:119`, up to 3 cells), and on the rescue page after a new signature (`blamedInput`/`sendRescue`, `rescue.ts:416`). |
| Tests | `legacy-sweep.test.ts` "leaves xUDT cells whose args carry extension flags…"; `legacy-sweep-postgres.test.ts` "leaves a token cell the node refuses to move…"; `rescue.test.ts` "leaves out a token cell the node blames…" |

**9. Sign-in sweep races the SDK's input selection (Fable L4).**

| | |
|---|---|
| Change | With recovery on, `KeyWayAccountSigner.getAddressObjs` returns only the Omnilock address (`account-lock.ts:295`), so CCC never selects old-address cells; `recovery.legacyAddress` still names it. |
| Test | `omnilock-recovery.test.ts` "SDK signers use the account's current lock…" |

**10. Docs (Opus L2, Opus M4, Fable I7).**

`docs-site/content/docs/account-recovery.mdx` gains "What a backup can't move": Fiber channel balances,
force-close settlements at the node's key, the fee reserve, the AdminList's 165 CKB, and cells the page doesn't
move. It also covers the pinned Omnilock and its mainnet trade-off, the readable approval, the chain check and
committed-only changes. The release notes, `src/rescue/README.md`, `contracts/README.md` and the README's
security section are updated too.

### Part 3: readable backup approvals (Fable M3)

| | |
|---|---|
| Format | `contracts/keyway-approval` (`approval_text` `lib.rs:91`, `full_address` :197) and its TypeScript twin `src/sdk/browser/recovery-approval.ts` (`recoveryApprovalText` :43, `rescueApproval` :63). On chain, `chain::rescue_text` (`chain.rs:26`) reads the outputs, their locks, capacities, types and data lengths, the inputs' capacities, and the group's script hash. It refuses anything but a rescue: at least one output, all to one lock that isn't the account's, no untyped data, outputs ≤ inputs. |
| EVM | `contracts/evm-personal-sign`: exec (0xFD) with the address as the 20-byte id. It checks an EIP-191 `personal_sign` of the text with k256 recovery and keccak; v may be 27/28 or 0/1. |
| JoyID | `contracts/joyid-webauthn` keeps its structure. Blob version 2 adds a network byte, and the challenge is base64url(text). |
| SDK | Backup kinds and record version 2 (all exec entries, `recovery-list.ts`); `prepareRecoverySpend` / `signRecoverySpendWithEvm` / `signRecoverySpendWithJoyId` (`recovery-spend.ts:49`–:75). Flag 0x12 is removed everywhere (`evmOmnilockMessage` and friends deleted). |
| Rescue page | Shows the exact text before asking for the signature (`plan.approvalText`). |
| Text size | Without the account line, the longest text is 480 bytes. As a JoyID challenge, with Chrome's extra clientDataJSON key, that makes a 1,015-byte blob. With the account line, an Omnilock destination alone made a 1,058-byte blob, over Omnilock's 1024, so the account line was dropped as the task allowed. The sighash and every other line stay. |
| Tests | `contracts/tests/tests/approval.rs`: Rust text vs the SDK on 400 cases, including 38 too long; bech32m vs CCC on all 400 random scripts (all hash types, both networks, args 0–259 bytes); both verifiers in CKB-VM on 120 random transactions from the SDK's builder (76 accepted, 44 refused as not a rescue, each exactly as the SDK decides); replays, wrong lines, old format, wrong network, foreign key; 40,000 signature mutations without a panic or false accept; the longest text fits 1024 bytes. `verifier.rs` (11 WebAuthn cases, ported); `audit_fable51_parity.rs`; the audit's own `verifier-fuzz` harness, updated (220,000 mutations, no accept). TypeScript: `audit-fable51-backup-phishing.test.ts` "M3 fixed…", `account-recovery-sdk.test.ts`, `rescue.test.ts`, `recovery-flow.test.ts` (replays the testnet proof offline from `tests/fixtures/recovery-audit-fixes.json`). |

Testnet, with an EVM key standing in for a wallet (E1) and a P-256 key answering like JoyID's page (J1):

| Step | Result |
|---|---|
| E1, correct approval | dry run accepted, 8,034,695 cycles (whole transaction) |
| J1, correct approval | dry run accepted, 7,333,084 cycles |
| J1 rescue to D1 (the rescue page's code) | `0xe7a8a2c4464efb3558fc351efd697b2ce4f9ef7f6a7c4b000c8a9c6bc5d8100a`, 9,834.99993392 CKB |
| Refund the account | `0x0afb8483ccd97588339b70b9e52941bdf7eadd4ee25d452b445d013f3610788c` |
| E1 rescue to D2 | `0xbaf1690323464a7b430eafbdcfbb10e745fc82688d2c04ad3a0796e06495e2dd`, 8,999.99998975 CKB |
| Correct text for D1 replayed on a transaction to D2 | rejected: E1 code 101 (recovers another address), J1 code 107 (wrong challenge) |
| Correct text, one shannon less arriving | rejected: 101 / 107 |
| Right sighash, wrong destination line | rejected: 101 / 107 |
| Old `CKB transaction: 0x…` format | rejected: 101 / 107 |

The texts the backups signed are in `research/omnilock/audit-fixes/joyid.out` and `evm.out`.

### Part 4: Omnilock pinned (Opus M4, Fable L3)

| | |
|---|---|
| On chain | Testnet official cell `0xec18bf0d…5d4602:0`: 139,936 bytes, data hash `0x6b29b6f10346b43c540e53806ba88ba0fe3a0c3a29d7448ef555840c8f8318fa`, Type ID locked by one secp256k1 key. Mainnet official cell `0xc76edf46…c842:0`: 123,552 bytes, data hash `0x768f306681da232ceb0b94f436c5f813377179762a831c5ad8797bd4fd2d118d`, under a multisig. The two are different builds. The dep group CCC lists for Omnilock is the genesis secp256k1 group (secp256k1_data, which the owner path needs). |
| Testnet decision | 140,000 CKB was affordable from faucet claims, so KeyWay deployed its own copy of the identical testnet bytes: `0xf4ce65847089d24bbc8e7d999f396d4227d34376bbfef0f5e3c11967c5a13271:0`, under secp256k1 with 20 zero-byte args. The deploy script refuses bytes whose hash isn't `0x6b29…18fa`. Deps: the genesis secp256k1 dep group and that cell. |
| Mainnet | There are no funds to deploy a copy, so the official cell is used by data hash. An upgrade can't change the code for KeyWay accounts, but replacing the cell would remove the dep until anyone redeploys the same bytes: funds frozen, never stolen. |
| Stored | `KEYWAY_OMNILOCK` (`account-lock.ts:18`). `KeyWayRecovery.omnilock` stores the code hash, hash type and cell deps at enable time, and `parseRecovery` accepts only KeyWay's deployments with their exact deps. They are used for the account lock, list lock, sweeps, signing, funding deps (`fundingLockCellDeps`) and the rescue page (`parseKeyWayAddress` accepts only KeyWay's code hash). `refuseForeignOmnilockOutputs` checks KeyWay's deployments as well as CCC's, which also closes Opus I3. |
| Tests | `omnilock-recovery.test.ts` (deps, parseRecovery refuses CCC's type-based Omnilock and other deps); `rescue.test.ts` (an address under CCC's Omnilock isn't a KeyWay address); `recovery-flow.test.ts` |

Recovery addresses change as a result. There's no migration, as asked: a stored record from before these fixes
fails `parseRecovery`.

## Verifier deployments

All are on testnet, under secp256k1 with 20 zero-byte args (unspendable), referenced by `data1`. They were
deployed by `research/omnilock/audit-fixes/deploy-verifiers.ts` and recorded in `research/omnilock/audit-fixes/state.json`.

| Binary | Deploy tx (index 0) | Data hash | Size | sha256 |
|---|---|---|---|---|
| `contracts/build/evm-personal-sign` | `0xff16f2aa117ba8e67aeb8946a8d3cb0c5f4627eab4fd8d7d5ecd938d7fa9014f` | `0x33bd1c699b633d685a6f60f6b0ca16fe8bb896f81323926ca6e0671bf8ab3c88` | 89,768 | `51419f064dddb633…` |
| `contracts/build/joyid-webauthn` (v2) | `0xb99678308cde0a54f856a00ec1e2ec46a318cdf05ef375cc381933dc00c7fb17` | `0xf1185da23bf04b638010038b40ec64b587654db5cb98eb39f0373ad8919bcd89` | 41,200 | `bac188bbcd86f227…` |

Reproducible build: the check builds a fresh `git archive` of `contracts/` in another directory with the pinned
toolchain (1.97.0, `cargo build -p joyid-webauthn -p evm-personal-sign --release --target riscv64imac-unknown-none-elf`),
and `cmp` against `contracts/build/` showed identical bytes for both. The deployed cells' data hashes equal the
SDK's code hashes (`EVM_PERSONAL_SIGN_VERIFIER`, `JOYID_WEBAUTHN_VERIFIER`).

## Checks

| Check | Result |
|---|---|
| `npm ci` | ok |
| `npx tsc --noEmit -p tsconfig.json` | ok. The phase 2–5 testnet scripts and the Opus hijack script are excluded: they ran against the replaced design. |
| `npx tsc -p tsconfig.sdk.json --noEmit` | ok |
| `npm test` | 205 pass, 17 skipped (they need Postgres), 0 fail; with `KEYWAY_AUTH_TEST_DATABASE_URL` set, 240 pass, 11 skipped |
| `npm run test:auth:postgres` | 36 pass, 0 fail |
| `cargo test --release` in `contracts/` | 19 pass, in CKB-VM through ckb-debugger 1.1.1 |
| `npx next build` | ok |
| `docs-site`: `npm run build` | ok |

## Not changed, but relevant (out of scope: Opus H1, Fable I1)

The Lit Action still signs any digest for any PKP the server names. The chain anchor stops a database write alone
from redirecting an account. It doesn't stop someone holding the Lit API key: they can still sign a list update
adding their own backup, because the emailed code and the notice are enforced by the same server.

What is new since the audits:

- Backups now need a signature over readable text, so a backup planted that way still can't move funds unseen by
  that backup's owner, but the attacker owns that backup.
- KeyWay's own list update is now the only way to change the list, and only the Lit key can sign it. This makes
  the Lit Action the single point to harden.

## Founder's test with a real JoyID passkey and a real EVM wallet

The cloud session had neither. The demo page (`/app`) is served with `Cross-Origin-Opener-Policy: same-origin`
for Fiber, which blocks JoyID's popup, so JoyID needs a page without it (as the rescue page has).

EVM wallet (testnet):

1. `npm ci && npm run build:staging && npm run dev`. Open `/app` and sign in with an email.
2. Send 1,000 testnet CKB to the shown address (faucet.nervos.org).
3. Recovery card: "Turn on with an EVM wallet".
   - The wallet shows the challenge, ending in `Request: …` and `Valid until: …`. Sign it.
   - Approve the dialog and enter the emailed code.
   - The card switches only after the transaction commits, and the "Account recovery is on" email arrives after
     that.
4. Open `/rescue`. Paste the new address, look it up, connect the same EVM wallet and enter a destination
   address from another wallet.
5. Check that the page's text and the wallet's `personal_sign` prompt are the same six lines: your destination,
   the CKB, "Tokens: none", the fee and the transaction hash. Sign. The page should report "Sent", and the
   explorer should show everything at the destination.

JoyID passkey (testnet):

6. On a page without `Cross-Origin-Opener-Policy: same-origin` that uses `KeyWayProvider` (for example a new
   route with `fiberNode="managed"` and no COOP header in `next.config.ts`), call
   `recovery.addBackup(await recovery.createJoyIdBackup(new JoyId.CkbSigner(new ccc.ClientPublicTestnet(), "KeyWay", icon)))`
   with your JoyID account.
   - JoyID should show the recovery challenge as text.
   - Approve, and enter the emailed code.
7. Fund the account again and open `/rescue`. Connect JoyID and pick a destination.
8. JoyID's sign screen should show "Sign Request from KeyWay rescue", the origin, and the same six lines as the
   page. Sign; the page should report "Sent".
9. If anything shows a different text, or the node refuses with code 107, stop there. Send the text the page
   showed and the error.
