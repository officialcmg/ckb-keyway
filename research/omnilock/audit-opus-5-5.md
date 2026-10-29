# Omnilock account recovery: independent audit (opus-5-5)

Branch audited: `origin/omnilock-recovery` at `5ecfca1` (phase 6 results present), plus the code it calls on `main`.
PoCs: `tests/audit-opus-5-5.test.ts` (each test passes while its finding stands) and
`research/omnilock/audit-opus-5-5/` (testnet scripts, verifier fuzzing, SMT cross-check, outputs). No product code was changed.

## Summary

The on-chain pieces are in good shape. The WebAuthn verifier builds reproducibly to the committed binary, which is the
deployed binary and matches the SDK's code hash. It passes its CKB-VM tests and 220,000 random mutations without a
false accept, and its challenge binding is strict. The TypeScript SMT port matches `sparse-merkle-tree` 0.6.1 on 400
random lists. KeyWay's own recovery transactions (turning recovery on, backup changes, the sign-in sweep) are checked
independently of how they were built, and only send funds to the account's own address.

The problems are in what surrounds that code:

- The server can sign anything with any user's key.
- A backup can take permanent control of the backup list, and KeyWay doesn't notice. I proved this on testnet.
- The rescue page trusts whatever its CKB node says about cells.
- The Fiber settlement sweep breaks once recovery is on.
- Omnilock itself can be upgraded by one testnet key.

| Severity | Count |
|---|---|
| Critical | 0 |
| High | 1 |
| Medium | 4 |
| Low | 4 |
| Info | 3 |

## Findings

### H1. The KeyWay server alone can sign any transaction with any user's key, including list changes that add its own backup

**Where:** `lit-actions/sign-ckb-digest.js`, `src/server/lit.ts` `signCkbDigest`, and `src/server/general-signing.ts`
`sign`. The latter is also used by `recovery.ts` and `legacy-sweep.ts`.

**What goes wrong:** The Lit Action signs any 32-byte digest for any `pkpId` it is given, with no policy of its own. Every check is enforced
by the backend that calls it: transaction policy, the emailed code, refusing to spend the AdminList, and the
recovery checks. Anyone holding `LIT_USAGE_API_KEY` and a user's PKP id can therefore do the following without the
user's email:

- Drain any account, whether on secp256k1 or the Omnilock owner path.
- Sign a list-update transaction that adds their own backup. The "always needs the emailed code" rule and the notice
  email are both carried out by that same server.

Recovery makes this worse in one way. A one-off server compromise can plant a backup and then use M3 to make it
permanent. That leaves theft capability on every future deposit after the server is cleaned up and keys are rotated.
So "the server alone must not be able to steal" does not hold. Before recovery, rotating keys ended a compromise;
with recovery, it may not.

**Repro:** This is a code reading. `sign-ckb-digest.js` has no check except the digest's format. `sign()` signs whatever
digest the caller computed.

**Fix:** Move the policy into the Lit Action. At minimum, have the Action:

- recompute the sighash itself from the full transaction, and
- refuse any transaction that spends a cell whose type is a Type ID named by the account's Omnilock args (the AdminList).

Better still, require a user-held factor that the server can't fake. For example, have the Action verify the
emailed-code proof or a session signature itself.

### M1. With recovery on, a settlement key holding a minimum-capacity token cell can never be swept

**Where:** `src/sdk/browser/settlement-sweep.ts` `sweepSettlement`. Its destination is the account's Omnilock in
`create-keyway.ts` `sweepNow` and `managed-node.ts` `sweepHostedSettlement`.

**What goes wrong:** Token cells are re-created at the destination with their *old* capacity. A standard xUDT cell
at its exact secp256k1 minimum is 142 CKB, but the Omnilock lock (54-byte args) needs 176 CKB. CCC raises that output
to 176 CKB and then looks for 34 more CKB in *new* inputs, instead of taking it from the plain output it is
building. There are none, so the sweep throws.

Both sweep loops swallow the error and retry every 10 minutes. Neither the tokens nor any plain CKB at the settlement
key ever reach the account. This is what force-closed token channels leave behind. Backups can't reach these funds
either, because the settlement key isn't under the Omnilock. Before recovery the same cells swept fine.

**Repro:** `finding: with recovery on, a settlement key holding a minimum-capacity token cell can never be swept`.
The sweep is rejected with `Insufficient CKB, need 34 extra CKB` even though 5,000 CKB of plain cells are available.
The same cells sweep to a secp256k1 destination without error.

**Fix:** Size each token output as `max(capacity, occupied at destination)`, as `legacy-sweep.ts` already does. Take
the difference from the plain CKB, falling back to leaving the cell for a later sweep. Add a test with an Omnilock
destination.

### M2. The rescue page trusts its CKB node for cell contents: a lying node can burn the account's CKB as fee, or its tokens

**Where:** `src/rescue/rescue.ts`: `openRescueAccount`, `planRescue` and `checkRescueTransaction`. The same applies to
`readRecoveryList`.

**What goes wrong:** The transaction commits only to out points. Capacities, types and data all come from the node
and are never checked. The node's operator could be the default third-party `testnet.ckb.dev`/`mainnet.ckb.dev`, a
URL the user typed, or anyone tampering with the network path. That node can cause two kinds of loss:

- **Fee burn.** If it understates a cell's capacity, the page builds and has the backup sign a transaction whose real
  fee is the difference. The page's own fee check uses the false numbers, so it passes.
- **Token burn.** If it reports an xUDT cell as plain CKB, that cell is spent into a plain output. xUDT allows inputs
  to exceed outputs, so the tokens are destroyed.

The only hint the user gets is a lower balance on screen.

**Repro:**
- `finding: a lying CKB node can make the rescue page burn the account's CKB as fee`, and the same for tokens.
- Testnet (`testnet-adminlist-hijack.ts burn`, output in `testnet-run.out`): the page showed 100 CKB and a fee of
  0.00000765 CKB. The real inputs were 9,803 CKB and the real fee 9,703 CKB. `test_tx_pool_accept`
  **accepted** the transaction (dry run only, not sent).

**Fix:** For every input and the AdminList, fetch the creating transaction, check that its hash equals the out point's
`txHash`, and take the cell from that verified transaction. Then cap the fee against the verified total, and refuse
when the plain output plus token capacity falls far short of the verified inputs. Liveness can't be proven this
way, but a dead cell only makes the transaction fail.

### M3. A backup can move the AdminList to its own lock. KeyWay then can't remove it, keeps sweeping funds to the address, and the rescue page gives up

**Where:**
- Omnilock admin mode finds the RCE cell by type hash among cell deps *or inputs*, whatever its lock
  (`rce.h` `rce_gather_rcrules_recursively`).
- `src/server/recovery.ts` `planBackupChange` requires the list under the Omnilock.
- `src/server/legacy-sweep.ts` and the settlement sweeps keep sending to the Omnilock.
- `src/rescue/rescue.ts` `openRescueAccount` only looks for the list among the account's own cells.
- The SDK shows the backup list stored in the database, not the one on chain.

**What goes wrong:** The docs already say "a backup can spend the AdminList", but they understate the consequences. A
compromised backup can do this, and so can a server compromise combined with H1. The backup recreates the list with
the same Type ID and the same members, under a lock it controls. From then on:

- Omnilock still accepts that backup as administrator.
- The Lit key can never change the list again. KeyWay's remove fails with "The recovery list isn't this account's".
- No path exists to turn recovery off or move to a new address.
- Every sign-in sweep and settlement sweep keeps feeding new funds to an address the backup controls forever.
- The rescue page tells legitimate backups that "no backup can move the funds", although Omnilock would accept them.

The user is shown none of this.

**Repro:** Testnet run with throwaway keys (`testnet-adminlist-hijack.ts`, output in `testnet-run.out`):

| Step | Transaction / result |
|---|---|
| Turn recovery on (KeyWay's `planRecovery` + `checkRecoveryTransaction`) | `0x7c1e9c4f5d26cdac1e4442a2f80ba61457ec07ddb86fb5c4408b2e6abc73047c` |
| E1 recreates the AdminList under its own lock T | `0x72e8c34784d8fd1db89ff9534f90473bf4c562b596cfa915bae0cd1ff07a36c4` (committed) |
| KeyWay removing E1 | `planBackupChange`: "The recovery list isn't this account's" |
| Rescue page | "This address's recovery list isn't on chain…" |
| E1 spends the account, list under T as a cell dep | `test_tx_pool_accept` accepted, 1,560,082 cycles |
| Lit key (owner) takes the list back | rejected: `Inputs[0].Lock` (T's lock) |

Offline: `finding: once a backup moves the AdminList to another lock, …` shows that the sign-in sweep still targets
the Omnilock.

**Fix:**
- Lock the AdminList with a script that only the owner path can satisfy, for example a secp256k1 lock of the Lit key
  or a dedicated lock that rejects admin-path spends. This changes the address scheme, so do it before release.
- Failing that:
  - On every sign-in, compare the on-chain list's lock and members with the stored ones.
  - Warn the user and stop all automatic sweeps into the Omnilock when they differ.
  - Offer a "move to a new account" flow.
  - Have the rescue page find the list by type alone, as Omnilock does.

### M4. Omnilock can be upgraded by one testnet key (a multisig on mainnet)

**Where:** `ccc.KnownScript.OmniLock` is referenced by type hash. Output in
`research/omnilock/audit-opus-5-5/script-upgradeability.out`.

**What goes wrong:**
- **Testnet:** the Omnilock code cell (`0xec18bf0d…5d4602:0`, Type ID args `0x761f51fc…`) is locked by a single
  secp256k1 key, `0x9c26427b733e19f774e74312382946db9548093a`. Whoever holds that key can replace Omnilock and
  spend every recovery account.
- **Mainnet:** the code cell (`0xc76edf46…c842:0`) is under a secp256k1 multisig, `0xdcf67c4a…24fe`.

Turning recovery on moves a user from the genesis secp256k1 lock, which can't be upgraded, to this one. The docs do
say "upgradable by its deployer", but not that this means one key can take all the funds. The JoyID code cells are
likewise single-key on testnet and multisig on mainnet. They matter only for address parsing here, not for spending.

**Fix:**
- Reference Omnilock by data hash (`data1`) of an audited release, and deploy or pin that cell.
- Or state plainly in the recovery dialog who can upgrade Omnilock.

### L1. Recovery state is saved when the transaction is broadcast, not when it commits

**Where:** `recovery.ts` `recoverySetup` and `recoveryBackupChange`: broadcast, then `saveWallet`, then the notice email.

**What goes wrong:** Suppose an enable or removal transaction is accepted by one node and later dropped. A conflicting
spend could cause this, such as an app's pre-signed transaction (RBF), a Fiber funding transaction, or the fee reserve.
The account would then say recovery is on with an AdminList that never existed, or a backup would be "removed" while
it is still on chain. The user would also get a notice email saying so.

In the first case:
- recovery can't be re-enabled ("already on");
- the sign-in sweep moves funds to an Omnilock whose backups can't work;
- the rescue page refuses.

**Repro:** Code reading. Nothing waits for the transaction to commit.

**Fix:** Persist a pending state, confirm the commit (or re-read the chain on the next request) before marking the
change done, and send the notice only after it commits.

### L2. "Move everything without KeyWay" doesn't cover Fiber channel balances, settlement keys or the fee reserve

**Where:** `docs-site/content/docs/account-recovery.mdx` and the README security model.

**What goes wrong:** Several kinds of funds are outside the backups' reach:
- channel balances;
- force-close settlements, which go to the node's key (KeyWay's own, for hosted nodes);
- the 62 CKB fee reserve.

They sit under keys the backups don't control, and if KeyWay disappears they need KeyWay or Lit. Users reading
"everything" may keep large balances in channels.

**Fix:** Say this in the recovery docs and dialog.

### L3. Rescue destinations aren't checked for a deployed lock

**Where:** `planRescue`.

**What goes wrong:** `planRescue` accepts any valid full-format address, including one whose code hash matches no
deployed script. Funds sent there are lost for good.

**Fix:** Require the destination's code hash to be a known script, or the code or type hash of a live cell.
Otherwise, show a strong warning.

### L4. Third-party token cells can block the sweep and the rescue

**Where:** `legacy-sweep.ts` `sweepCellKind`, `rescue.ts` `rescueCellKind`, and `recovery.ts` `cellKind`.

**What goes wrong:** All three treat any cell with an xUDT code hash and at least 16 bytes of data as a movable token,
and add only the plain xUDT/RUSD deps. xUDT cells that need more to move, such as extension scripts or witness data,
make the whole transaction fail every time. Anyone can send such a cell to a public address. Because the rescue takes
the first 100 movable cells in out-point order, the page could be blocked for an account. I did not build such a cell
on chain.

**Fix:** Treat xUDT cells whose args carry flags as "other". Also, retry without any cell that the node's dry run
blames.

### I1. Backup ownership proofs have no nonce or expiry

**Where:** `recoveryBackupChallenge`.

**What goes wrong:** The challenge text binds the account and the backup but nothing else. One signature works for
turning recovery on, for adding the backup, and for re-adding it after removal, indefinitely. No benefit to an
attacker was found, since re-adding requires the emailed code.

**Repro:** `info: a backup's ownership proof has no nonce or expiry…`

**Fix:** Include the server's confirmation nonce in the challenge.

### I2. The verifier accepts high-s signatures and escaped JSON strings

Both are deliberate (WebAuthn doesn't normalise signatures, and the parser unescapes per RFC 8259). The only effect is
witness malleability: the transaction hash doesn't change. Fuzzing confirmed that nothing else is accepted.

### I3. `refuseForeignOmnilockOutputs` only matches Omnilock's type hash

An output using the Omnilock code through `data1` and the user's auth passes the check. It is only shown as a foreign
address, so nothing is mislabelled as the user's own. No theft path was found.

## Checked and found sound

- **Verifier binary:**
  - A local build with toolchain 1.97.0 is byte-identical to `contracts/build/joyid-webauthn`.
  - The on-chain cell `0x333fa2ab…387b:0` has data hash `0x24306cbe…9720`, which equals the SDK's code hash, and the
    cell is live under the all-zero secp256k1 lock (`verifier-deployment.ts`).
  - All 11 contract tests pass in CKB-VM (ckb-debugger 1.1.1), at about 6.5M cycles.
- **Verifier logic** (`verifier-fuzz/`, output in `verifier-fuzz.out`):
  - Strict JSON handling: duplicate or escaped-duplicate keys, nested or misplaced challenges, a BOM, trailing data,
    lone surrogates, depth, leading zeros, and the type field are all handled correctly.
  - The challenge is bound to the sighash.
  - The public key must hash to the identity.
  - Padding must be zero, the length is capped at 1024, and the version is checked.
  - 220k random mutations caused no panic and no forgery.
  - Omnilock's `verify_via_exec` checks the 62-byte preimage hash and computes the sighash itself. Its exec buffer is
    32 KB, so a 1024-byte signature fits.
- **SMT:** the TS port is identical to sparse-merkle-tree 0.6.1 on 400 random lists of 1–8 backups, including
  deep-forking keys, for 1,800 proofs (`smt-crosscheck.out`).
- **Signature binding:**
  - The owner path signs each group with its own witness length (65 vs 85), so the digests differ.
  - Admin-path signatures cover Omnilock's group sighash, which includes the transaction hash and therefore the out
    points, so they don't replay across transactions or networks.
  - One signature can cover two groups only when both groups' first witnesses are byte-identical. The signer then
    signs the whole transaction anyway.
- **Server checks:**
  - General signing and funding refuse to spend the AdminList.
  - `checkRecoveryTransaction`, `checkBackupChangeTransaction` and `checkLegacySweepTransaction` constrain inputs,
    outputs (own lock only), tokens and fees.
  - Each nonce is bound to its plan digest and to an emailed code, and is consumed.
  - Enables are serialised by `withUserLock`; sweeps by an advisory lock plus a pending-transaction record.
- **Rescue page:** it takes no URL parameters and is offered only over HTTPS or localhost. The destination is the
  only output lock, and the hash is re-checked after signing.

## Not checked

- A real JoyID popup and passkey: I used the phase stand-ins.
- Mainnet.
- Lit Chipotle's own guarantees.
- Fiber's handling of the Omnilock shutdown script on cooperative close.
- A poison token built on chain (L4).
- The React dialogs beyond reading the code.
