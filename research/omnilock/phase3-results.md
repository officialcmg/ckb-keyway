# Omnilock opt-in recovery, phase 3: the sign-in check — testnet results

When a recovery user signs in, the server moves anything it can from the account's old secp256k1 address to its
Omnilock address. No monitoring service. Code: `src/server/legacy-sweep.ts`, hooked in `src/server/http.ts`
(`bootstrapRequest`), migration 17 (`keyway_v2_legacy_sweeps`).

Run on CKB testnet on 2026-10-29 with fresh throwaway keys (`phase3/keys.json`, gitignored, never printed): **K**
stands in for the account's Lit key, **E** is its EVM backup, **I** sends to K's old address and issues a test xUDT.
One faucet claim of 10000 CKB each to K and I.

| Step | Result | Transaction |
|---|---|---|
| 1. Turn recovery on (`phase3/step1-enable.ts`, phase 2's flow through `recoverySetup`) | **PASS** | `0xbe07c168bc4dfcf5189492c5815afda17e7fc30038a795d1bd0d1d389f08cb5c` |
| 2a. I sends to K's old address: 300 CKB, 70 CKB, 142 CKB holding 1,000,000 of a test xUDT, a 70 CKB cell with data `0x1234` | sent | `0x4056acb3f6f0a8f3b55c48486d23cae6241645e671871e097f24494ae015c114` |
| 3a. Sign-in sweep, three sign-ins at once (`phase3/step3-signin.ts mixed`) | **PASS** | `0x3e2684ef105a19ae452336b58429be91c2a79de7cf18f5dcd6031eff70a2f288` |
| 2b. I sends one lone 142 CKB cell holding 500,000 of the token | sent | `0xc6c70101ba1d2be34610fefada860f7afbeba32d73b6992d83450c3109d52cb9` |
| 3b. Sign-in sweep with the top-up from the new address (`phase3/step3-signin.ts lone-token`) | **PASS** | `0xe993508811cfea891534f06e21e49907a71455c1a5a29099d3c8c34dd3e7f76d` |
| Negative: the same shapes with any other destination (dry runs) | refused by the policy | dry runs only |

Every sent transaction was dry-run with `test_tx_pool_accept` first and waited on until committed.

- K old (secp256k1): `ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqwfhy973zzyurc5z9ald8hpn93vrjurf6sqfpcmg`
- K new (Omnilock): `ckt1qrejnmlar3r452tcg57gvq8patctcgy8acync0hxfnyka35ywafvkqgqexush6yggns0zsghha57uxvk9swtsd82qy4uv08ar4fe9cuqhek9cy2m8uhakj6aftts5wtwvru6v49aejqv5p46du5`
- Test xUDT: type args = I's lock hash `0x6571202c…d909`, type hash `0x58675e8f…6b15` (CCC's testnet xUDT deployment).

## What happened on testnet

**3a** (inputs 300 + 70 + 142 = 512 CKB; 758 bytes, 1,649,825 cycles, fee 0.00001137 CKB at 1500 shannons/KB):

- Output 0: the token cell at the new address, 176 CKB, data `0x40420f00…` (1,000,000), one-to-one with its input.
- Output 1: one plain cell at the new address, 335.99998863 CKB = 512 − 176 − fee. The 70 CKB cell, below the
  95 CKB Omnilock minimum on its own, was merged into it.
- Left at the old address and logged: the 70 CKB cell with data (`…c114:3`).
- The three concurrent sign-ins returned `swept`, `busy`, `busy`; one transaction was built and sent.
- A sign-in while it was in the mempool returned `{ status: "pending", transactionHash: 0x3e2684ef… }` and built nothing.
- A sign-in after commit returned `empty` (only the cell with data remains).

**3b** (lone token cell; 864 bytes, 3,055,459 cycles, fee 0.00001296 CKB):

- 142 CKB can't hold the token at the 54-byte Omnilock lock (176 CKB). The planner added the largest plain cell at
  the new address (9802.99999019 CKB) as a second input, signed by the same key on the Omnilock owner path (85-byte
  witness). Outputs: the token cell (176 CKB, data `0x20a10700…` = 500,000) and the plain cell back to the new
  address, 9768.99997723 = 9802.99999019 + 142 − 176 − fee. Concurrent sign-ins again gave `swept`, `busy`, `busy`;
  then `pending`, then `empty`.

Final balances: old address 0 CKB plain (the 70 CKB cell with data stays); new address holds the AdminList (197),
both token cells (176 each, 1,000,000 + 500,000 of the token), 335.99998863 and 9768.99997723 CKB.

**Negative dry runs.** Before each real sweep, `step3-signin.ts` took the planned transaction, pointed every output
at another destination, signed it with K and ran both the policy and `test_tx_pool_accept`:

| Destination | `checkLegacySweepTransaction` | Chain dry run |
|---|---|---|
| I's address | refused: "output 0 goes somewhere other than the account's recovery address" | accepted |
| K's old address | refused (same) | accepted |
| An Omnilock of K's key pointing at another AdminList | refused (same) | accepted |

Same results for 3a and 3b. The chain would accept each of them, so the policy is what stops them.
(`phase3/state.json` holds the full results.)

## Design

**Hook: `/bootstrap`.** Every sign-in ends in a bootstrap call: the SDK calls it right after `verify-code` and on
every page load with a stored session, in both Fiber modes (the browser node's `connectKeyWay`, and `nodeMode:
"managed"` from the provider and `connectManagedKeyWay`). `verify-code` itself is too early (a first sign-in has no
wallet yet) and doesn't read the wallet. `bootstrapRequest` returns its response first; when the wallet it returns
has `recovery`, it calls `sweepLegacyAfterSignIn(user)`, which only schedules the sweep with `setImmediate` and
logs any failure (`[keyway] old address sweep failed`). Signing in never waits for it or fails because of it. A
failed sweep leaves nothing behind, so the next sign-in tries again. A managed-mode bootstrap returns early in
`bootstrapLocked`, and the sweep still runs, because the hook is in the HTTP handler.

**Signing without the user's session.** The server signs with `sign()` in `general-signing.ts`, the same path as
every other signature: the `sign-ckb-digest` Lit action, run with the server's `LIT_USAGE_API_KEY` and the
wallet's PKP id, with the recovered public key checked against `litPublicKey`. The user's session isn't needed (the
sweep reads the wallet from the database again under its lock), so it can run after the response. The old lock is
the secp256k1 lock of that key, so `signAccountGroups` writes a 65-byte witness; when a top-up cell joins, the
Omnilock group gets the 85-byte owner witness from the same key. Each sweep counts as a signing event
(`recordSigningEvent`), but nothing goes into `keyway_v2_signed_outflows`/`keyway_v2_token_outflows`, so it doesn't
count toward the daily email-confirmation amount. `sign()` now takes only `{ wallet, signDigest }`; that is the
only change outside the new file and the hook.

**Destination.** `omnilockArgsFor(litPublicKey, recovery.adminListTypeHash)` with CCC's Omnilock deployment,
computed on the server from the stored key and AdminList type hash (`parseRecovery` already checks the stored
`omnilockArgs` against them). No request input reaches the sweep at all.

**Policy (`checkLegacySweepTransaction`), exactly this shape:**

- Version 0, no header deps.
- Inputs: at least one cell of the old secp256k1 lock, each plain CKB or a standard token (xUDT, sUDT, or
  xUDT-compatible like RUSD, with at least a 16-byte amount), plus at most one plain cell of the account's own
  Omnilock. Never the AdminList, never anyone else's cell.
- Outputs: every one locked by the account's Omnilock; at most one plain output, with no data; the other outputs are
  the moved token cells, one-to-one with their inputs' type and data. No other type script.
- Fee positive and within `feeRateCap()`.

The sweep runs this check on the built transaction before signing.

**What moves.** Plain CKB (no type, no data) and standard tokens, as `recovery.ts` and the settlement sweep already
treat them, now with sUDT too (its cell deps are added). Everything else stays and is logged with its out point,
type code hash, data size and capacity: Nervos DAO deposits, Spore/NFTs, unknown types, cells with data, and token
cells with less than 16 bytes of data. At most 60 cells per sweep; the rest moves at a later sign-in.

**Amounts below the Omnilock minimum.** The minimum cell at the 54-byte Omnilock lock is 95 CKB plain and 176 CKB for
a standard xUDT, which hold 61 and 142 CKB at the old lock. Small payments and token transfers to the old address
usually arrive at exactly those secp256k1 minimums, so most of them can't move one cell to one cell. The planner
tries, in order:

1. Merge every plain cell into one plain output; token cells get exactly their Omnilock minimum. Used when what is
   left after the token cells and the fee makes a 95 CKB cell.
2. With tokens, no plain output: what is left goes into the first token cell. Used when it covers the fee but not
   another 95 CKB cell.
3. Top-up: the largest plain cell at the new address joins as an input and the merged plain output goes back to the
   new address. This covers a lone token cell (142 → 176 CKB) and a lone small plain cell (say 70 CKB). The funds
   only move between the user's own two addresses, and the fee still comes out of the pooled CKB.
4. Otherwise (no plain cell at the new address big enough), nothing is sent. The sweep logs the shortfall and waits
   for a later sign-in.

Why the top-up: without it, a token sent to the old address would stay there until someone also sent 34 CKB of
plain CKB to the old address, and nobody does that once the account's visible address has changed. The cost is one
of the new address's cells in a transaction the user didn't start. See the open questions.

**No double sends.**

- Concurrency: the sweep runs under `pg_try_advisory_lock(hashtextextended('keyway-legacy-sweep:<user>', 0))` on a
  reserved connection. A sign-in that can't take the lock returns `busy` at once and doesn't wait.
- Mempool: before sending, the signed transaction's hash is written to `keyway_v2_legacy_sweeps` (one row per user).
  Writing it first means a crash right after sending can't lead to a second transaction. The next sign-in asks the
  node about that hash (`lastSweepDecision`):
  - `sent`, `pending` or `proposed`: wait, build nothing.
  - `committed`: its inputs are left out of the next plan, because the indexer can still list them for a while.
  - `rejected`, or unknown for more than 10 minutes after sending: forget it.
  - Unknown for less than 10 minutes: wait, because the node may not have seen it yet.
  
  A send that fails deletes its row.
- The plan is deterministic (cells sorted by out point), so a rebuild over the same cells gives the same transaction
  hash, never a conflicting one.

## Fiber: where each payout lands

| Path | Pays to | After recovery |
|---|---|---|
| Channel opened **before** recovery, cooperative or force close, either mode | its `shutdown_script`, fixed at open = old secp256k1 lock (KeyWay refuses a `close_script` on `shutdownChannel`) | old address → **sign-in check** |
| Hosted channel opened after recovery | `open-channel` sets `shutdown_script` from `ownLockScript(user)`, which reads the wallet fresh → `currentLock` | new address directly |
| Browser channel opened after recovery | `shutdown_script` = the CCC funding resolver's `signer.getRecommendedAddressObj()`; `RemoteCkbSigner` with `recovery` returns the Omnilock | new address, **if** the browser node started after recovery was on; a node started before keeps the old signer until it restarts → old address → **sign-in check** |
| Hosted force-close settlement (`sweepHostedSettlement`) | destination `ownLockScript(user)`, read fresh each sweep | new address directly |
| Browser force-close settlement (`create-keyway.ts` `sweepNow`) | `fundingSigner.getRecommendedAddressObj()` | new address if the node started after recovery; otherwise old address → **sign-in check** |
| Fee reserve returned once every channel is settled | the same two settlement sweeps with `keepReserve = 0` | as the two rows above |
| Channel funding change, fee reserve payment | spent from the account by `RemoteCkbSigner`/`KeyWaySigner` with `recovery`; change goes to the recommended (Omnilock) address | new address |

So the sign-in check is what moves funds from:

- channels opened before recovery was turned on (every close of them);
- a browser node that was already running when recovery was turned on (its channel opens, settlements and returned
  fee reserve until it restarts);
- anyone paying the old address.

## Tests

- `tests/legacy-sweep.test.ts` (offline, 5 tests):
  - Selection: plain merged into one output; xUDT and sUDT moved one-to-one; DAO, unknown type, cell with data and
    token cell with a short amount left; the 65-byte witness.
  - Committed inputs are skipped.
  - Amounts below the minimum: the top-up from the largest plain cell (never the AdminList) with the 85-byte
    Omnilock witness; `short` with no cell to top up from; leftover kept in a token cell; a lone 142 CKB token cell.
  - Policy: refuses every other destination (a stranger, the old address, another Omnilock of the key, a different
    AdminList), an extra output, a second plain output, data or an unknown type on an output, a changed token amount
    or type, a fee too high or negative, a foreign input, the AdminList as input, no old-address input, two
    new-address inputs, and header deps.
  - The mempool rule (`lastSweepDecision`).
  - The after-sign-in start returns at once and only logs a failure.
- `tests/legacy-sweep-postgres.test.ts` (5 subtests, added to `npm run test:auth:postgres`):
  - Three concurrent sweeps give one broadcast, with the others `busy`.
  - No outflow recorded; a signing event recorded.
  - `pending`/`proposed` isn't rebuilt even after new funds arrive.
  - After commit, the old inputs are skipped and the new cell moves.
  - A rejected sweep is rebuilt with the same hash; a failed send leaves no row and is retried.
  - An unknown hash is waited for, then forgotten after 10 minutes.
  - An account without recovery gives `off`; nothing at the old address gives `empty`.
- `npm test`: 180 tests, 164 pass, 16 skipped (the Postgres ones), 0 fail.
- `npm run test:auth:postgres`: 29 pass, 0 fail.
- Both `tsc` configs are clean.

## Open points

- **Top-up from the new address.** It spends one of the user's Omnilock cells in a transaction the user didn't start,
  right after sign-in. If the user signs a spend of that same cell at the same moment, one of the two transactions
  fails. A failed sweep is retried at the next sign-in; a failed user transaction can be signed again. The
  alternative is to skip the top-up and wait, but then tokens at the old address stay there in practice.
- **Pre-recovery channels close to the old address** because their shutdown script was fixed when they opened. For
  a cooperative close, KeyWay could pass `close_script` = the account's current lock instead of refusing it. That
  would need its own check (Fiber's support for an Omnilock close script, and the policy in `fiber-methods.ts`).
- The general signing policy still lets the user spend old-address cells (`accountLocks` includes the secp256k1
  lock). A user transaction and a sweep over the same cells conflict harmlessly: one fails, and the sweep retries.
- Funds wait at the old address until the next sign-in, by design. They are still the user's, and the Lit key
  spends them.
- Migration 17: the other session working on `omnilock-recovery` may also add a migration 17. Renumber whichever
  merges second.
- The sweep runs on every bootstrap of a recovery account. Each run costs one try-lock, one indexer query and,
  rarely, one `get_transaction`; no rate limit was added.
