# Send limits enforced inside Lit, and back-to-back sends across clients

Status: implemented on branch `send-limits`. CKB testnet only. Builds on `research/lit-policy/README.md`; read its
section (d) and "What stays trusted" first.

## The problem

1. **Sends are policed only by the server.** The policy Action (`lit-actions/sign-ckb-transaction.js`) enforces
   the recovery list's rules and emails its own code for list changes, but it signs any ordinary send. The 24-hour
   amount and the emailed code for sends live in `transaction-policy.ts`, `general-signing.ts`
   (`outflowNeedsEmailCode`, `reserveOutflow`) and `fiber-payments.ts`. A compromised server, or a leaked
   `LIT_USAGE_API_KEY`, can drain any account.
2. **A second client can't send until the first send confirms.** CCC's in-memory cache chains sends within one
   page. A fresh client (another tab, a reload, another device, an app backend next to its frontend) doesn't know
   the first send's transaction, picks the same cell, and the node refuses the second send.

Goal: a compromised server (or usage key) can't move more than the account's daily amount in 24 hours without the
code Lit emails to the user, and any client can send right after any other.

## 1. Facts that shape the design

| Question | Answer | Source |
|---|---|---|
| Can an Action keep state between runs? | No. Each run starts fresh; state must live outside and be verified when read. | [Lit Actions overview](https://developer.litprotocol.com/lit-actions.md), [Patterns](https://developer.litprotocol.com/lit-actions/patterns.md) |
| What can an Action fetch? | Any HTTP, up to 50 requests a run; 15 minutes; 1 MB response. | [Limits](https://developer.litprotocol.com/lit-actions/limits.md) |
| Does an Action have a trustworthy clock? | `Date.now()` inside the TEE. The existing code tickets already rely on it. | `lit-actions/sign-ckb-transaction.js` (`parseTicket`) |
| Can a CKB transaction spend an output of a transaction still in the pool? | Yes. The pool accepts chains of pending transactions; a child is committed after (or with) its parent. | [CKB tx-pool](https://github.com/nervosnetwork/ckb/blob/develop/tx-pool/src/component/pool_map.rs), RFC 0022 |
| What happens to two transactions that spend the same cell? | At most one is ever committed. With RBF the pool may swap the first for a higher-fee second; the loser is dead for good. | [RFC 0022](https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0022-transaction-structure/0022-transaction-structure.md), [RBF](https://github.com/nervosnetwork/ckb/pull/4140) |
| Does `get_transaction` return pool transactions? | Yes, with status `pending` or `proposed`; committed ones carry `block_hash`. | [CKB RPC](https://github.com/nervosnetwork/ckb/tree/develop/rpc#method-get_transaction) |
| Which witnesses does a secp256k1 signature cover? | Sighash-all hashes the transaction hash, every witness of the lock group (the indices of its inputs) and every witness past the last input. | [RFC 0024 / system scripts](https://github.com/nervosnetwork/ckb-system-scripts/wiki/How-to-sign-transaction) |
| Does the Type ID script need a cell dep? | No. It is built into CKB. One live cell per Type ID; a new one only from its first input. | [RFC 0022 Type ID](https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0022-transaction-structure/0022-transaction-structure.md#type-id) |
| Who chooses a Fiber funding transaction's inputs? | The Fiber node. `open_channel_with_external_funding` collects cells under `funding_lock_script` itself and returns an unsigned transaction already agreed with the peer; the external signer can only fill witnesses. | `@fiber-pay/sdk` `createCccExternalFundingResolver`, `src/server/managed-node.ts` |
| Does CCC's fee step see what `prepareTransaction` adds? | Yes. `Transaction.completeFee` calls `signer.prepareTransaction` before estimating the fee. | `@ckb-ccc/core` `ckb/transaction.ts` |
| How does CCC chain sends? | `client.sendTransaction` calls `cache.markTransactions`, which marks inputs unusable and outputs usable; `findCells` reads the cache first. | `@ckb-ccc/core` `client/client.ts`, `client/cache/cache.ts` |

The race in section (d) of the lit-policy README is the core problem: an Action that reads the 24-hour total from
the chain and signs if it's under the amount can be asked for many signatures in parallel. Each sees the same
history and passes.

## 2. Options

### (a) Code for every send (the opt-in flag in lit-policy (d) 1)

No state, no race. Every on-chain send asks for a code, channel opens included. Rejected: users must see the code
only when they're over their amount.

### (b) Wait for a block between sends

Each send must spend a cell that is committed and that the previous send created. Parallel requests conflict, and
the sum is read from committed history only. Rejected by the founder: it slows every account to one send a block.

### (c) Chain every send on one cell, pending outputs included (chosen)

Every send must spend the account's **send-limit cell** and create its successor. Any two sends spend the same
cell, so at most one of them can commit; a second send made before the first confirms spends the first one's new
cell from the pool, so back-to-back sends chain within seconds. Because only the sends a transaction descends
from can ever commit together with it, the 24-hour total is exactly the sum over its ancestors in that chain, and
each send carries that list itself.

### (d) Chain on the newest plain change

The same chaining idea on a plain cell. It would let Fiber's funding builder pick the cell, but a plain cell can't
carry the settings, can't be found by the indexer, and any plain cell sent to the address would look the same. (c)
keeps the settings, the chain and the lookups on one Type ID cell.

## 3. The chosen design

### The send-limit cell

One cell per account, created when the account turns limits on:

- **Lock:** the account key's own secp256k1 address. Only the key can spend it; recovery backups can't (they sign
  the administrator-mode Omnilock), and it doesn't move when recovery is turned on.
- **Type:** a Type ID, so there is one live cell per chain and the indexer finds it.
- **Data:** `"KWSL" ‖ 0x01 ‖ email fingerprint (32) ‖ flags (1) ‖ CKB amount (u64 LE) ‖ n (1) ‖ n × (token type hash
  (32) ‖ amount (u128 LE))`, 47 + 48n bytes. The fingerprint is the same keyed HMAC as the recovery binding
  (`emailFingerprint`): never the address, never encrypted. A CKB amount of `2^64-1` means no limit. Flag bit 0 means
  tokens (and NFTs, and any other type the Action counts by cell) without an amount of their own are unlimited;
  without it they always need the code. KeyWay sets it on every cell it writes, as the server's rule has it: only
  assets with an amount of their own are limited. Cells written before that have it off until their next settings
  change, which sets it (a weakening, so it needs the code). At most 8 tokens.
- **Size:** 173 bytes with no tokens, so 173 CKB, plus 1 CKB the server leaves in it to pay the fee of later
  settings changes. Ordinary sends pay their fee from their own change. That CKB stays the user's.

Only a transaction the account's key signed can create or change it, and the key signs only through the Action:

- **Create (genesis)** needs the Lit code sent to the address being bound, as turning recovery on does. The code is
  for the transaction's hash with the fingerprint field zeroed, so the binding the Action returns can go into the
  cell's data afterwards. The transaction must move no value out, create the cell as output 0 with its Type ID
  from input 0, and input 0 must be the oldest live plain cell at the key's secp256k1 address. The Action reads
  that cell first, then the live send-limit cells, from the same node: two geneses therefore spend the same cell
  or the second sees the first, so an account never has two. A genesis is refused if the account already has one.
- **Change:** the fingerprint never changes. Raising an amount, removing one, or turning tokens unlimited
  (weakening) needs the code sent to the bound address. Lowering or adding applies at once, even when today's total
  is already past the new amount (a change that moves nothing but its fee isn't counted against the amount).
- **Never destroyed:** every transaction that spends it creates exactly one successor with the same Type ID and
  lock.
- **Proof it's real:** anyone can create a Type ID cell with this data at the user's address. A cell only counts if
  the transaction that created it was signed by the key: either it spent the previous send-limit cell (a
  continuation) or it is a genesis whose input 0 was a plain cell at the key's secp256k1 address. The Action
  checks one step back (it fetches that input's transaction); by induction every earlier step was checked by the
  Action when it signed. For the "does this account have limits?" check below, the Action uses the recovery list's
  lock-history proof (`madeByKey`), with one difference: any input, not only input 0, spent from the key's own
  address counts, because a send-limit transaction spends the cell wherever it sits.

### On by default

Before an account's first send, KeyWay offers to turn limits on: the pending-transactions answer carries
`sendLimitOffer` (100,000 CKB a day, `DEFAULT_DAILY_LIMIT_CKB`, or the account's own CKB amount if it set one) when
the policy signer is on, the account has no send-limit cell, it has no recovery, and it holds at least 236 CKB of plain
CKB at its key's secp256k1 address. The SDK signer asks the user once (the "Protect your account" dialog, which they
can edit, or an app's `approveDailyLimit`), runs the usual genesis with the Lit code, and builds the send on the new
cell. It asks while CCC collects inputs, before any are chosen, so the genesis can take the oldest plain cell. A
cancel cancels the send; an account whose oldest cell a pending send holds sends as before and is asked again next
time. Channel fundings never ask: Fiber picks their inputs, so a genesis just before one would race it. Live run on
testnet: `default-on.ts`, output in `default-on.out`.

### What every transaction must do

The Action works out each transaction's outflow itself, from the input cells it fetches and checks against their
hashes:

- **CKB:** capacity of the account's inputs minus capacity of its outputs, over all of the account's locks
  (secp256k1, its administrator-mode Omnilock, its owner-only list lock). Change back to the account doesn't
  count; the fee does. CKB the account gets back under a type script other than Nervos DAO, Type ID or a UDT without
  extension scripts counts as staying only as far as the account already held that much under the same script:
  that script runs when the cell is spent, so whoever wrote it could keep the CKB.
- **Tokens:** per type script hash, the account's input amount minus its output amount. xUDT (CCC's deployment, the
  RUSD-compatible one and the xUDT binary referenced by data hash) and sUDT count their 16-byte amount; any other
  type counts cells, and counts as leaving whenever one of the account's cells of it doesn't come back unchanged. The
  send-limit cell, the recovery list and Nervos DAO cells aren't tokens (their CKB still counts).

Then:

| Transaction | Rule |
|---|---|
| Spends the send-limit cell (a **chained** send) | Must carry the chain record (below). Signs without a code only if, for every asset that leaves, the 24-hour total plus this transaction stays under the amount. Otherwise it needs the Lit code. |
| Moves at most 0.001 CKB out and no tokens (**exempt**: self-transfers, merging cells, the legacy sweep, recovery changes, a genesis) | Signs as before. It can't take value out, so it needs no place in the chain. |
| Anything else (**unchained**), e.g. a Fiber channel funding | If the account has a live send-limit cell, needs the Lit code. Otherwise (limits never turned on) signs as before. |

### The chain record

The witness of the send-limit input carries `"KWSR" ‖ 0x01 ‖ count (1) ‖ entries` in its `input_type`. Each entry is
`transaction hash (32) ‖ commit time (u64 ms, 0 if not known yet) ‖ CKB (u64) ‖ k (1) ‖ k × (asset (32) ‖ amount
(u128))`. The last entry is the transaction itself; the others are its ancestors in the chain that may still be in
the window.

- The witness is in the secp256k1 lock group, so the account's signature covers it.
- The Action reads the previous record from the transaction that created the send-limit input (it fetched that
  transaction anyway). The record may keep or drop each previous entry, in order and unchanged, but must keep
  every entry younger than 24 hours, and its own entry must match the outflow the Action computed.
- An entry's time is the block timestamp of its transaction. A pending entry counts as now. The first record after
  an ancestor commits may fill in its time; the Action checks it against the block header. So in steady state a
  send looks up one header, not the whole day.
- The 24-hour total is the sum of the previous entries younger than 24 hours, by the Action's own reading, never
  by what the record claims.
- At most 255 entries, the transaction's own included: an account can make 255 limited sends in 24 hours.
- The Action refuses to sign a transaction with a record-shaped witness anywhere else. Other parties' inputs'
  witnesses aren't covered by the account's signature, so someone could add one there after signing; when it reads
  a previous record the Action therefore takes only the one on the input that spent the previous send-limit cell.

**Why the race is closed:** two sends that could both commit can't spend the same send-limit cell, so one descends
from the other, and the later one's record covers the earlier one. Parallel requests all spend the newest cell:
one commits, the rest are dead. Splitting the balance into many cells changes nothing, because every send still
needs the one send-limit cell. A send whose record leaves an ancestor out is refused before signing.

### Fiber channel funding

The Fiber node chooses the funding transaction's inputs and fixes the whole transaction with the peer before
KeyWay signs, so it can't spend the send-limit cell. An unchained funding would race exactly as above. So, for an
account with limits on, **a channel funding needs the Lit code**, at any amount. That is the precise reason it isn't
counted against the allowance: it never signs without the user's code. Funds already in a channel are outside
Lit's view (the Fiber key, not the PKP, moves them), so Fiber payments still count only toward the server's
total, as the founder's rule says, and the server keeps asking for a code once that total reaches the amount.

A later step can make funding code-free under the amount: top up a separate "funding" address with a chained,
counted send, and fund channels only from there.

### Server and SDK

- **Planning without a Lit run.** The Action has a `plan` mode that needs no key: the account's public key, the
  transaction, and it returns the record, the totals and whether a code is needed. The server runs the Action's own
  source locally in that mode at preview time (`src/server/send-limits.ts`), so the preview knows, from the same
  code Lit will run, whether to ask for a code, and puts the record into the witness. Lit then checks it.
- **Chaining in the SDK.** `KeyWaySigner.prepareTransaction` appends the newest send-limit cell (pending included)
  as an input, its unchanged copy as an output, and a witness with room for the record. CCC's fee step already
  calls `prepareTransaction`, so the fee covers it (for apps that use CCC's `completeFee*`; an app that sets its fee by
  hand must leave room for about 300 more bytes), and the transaction hash the user approves doesn't change when
  the server fills in the record (witnesses aren't in the hash).
- **Codes.** When the plan says a code is needed, `request-email-code` has the Action email it (`send-code`), the
  server stores only the ticket, and the SDK's prompt takes 8 digits. The email names the full address of each
  recipient and what it gets, so a page that swapped the recipient can't send one that reads as expected. When
  only the server's own rule (Fiber payments in the total) asks for a code, the Action emails it too, so the user
  always gets one code.
- **Turning limits on or changing them** (`signing-settings`): the server builds the genesis or the change
  transaction itself, has the Action sign it (with the code when needed), broadcasts it and records it as pending.
  An account with fewer than ~175 free CKB keeps its amounts on the server only until it can afford the cell.
- **Pending sends (Goal 2).** Every transaction the server gets signed for an account is stored in
  `keyway_v2_pending_transactions` (migration 20). `POST /api/keyway/pending-transactions` returns the account's
  pending ones, after dropping those the node reports committed or rejected, or no longer knows after a grace period.
  It also returns the newest send-limit cell and the record size to reserve. The server finds that cell the way the
  Action does, from one node: the send-limit-shaped cells at the address (up to 1024, so look-alikes anyone plants
  can't hide it), each checked against the key's own history in its block, in batched requests. The node's status is read raw
  (`get_transaction` with verbosity 1), because CCC returns nothing for "unknown" and "rejected". The SDK loads this when its signer
  starts and before every `findCells` (the step CCC uses to pick inputs), then marks the transactions in CCC's cache
  in the order they were signed, so their spent cells are skipped and their change can be used.

## 4. What it stops

- A compromised server or usage key moving more than the daily amount in any 24 hours without the code: parallel
  requests, balance splitting, delayed broadcast, hiding an ancestor, leaving the send-limit cell out, using a
  forged send-limit cell, and channel funding all fail (tests in `tests/send-limits-action.test.ts`).
- The server choosing the email the code goes to, or raising the amount, on an account with a send-limit cell.

## 5. What stays trusted

- **Turning limits on.** Whoever runs the server at genesis picks the bound address (trust on first use), as for
  recovery. An account that never turned limits on is exactly as exposed as today. Limits take effect once the
  genesis is committed (about one block): the "does this account have limits?" check reads the indexer, which
  only sees committed cells, so a send that leaves the cell out is treated as before during that block. The live
  proof shows both sides of it (section 6).
- **Accounts whose amounts live only on the server**: set before this change, without 175 free CKB, or with
  recovery on. A genesis needs a plain cell at the key's secp256k1 address, and the sign-in sweep empties that
  address on recovery accounts, so they can't make the cell yet (a follow-up: move ~176 CKB there first with an
  exempt transfer, or accept the oldest plain Omnilock cell as input 0). The server answers `enforcedByLit: false`
  for these, so an app can tell the user.
- **Trust on first use is permanent and can be started by the server.** For an account with no send-limit cell, a
  compromised server can create one bound to its own address with an amount of 0. The cell can't be destroyed and
  its fingerprint can't change, so after the compromise every send from that account needs a code only the attacker
  receives, until a later version adds a way out (for example a rebind authorised by the code to the recovery-bound
  address). It can't move funds that way, but it can freeze them; recovery backups can still move funds at the
  Omnilock address. Accounts that turn limits on while the server is honest are protected from this.
- **The server's copy of the amounts.** `signing-settings get` returns the server's database, written when the
  change is signed and sent. If that transaction is later dropped, the database and the cell differ until the next
  change; Lit enforces the cell.
- **Pending list edge cases.** A client marks the listed transactions in CCC's cache, which has no "unmark": a
  transaction that later drops out keeps its cells marked in that tab until it reloads. Two clients that both hold an
  approval dialog open on the same send-limit cell each get a valid signature; the node keeps one. Channel funding
  doesn't use the list (Fiber chooses its inputs).
- **Retired Action CIDs left in the Lit group.** A compromised server can sign anything through any older
  Action still in the group, including a record or a genesis-shaped transaction that this Action would then
  trust. The group must hold only the CIDs pinned in `src/server/lit-config.ts`.
- **Fiber.** Payments and channel balances are moved by the Fiber key, which a compromised server can obtain
  (`wrap-fiber-key`). Only the funding needs the code.
- **Exempt transactions** may burn up to 0.001 CKB each as fee, so a compromised server could waste about
  1 CKB per thousand Lit runs.
- **CKB RPC:** transaction status, block timestamps and which cells are live, as before. A lying node, not the
  server, could make an old ancestor look older than it is.
- **Recovery backups** can create a send-limit cell's genesis only by signing for the key's secp256k1 address,
  which they can't. They can still move everything at the Omnilock address, by design.
- **The Lit clock**, the TEE network, the founder's Lit account, and everything else listed in the lit-policy
  README. The retired `sign-ckb-digest` CID must stay out of the group, or none of this holds.

## 6. Live proof and latency

`research/send-limits/live.ts` runs on CKB testnet with two faucet-funded throwaway keys standing in for two
accounts' PKPs. The Action runs unchanged under a stand-in Lit runtime (key operations use the test key, email goes
to a log) against the live RPC; everything else is the production code: the server's preview, local planning and
Lit code flow, the pending-transaction list in Postgres, and `KeyWaySigner` with a fresh CCC client per send (a new
tab or device). Output: `research/send-limits/live.out`.

| Step | What happened on testnet |
|---|---|
| 1 | Account A turns on 300 CKB a day: the Action emails an 8-digit code; the genesis (`0x91b1acbd…31cd`) carries 47 bytes, the fingerprint and the amount, no address. |
| 2 | Two 100 CKB sends from two fresh clients, the second while the first (and the genesis) are still pending. Both chain on the pending send-limit cell and are accepted (730 ms and 834 ms end to end). |
| 3 | A "compromised server" asks for two 90 CKB sends at once; each is under the amount on its own (200 + 90 < 300) and the Action signs both. The node accepts one and refuses the other (`PoolRejectedRBF`): they spend the same cell. |
| 4 | The next send (70 CKB) needs the code; with it, it goes through. Without it, the client's prompt is cancelled and nothing is signed. |
| 5 | A send that leaves the cell out: while the genesis is pending it is treated as before limits (see section 5); once the genesis commits (63 s here) the plan says "unchained", and Lit refuses without the code. |
| 6 | Account B (no limits): two sends from two fresh clients back to back, the second before the first confirms, both accepted. A client without the pending list builds the same transaction again and the node refuses it with `PoolRejectedDuplicatedTransaction`: the reported bug. |

Latency of one Action run, median of five, against the live RPC from the machine that ran the proof (about 80 ms a
round trip to `testnet.ckb.dev`). This is the Action's own time; real Lit adds its fixed overhead on top, and its
nodes' distance to the RPC changes the round trips.

| | ms |
|---|---|
| Previous policy Action, plain send | 81 |
| This Action, account without limits (one extra indexer read: "does it have limits?") | 160 |
| This Action, chained send with limits on (the proof the cell is the account's, and the ancestors' times, in parallel) | 237 |
| Server-side plan at preview (keyless, same rules, before the user approves) | 237 |

So a send gets about 0.08 s (no limits) or 0.16 s (limits on) slower inside Lit, plus about 0.24 s at preview on the
server: roughly +0.4 s per send with limits on. Today's policy signer takes 0.65 to 2.4 s, so expect about 1.05 to
2.8 s. Back-to-back sends don't wait for a block.

## 7. Founder steps

1. Run the migration (`npm run migrate:production`): it adds `keyway_v2_pending_transactions`.
2. In the Chipotle dashboard, paste `lit-actions/sign-ckb-transaction.js` into **Action Runner**, click **Get Lit
   Action IPFS CID**, and check it is `QmaZABPThjFpeBWpRSw3TXosHG4yVsfbHwsF9RGruGuS9b`, the same as `LIT_ACTION_CIDS["sign-ckb-transaction"]` in
   `src/server/lit-config.ts`.
3. Register it under **IPFS Actions** (for example as `keyway-ckb-policy-signer-v2`) and add it to group 1,
   `CKB Keyway`.
4. Run `npm run verify:lit -- --policy` locally. It should print "policy Action".
5. Deploy the server and publish the SDK (version of your choosing).
6. Remove the previous policy CID (`QmUs7kRWcAV1ARk3t4nmvgPFfYqJRfvJa8RUx5T1B1715C`) from group 1. Until then the
   server can still sign sends through the old Action and its weaker checks.
7. Live check: sign in, set a daily amount (a code arrives; the cell appears at the secp256k1 address), send under
   the amount twice from two tabs without waiting, then send over it (8-digit code).

## 8. Rollback

1. Re-add the previous policy CID to group 1, set `LIT_ACTION_CIDS["sign-ckb-transaction"]` back to it, and deploy
   the previous server. Send-limit cells stay on chain; the old Action signs transactions that spend them like any
   other typed cell, and the old server never builds them.
2. The pending-transactions table can stay; the old server doesn't read it.
