# Moving signing policy into Lit

Status: implemented on branch `lit-policy`, off by default. CKB testnet only.

## The problem

Two audits found the same thing (`research/omnilock/audit-opus-5-5.md` H1, `research/omnilock/audit-fable-5-1.md` I1):
`lit-actions/sign-ckb-digest.js` signs any 32-byte digest for any PKP in KeyWay's Lit group. Its only gate is
`LIT_USAGE_API_KEY`. Every rule lives in KeyWay's server:

- transaction policy (`transaction-policy.ts`)
- daily amounts and the emailed code (`general-signing.ts`, `email-template.ts`)
- turning recovery on and changing backups (`recovery.ts`)
- never touching the backup list (AdminList)

Anyone with the server or the usage key can therefore sign anything for any user. That includes adding their own
recovery backup, which outlives a key rotation.

Goal: the server alone can no longer move a user's funds or change their recovery backups. This change fully
delivers the second half. The first half is only partly done; see [What stays trusted](#what-stays-trusted).

## 1. What a Chipotle Lit Action can do

KeyWay runs Actions on Lit's Chipotle API (`POST https://api.chipotle.litprotocol.com/core/v1/lit_action`, see
`src/server/lit.ts`). It sends the source inline. Chipotle derives the source's IPFS CID and runs the Action only if
the usage key may execute in a group that contains that CID (`src/server/lit-cid.ts` computes the same CID).

| Question | Answer | Source |
|---|---|---|
| Can an Action `fetch`? | Yes: "make arbitrary HTTP requests", up to 50 outbound requests per run. | [Lit Actions overview](https://developer.litprotocol.com/lit-actions.md), [Limits](https://developer.litprotocol.com/lit-actions/limits.md) |
| Can it hold a secret only it can decrypt? | Yes. `Lit.Actions.getLitActionPrivateKey()` returns a key "deterministically derived by the TEE's KMS from this action's IPFS CID"; every action can read its own key and no other. Secrets can be encrypted to a key derived from it ("encrypt-to-action", HPKE/X25519), and "only the action whose CID the key came from can decrypt". `Lit.Actions.Encrypt/Decrypt({ pkpId })` is a "PKP vault": any Action in the group with that PKP can decrypt. | [Chipotle SDK reference](https://developer.litprotocol.com/lit-actions/chipotle.md), [Secrets](https://developer.litprotocol.com/lit-actions/secrets.md), [Derived actions](https://developer.litprotocol.com/lit-actions/derived-actions.md) |
| Can it keep state? | No. "Each run starts fresh and remembers nothing from earlier calls." State must be stored outside and verified when read ("signed data in untrusted storage"). | [Lit Actions overview](https://developer.litprotocol.com/lit-actions.md), [Patterns](https://developer.litprotocol.com/lit-actions/patterns.md) |
| Can it verify signatures? | Yes. `ethers` (v5) is a global, so `ethers.utils.recoverPublicKey` works. | [Chipotle SDK reference](https://developer.litprotocol.com/lit-actions/chipotle.md) |
| Can it use `crypto.subtle`? | Not on the doc pages I read. It is in production use: KeyWay's registered `wrap-fiber-key.js` uses `crypto.subtle` (ECDH P-256, HKDF, AES-GCM) and `crypto.getRandomValues`. | `lit-actions/wrap-fiber-key.js` |
| Limits | 15 minutes, 64 MB memory, 10 key operations per run, 50 fetches, 16 MB for code plus `js_params`, 1 MB response. | [Limits](https://developer.litprotocol.com/lit-actions/limits.md) |
| Trust in `js_params` | "`js_params` are untrusted". Values hardcoded in the source are part of the CID. | [Patterns](https://developer.litprotocol.com/lit-actions/patterns.md) |

Two consequences shape everything below:

1. **Every CID in the group counts.** The usage key can run any Action in group 1. As long as `sign-ckb-digest`
   stays registered, a new Action adds nothing against a compromised server. Removing that CID is part of the
   switch.
2. **With no state, "first wins" needs the chain.** A server can re-run any Action. So nothing an Action produced
   can tell a first binding from a later one, unless the record lives somewhere only a transaction signed by the
   account can create. That place is CKB.

Email sending: [Resend API keys](https://resend.com/docs/api-reference/api-keys/create-api-key) can be
`sending_access` ("can only send emails") and restricted to one domain. Only a `full_access` key can read sent
emails back.

## 2. Options, ranked

### (a) The Action rebuilds the sighash from the full transaction and enforces the list's rules (shipped)

How it works: the Action takes the whole transaction instead of a digest.

1. It fetches every input's creating transaction from CKB testnet and checks each against its hash.
2. It derives the account's locks from the PKP's own key: the secp256k1 lock, the administrator-mode Omnilock and
   the AdminList's owner-only lock.
3. It computes each lock group's sighash itself and signs only those.

It also enforces these invariants on the recovery list:

- A transaction may touch at most one list.
- A list can't be destroyed.
- A list's lock, Type ID and capacity never change.
- A change adds or removes exactly one backup. It compares the members recorded on chain before and after, each
  checked against its SMT root. Records are version 3 (`"KWRL" ‖ 0x03 ‖ count ‖ 21-byte auths`, see
  `research/backup-unlinking/README.md`); the Action accepts no other version.
- At most 8 backups, each one of KeyWay's two version 3 verifiers (salted identities) for this account. The record
  holds only salted auths, so the server passes `backups`: the kind and 20-byte id (EVM address, or blake160 of the
  JoyID passkey's public key) of every backup on the list before and after. The Action rebuilds each auth as
  `0xFD ‖ blake160(verifier ‖ 0x02 ‖ 0x00 ‖ 8 zero bytes ‖ blake160(id ‖ salt))`, where the salt is the list's
  Type ID type hash, and refuses any listed auth it can't rebuild that way: another account's salt, an unsalted
  id, the old verifiers, or anything else. It also refuses an id that isn't on the list. The emailed code names
  backups by these ids.
- A new list must be output 0, under the owner-only lock, with its Type ID from input 0, which must be a plain
  CKB cell (no type, no data) at the account's own secp256k1 address. Every administrator-mode output must name
  that list.
- First wins: a new list is refused if the indexer shows any live list under the key's owner-only lock already.
  A cell there only counts as a list if the transaction that created it spent, as input 0, a cell from the key's
  own secp256k1 address or its list lock (a change must spend the list as input 0 for the same reason). The
  Action reads that from the key's own lock history (indexer `get_transactions` on those two locks, inputs at
  index 0), which only the key can add inputs to, and only in the blocks that hold candidate lists (a
  `block_range` filter, in batches of 256 queries). Candidates and history come from the same node, so a node
  behind can't leave a list out. With the indexer read 256 cells a page, even 1024 fake lists keep an enable to
  about 15 requests, well within Lit's limit on outbound requests per run, with room for the code email. It never downloads a candidate's transaction, so an outsider
  can't make the check slow or exhaust memory by planting lists from huge, witness-padded transactions, and a
  long account history costs nothing. The indexer is queried with `script_search_mode: "exact"`:
  its default prefix search would also return unspendable cells planted under longer args, which would block
  every enable or send. An administrator-mode Omnilock doesn't count, because anyone can make one
  with this key's auth and their own list. Anyone can send a cell to the list lock, so this stops outsiders
  blocking an account with fake lists. A failed lookup refuses the request rather than leaving a list out.
  Only Type ID cells are fetched, up to 1024. Every fake list locks its capacity under this key for good, so
  blocking an account that way costs an attacker more than 1024 such cells, about 131k CKB. A candidate's block
  is refused if it holds 1024 or more entries of this key's history, which an outsider can only cause by giving
  the key that many cells in one block.
- Dusting: an enable must spend every plain cell at the secp256k1 address, and the server plans at most 60 inputs.
  Anyone can send many small plain cells there to stall turning recovery on. The Action only asks the indexer for
  plain cells (no type, no data), so typed cells sent there don't count toward its limit of 256. The user keeps
  the CKB and can merge the plain cells into fewer with an ordinary send, so this is a nuisance, not a freeze.
- An enable must spend every live plain cell at the key's secp256k1 address. Two enables signed before either is
  indexed then spend the same cells, so at most one can commit. Input 0 being plain means every enable spends at
  least one plain cell, so two enables made only from typed cells someone sent to the address can't both pass.
  The Action reads the plain cells first and the lists second, both from the same node: an enable that commits
  between the two reads either still shows its plain input 0 in the first (so this one must spend it too) or its
  list in the second. Read the other way round, or from two nodes, a list committed in between was missed.
- A change to a list without an on-chain record needs the previous record (version 3) from the server. That record
  must hash to the list's root, and the one-backup rule applies as usual.
- No output may go to an administrator-mode Omnilock of the key in any shape but the account's own (KeyWay's
  Omnilock, flags exactly 0x01): not with extra flags (anyone-can-pay, time lock, …), and not under the official
  Omnilock deployment. Those would let the named list's members spend the funds too, and KeyWay never builds them.
- Outside turning recovery on, every output to an administrator-mode Omnilock of the key must name the key's one
  live list. Without this, a server could make a second list with its own backup and email, then move the funds
  to that list's address in an ordinary transaction. The independent review found that gap; it is closed and has
  a regression test.
- No other mode signs a raw digest:
  - `identity` signs only the fixed `sha256("CKB KeyWay identity v1")`.
  - `message` hashes `"Nervos Message:" + text` itself.

What it stops:

- Signing arbitrary digests.
- Moving the list to another lock or Type ID, the persistent takeover in audit-opus M3.
- Destroying the list.
- Swapping several backups at once.
- Spending the list in an ordinary transaction.
- Lying about input cells: a server or RPC can't make the Action sign a different input set or lock group than the
  chain has.

What it doesn't stop:

- Sends to anywhere other than an address naming a different list of the same key.
- A list change of the allowed shape, such as adding one attacker backup, unless (b) applies.

### (b) Lit makes, emails and checks the code for list changes, with a fingerprint of the email bound on chain (shipped)

How it works:

- The email address never goes on chain, in the clear or encrypted. Only a fingerprint of it does:
  `HMAC-SHA256(SHA-256("keyway-email-binding-key/v1" ‖ PKP private key), "keyway-email-binding/v2|" ‖ pkp ‖ "|" ‖
  lowercase email)`. The binding is `"KWEB" ‖ 0x02 ‖ fingerprint`, 37 bytes.
  - Only an Action holding the PKP can compute it, so nobody can test guessed addresses against the chain.
  - The key is per account, so the same email gives unrelated fingerprints on different accounts.
  - The key comes from the PKP, not from `getLitActionPrivateKey`. That key is derived from the Action's CID, so a
    later version of the Action couldn't check fingerprints made by this one. The PKP-derived key survives upgrades.
  - An earlier draft stored the address encrypted to the PKP (`Lit.Actions.Encrypt`, 1 KB). That was dropped: a
    ciphertext on a public chain is permanent, and a single key leak would expose every bound address at once.
- When recovery is turned on, the Action:
  - emails a code to the address it is given;
  - returns the binding of that address;
  - signs only if the transaction carries that binding in witness 0's `input_type`, the server passes the same
    address, and the code matches.
- Witness 0 is covered by the account's own signature. The enabling transaction is the only transaction that can
  ever spend input 0, which the list's Type ID is derived from. So the binding is fixed for the life of the list.
- For every later list change, the server passes the account's address and the Action:
  - finds that enabling transaction from the list's Type ID, which the server can't substitute;
  - checks it is committed and that witness 0 carries a valid signature by the account key;
  - refuses unless the address's fingerprint matches the binding, then emails the code there.
  The server can't choose the address: any other address is refused before an email is sent.
- Code: `HMAC-SHA256(action key, pkp | tx hash | email | ticket)`, as 8 digits. The action key comes from
  `getLitActionPrivateKey`, so only this exact Action can compute it. The ticket is `v1.<expiry ms>.<random>`,
  expiring within 10 minutes, with a minute's slack for clock differences between Lit nodes. The code never leaves
  Lit except in the email.

What it stops:

- A compromised server adding, removing or swapping backups on an account that turned recovery on through this
  Action.
- The server reading or forging the code.
- The server redirecting the code email.

What it doesn't stop:

- Trust on first use: whoever runs the server when recovery is turned on picks the bound address.
- Someone who controls the user's inbox.
- Accounts that turned recovery on before the switch. They have no binding; they keep the server's code and the
  shape rules from (a).
- An attacker who controls both KeyWay's DNS for `auth.ckbkeyway.dev` and a Resend account. The sender address is
  hardcoded, so only a Resend account with that domain verified can send the email.

Brute force: there is no state, so the Action can't count attempts. The server still counts five tries for normal
use. A ticket is stateless: the Action checks its format and expiry, not that `send-code` issued it. So someone
calling the Action directly with the usage key can make their own tickets and keep guessing without any email
reaching the user. Each guess is one Lit run, and the code for a ticket is an HMAC under the Action's key, so a
made-up ticket is no easier to guess than a real one: each guess has a 1 in 10^8 chance, and only the rate of Lit
runs limits how many can be made.

### (c) A user-held factor the Action verifies (not shipped)

Examples: a passkey, or a per-device key bound on chain like the email.

This is the only option that can also cover sends. Three problems ruled it out for now:

- It has the same first-use binding problem.
- A hostile frontend (the browser code comes from KeyWay or from apps) can ask the user's key to sign anything
  without showing it. The email shows the change from a channel the server doesn't control.
- Losing the device locks list changes. It needs new UI.

It is the natural next step for sends; see (d).

### (d) Daily amounts enforced in Lit (not shipped; design for the next step)

An Action can't keep the 24-hour total. Computing it from the chain alone is racy: a compromised server splits the
balance (a self-transfer, which is free) and asks for many parallel signatures. Each sees the same chain and passes.

Two designs avoid the race:

1. An opt-in flag in the on-chain binding: "every send that leaves the account needs the Lit code". There is no
   allowance, so no state is needed. The cost is a code for every on-chain send, channel opening included.
2. Serialise code-free sends:
   - Each one must spend the account's oldest live plain cell, which the Action computes, so parallel requests
     conflict on chain.
   - Read the daily amount from the binding.
   - Sum the account's outflow over the last ~10,800 blocks with batched RPC.

Both change send UX and every transaction builder. Neither is safe to ship in this change.

## 3. The chosen design

(a) and (b) together, in `lit-actions/sign-ckb-transaction.js` (CID pinned in `src/server/lit-config.ts`
`LIT_ACTION_CIDS`, checked by `tests/lit-action-packaging.test.ts`).

Server side:

- `LIT_SIGNER = "policy"` in `src/server/lit-config.ts` switches every signing path to the policy Action. It is a
  constant in code, not an environment variable, so a deploy can't change the signer:
  - general transactions, messages, channel funding, the legacy sweep, recovery, and identity at account creation
    (`general-signing.ts` `signGroups`, `funding-transaction.ts`, `legacy-sweep.ts`, `recovery.ts`,
    `bootstrap.ts`, `pkp-identity.ts`).
- With `"digest"` (the value this PR ships), the server uses `sign-ckb-digest` exactly as before.
- With the policy signer on:
  - Turning recovery on and backup changes on bound accounts use `policySendCode`. The server stores only the
    ticket and the binding, and replies `codeLength: 8`. The SDK's code dialog then takes 8 digits.
  - `planRecovery` reserves the 37-byte binding in witness 0 before computing the fee. Witnesses aren't in the
    transaction hash, so the hash the code is for doesn't change when the binding goes in.
  - The request is used up only after the Action has signed, so a mistyped code doesn't end the request.
  - Recovery records gain `litEmailBound: true`.
- Every signature the Action returns is checked against the digest the server computed and the wallet's public key
  (`policySignTransaction`).

Separate small fix: a hosted Fiber payment `send` that carries an `Idempotency-Key` now runs under
`runIdempotentMutation` (`fiber-payments.ts`). A retry after a lost response returns the first result, or the
first error, and never pays twice. A repeat that arrives while the first send is still running waits up to 30
seconds for its outcome.

If a payment succeeds but its result can't be stored, the record stays "running" and is never marked failed.
A repeat then never reports a failure for a payment that went through. It reports "still in progress", then,
after 24 hours, that the record expired. Neither means the payment failed: check the payment's status before
retrying it with a new key. Not handled: the server crashing after Fiber accepted a payment but before the result was stored. A retry then
says "still in progress" until the key expires in 24 hours. It never pays twice, but checking the outcome with
Fiber's `get_payment` is left for later. The SDK already retries once with the same key on network errors and 5xx
(`api-client.ts`).

## What stays trusted

Plainly, after the switch:

- **On-chain sends.** Plain transfers, tokens, channel funding and sweeps are still policed only by the server. A
  compromised server, or the usage key, can still drain an account, with or without recovery. The goal "the
  server alone can't move funds" is **not** met yet; see (d).
- **Fiber channel funds.** `wrap-fiber-key.js` re-encrypts the Fiber key to whatever browser key the server
  relays. A compromised server can obtain a user's Fiber key.
- **Creation and first use.** The server chooses the email bound when recovery is turned on.
- **Recovery accounts from before the switch.** No binding, so a compromised server can still add one backup per
  transaction to them, without a code. The shape and first-wins rules still apply. To get the binding, these
  users have to turn recovery off and on again; there is no in-place migration yet.
- **Accounts with recovery off.** A compromised server can turn recovery on for them with its own backup and its
  own email. That is no worse than what it can already do with a plain send, but it is not prevented.
- **Lit itself.** The TEE network, Chipotle's group check, and the founder's Lit account key, which can register
  any CID.
- **`LIT_PROVISIONING_API_KEY` on the server.** If it can add Actions to group 1, the server can register an
  unrestricted Action and none of this holds. **The founder must confirm this key can only create PKPs and add
  PKPs to the group, not add actions.** Otherwise PKP provisioning has to move off the server.
- **Email.** Resend, the user's inbox, and KeyWay's DNS. Also, no `full_access` Resend key may be on the server,
  or it could read the code emails back.
- **CKB RPC.** Pinned hosts `testnet.ckb.dev` and `testnet.ckbapp.dev`. Every transaction is checked against its
  hash. The binding's witness is checked against the account key's signature. Members are checked against the
  on-chain root. Two things the RPC is simply believed on:
  - a transaction's commit status;
  - whether a list cell is still live, which the first-wins check uses.
  A lying node, not the KeyWay server, could exploit those.
- **The Resend account.** A sending-only key can't read mail back, but anyone with KeyWay's Resend dashboard can
  read the sent codes.
- **Real Lit API shapes.** The Action assumes `Lit.Actions.getPrivateKey` and `getLitActionPrivateKey` return hex
  (with or without `0x` for the PKP key). The tests use a stand-in for Lit, so step 4 below has to run on staging
  before production.

## Founder steps

You run these locally. The server has no Lit account credentials.

1. **Resend.** The Action sends codes with the server's existing `RESEND_API_KEY`. Make sure that key is a
   `sending_access` key restricted to `auth.ckbkeyway.dev`: a `full_access` key could read sent emails, codes
   included, back from Resend.
2. **Check the provisioning key.** In the Chipotle dashboard, confirm that `LIT_PROVISIONING_API_KEY` can't add
   actions to groups.
3. **Register the policy Action.**
   1. In the Chipotle dashboard, open **Action Runner** and paste `lit-actions/sign-ckb-transaction.js` exactly.
   2. Click **Get Lit Action IPFS CID**. It must be `QmXEKyvWa2MwCSY9qMBGUp3aawRrWeSW6xqP4SS2w8x2gd`, the same as
      `LIT_ACTION_CIDS["sign-ckb-transaction"]` in `src/server/lit-config.ts`. Any other
      CID means the pasted source differs from this branch.
   3. Under **IPFS Actions**, register the CID as `keyway-ckb-policy-signer`.
   4. Add the CID to group 1, `CKB Keyway`. The PKPs are already in that group.
4. **Check it against real Lit.** Run `npm run verify:lit -- --policy`. It should print "policy Action".
5. **Switch.** Change `LIT_SIGNER` to `"policy"` in `src/server/lit-config.ts`, merge and deploy. No migration is
   needed. Then sign in, sign a message, send a small transaction, turn recovery on, and add and remove a backup.
   The codes should arrive from `security@auth.ckbkeyway.dev` with 8 digits.
6. **Remove the old signer.** Once production signs through the policy Action, remove the `sign-ckb-digest` CID
   (`QmXJAW3CKLUuKa9RjEZKCMzEmLYcT7z4tmrzxZvGGfm6Q3`) from group 1. Until you do, the server
   can still sign any digest, and nothing above holds. Then rotate `LIT_USAGE_API_KEY`.
7. Keep `generate-fiber-key` and `wrap-fiber-key` in the group. They are unchanged.

## Rollback

1. Re-add the `sign-ckb-digest` CID to group 1.
2. Set `LIT_SIGNER` back to `"digest"` in `src/server/lit-config.ts` and deploy.

Accounts that turned recovery on under the policy signer keep their on-chain binding. With the digest signer back,
their list changes use the server's 6-digit code again, as before. Nothing in the database needs undoing.

## Tests

- `tests/lit-policy-action.test.ts` runs the Action's source unchanged under Node. It uses a fake `Lit` global, a
  fake ethers v5 `SigningKey`, a fake CKB RPC and a fake email API (`tests/lit-action-fixture.ts`). It covers:
  - blake2b, the transaction hash and the SMT root against CCC and the SDK;
  - identity and message modes, and that there is no digest mode;
  - plain signing from chain cells;
  - turning recovery on: wrong code, a binding for another address, a changed transaction, and expired tickets;
  - that the enabling transaction holds only the 37-byte fingerprint and no part of the address;
  - that a fingerprint differs per account and stays the same under a new Action CID;
  - a bound backup change, where the server can't redirect the code: a wrong address is refused;
  - every list invariant, including adds under another salt or the old verifiers;
  - accounts that turned recovery on before this Action, and lists without a record.
- `tests/lit-policy-v3-parity.test.ts` checks the Action against KeyWay's own encoders: the testnet proof's
  version 3 records and salted auths, an enable with an EVM wallet and a JoyID passkey built by the server, and
  refusals for the wrong salt, an extra or missing auth, the old verifier hashes and a version 2 record.
- `tests/recovery-postgres.test.ts` runs the whole flow through Postgres and the Action: turning recovery on,
  adding an EVM wallet and a JoyID passkey, and removing a backup, checking the on-chain record each time.
- `tests/general-signing-postgres.test.ts` covers the Lit-code request bookkeeping.
- `tests/fiber-payments-postgres.test.ts` covers idempotent payment retries.
