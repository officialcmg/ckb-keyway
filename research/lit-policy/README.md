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
  checked against its SMT root.
- At most 8 backups, and only KeyWay's two verifiers.
- A new list must be output 0, under the owner-only lock, with its Type ID from input 0, which must be the
  account's own secp256k1 cell. Every administrator-mode output must name that list.
- First wins: a new list is refused if the indexer shows any live list under the key's owner-only lock already.
  A cell there only counts as a list if the transaction that created it spent a cell from the key's own
  secp256k1 address or its list lock. An administrator-mode Omnilock doesn't count, because anyone can make one
  with this key's auth and their own list. Anyone can send a cell to the list lock, so this stops outsiders
  blocking an account with fake lists. A failed lookup refuses the request rather than leaving a list out.
- An enable must spend every live plain cell at the key's secp256k1 address. Two enables signed before either is
  indexed then spend the same cells, so at most one can commit.
- A change to a list made before on-chain records existed needs the previous record from the server. That record
  must hash to the list's root, and the one-backup rule applies as usual.
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

### (b) Lit makes, emails and checks the code for list changes, with the email bound on chain (shipped)

How it works:

- When recovery is turned on, the Action:
  - emails a code to the address it is given;
  - returns an encrypted binding of that address, `Lit.Actions.Encrypt` to the PKP, padded to 1024 bytes;
  - signs only if the transaction carries that binding in witness 0's `input_type` and the code matches.
- Witness 0 is covered by the account's own signature. The enabling transaction is the only transaction that can
  ever spend input 0, which the list's Type ID is derived from. So the binding is fixed for the life of the list.
- For every later list change, the Action:
  - finds that enabling transaction from the list's Type ID, which the server can't substitute;
  - checks it is committed and that witness 0 carries a valid signature by the account key;
  - decrypts the bound address and emails the code there.
  The server can't choose the address.
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
use. Someone calling the Action directly with the usage key gets one guess per Lit run: 10^8 codes, 10-minute
tickets, and every ticket emails the user.

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

(a) and (b) together, in `lit-actions/sign-ckb-transaction.js` (pinned CID in `src/server/lit-policy.ts`
`POLICY_ACTION_CID` and `.env.example` `LIT_POLICY_ACTION_CID`, checked by `tests/lit-action-packaging.test.ts`).

Server side:

- `KEYWAY_LIT_SIGNER=policy` switches every signing path to the policy Action:
  - general transactions, messages, channel funding, the legacy sweep, recovery, and identity at account creation
    (`general-signing.ts` `signGroups`, `funding-transaction.ts`, `legacy-sweep.ts`, `recovery.ts`,
    `bootstrap.ts`, `pkp-identity.ts`).
- Unset, the server uses `sign-ckb-digest` exactly as before. The server works with either during the switch.
- With the policy signer on:
  - Turning recovery on and backup changes on bound accounts use `policySendCode`. The server stores only the
    ticket and the binding, and replies `codeLength: 8`. The SDK's code dialog then takes 8 digits.
  - `planRecovery` reserves the 1024-byte binding in witness 0 before computing the fee. Witnesses aren't in the
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
A repeat then never reports a failure for a payment that went through. Not handled: the server crashing after Fiber accepted a payment but before the result was stored. A retry then
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
- **Real Lit API shapes.** The Action assumes `Lit.Actions.Encrypt` returns a string of at most 1017 bytes and
  `getLitActionPrivateKey` returns hex. The tests use a stand-in for Lit, so step 4 below has to run on staging
  before production.

## Founder steps

You run these locally. The server has no Lit account credentials.

1. **Resend.** Create a `sending_access` key restricted to `auth.ckbkeyway.dev`. Set it as `LIT_EMAIL_API_KEY` on
   the API service. Make sure every Resend key the server holds, including `RESEND_API_KEY`, is `sending_access`.
2. **Check the provisioning key.** In the Chipotle dashboard, confirm that `LIT_PROVISIONING_API_KEY` can't add
   actions to groups.
3. **Register the policy Action.**
   1. In the Chipotle dashboard, open **Action Runner** and paste `lit-actions/sign-ckb-transaction.js` exactly.
   2. Click **Get Lit Action IPFS CID**. It must equal `LIT_POLICY_ACTION_CID` in `.env.example`
      (`POLICY_ACTION_CID` in `src/server/lit-policy.ts`).
   3. Under **IPFS Actions**, register the CID as `keyway-ckb-policy-signer`.
   4. Add the CID to group 1, `CKB Keyway`. The PKPs are already in that group.
4. **Smoke test on staging.**
   1. Set `KEYWAY_LIT_SIGNER=policy` on `keyway-api-staging`.
   2. Run `KEYWAY_LIT_SIGNER=policy npm run verify:lit` with a staging PKP. It should print "policy Action".
   3. Sign in, sign a message, send a small transaction, turn recovery on, and add and remove a backup. The codes
      should arrive from `security@auth.ckbkeyway.dev` with 8 digits.
5. **Switch production.** Set `KEYWAY_LIT_SIGNER=policy` and `LIT_EMAIL_API_KEY` on the production API, then
   deploy. No migration is needed.
6. **Remove the old signer.** Once production signs through the policy Action, remove the `sign-ckb-digest` CID
   (`LIT_SIGN_ACTION_CID`, `QmXJAW3CKLUuKa9RjEZKCMzEmLYcT7z4tmrzxZvGGfm6Q3`) from group 1. Until you do, the server
   can still sign any digest, and nothing above holds. Then rotate `LIT_USAGE_API_KEY`.
7. Keep `generate-fiber-key` and `wrap-fiber-key` in the group. They are unchanged.

## Rollback

1. Re-add the `sign-ckb-digest` CID to group 1.
2. Unset `KEYWAY_LIT_SIGNER` and redeploy.

Accounts that turned recovery on under the policy signer keep their on-chain binding. With the digest signer back,
their list changes use the server's 6-digit code again, as before. Nothing in the database needs undoing.

## Tests

- `tests/lit-policy-action.test.ts` runs the Action's source unchanged under Node. It uses a fake `Lit` global, a
  fake ethers v5 `SigningKey`, a fake CKB RPC and a fake email API (`tests/lit-action-fixture.ts`). It covers:
  - blake2b, the transaction hash and the SMT root against CCC and the SDK;
  - identity and message modes, and that there is no digest mode;
  - plain signing from chain cells;
  - turning recovery on: wrong code, a binding for another address, a changed transaction, and expired tickets;
  - a bound backup change, where the server can't redirect the code;
  - every list invariant;
  - accounts that turned recovery on before this Action.
- `tests/recovery-postgres.test.ts` runs the whole flow through Postgres and the Action: turning recovery on and
  adding a backup.
- `tests/general-signing-postgres.test.ts` covers the Lit-code request bookkeeping.
- `tests/fiber-payments-postgres.test.ts` covers idempotent payment retries.
