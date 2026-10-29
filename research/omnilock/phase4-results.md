# Omnilock opt-in recovery, phase 4: adding and removing backups — testnet results

Run on CKB testnet on 2026-10-29, on the account from `joyid-verifier-results.md` (throwaway keys in
`phase4/keys.json`, gitignored, never printed): **K** stands in for the account's Lit key; recovery was turned on
with **J1** (a P-256 key answering as a JoyID passkey) as its only backup. **E1** is an EVM backup, **J2** a second
JoyID-style backup. Every transaction was dry-run with `test_tx_pool_accept` first and waited on until committed.

| Step | Result | Transaction |
|---|---|---|
| Recovery on, J1 only (`joyid-verifier-results.md`) | **PASS** | `0x749adad0d67555b18816d419c79c662f5d6bc68655abf6cafcd713329e3861cc` |
| 1. Add EVM backup E1 through `src/server/recovery.ts` (preview → request-email-code → apply) | **PASS** | `0x310a9cebc1c06316c458cf5f96982c0e11a2b2a1b10c054166600637d5e56829` |
| 2. Add JoyID-style backup J2, same flow | **PASS** | `0x6d2d989c457f1c9ad8ea2e9679e93c41ef3af3251a08800fd1b56897cf361d2e` |
| 3. Spend with J2 (administrator path, WebAuthn verifier) | **PASS** | `0xfce3fdd7c941deb8cba68815eda4b08fe595221879a951f4bbd069851cf115e2` |
| 4. Spend with E1 (administrator path, flag 0x12) | **PASS** | `0xe835a32ddacfa58d7b94370f1c796ea146c5d0327b28b35f11ca1dabc953b22b` |
| 5. Remove E1, same flow | **PASS** | `0xa8fd196ee0bd09bff0fcba3e0cd3e426c3f8abb477cca9701a4d6a13c18a2c62` |
| 6. E1 spends again (dry run) | **rejected**, Omnilock error 59 (`ERROR_NOT_ON_WHITE_LIST`) | dry run only |

The account's address never changed: `ckt1qrejnmlar3r452tcg57gvq8patctcgy8acync0hxfnyka35ywafvkqgqgdjlm57uyv26crn0avnklwuvkyh4y3hxqxez38x39zseegcgl6l6e8wjn8ygq9js4v73sqkdyvdg0s203azz27kznm9`.
AdminList type script hash and Type ID args stayed the same across the three list updates; only its out point and
root changed.

## What the server builds (`recoveryBackupChange`, `planBackupChange`, `checkBackupChangeTransaction`)

Same shape as turning recovery on: `POST /api/v1/keyway/recovery-backups` with `operation` `preview`,
`request-email-code`, `apply` and `{ change: "add" | "remove", backup }`.

- **Always the emailed code.** The approval is a `recovery` request issued with `requiresEmailCode: true`, so a
  daily amount doesn't skip it (tested with one set). The email names the backup: "Adding: EVM wallet
  0x83db08f1…6473e2" plus "This backup will be able to move everything in your account without KeyWay.", or
  "Removing: …", the number of backups after the change, the fee and the network.
- **Adding needs the backup's ownership proof** (EIP-191 personal_sign, or the JoyID WebAuthn assertion, of
  `recoveryBackupChallenge(legacy address, backup)`), checked at preview and again at apply. Removing needs only
  the code.
- **The transaction.** The current list comes from the chain (`readRecoveryList`, below). Input 0 is the AdminList
  cell, then the account's plain Omnilock cells, largest first, until they cover the fee and a change cell.
  Output 0 recreates the AdminList with the same lock, Type ID and capacity and the new root (the data stays 37
  bytes); witness 0 carries the 85-byte owner placeholder and, in `output_type`, the new list record; output 1 is
  the change, back to the account's own Omnilock. One owner signature (the Lit key, `signAccountGroups`) covers the
  whole lock group. The approval digest binds this exact transaction, so any change to the account's cells or the
  list since the preview refuses it.
- **Checked independently** before signing: input 0 is the account's AdminList, every other input plain CKB at
  the account's Omnilock; output 0 has the AdminList's lock, Type ID and capacity, the root of exactly the new
  list and its record; every other output is plain CKB at the account's address; the fee is within the cap.
  General signing still refuses any transaction that spends the AdminList (`refuseAdminListSpend`), so this flow
  is the only way the list changes.
- **Keeping one backup.** Removing the last backup is refused: "Keep at least one backup. Add another backup
  before removing this one". At most 8 backups, no duplicates, and a backup that isn't listed can't be removed.
- After apply the wallet record keeps the new `backups` and the AdminList's new out point; the address, the
  Omnilock args and the type hash don't change.

Measured:

| Tx | Size (bytes) | Fee (shannons) | Cycles |
|---|---|---|---|
| Add E1 (1 → 2 backups) | 849 | 1,274 | 2,413,898 |
| Add J2 (2 → 3) | 912 | 1,368 | 2,405,084 |
| Remove E1 (3 → 2) | 891 | 1,337 | 2,430,788 |
| J2 spend, 3-member list, 768-byte passkey blob | 1,595 | 2,393 | 6,843,676 |
| E1 spend, 3-member list | 789 | 1,184 | 1,618,021 |

## The list on chain (part B)

The AdminList cell holds only the SMT root, and a proof needs every member, so every transaction that creates or
changes a list now records the whole list where Omnilock and Type ID don't look: the `output_type` field of the
WitnessArgs at the AdminList output's index (0). The owner's signature covers it (sighash_all includes the whole
first witness apart from the zeroed lock).

Format, version 1 (`src/sdk/browser/recovery-list.ts`): `"KWRL" (4b57524c) ‖ 0x01 ‖ count ‖ entries`, each
entry an Omnilock auth flag followed by what the auth is made from:

- `0x12 ‖ 20-byte EVM address` → auth `0x12 ‖ address`;
- `0xFD ‖ 62-byte exec preimage` → auth `0xFD ‖ blake160(preimage)`; the JoyID address is the main-key lock with
  args `0x0001 ‖ preimage[42..62]`, and the preimage is what the spend's witness carries.

`readRecoveryList(client, recovery)` finds the live AdminList by its Type ID, loads the transaction that created
it, decodes the record at that output's index, rebuilds the SMT and refuses unless the root equals the cell's
data. It returns the entries, the root and every member's proof, which is all a backup needs to sign a spend
(`signRecoverySpendWithEvm` / `signRecoverySpendWithJoyId`) with KeyWay and its database gone. Every spend in this
run and in `joyid-verifier-results.md` took its list and proof from `readRecoveryList`, not from the database.
The server also reads the list from the chain when planning a change; for a list created before this format, it
falls back to the stored list only if it hashes to the on-chain root.

The phase 2 enable transaction now writes the record too (`planRecovery`; `checkRecoveryTransaction` checks it).
It adds 73 bytes for one backup. `tests/fixtures/recovery-enable.json` now records this run's enable, J1 spend and
add-E1 transactions; `tests/recovery-flow.test.ts` rebuilds the enable and the add-E1 transactions offline with
the same hashes and checks their records and signatures.

Records seen on chain:

- enable: `4b57524c 01 01 fd ‖ preimage(J1)`
- add E1: `… 02 fd ‖ preimage(J1) 12 ‖ 83db08f1…6473e2`
- add J2: `… 03 …` J1, E1, J2; remove E1: `… 02 …` J1, J2. Roots: {J1} `0x06dcf467…62c6`,
  {J1, E1} `0x44f0a6f3…8283`.

## SDK

- `useCkbWallet().recovery.addBackup(proof)` takes a proof from `createEvmBackup` or `createJoyIdBackup`;
  `recovery.removeBackup(backup)` takes `{ kind, address }`. Both show the built-in `KeyWayBackupChangeModal`
  ("Add this backup?" / "Remove this backup?", what it means, the backup, the count after, the fee, "Your address
  doesn't change."), which an app replaces with `approveBackupChange` on `KeyWayProvider`, as with
  `approveRecovery`. The emailed code always follows (`reason: "recovery-backup"`). The hook's `backups` update
  from the result.
- `changeRecoveryBackup` (`src/sdk/browser/account-recovery.ts`) is the flow behind it.
- `readRecoveryList` and the two spend helpers are in `src/sdk/browser` for the rescue page; they aren't part of
  the published package's exports yet (`tests/package-surface.test.ts` pins that list).

## Negative checks

- On chain: E1's spend after its removal is rejected with 59. The proof it used is valid for the root before the
  removal (the SMT doesn't depend on order), so this is also the stale-proof case. The JoyID negatives
  (another transaction's signature, wrong key, missing verifier, owner-lock style with a JoyID input) are in
  `joyid-verifier-results.md`.
- Offline (`tests/recovery-flow.test.ts`): removing the last backup, removing one that isn't listed, adding a
  duplicate or a ninth; and the checker refusing change to a stranger, a different AdminList lock or capacity, a
  root or record that doesn't match the list, swapped inputs, a foreign input and an oversized fee. A record that
  doesn't hash to the root, a malformed or unknown-version record and a missing record are refused by the reader.
- Postgres (`tests/recovery-postgres.test.ts`): add and remove through the real approval and email-code tables,
  apply without the code or with an expired approval, adding without the backup's signature, the daily amount not
  skipping the code, the stored wallet after each change.

## Checks

`npm ci`; `npx tsc --noEmit -p tsconfig.json`; `npx tsc -p tsconfig.sdk.json --noEmit`; `npm test` (188 tests: 172
pass, 16 Postgres-only skipped, 0 fail); `npm run test:auth:postgres` against a local Postgres (27 pass); in
`contracts/`, `cargo test --release` (11 pass, the real binaries in CKB-VM). `app/` and `docs-site/` weren't
touched.

## Rerun

```sh
npm ci
(cd contracts && cargo build -p joyid-webauthn --release --target riscv64imac-unknown-none-elf)
export DATABASE_URL=postgres://…   # a disposable local database, migrated with npm run migrate
npx tsx research/omnilock/phase4/faucet.ts K          # creates keys.json on first run
npx tsx research/omnilock/phase4/joyid-enable.ts
npx tsx research/omnilock/phase4/joyid-spend.ts J1 joyIdSpend --fund-joyid
npx tsx research/omnilock/phase4/joyid-negative.ts
npx tsx research/omnilock/phase4/change-backup.ts add E1
npx tsx research/omnilock/phase4/change-backup.ts add J2
npx tsx research/omnilock/phase4/joyid-spend.ts J2 spendJ2
npx tsx research/omnilock/phase4/evm-spend.ts E1
npx tsx research/omnilock/phase4/change-backup.ts remove E1
npx tsx research/omnilock/phase4/evm-spend.ts E1 --dry-run   # rejected, 59
```

(`deploy-verifier.ts` with D1–D4 funded deploys the verifier; it is already on testnet.)

## For the founder

- **Keep at least one backup** is a product decision made here: removing the last one is refused, so an account
  with recovery on always has one. Turning recovery off entirely (back to a plain address) isn't built.
- A backup can still spend the AdminList cell itself through the administrator path (Omnilock finds the RC cell
  among the inputs; spike gotcha 5, not exercised on chain), so a backup could rewrite the list. KeyWay never signs such a transaction,
  but a backup holder could. Locking the AdminList with something other than the account's own Omnilock would
  close that; it would change the address scheme, so it isn't done here.
- What JoyID's page shows for `CKB transaction: 0x…` needs a real JoyID (manual steps in
  `joyid-verifier-results.md`).
- The verifier is deployed on testnet only; mainnet needs the same bytes deployed and its cell dep added.
