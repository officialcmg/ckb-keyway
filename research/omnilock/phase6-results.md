# Omnilock opt-in recovery, session 3: merge, phase 5 (rescue page), phase 6 (docs and demo)

Branch `omnilock-recovery`. Not released, nothing deployed, no version bumped.

## Step 0: merge

Both earlier sessions had finished (`phase3-results.md` on `omnilock-signin-sweep`, `phase4-results.md` on
`omnilock-recovery`). `origin/omnilock-signin-sweep` was merged into `omnilock-recovery` (`e2384e6`). One conflict,
the imports in `src/server/http.ts`; both kept (`recoveryBackupChange`, `recoverySetup` and
`sweepLegacyAfterSignIn`). Migration 17 (`legacy-address-sweeps`) didn't collide. Checks after the merge: both
typechecks, `npm test` 177 pass / 17 skipped / 0 fail, Postgres suite 33 pass.

## Phase 5: rescue page

See `phase5-results.md` for the full run. In short: `src/rescue/rescue.ts` (standalone, public CKB node only,
10 tests), `app/rescue` (the page), a notice email after recovery is turned on and after each backup change
(full address, backups, rescue link), and a testnet proof:

| Step | Transaction |
|---|---|
| Recovery on (E1 + J1) | `0x5d488515e7acc62f4b98bfd4d53b35254c4a4d113bfbc8f0cac9eff3514cab13` |
| Rescue with the EVM backup, real browser run of the page | `0x61985471826a64ff8308797ba51b3b2f77c0acd729e8d0086c237d5d2c984c79`, repeated `0x66fafd9ad691784ca81674a304ae7f6aedf6b35d67cfe23431dd0f6adc61c91d` |
| Rescue with the JoyID-style backup, through the module | `0x3400554e24c52b4ea61a84624571b5173393a02bf04406623dd2f44b840b9e59` |
| Negatives (dry runs) | non-backup: error 59; swapped destination: -31; wrong passkey: refused before sending; a backup spending the AdminList: **accepted** |

Screenshots: `phase5/screenshots/` (errors, phone layout at 390 px with no sideways scroll, review, sent).

## Phase 6: docs and demo

- `docs-site/content/docs/account-recovery.mdx` ("Account address & recovery", in `meta.json` under Concepts):
  what recovery is, why the address changes once, costs (197 CKB list; 61 → 95, 142 → 176), backup kinds (EVM
  wallet with the "CKB transaction: 0x…" prompt; JoyID main passkey, synced passkeys), the emailed code rule and the
  notice email, the sign-in check, the rescue page, the API (`useCkbWallet().recovery`, approval props, preview
  types) and known limits (Omnilock unaudited and upgradable by its deployer, the passkey verifier unaudited, a
  backup can rewrite the list, message signing reports the Lit public key, testnet only).
- Updated: `react-sdk.mdx` (props, `legacyAddress`, `recovery`), `authentication.mdx` ("same CKB address on future
  logins" now says it changes once with recovery), `core-concepts.mdx`, `README.md` (API table, approval props,
  security model), `docs/ARCHITECTURE.md`, and the landing page line "KeyWay accounts are ordinary secp256k1
  lock addresses".
- Demo (`app/app`): an "Account recovery" card in the same style as the others: turn on with an EVM wallet, the
  list, add an EVM wallet, remove (hidden for the last backup), the earlier address, a link to `/rescue`.
  Screenshots: `phase6/`. The demo builds against the published `@ckb-keyway/react` 0.2.4, which has no
  `recovery`, so the card reads it defensively and stays hidden until the demo uses 0.2.5 (or
  `KEYWAY_LOCAL_SDK=1`). Both builds pass. The card wasn't run against a live backend.
- `release-notes-0.2.5.md`: draft.

## Checks (final head)

`npm ci`; `npx tsc --noEmit -p tsconfig.json`; `npx tsc -p tsconfig.sdk.json --noEmit`; `npm test` (205 tests:
188 pass, 17 Postgres-only skipped, 0 fail); `npm run test:auth:postgres` (33 pass); `npx next build` (also with
`KEYWAY_LOCAL_SDK=1` after `npm run build:sdk`); `docs-site`: `npm ci && npm run build`.

## New dependency

`@ckb-ccc/joy-id` 1.1.3 (exact), the release built on this repo's `@ckb-ccc/core` 1.16.1, for the rescue page's
JoyID button. It is used only by `app/rescue`, not by the SDK package.

## Open questions for the founder

1. **A backup can spend the AdminList** (confirmed by dry run). Locking the list with something other than the
   account's own Omnilock would close it but changes the address scheme.
2. **JoyID popups and COOP.** `/rescue` is served with `same-origin-allow-popups` so JoyID's popup can answer.
   `/app` keeps `same-origin` (the browser Fiber node needs isolation), so the demo card offers EVM wallets only
   and JoyID backups there need an app page without that header.
3. **A real JoyID run** of the rescue page (popup, passkey) still needs doing by hand.
4. **Mainnet**: the page's switch is prepared and labelled untested; the JoyID verifier and RUSD lookup are
   testnet only.
5. The notice email links `https://ckbkeyway.dev/rescue`; it is live only once the site is deployed from this
   branch.
