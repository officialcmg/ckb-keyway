# Omnilock opt-in recovery, phase 5: the rescue page — testnet results

Run on CKB testnet on 2026-10-29 with throwaway keys (`phase5/keys.json`, gitignored, never printed): **K**
stands in for the account's Lit key, **E1** is an EVM backup, **J1** a P-256 key answering as a JoyID passkey,
**F** funds the account and issues a test xUDT, **X** is an EVM wallet that isn't a backup, **D1**/**D2** receive
the rescues. Recovery was turned on through `src/server/recovery.ts` against a local Postgres; everything after
that used only `src/rescue/rescue.ts` and the public node `https://testnet.ckb.dev/`.

KeyWay address: `ckt1qrejnmlar3r452tcg57gvq8patctcgy8acync0hxfnyka35ywafvkqgqqywhsqz6a9nuq7n78x78eqrnwzsj37faqxrn7dq20dqufhj5gwyme9azeu9hjf6c4fyrhs5qhgasjkf2vj44ypl035x`

| Step | Result | Transaction |
|---|---|---|
| 1. Recovery on with E1 and J1 (`step1-enable.ts`); notice email checked | **PASS** | `0x5d488515e7acc62f4b98bfd4d53b35254c4a4d113bfbc8f0cac9eff3514cab13` |
| 2. F sends 1000 + 300 CKB and 1,000,000 test xUDT (176 CKB cell) to the address | **PASS** | `0xeb62fdb52930200799533fc84e3ca8d443b3a7aef2f8b0694aa829c519cb4b8c` |
| 3. Rescue to D1 in a real browser, EVM backup E1 (`step3-browser-evm.ts`) | **PASS** | `0x61985471826a64ff8308797ba51b3b2f77c0acd729e8d0086c237d5d2c984c79` |
| 3b. Funded again (`0x27d757e3…da68`) and the browser run repeated after a styling fix; the screenshots are from this run | **PASS** | `0x66fafd9ad691784ca81674a304ae7f6aedf6b35d67cfe23431dd0f6adc61c91d` |
| 4. Funded again (`0x82e59474…71fe`), rescue to D2 with the JoyID-style backup J1 through the module (`step4-joyid.ts`) | **PASS** | `0x3400554e24c52b4ea61a84624571b5173393a02bf04406623dd2f44b840b9e59` |

Each rescue moved every plain cell and the token cell; the AdminList (197 CKB) stayed. Token fixed at 142 CKB at
the destination's secp256k1 lock (176 at the Omnilock); the 34 CKB difference joined the plain output. Fees:
1,370 shannons (EVM, 3 inputs), 2,963 (JoyID, 1,719 bytes with the 1024-byte passkey slot used to size the fee).
Each backup was asked to sign exactly once: E1 saw `CKB transaction: 0x8d00d5b9…5d02`, J1's page
`CKB transaction: 0x8bca518c…9c48`.

## The browser run

`step3-browser-evm.ts` starts headless Chromium (Playwright) against `next start` of this branch, with an injected
EIP-1193 provider whose `personal_sign` is answered outside the page by E1. It checks, in order, with the page's
own messages:

- the account's old secp256k1 address: "This address doesn't have recovery on. Turning recovery on gives a
  KeyWay account a new address; enter that one" (`02-error-recovery-off.png`);
- the address with a `ckb1` prefix while on testnet: "That address is on CKB mainnet. Switch the network above";
- a corrupted address: "That address isn't valid. Check it and try again";
- no wallet injected: "No EVM wallet found in this browser…";
- X connected: "EVM wallet 0xe6e9…82cf isn't a backup of this account. Its backups are: EVM wallet 0x30033cae…ec1ef8,
  JoyID ckt1qrfrwc…xsx9hu" (`03-error-not-a-backup.png`);
- the KeyWay address as destination: "That's this KeyWay address. Send to an address you control with another
  wallet";
- a 390 px phone viewport through to the review: no sideways scroll (`04-phone-account.png`,
  `05-phone-review.png`);
- then the rescue on desktop (`06-account.png`, `07-review.png`, `08-sent.png`).

Screenshots: `phase5/screenshots/`. The JoyID button uses CCC's JoyID signer (`@ckb-ccc/joy-id` 1.1.3, the
version built on this repo's `@ckb-ccc/core` 1.16.1), which opens JoyID's pages in a popup; a real JoyID wasn't
available here, so the JoyID path was proved through the module with the same stand-in as phase 4. `/rescue`
is served with `Cross-Origin-Opener-Policy: same-origin-allow-popups` and no COEP (`next.config.ts`), since the
site-wide `same-origin` would cut the popup's link back to the page; the rest of the site keeps its headers.

## Negative checks (dry runs, `negative.ts`; nothing sent)

Funded with `0x6a1d46d8fc1a5841e02d0c0af36635cf27665fbb0a8f3b71c56a0f1f4126d488`.

| Case | Result |
|---|---|
| 1. X (not on the list) signs, with a proof from the list plus X | rejected, Omnilock error 59 (`ERROR_NOT_ON_WHITE_LIST`) |
| 2. E1 signs, then the destination is swapped for X's address | rejected, error -31 (signature mismatch) |
| 3. Another passkey answers as J1 | refused by the module before sending (the assertion doesn't verify against J1's key); the on-chain refusal of a wrong key is in `joyid-verifier-results.md` |
| 4. E1 signs a transaction that also spends the AdminList | **accepted** by `test_tx_pool_accept` (not sent) |

Case 4 confirms on chain what phase 4 noted: a backup holder can spend the AdminList cell (and so destroy or
rewrite the list) with the administrator path. The rescue page never builds such a transaction
(`checkRescueTransaction` refuses it, tested), and KeyWay's server never signs one, but a backup holder using other
software could. See "For the founder".

## The notice email

Turning recovery on and every backup change now send a second email after the transaction is broadcast
(`createRecoveryNoticeEmailTemplate`, `src/server/recovery.ts`): the full new address, every backup in full, and
"If <app> or KeyWay is ever unavailable, any of these backups can move everything at this address to a wallet you
choose at https://ckbkeyway.dev/rescue." It goes through the same `sendEmail` as the code emails; a failure is
logged and doesn't undo the change. Checked in `step1-enable.ts` and in `tests/recovery-postgres.test.ts`.

## Code

- `src/rescue/rescue.ts` (+ `README.md`): `rescueClient`, `parseKeyWayAddress`, `openRescueAccount`,
  `connectEvmBackup`, `rescueEntryForJoyId`, `planRescue`, `checkRescueTransaction`, `signRescueWithEvm`,
  `signRescueWithJoyId`, `sendRescue`. Imports only `@ckb-ccc/core` and `src/sdk/browser` helpers.
- `app/rescue/` — the page: network switch (mainnet marked untested), optional node URL (HTTPS, or a local
  node), address, backups and balance, connect a backup, destination, review, sign, hash with explorer link.
- `tests/rescue.test.ts` — 10 tests against an offline client.

## Checks

`npm ci`; both typechecks; `npm test` (205 tests: 188 pass, 17 Postgres-only skipped, 0 fail);
`npm run test:auth:postgres` (33 pass); `npx next build`.

## Rerun

```sh
export DATABASE_URL=postgres://…   # a disposable local database, migrated with npm run migrate
npx tsx research/omnilock/phase5/faucet.ts K && npx tsx research/omnilock/phase5/faucet.ts F
npx tsx research/omnilock/phase5/step1-enable.ts
npx tsx research/omnilock/phase5/step2-fund.ts fundEvm 1000
npx next build && npx next start -p 3100 &   # then:
npx tsx research/omnilock/phase5/step3-browser-evm.ts
npx tsx research/omnilock/phase5/step2-fund.ts fundJoyId 1000
npx tsx research/omnilock/phase5/step4-joyid.ts
npx tsx research/omnilock/phase5/step2-fund.ts fundNegative 200
npx tsx research/omnilock/phase5/negative.ts
```

## For the founder

- A backup can spend the AdminList (case 4). Closing this needs the AdminList locked by something other than the
  account's own Omnilock, which changes the address scheme; not done here.
- Mainnet: the page's switch is there and labelled untested. JoyID backups need the verifier deployed on
  mainnet; RUSD's contract lookup is testnet-only.
- The rescue page link in the email is `https://ckbkeyway.dev/rescue` (`RESCUE_PAGE_URL`); it is live only after
  the site is deployed with this branch.
- A real JoyID run of the page (popup, passkey) is still to do by hand.
