# @ckb-keyway/react 0.2.5 — draft release notes

Not released. Version numbers are unchanged until the release is approved.

## Account recovery (opt-in, CKB testnet)

Users can name backups that move everything in their account without KeyWay: an EVM wallet or a JoyID passkey.

- `useCkbWallet().recovery`: `status`, `backups`, `legacyAddress`, `enable(backups)`, `addBackup(proof)`,
  `removeBackup(backup)`, `createEvmBackup(ethereum?)`, `createJoyIdBackup(joyIdSigner)`.
- `useCkbWallet().legacyAddress`: the address from before recovery was turned on.
- `KeyWayProvider` props `approveRecovery` and `approveBackupChange` replace the built-in dialogs. New exported
  types: `RecoveryPreview`, `BackupChangePreview`, `RecoveryEnabled`, `BackupChanged`, `RecoveryBackup`,
  `RecoveryBackupProof`, `ApproveRecovery`, `ApproveBackupChange`, `EthereumProvider`, `KeyWayRecovery`.
- Turning recovery on changes the account's address once, to an Omnilock address. Adding or removing a backup
  doesn't change it again. The signer, balance and channel funding follow the new address automatically.
- Turning recovery on and every backup change always need the emailed code, whatever the daily amount. Adding a
  backup needs the backup's own signature.
- Costs: about 197 CKB stays in the backup list; the smallest plain cell goes from 61 to 95 CKB and the smallest
  token cell from 142 to 176 CKB.
- After each change, users get an email with their full address, their backups and the rescue page link.
- On every sign-in, KeyWay moves CKB and tokens that reach the old address to the new one.
- Rescue page: ckbkeyway.dev/rescue moves everything with one backup and a public CKB node only. Source in
  `src/rescue`.

## Known limits

- Omnilock has no public audit and its deployer can upgrade it. KeyWay's JoyID passkey verifier is unaudited.
- A backup holder can rewrite the backup list with other software; KeyWay and the rescue page never do.
- Message signing still reports the account's secp256k1 public key.
- JoyID backups are testnet only (the verifier isn't deployed on mainnet). JoyID's popup doesn't work on pages
  served with `Cross-Origin-Opener-Policy: same-origin`.

## Upgrading

No breaking changes. Apps that don't call `recovery` see no difference. Apps that show the user's address should
read `useCkbWallet().address` rather than caching it, since it changes once if the user turns recovery on.
