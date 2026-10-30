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
- Omnilock is pinned by data hash (`data1`): KeyWay's own copy of the official testnet binary, under a lock nobody
  can unlock. The account's recovery settings store the code hash and cell deps.
- The backup list has its own owner-only lock (the Lit key, without administrator mode). Backups can't spend,
  move or rewrite it.
- Backups approve a move by signing a readable text naming the destination, the CKB, the token cells, the fee and
  the transaction hash. KeyWay's verifiers (`contracts/`) rebuild it from the transaction on chain, for EVM wallets
  (personal_sign) and JoyID passkeys (WebAuthn) alike.
- Turning recovery on and every backup change always need the emailed code, whatever the daily amount. Adding a
  backup needs the backup's own signature over a challenge with a nonce from KeyWay that expires after 15
  minutes. `createEvmBackup` and `createJoyIdBackup` fetch it.
- Changes take effect once their transaction is committed: `enable`, `addBackup` and `removeBackup` resolve then.
- KeyWay and the SDK check each account's recovery settings against the chain before using them.
- Costs: 165 CKB stays in the backup list; the smallest plain cell goes from 61 to 95 CKB and the smallest
  token cell from 142 to 176 CKB.
- After each change, users get an email with their full address, their backups and the rescue page link.
- On every sign-in, KeyWay moves CKB and tokens that reach the old address to the new one. The SDK no longer
  selects the old address's cells itself.
- Fiber settlement sweeps size token cells for the Omnilock (176 CKB) and leave a token cell for later when the
  plain CKB can't cover it.
- Rescue page: ckbkeyway.dev/rescue moves everything with one backup and a public CKB node only. It reads every
  cell from the transaction that created it, shows the text the backup signs, and only sends to locks it knows.
  Source in `src/rescue`.

## Known limits

- Omnilock has no public audit. KeyWay's verifiers are unaudited.
- Backups don't reach Fiber channel balances, force-close settlements at the node's key, the fee reserve or the
  backup list's own 165 CKB.
- Message signing still reports the account's secp256k1 public key.
- Backups are testnet only (the verifiers aren't deployed on mainnet). JoyID's popup doesn't work on pages served
  with `Cross-Origin-Opener-Policy: same-origin`.

## Upgrading

No breaking changes for apps that don't call `recovery`. Apps that show the user's address should read
`useCkbWallet().address` rather than caching it, since it changes once if the user turns recovery on. Recovery
addresses made before the audit fixes (testnet only) aren't carried over.
