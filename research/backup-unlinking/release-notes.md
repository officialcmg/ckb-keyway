# @ckb-keyway/react: salted backup identities (draft, version to be decided)

## Backups no longer link a person's accounts across apps

Each app gives the same email its own KeyWay account. A recovery backup used to have the same identity on chain in
every account (the EVM address, or the JoyID passkey's key hash, in clear in the list record), so anyone reading the
chain could link one person's accounts in different apps through a shared backup.

A backup's identity is now salted with the account's AdminList type hash: `blake160(backup ID ‖ salt)`. The same
EVM wallet or passkey has an unrelated identity in each account, and the list recorded on chain holds only these
salted identities. KeyWay's server, its emails and the app still show the real backups. The salt is public, so
someone who already knows a backup's address can check whether it's on a given account's list, and a rescue
reveals the backup that signed it.

## Breaking: existing recovery lists stop working (testnet)

New verifiers on testnet (data hashes `0x14715402…b86f` EVM, `0x01ac20c4…2957` WebAuthn) check salted identities.
Account addresses don't change, but backup lists written before this release name unsalted identities and the old
verifiers, and the new SDK, server and rescue page refuse their records (version 2). There are no users with
recovery on, so this release has no migration path; KeyWay's own testnet proof accounts from earlier releases are
left as they are. Recovery is testnet only.

## Changes

- `OnChainRecoveryList` has `auths` (the members' salted auths) and `salt` instead of `entries`. A backup is found
  on a list by computing its auth with the account's salt.
- `RecoverySpend.list` is now `RecoverySpend.auths`.
- The rescue page shows how many backups an account has and, once a backup is connected, that it is on the list.
- Needs the server deployed from the same commit: its recovery records and checks use the new list format.
