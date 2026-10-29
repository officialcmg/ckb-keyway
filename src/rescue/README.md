# Rescue

`rescue.ts` is the logic behind the rescue page (`app/rescue`, served at ckbkeyway.dev/rescue): moving everything
out of a KeyWay account with recovery on, signed by one of its backups. It needs only a public CKB node. It never
calls a KeyWay server, database, Lit or any secret, so it keeps working if KeyWay is gone.

What it reads, all from the chain:

1. The KeyWay address is an Omnilock in administrator mode: args `0x00 ‖ blake160(account key) ‖ 0x01 ‖ AdminList
   type hash`. `parseKeyWayAddress` checks that shape.
2. The AdminList cell is found among the address's own cells by that type hash. It holds only the SMT root of
   the backup list.
3. The transaction that last wrote the AdminList records the whole list (`readRecoveryList` in
   `src/sdk/browser/recovery-list.ts`). The list is rebuilt and refused unless it hashes to the cell's root.

What it sends: one transaction, built by `planRescue` and checked by `checkRescueTransaction`. Every plain CKB
cell and token cell (xUDT, sUDT, RUSD) at the address goes to the destination; tokens move one to one with their
data. The AdminList is a cell dep, never an input, so it and its CKB stay. Other cells (Nervos DAO, NFTs, cells
with data) are left alone. The backup signs once: an EVM wallet personal_signs `CKB transaction: 0x<sighash>`
(Omnilock flag 0x12), a JoyID passkey signs the same text through KeyWay's WebAuthn verifier.

Tests: `tests/rescue.test.ts`. Testnet proof: `research/omnilock/phase5-results.md`.

To host it yourself, run this repository's Next app (`npm ci && npx next build && npx next start`) and open
`/rescue`, or call the functions from your own page. Mainnet is prepared (`rescueClient("mainnet")`) but
untested, and JoyID backups need KeyWay's verifier deployed there first.
