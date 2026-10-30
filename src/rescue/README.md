# Rescue

`rescue.ts` is the logic behind the rescue page (`app/rescue`, served at ckbkeyway.dev/rescue): moving everything
out of a KeyWay account with recovery on, signed by one of its backups. It needs only a public CKB node. It never
calls a KeyWay server, database, Lit or any secret, so it keeps working if KeyWay is gone.

What it reads, all from the chain:

1. The KeyWay address is KeyWay's pinned Omnilock (by data hash) in administrator mode: args `0x00 ‖
   blake160(account key) ‖ 0x01 ‖ AdminList type hash`. `parseKeyWayAddress` checks that shape.
2. The AdminList cell is found by that type hash under its owner-only lock (`0x00 ‖ blake160(account key) ‖
   0x00`). It holds only the SMT root of the backup list.
3. The transaction that last wrote the AdminList records the whole list (`recoveryListFrom` in
   `src/sdk/browser/recovery-list.ts`). The list is rebuilt and refused unless it hashes to the cell's root.

The node is trusted only for which cells exist. Every cell, the AdminList included, is read from the transaction
that created it, after checking that transaction's hash against the out point (`verifiedCell`), so a node can't
change a cell's capacity, lock, type or data.

What it sends: one transaction, built by `planRescue` and checked by `checkRescueTransaction`. Every plain CKB
cell and token cell (xUDT, sUDT, RUSD) at the address goes to the destination; tokens move one to one with their
data. The AdminList is a cell dep, never an input, so it and its CKB stay. Other cells (Nervos DAO, NFTs, cells
with data, tokens with extension flags) are left alone; if the node's dry run blames one token cell, it is left
out and the rescue is built again. Destinations must use a lock the page knows. The backup signs once, the
readable approval (`src/sdk/browser/recovery-approval.ts`) naming the destination, the CKB, the token cells, the
fee and the sighash: an EVM wallet with personal_sign, a JoyID passkey through WebAuthn. KeyWay's verifiers
(`contracts/`) rebuild that text from the transaction and accept nothing else.

Tests: `tests/rescue.test.ts`, `tests/audit-fable51-rescue-rpc.test.ts`. Testnet proof:
`research/omnilock/audit-fixes-results.md`.

To host it yourself, run this repository's Next app (`npm ci && npx next build && npx next start`) and open
`/rescue`, or call the functions from your own page. Mainnet is prepared (`rescueClient("mainnet")`) but
untested, and backups need KeyWay's verifiers deployed there first.
