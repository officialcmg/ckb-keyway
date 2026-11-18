# Force close on Channel V2 (Fiber 0.10.1): live testnet results

**Result: both modes finished.** In each mode a committed transaction downstream of the commitment pays the user's own
address: 4 h 02 min after the force close with the node in the browser, 4 h 05 min with a hosted node.

**One defect found, in browser mode, and fixed on this branch:** the user's share arrived, but the 62 CKB fee reserve
stayed at the node key, and would have stayed for good. It came back to the user's address once the page ran the
fixed SDK. See "Defect: the fee reserve never came back in browser mode".

CKB testnet, production KeyWay API, 2026-11-18. All times UTC. Block numbers, block times and epochs are from CKB RPC
(`testnet.ckb.dev`), not an explorer; times marked "harness clock" are the test machine's clock when the SDK call
returned. SDK: `main` (`67b6b79`, `@ckb-keyway/react` 0.2.14, Fiber 0.10.1) built locally and served under the
production origin, for everything up to and including the payment to each user's address; the last browser-mode step
(the fee reserve's return) ran this branch's SDK, with the fix. The API and the hosted nodes are production.

The 2026-11-17 live run (`docs/LIVE_TEST_2026-11-17.md`) left the force close of a Channel V2 channel to unit tests.
This run does the honest force close (the node closes with its own latest state) once with the node in the browser and
once with a hosted node. Not part of this run: the penalty for a revoked state, and a node database created on Fiber 0.9.1.

## What was done

Two disposable accounts (emailed sign-in codes), one per mode, at the same time:

1. Sign in, fund the user's address with 10,000 CKB from the Nervos testnet faucet, start the node.
2. Open a public channel with 500 CKB through the SDK. Both channels were opened with the public testnet node
   `02b6d4e3ab86a2ca2fad6fae0ecb2e1e559e0b911939872a90abdda6d20302be71`, which added 250 CKB to each.
3. The two accounts paid each other 1 CKB over these channels, routed through that node (each payment `Success`, fee
   0.001 CKB), so each channel was closed from a state after one payment sent and one received, with no payment pending.
4. Force close through the SDK: `node.shutdownChannel({ channel_id, force: true })`, approving the "Force close" dialog.
5. The page stayed signed in with the node running (browser mode) or in use, listing its channels every minute (hosted
   mode), while the harness followed the funding cell on chain until a transaction downstream of the commitment paid
   the user's own lock.
6. Browser mode only, after the payment: the harness was started again on the same account and browser profile to
   see whether the fee reserve left at the node key would come back too, first with the same SDK for 45 minutes, then
   with the fix. (In hosted mode the reserve came back with the share.)

Harness: `research/e2e/browser-settlement.mjs` (`FIBER_MODE=hosted` for the hosted run, `KEYWAY_EVIDENCE` for each
run's own folder, `KEYWAY_PAY_WITH` for the payment exchange, `KEYWAY_RESERVE_MINUTES` for how long a run stays on
after the payment to watch the fee reserve), `research/e2e/trace-close.mjs` to read a close from the chain,
`research/e2e/claim-dry-run.mjs` for the early check below. The reserve watch was added during the run: the two
restarts in step 6 were made by hand, by marking the saved run as paid but not finished.

## Browser mode

- User address `ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsq0xg7plqezsvqhv3qjd50lxw05h9el0wuqlxgqgr`
  (secp256k1 lock, args `0xe64783f06450602ec8824da3fe673e972e7ef770`)
- Node `023378f0ecf198e02856ae7f16ed6a8e7f2e53c9b5b00962446a6fd093c5a58fbf`
- Channel `0xb3189e4cf4b3f0e1dc0d0168f55c1099cbca386c27f624fd7525c57d21200a1c`

| Step | Transaction | Block | Time (UTC) |
|---|---|---|---|
| Funding, 750 CKB (500 user + 250 peer) | `0x0c198c84841fb485a3fef9d185379eb6336558920fec14f221b0b321f4783a2e` | 23099036 | 01:06:16 |
| Fee reserve, 62 CKB to the node key (lock args `0xdca3a45df6d6ea042294af013a4a80d58f7c1956`) | `0xb2d7cc8466720aab75f88e8335e7ae11ab220b4a996ca6fc2ab408c4b0c2459a` | 23099040 | 01:07:09 |
| Payment sent, 1 CKB (payment hash `0x37484c8d…af67`) and received, 1 CKB (`0x7137d471…f02d`) | off chain | n/a | 01:13:06 (harness clock) |
| Force close accepted by the node | n/a | n/a | 01:13:08 (harness clock) |
| Commitment, 749.99999543 CKB | `0x314702be3d8d98f1efb15ed0cf7404bfc0c1ebd86411e9cc6fcf3aa5d0c23879` | 23099093 | 01:13:25 |
| The peer's side claims first: 250.001 CKB out of the commitment cell, 499.99899543 CKB left in a successor commitment cell for the user | `0x16c198dfa5160275120e9ef2a39cabaa6969c63710764e32d906b34af109ba7e` | 23100896 | 05:13:39 |
| Claim of the user's share by the in-page watchtower: the successor cell and the 62 CKB fee reserve in, 561.99898905 CKB to the node key | `0x63466adcc2bb9842e8a1cc8253bf98f888acb0c5f53639f5ff9c5479e3b245e1` | 23100903 | 05:15:06 |
| Sweep by the SDK: **499.99896589 CKB to the user's address**, 62 CKB (the fee reserve) kept at the node key | `0x91ff72f977e25838bf02fba093c6ea0b025a956ee1b7b15c25bb185cc42e6849` | 23100909 | 05:15:45 |
| Return of the fee reserve, by the SDK with this branch's fix: 61.99988206 CKB to the user's address, nothing left at the node key | `0xa3b3bce7c638b5f7b87895753554d67664a319d0cda890715421521ce317ccdd` | 23101293 | 06:08:40 |

The commitment cell's lock args are 58 bytes (Channel V2), commitment number 5, delay `0xa000010000000001`: a relative
`since` of 1 epoch. The commitment is in epoch 14210 at block 1441 of 1800, so the delay ends at epoch 14211, block
1441 of 1800. That is block 23100893, 05:13:09.

- **Commitment delay observed:** 4 h 00 min 14 s (1803 blocks) from the commitment's block to the first block with a
  claim in it; the delay itself (1800 blocks) took 3 h 59 min 44 s.
- **Force close to the user's address:** 4 h 02 min 37 s (force close accepted 01:13:08 harness clock, sweep in a
  block at 05:15:45); 4 h 02 min 20 s from the commitment's block. The user's own claim and sweep took 2 min 36 s from
  the end of the delay.
- **Amounts:** the user's balance in the channel was 499.999 CKB (500 funded, 1.001 paid including the routing fee, 1
  received). 499.99896589 CKB reached the user's address: 0.00003411 CKB less, which is the commitment transaction's
  fee (457 shannons), the claim's fee (638) and the sweep's fee (2316). The reserve's return cost another 11794
  shannons. At the end the node key held 0 CKB and the user's address 9999.99850945 CKB of the 10,000 from the
  faucet (`get_cells_capacity` at block 23101301).
- **The peer's part:** claimed by the peer's side three blocks after the delay ended, in one transaction with the
  delay's `since` on the commitment input: 250.001 CKB went, together with one of that lock's existing cells, to the
  secp256k1 lock with args `0x24ab9e804a1b7f3f303ff54af57e6a0112c72f2a` (1412.00095478 CKB, still live at the time
  of writing; fee 785 shannons). That this lock is the public node's own is inferred from it
  paying the fee and receiving the peer's part; it was not checked any other way.

Early check, 01:16 (before the delay): the claim the in-page watchtower builds for this commitment (unlock `0xFE`,
`since` `0xa000010000000001`, 499.999 CKB out of the cell for the user, 250.00099543 CKB left in a successor cell for
the peer), built from the page's own watchtower data without the fee cell and run through CKB `estimate_cycles`, was
accepted by the commitment lock (1,513,074 cycles). Nothing was sent.

### What did not go to plan in browser mode

The watchtower's first claim, at 05:13:38 (harness clock), was the one checked above: it spends the commitment cell
itself. The node pool refused it (`PoolRejectedRBF`, "Tx's current fee is 785, expect it to >= 1962 to replace old
txs") because the peer's claim of the same cell was already in the pool. The watchtower logged "could not be settled
yet" and, on its next pass a minute later (05:14:38), claimed the user's share from the successor cell the peer's
claim had left, with no `since`. That transaction is the claim in the table. So the claim that ran live is the
"peer settled first" one; the "user settles first" claim was only checked with `estimate_cycles`, not committed.

Who settles first decides who carries the commitment transaction's fee: the first claim takes its full balance out
of the cell and the rest stays in the successor. Here the peer was first, so the 457 shannons came off the user's
part (499.99899543 CKB instead of 499.999). In the early check, where the user would have been first, they came off
the peer's part.

### Defect: the fee reserve never came back in browser mode

**What happened.** The sweep at 05:15:45 paid the user's share and kept 62 CKB at the node key, as it does while any
channel may still need settling. After that sweep nothing of the channel was left to settle: the commitment cell and
its successor were both spent. The harness kept the page open with the node running for another 45 minutes (05:18:46
to 06:04:37, after a restart of the harness, which had ended at the payment). The node went on reporting the channel
as `CLOSED` / `UNCOOPERATIVE_LOCAL|WAITING_ONCHAIN_SETTLEMENT` at every reading, one a minute, and at 06:04:37 the
node key still held the 62 CKB. The hosted node, by contrast, dropped `WAITING_ONCHAIN_SETTLEMENT` within a minute
and a half of its claim, and the API's sweep returned the share and the reserve together.

**Root cause** (Fiber v0.10.1 source, `d9b6bbd`). A node checks every 5 minutes whether a force-closed channel has
settled: no live cell is left under the commitment lock (`network.rs`, `check_channel_shutdown_settlement`). The
browser node does notice this: its log has "on-chain settlement reconciliation incomplete; keeping
ONCHAIN_SETTLEMENT_CONFIRMED" (`channel.rs:4438`) 46 times, from 05:15:36 to 06:03:43. But it only drops
`WAITING_ONCHAIN_SETTLEMENT` when no payment of the closing commitment is unresolved, and
`has_unresolved_onchain_tlcs` (`onchain_tlc_reconcile.rs`) answers "unresolved" for every force close that has no
stored settlement snapshot ("a force-close without a valid snapshot must keep waiting"). The only places that store
that snapshot build it from `store.get_local_watch_channel`, the node's own watchtower data, and without the
`watchtower` feature that function returns `None` (`store_impl/mod.rs`). `fiber-wasm` compiles the library with
`default-features = false`, so the browser node never has a snapshot and never finishes a force close, with or
without payments. The SDK released the reserve only when the node reported every channel as finished
(`needsFeeReserve`), so in browser mode one force-closed channel kept the reserve at the node key for good.

**Fix** (in the SDK, this branch). For a channel that is closed by force and still reported as waiting, the browser
sweep now asks the chain instead of the node: `forceCloseSettled` (`watchtower-settle.ts`) follows the funding cell
to the commitment and through every settlement, and answers yes only once nothing is left under the channel's
commitment lock, which is the node's own test. `needsFeeReserveOnChain` (`settlement-sweep.ts`) keeps the reserve
for any other unfinished channel, and whenever the chain can't be asked. The hosted path is unchanged.

**Regression test.** `tests/fee-reserve.test.ts`, "a force close the chain shows as fully settled gives the reserve
back, though the browser node still says waiting", uses the state the node reported in this run. With the decision
as it was (the node's word only) it fails: `Expected values to be strictly equal: true !== false`. With the fix it
passes. `tests/watchtower-settle.test.ts` adds the chain cases: commitment cell live, the user's part still locked
after the peer's claim, cell emptied by one or by two settlements, channel open.

**On the same channel.** The page was started again at 06:08 with this branch's SDK (same account, same browser
profile). On its first sweep the SDK sent the 62 CKB to the user's address: `0xa3b3bce7…ccdd`, block 23101293,
06:08:40. The node still reported the channel as waiting at that time.

Anyone who force closed a browser-mode channel on 0.2.14 is in the same position until they run an SDK with this fix:
their share is paid, their 62 CKB reserve is at their node key, and it is returned on the next sweep after the update.

## Hosted mode

- User address `ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsq2ntrl0h0gej7g7ashkmjrlwalp8srrwwc66rlyc`
  (secp256k1 lock, args `0x5358fefbbd199791eec2f6dc87f777e13c06373b`)
- Node `02a9aa320f1365214e620ba56c575b454ccf60e9fae5e3f108ef97edb1fbc0887a`
- Channel `0xe19de0cd53e5014f65d5eb7684d349eb789f630c7015794245127a8b8d7e19c3`

| Step | Transaction | Block | Time (UTC) |
|---|---|---|---|
| Funding, 750 CKB (500 user + 250 peer) | `0x103eb91868ec9532bf995d83b3b17e9ed6101f8c69ac2875861f1c5e87490c6e` | 23099035 | 01:06:12 |
| Fee reserve, 62 CKB to the hosted node's key (lock args `0x536e4e20a4becc6ea4787d1b420c5676714611d2`) | `0xd3f163cd15ff532483e6fec63967235c3c35a40efa6b23542453ee49d1826b88` | 23099040 | 01:07:09 |
| Payment sent, 1 CKB (payment hash `0x7137d471…f02d`) and received, 1 CKB (`0x37484c8d…af67`) | off chain | n/a | 01:12:24 and 01:13:06 (harness clock) |
| Force close accepted by the node | n/a | n/a | 01:13:07 (harness clock) |
| Commitment, 749.99999543 CKB | `0xf68fb120c50b9e26aedb6ba656d0c68e8306e4fa06f2342125d985ecb4777ffd` | 23099093 | 01:13:25 |
| The peer's side claims first: 250.001 CKB out of the commitment cell, 499.99899543 CKB left in a successor commitment cell for the user | `0xebc89d13cff34a0de9a3e710271c13cd92b63a53562a250a86c75b9777e4a395` | 23100896 | 05:13:39 |
| Claim of the user's share by the hosted node's watchtower: the successor cell and the 62 CKB fee reserve in, 561.99898905 CKB to the hosted node's key | `0x8b6c592c26ed382952b9b80b9241ef5d317c66fdce29f0ea6488a6c6b3c09b0a` | 23100903 | 05:15:06 |
| Sweep by the API: **561.99887111 CKB to the user's address** (the user's share and the fee reserve), nothing left at the hosted node's key | `0xb5ca1a17b406fbaaef7a49bae24552711f5a2355195d9f6c622dc26dfe3fdf8e` | 23100932 | 05:18:22 |

Same commitment format and delay as in browser mode (58-byte args, commitment number 5, delay `0xa000010000000001`),
in the same block, so the delay ended at the same block (23100893, 05:13:09).

- **Commitment delay observed:** 4 h 00 min 14 s (1803 blocks) from the commitment's block to the first block with a
  claim in it, as in browser mode.
- **Force close to the user's address:** 4 h 05 min 15 s (force close accepted 01:13:07 harness clock, sweep in a
  block at 05:18:22); 4 h 04 min 57 s from the commitment's block. The sweep came 3 min 16 s after the claim; the
  API sweeps at most once per 10 minutes per user, so this gap can be up to about 10 minutes longer.
- **Amounts:** the user's balance in the channel was 499.999 CKB, and the fee reserve 62 CKB. 561.99887111 CKB
  reached the user's address: 0.00012889 CKB less, which is the commitment transaction's fee (457 shannons), the
  claim's fee (638) and the sweep's fee (11794). After the sweep the hosted node's key held 0 CKB and the user's
  address 9999.99853261 CKB of the 10,000 from the faucet (`get_cells_capacity` at block 23100949).
- **The peer's part:** as in browser mode, claimed first, in block 23100896: 250.001 CKB went, with one of that
  lock's existing cells, to the same lock `0x24ab9e80…2f2a` (1271.66702358 CKB, still live at the time of writing;
  fee 785 shannons).
- The node reported the channel as `Closed` / `UNCOOPERATIVE_LOCAL|WAITING_ONCHAIN_SETTLEMENT` until 05:15:35 and as
  `Closed` / `UNCOOPERATIVE_LOCAL` from 05:16:36 (harness clock, one reading a minute).
- Not checked: whether the hosted node's watchtower also tried to claim the commitment cell itself before the peer's
  claim was committed. The hosted node's logs were not read; only the chain and the SDK's view of the node were.

## Not covered

- The watchtower's penalty for a revoked state, and a node database created on Fiber 0.9.1 (both out of this run's scope).
- A claim by the user's side of the commitment cell itself, before the peer's: both channels' peers claimed first.
  In browser mode that claim was built and accepted by `estimate_cycles` but lost to the peer's in the pool; in
  hosted mode it is not known whether it was tried.
- A force close with a payment pending, a force close started by the peer, and a peer that never claims its part.
- Token (UDT) channels: both channels held CKB only.
- A page that is closed, or a hosted node that is not in use, during or after the delay. Both pages stayed open and
  signed in for the whole run.
- A private channel, and any peer other than the one public testnet node.
- The published package and the deployed website: the SDK was built locally. The fix is not published or deployed.
- The fix with more than one channel, on mainnet, and with the user's claim first (the reserve should then stay
  until the peer has claimed its part): unit tests only.

## Reading it from the chain

```bash
node research/e2e/trace-close.mjs 0x0c198c84841fb485a3fef9d185379eb6336558920fec14f221b0b321f4783a2e:0 0x103eb91868ec9532bf995d83b3b17e9ed6101f8c69ac2875861f1c5e87490c6e:0
```

prints both closes from CKB RPC alone: each transaction downstream of the funding cell with its block, block time,
epoch, the inputs' `since` and whether each output is still live.

## Checks on this branch

On the final commit, with `KEYWAY_AUTH_TEST_DATABASE_URL` unset: `npm test` ran 683 tests (572 passed, 0 failed, 111 skipped, the ones that need a database); `npm run typecheck` passes.
