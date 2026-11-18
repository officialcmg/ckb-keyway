# Force close on Channel V2 (Fiber 0.10.1): live testnet results

**Status: in progress.** Both channels are force-closed and their commitments are on chain; the claims wait for the
commitment delay. See "Not finished" at the end for what is still unclaimed. This file is updated as the run goes on.

CKB testnet, production KeyWay API, 2026-11-18. All times UTC. Block numbers, block times and epochs are from CKB RPC
(`testnet.ckb.dev`), not an explorer; times marked "harness clock" are the test machine's clock when the SDK call
returned. SDK: this branch's `main` (`67b6b79`, `@ckb-keyway/react` 0.2.14, Fiber 0.10.1) built locally and served
under the production origin; the API and the hosted nodes are production.

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
   mode), while the harness followed the funding cell on chain.

Harness: `research/e2e/browser-settlement.mjs` (`FIBER_MODE=hosted` for the hosted run, `KEYWAY_EVIDENCE` for each
run's own folder, `KEYWAY_PAY_WITH` for the payment exchange), `research/e2e/trace-close.mjs` to read a close from the
chain, `research/e2e/claim-dry-run.mjs` for the early check below.

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

The commitment cell's lock args are 58 bytes (Channel V2), commitment number 5, delay `0xa000010000000001`: a relative
`since` of 1 epoch. The commitment is in epoch 14210 at block 1441 of 1800, so the first claim can be committed from
epoch 14211, 1441/1800 of the way through.

Early check, 01:16 (before the delay): the claim the in-page watchtower builds for this commitment (unlock `0xFE`,
`since` `0xa000010000000001`, 499.999 CKB out of the cell for the user, 250.00099543 CKB left in a successor cell for
the peer), built from the page's own watchtower data without the fee cell and run through CKB `estimate_cycles`, was
accepted by the commitment lock (1,513,074 cycles). Nothing was sent.

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

Same commitment format and delay as in browser mode (58-byte args, commitment number 5, delay `0xa000010000000001`).

## Not finished

As of 01:17 UTC on 2026-11-18 (tip block 23099120, epoch 14210 1468/1800) the delay had not passed. Still unclaimed:

| Mode | Channel | Commitment cell (live) | What claims it |
|---|---|---|---|
| Browser | `0xb3189e4c…0a1c` | `0x314702be3d8d98f1efb15ed0cf7404bfc0c1ebd86411e9cc6fcf3aa5d0c23879:0`, 749.99999543 CKB | The in-page watchtower, with the page open and the node running, once the tip reaches epoch 14211 1441/1800 (estimated about 05:00 to 05:15 UTC). It pays the user's 499.999 CKB to the node key (`0xdca3a45d…1956`); the SDK's sweep then pays the user's address. The peer's 250.00099543 CKB is the peer's to claim. |
| Hosted | `0xe19de0cd…19c3` | `0xf68fb120c50b9e26aedb6ba656d0c68e8306e4fa06f2342125d985ecb4777ffd:0`, 749.99999543 CKB | The hosted node's own watchtower, after the same delay, to the node's key (`0x536e4e20…11d2`); the API then sweeps that key to the user's address while the signed-in page keeps using the node. |

To read the result from the chain later:

```bash
node research/e2e/trace-close.mjs 0x0c198c84841fb485a3fef9d185379eb6336558920fec14f221b0b321f4783a2e:0 0x103eb91868ec9532bf995d83b3b17e9ed6101f8c69ac2875861f1c5e87490c6e:0
```

A mode is done when a transaction downstream of its commitment pays the user's lock given above.
