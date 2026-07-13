# Testnet Evidence

Verification date: July 13, 2026

Environment:

- Production reference app: `https://ckb-keyway.vercel.app`
- CKB Pudge testnet
- Fiber WASM `0.9.0-rc7`
- Independent receiver: the public Fiber Checkout testnet demo

## Channel activation

The disposable wallet authenticated by email, recovered the same CKB address after logout, connected to Fiber testnet, approved the funding preview, and reached `ChannelReady`.

- Funding transaction: `0x6cbe309c362fca8df9d9d57359ccedb5f31691e265abbfc32d3a4c5e5527c319`
- Channel ID: `0xfb2ed16a558fd89565c6b3d14596eff90228e11c91a579c25a58c5ae8d4a0ed9`
- Funding outpoint: `0x6cbe309c362fca8df9d9d57359ccedb5f31691e265abbfc32d3a4c5e5527c319:0x0`
- Fiber packed outpoint: `0x6cbe309c362fca8df9d9d57359ccedb5f31691e265abbfc32d3a4c5e5527c31900000000`
- Block: `21735029`
- KeyWay contribution shown before approval: `999.99999754 CKB`
- Total transaction fee shown before approval: `0.0000071 CKB`
- Collaborative FundingLock output: `1,250 CKB`
- KeyWay on-chain change: `8,999.99999536 CKB`

Explorer: [view the funding transaction](https://testnet.explorer.nervos.org/transaction/0x6cbe309c362fca8df9d9d57359ccedb5f31691e265abbfc32d3a4c5e5527c319).

The transaction has two inputs and three outputs: one KeyWay input, one peer input, the Fiber FundingLock output, and change for both parties. This is why the signing policy validates KeyWay's own debit while permitting peer-owned collaborative inputs.

## Fiber payment

The independent receiver generated a fixed 1 CKB invoice. The recovered KeyWay wallet parsed it, displayed an explicit confirmation, submitted it through Fiber, and reported settlement. The receiver independently changed from `Waiting for payment` to `Payment confirmed`.

- Amount: `1 CKB`
- Payment hash: `0x705dae6371d3b2b10e417bf18b9cac0235e654eb59ffd8a1432e0cf3250d472b`
- Sender state: settled
- Receiver state: payment confirmed
- Sender console errors: none
- Receiver console errors: none

Fiber payments are off-chain, so this payment does not have a separate CKB transaction hash.

## Automated checks

The same release passed:

```text
npm run typecheck
npm test
npm run build
```

Automated coverage includes PKP recovery, signature formatting, Lit Action boundaries, encrypted Fiber-key round trips, device leases, collaborative funding policy, CCC-to-RPC transaction serialization, peer selection, and actionable error mapping.
