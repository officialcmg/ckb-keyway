# CKB KeyWay

Email-authenticated wallet infrastructure for Fiber Network. The included Next.js app is a reference client for the reusable browser and server SDK modules under `src/sdk`.

## Browser SDK

```ts
import { createKeyWay, loadFiberKey } from "@ckb-keyway/sdk/browser";

const keyway = createKeyWay({
  identifier: wallet.litPkpId,
  sessionJwt: stytchSessionJwt,
  ckbPublicKey: wallet.litPublicKey,
  loadFiberKey: (leaseId) => loadFiberKey(stytchSessionJwt, leaseId),
  confirmFunding: ({ amountCkb, feeCkb, destination }) =>
    showFundingConfirmation({ amountCkb, feeCkb, destination }),
});

await keyway.start();
const invoice = await keyway.newInvoice({ /* Fiber invoice parameters */ });

const channel = await keyway.openFundedChannel({
  pubkey: peerPublicKey,
  funding_amount: "0x2540be400", // 100 CKB in shannons
  public: true,
});
```

`bootstrapKeyWay(sessionJwt)` provisions or recovers the public `wallet` metadata used above. The credential provider deliberately returns no CKB secret key. `openFundedChannel` uses Fiber Pay's external-funding flow and a CCC signer that delegates only policy-checked, explicitly confirmed transactions to Lit.

## Security boundaries

- The raw Lit PKP private key is not exported to the application.
- The Fiber identity key is encrypted at rest, but exists in the KeyWay backend and browser/WASM memory while it is recovered and used.
- Web Locks, BroadcastChannel, and a short authenticated server lease prevent accidental concurrent node use.
- Fiber channel-state recovery is same-device because the node database remains in IndexedDB.
- Email compromise can authorize recovery; the testnet prototype has not been audited and is not production custody software.

## Verification

```sh
npm run typecheck
npm test
npm run build
```
