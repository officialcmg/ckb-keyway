# CKB KeyWay

Email-authenticated wallet infrastructure for Fiber Network. The included Next.js app is a reference client for the reusable browser and server SDK modules under `src/sdk`.

## Browser SDK

```ts
import { createKeyWay } from "@ckb-keyway/sdk/browser";

const keyway = createKeyWay({
  identifier: stytchUserId,
  loadFiberKey: () => authenticatedApi.getFiberKey(),
});

await keyway.start();
const invoice = await keyway.newInvoice({ /* Fiber invoice parameters */ });
```

The credential provider deliberately returns no CKB secret key. Channel funding must use Fiber Pay's external-funding flow and the Lit-backed remote signer.

The authenticated loader obtains the Lit-protected Fiber key from KeyWay's backend. Fiber channel-state recovery remains same-device until encrypted database migration is implemented.
