# CKB KeyWay

Email-authenticated wallet infrastructure for Fiber Network. The included Next.js app is a reference client for the reusable browser and server SDK modules under `src/sdk`.

## Browser SDK

```ts
import { createKeyWay, loadSameDeviceFiberKey } from "@ckb-keyway/sdk/browser";

const keyway = createKeyWay({
  identifier: stytchUserId,
  loadFiberKey: () => loadSameDeviceFiberKey(stytchUserId),
});

await keyway.start();
const invoice = await keyway.newInvoice({ /* Fiber invoice parameters */ });
```

The credential provider deliberately returns no CKB secret key. Channel funding must use Fiber Pay's external-funding flow and the Lit-backed remote signer.

The MVP Fiber identity and Fiber channel database are recoverable only in the same browser profile. Cross-device identity recovery is intentionally blocked until encrypted channel-state migration and a single-writer lease exist.
