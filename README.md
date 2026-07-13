# CKB KeyWay

CKB KeyWay is reusable email-authenticated wallet infrastructure for Fiber Network. It combines Stytch email OTP, a Lit Chipotle PKP, CCC transaction construction, and a browser Fiber node so an application can recover a stable CKB identity and externally fund Fiber channels without exporting the PKP private key.

The repository contains two deliverables:

- A browser/server SDK under `src/sdk`.
- A deployed Next.js reference wallet demonstrating login, recovery, channel activation, invoices, and payments.

Live testnet demo: [ckb-keyway.vercel.app](https://ckb-keyway.vercel.app)

## Working flow

1. Stytch verifies the user's email OTP and supplies a stable user ID.
2. The backend provisions or recovers one Lit PKP and its CKB testnet address.
3. A separately generated Fiber identity key is recovered after authentication and loaded into the browser WASM node.
4. The browser connects to Fiber testnet relays and a channel peer.
5. Fiber and the peer collaboratively construct an unsigned funding transaction.
6. The backend validates the complete transaction and computes only the KeyWay lock group's CKB sighash.
7. A pinned Lit Action signs that digest. KeyWay verifies the recovered public key and inserts only its witness.
8. Fiber submits the signed transaction, waits for `ChannelReady`, and can send or receive invoices.

## Run locally

Requirements: Node.js 20 or newer, a Stytch Consumer test project, and a configured Lit Chipotle account.

```sh
npm install
cp .env.example .env.local
npm run dev
```

Configure Stytch email OTP and allow `http://localhost:3000` as an SDK domain. Register the three Actions in `lit-actions/` with Chipotle, permit the runtime usage key to execute them for the application's PKPs, and place only server credentials in `.env.local`. Never expose `STYTCH_SECRET`, `LIT_USAGE_API_KEY`, or `LIT_PROVISIONING_API_KEY` to browser code.

## Browser SDK

`connectKeyWay` is the high-level entry point used by the reference app. It bootstraps the authenticated wallet, acquires the device lock and lease, starts Fiber without a CKB secret key, connects testnet relays, and returns the wallet balance.

```ts
import { connectKeyWay } from "@ckb-keyway/sdk/browser";

const connected = await connectKeyWay({
  sessionJwt: stytchSessionJwt,
  confirmFunding: ({ amountCkb, feeCkb }) =>
    showConfirmation(`Lock ${amountCkb} CKB with a ${feeCkb} CKB fee?`),
});

const opened = await connected.keyway.activateCkbChannel(1_000n * 100_000_000n);
await connected.keyway.waitForChannelReady(opened.channelId);

const payment = await connected.keyway.sendPayment({
  invoice: fiberInvoice,
  timeout: "0x1d4c0",
  max_fee_amount: "0x5f5e100",
});
await connected.keyway.waitForPayment(payment.payment_hash);

await connected.keyway.stop();
```

See [`examples/browser-wallet.ts`](examples/browser-wallet.ts) for a complete minimal lifecycle. The package is intentionally private during the hackathon; its `./browser` and `./server` exports are ready to be split or published after the API stabilizes.

## Security model

- The Lit PKP private key is not returned to the browser or KeyWay backend.
- The backend accepts a complete CKB transaction, enforces testnet funding and fee limits, computes CCC's exact sighash, and invokes only a pinned Lit Action.
- The stored Fiber identity key is encrypted at rest. The MVP backend can observe it during recovery, and it necessarily exists in browser/WASM memory while Fiber runs.
- Web Locks, `BroadcastChannel`, and a short authenticated backend lease enforce one active browser node.
- Channel data remains in that browser's IndexedDB. The CKB identity can be recovered elsewhere, but Fiber startup is blocked after channel use until safe database transfer exists.
- Email compromise can authorize recovery. This testnet prototype is experimental, unaudited, and not production custody software.

## Verified testnet result

On July 13, 2026, a disposable KeyWay wallet recovered after logout, resumed its persisted `ChannelReady` state, and settled an independent 1 CKB Fiber invoice.

- Funding transaction: [`0x6cbe309c362fca8df9d9d57359ccedb5f31691e265abbfc32d3a4c5e5527c319`](https://testnet.explorer.nervos.org/transaction/0x6cbe309c362fca8df9d9d57359ccedb5f31691e265abbfc32d3a4c5e5527c319)
- Channel ID: `0xfb2ed16a558fd89565c6b3d14596eff90228e11c91a579c25a58c5ae8d4a0ed9`
- Funding output: index `0x0`, 1,250 CKB collaborative channel capacity
- Fiber payment hash: `0x705dae6371d3b2b10e417bf18b9cac0235e654eb59ffd8a1432e0cf3250d472b`
- Sender result: settled
- Independent receiver result: payment confirmed

See [`docs/TESTNET_EVIDENCE.md`](docs/TESTNET_EVIDENCE.md) for the reproducible evidence and [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for component boundaries.

## Verification

```sh
npm run typecheck
npm test
npm run build
```

The production deployment also sends `Cross-Origin-Opener-Policy: same-origin` and `Cross-Origin-Embedder-Policy: require-corp`, which Fiber's multithreaded WASM runtime requires.

## Current limitations

- Testnet CKB only; UDTs, swaps, merchant checkout, and mainnet are out of scope.
- Fiber channel state is same-browser only and has no migration UI yet.
- The backend is trusted to authorize Lit operations and can observe the decrypted Fiber key.
- The reference wallet uses fixed activation and maximum-payment-fee limits for a predictable demo.
- Lit, Fiber WASM, public peers, Stytch, and the CKB testnet RPC remain external availability dependencies.

## Upstream foundations

- `@nervosnetwork/fiber-js` `0.9.0-rc7`
- `@fiber-pay/sdk` `0.2.7`
- `@ckb-ccc/core` `1.16.1`
- `@stytch/nextjs` `22.0.11`
- Lit Chipotle Actions pinned by immutable IPFS CID

CKB KeyWay is independent experimental infrastructure and is not affiliated with or endorsed by these projects.
