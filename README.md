# CKB KeyWay

CKB KeyWay is reusable email-authenticated wallet infrastructure for Fiber Network. It combines Stytch email OTP, a Lit Chipotle PKP, CCC transaction construction, and a browser Fiber node so an application can recover a stable CKB identity and externally fund Fiber channels without exporting the PKP private key.

The repository contains two independent deliverables:

- The public React SDK under `src/sdk`, including its framework-independent browser client.
- A standalone Node/Postgres backend and a Next.js reference wallet demonstrating login, recovery, channel activation, invoices, and payments.

Project overview: [ckb-keyway.vercel.app](https://ckb-keyway.vercel.app)

Live testnet wallet: [ckb-keyway.vercel.app/app](https://ckb-keyway.vercel.app/app)

Standalone API: [keyway-api-production.up.railway.app](https://keyway-api-production.up.railway.app/healthz)

## Working flow

1. The SDK sends email OTP requests to the managed KeyWay API; Stytch remains private backend infrastructure and supplies a stable user ID.
2. The backend provisions or recovers one Lit PKP and its CKB testnet address.
3. A separately generated Fiber identity key is recovered after authentication and loaded into the browser WASM node.
4. The browser connects to Fiber testnet relays and a channel peer.
5. Fiber and the peer collaboratively construct an unsigned funding transaction.
6. The backend validates the complete transaction and computes only the KeyWay lock group's CKB sighash.
7. A pinned Lit Action signs that digest. KeyWay verifies the recovered public key and inserts only its witness.
8. Fiber submits the signed transaction, waits for `ChannelReady`, and can send or receive invoices.

KeyWay connects each browser node to the official testnet relays for network reachability and gossip. Its convenience activation flow then prefers the browser-reachable Bottle or Bracer channel providers, falling back to eligible nodes discovered from the Fiber graph. The 400 CKB value in `channel-peers.ts` is the minimum request KeyWay will send to those providers, not their contribution. In the verified 1,250 CKB testnet channel below, KeyWay requested 1,000 CKB and the accepting peer contributed the remaining 250 CKB; applications should read the negotiated `local_balance` and `remote_balance` rather than assume that split for every channel.

## Run locally

Requirements: Node.js 20 or newer, a Stytch Consumer test project, a configured Lit Chipotle account, and Postgres.

```sh
npm install
cp .env.example .env.local
npm run build:api
npm run api
# In another terminal:
npm run dev
```

Configure Stytch email OTP for backend API access. The browser never receives a Stytch token, so no consuming domain is registered in Stytch. Add the frontend origin to `KEYWAY_ALLOWED_ORIGINS`, register the three Actions in `lit-actions/` with Chipotle, and place only server credentials in `.env.local`. Never expose `STYTCH_SECRET`, `LIT_USAGE_API_KEY`, or `LIT_PROVISIONING_API_KEY` to browser code.

## React SDK

The public package owns email OTP, the login modal, wallet provisioning, and Fiber startup behind one provider. It also retains `connectKeyWay` for lower-level integrations.

> **Testnet prerelease limitation:** installing the package is not enough for an arbitrary application to use the managed KeyWay API yet. The application's exact browser origin must first be added manually to the backend `KEYWAY_ALLOWED_ORIGINS` list; otherwise OTP and wallet requests fail CORS checks. Self-service application registration and origin management are not implemented in `0.0.1`.

```sh
npm install @ckb-keyway/react
```

```tsx
import { KeyWayLoginButton, KeyWayProvider, useKeyWay } from "@ckb-keyway/react";

function Wallet() {
  return (
    <KeyWayProvider appName="My Fiber App" theme="light">
      <KeyWayLoginButton />
      <Balance />
    </KeyWayProvider>
  );
}

function Balance() {
  const { ready, authenticated, connection } = useKeyWay();
  if (!ready) return <p>Loading KeyWay...</p>;
  if (!authenticated) return null;
  return connection ? <p>{connection.balanceShannons.toString()} shannons</p> : null;
}
```

`KeyWayLoginButton` opens the built-in email OTP modal. After verification, KeyWay recovers or provisions the same CKB identity and starts the browser Fiber node automatically. Channel activation uses a built-in transaction confirmation unless the application supplies `confirmFunding`. Applications can call `login()` and `logout()` from `useKeyWay()` when they want custom buttons.

### React API

| API | Purpose |
| --- | --- |
| `KeyWayProvider` | Owns email OTP, wallet recovery, Fiber startup, and funding confirmation |
| `KeyWayLoginButton` | Opens the email OTP modal and logs out an authenticated user |
| `KeyWayConnectButton` | Manually starts or stops Fiber when `autoConnect` is disabled |
| `useKeyWay()` | Returns auth status, user, wallet connection, errors, and lifecycle methods |

The SDK uses CKB KeyWay's managed backend automatically. `appName` brands the SDK modal, `theme` accepts `"light"` or `"dark"`, `autoConnect` defaults to `true`, and `confirmFunding` can replace the built-in funding modal. `useKeyWay()` returns `ready`, `authenticated`, `user`, `connection`, `status`, `error`, `login`, `logout`, `connect`, and `disconnect`. Fiber operations are available on `connection.keyway`, including channel, invoice, peer, and payment methods. Backend URLs, Stytch credentials, and Stytch configuration are intentionally absent from the public API.

`appName` does not alter the sender or contents of the OTP email. Stytch email templates are configured server-side. Per-application email branding requires a registered KeyWay application whose verified identity maps to an approved template; this would be a future feature.

With the default `autoConnect`, successful OTP immediately recovers the wallet, starts its browser Fiber node, connects testnet relays, and fetches an initial CKB balance. Use `autoConnect={false}` with `connect()` and `disconnect()` when an application wants explicit node lifecycle control. Logout and provider cleanup stop the node but deliberately preserve its IndexedDB channel state.

The same package exports the headless connection API:

```ts
import { connectKeyWay } from "@ckb-keyway/react";

const connected = await connectKeyWay({
  authToken: keyWaySessionToken,
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

`connection.keyway` also exposes direct peer/channel operations and Fiber's route inspection surface: `connectPeer`, `openFundedChannel`, `listChannels`, `graphNodes`, `graphChannels`, `buildRouter`, and `sendPaymentWithRouter`. `sendPayment({ dry_run: true, ... })` checks whether the node can currently build a route for a specific payment without sending it.

`listChannels({ include_closed: false })` exposes each channel's current `local_balance`, `remote_balance`, and in-flight TLC balances in shannons. These are off-chain allocations inside the channel, not the wallet's on-chain CKB balance. The reference app presents the sum of ready-channel local balances as the primary Fiber balance, keeps loose on-chain CKB separate, and lists every non-closed channel with explicit user-side and peer-side balances.

The SDK also exposes Fiber's low-level close operation. A cooperative close requires the peer to participate and may require an explicit close script and fee rate; `force: true` uses the channel's previously configured shutdown script when the peer cannot cooperate, but settlement is delayed by the channel's commitment delay.

```ts
await connection.keyway.shutdownChannel({
  channel_id: channelId,
  force: true,
});
```

Closing consumes the channel's on-chain funding cell and settles the final channel allocation back into normal CKB cells. The `channel_outpoint` shown by diagnostics is that funding cell's unique CKB reference: the funding transaction hash plus its output index. It is the channel's on-chain anchor, not the channel ID or a balance.

The consuming React application does not need Next.js or backend configuration. The lower-level API is for advanced integrations that already obtained a KeyWay session; normal applications use `KeyWayProvider` and never handle the token.

The current testnet prerelease has no application IDs or developer dashboard. A consuming origin must therefore be added manually to the managed backend's `KEYWAY_ALLOWED_ORIGINS`; no Stytch dashboard access or Stytch domain registration is required. Application IDs and self-service origin registration are post-hackathon onboarding work.

Build the distributable React SDK with:

```sh
npm run build:package
```

The private standalone backend runs with `npm run api` and requires `DATABASE_URL`, `KEYWAY_ALLOWED_ORIGINS`, Stytch server credentials, and the Lit server credentials from `.env.example`. It is deployed by CKB KeyWay and is not exported by the public SDK. The Next.js reference app has no API routes: both it and external consumers use the same SDK-managed Railway endpoint.

See [`examples/browser-wallet.ts`](examples/browser-wallet.ts) for a complete minimal lifecycle. The repository package is private. `npm run pack:sdk` stages and packs only `package.sdk.json`, the React/browser build, README, and license. Server-only `postgres` and `stytch` dependencies, Railway code, and Lit Actions are excluded. Publish only with `npm run publish:sdk`.

## Security model

- The Lit PKP private key is not returned to the browser or KeyWay backend.
- The backend accepts a complete CKB transaction, enforces testnet funding and fee limits, computes CCC's exact sighash, and invokes only a pinned Lit Action.
- The stored Fiber identity key is encrypted at rest. The MVP backend can observe it during recovery, and it necessarily exists in browser/WASM memory while Fiber runs.
- Web Locks, `BroadcastChannel`, and an atomic Postgres lease enforce one active browser node.
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
- Channel balances and raw channel shutdown are available through `connection.keyway`; the reference wallet renders balances and channels but does not yet provide a close-channel screen.
- The backend is trusted to authorize Lit operations and can observe the decrypted Fiber key.
- The reference wallet uses fixed activation and maximum-payment-fee limits for a predictable demo.
- CKB balance is an indexer-derived sum of live cells, not an account field. The reference wallet polls it every ten seconds, so a newly mined or faucet-created cell can still appear after indexer delay.
- Lit, Fiber WASM, public peers, Stytch, and the CKB testnet RPC remain external availability dependencies.

## Upstream foundations

- `@nervosnetwork/fiber-js` `0.9.0-rc7`
- `@fiber-pay/sdk` `0.2.7`
- `@ckb-ccc/core` `1.16.1`
- `stytch` server SDK `14.2.0` (private backend only)
- Lit Chipotle Actions pinned by immutable IPFS CID

CKB KeyWay is independent experimental infrastructure and is not affiliated with or endorsed by these projects.

## License

CKB KeyWay is released under the [MIT License](LICENSE).
