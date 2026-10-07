# CKB KeyWay

> The Better Auth/Resend backend and updated demo are deployed. SDK 0.2.0 is not published yet; the demo temporarily builds the repository SDK. Published 0.1.0 authentication is incompatible with the replacement backend. Live funded acceptance is in progress, and legacy test-data deletion is blocked by the execution safety reviewer; see [operator status](docs/AUTH_REPLACEMENT.md).

CKB KeyWay is reusable email-authenticated wallet infrastructure for Fiber Network. It combines Better Auth email OTP and Resend delivery, a Lit Chipotle PKP, CCC transaction construction, and a managed or browser Fiber node so an application can recover a stable CKB identity and externally fund Fiber channels without exporting the PKP private key.

The repository contains two independent deliverables:

- The public React SDK under `src/sdk`, including its framework-independent browser client.
- A standalone Node/Postgres backend and a Next.js reference wallet demonstrating login, recovery, channel activation, invoices, and payments.

Project overview: [ckb-keyway.vercel.app](https://ckbkeyway.dev)

Live testnet wallet: [ckb-keyway.vercel.app/app](https://ckbkeyway.dev/app)

React SDK documentation: [ckb-keyway-docs.vercel.app](https://docs.ckbkeyway.dev)

npm package: [@ckb-keyway/react](https://www.npmjs.com/package/@ckb-keyway/react)

Standalone API: [keyway-api-production.up.railway.app](https://keyway-api-production.up.railway.app/healthz)

## Working flow

1. The SDK sends email OTP requests to the managed KeyWay API; Better Auth verifies app-specific codes and creates application-bound sessions; KeyWay supplies permanent application account IDs.
2. The backend provisions or recovers one Lit PKP and its CKB testnet address.
3. Managed mode connects to the user's persistent native Fiber node. Optional browser mode recovers its separate Fiber identity and loads a WASM node.
4. The selected node connects to Fiber testnet peers.
5. Fiber and the peer collaboratively construct an unsigned funding transaction.
6. The backend validates the complete transaction and computes only the KeyWay lock group's CKB sighash.
7. A pinned Lit Action signs that digest. KeyWay verifies the recovered public key and inserts only its witness.
8. Fiber submits the signed transaction, waits for `ChannelReady`, and can send or receive invoices.
9. Managed logout clears the SDK session while the native node stays online. Browser logout stops Fiber and uploads an encrypted wallet-scoped IndexedDB backup before releasing device ownership.

KeyWay connects each browser node to the official testnet relays for network reachability and gossip. Its convenience activation flow then prefers the browser-reachable Bottle or Bracer channel providers, falling back to eligible nodes discovered from the Fiber graph. The 400 CKB value in `channel-peers.ts` is the minimum request KeyWay will send to those providers, not their contribution. In the verified 1,250 CKB testnet channel below, KeyWay requested 1,000 CKB and the accepting peer contributed the remaining 250 CKB; applications should read the negotiated `local_balance` and `remote_balance` rather than assume that split for every channel.

## Run locally

Requirements: Node.js 20 or newer, a verified Resend sender, a configured Lit Chipotle account, and Postgres.

```sh
npm install
cp .env.example .env.local
npm run build:api
npm run api
# In another terminal:
npm run dev
```

Configure Better Auth, Postgres and a verified Resend sender using `.env.example`. Run `npm run migrate` explicitly before production startup. Consumers register exact origins in the developer console; the demo uses `NEXT_PUBLIC_KEYWAY_APP_ID`. Keep database, Better Auth, Resend and Lit credentials server-only.

## React SDK

The public package owns email OTP, the login modal, wallet provisioning, and Fiber startup behind one provider. Managed mode is the default from version 0.0.7; browser mode remains an explicit option. The package exports `connectManagedKeyWay` and `connectKeyWay` for lower-level integrations.

Create an application at [ckb-keyway.vercel.app/dashboard](https://ckbkeyway.dev/dashboard), register its exact development and production origins, and copy its public app ID.

```sh
npm install @ckb-keyway/react
```

```tsx
import { KeyWayLoginButton, KeyWayProvider, useKeyWay, useCkbWallet } from "@ckb-keyway/react";

function Wallet() {
  return (
    <KeyWayProvider appId="keyway_..." appName="My Fiber App" theme="light">
      <KeyWayLoginButton />
      <Balance />
    </KeyWayProvider>
  );
}

function Balance() {
  const { ready, authenticated } = useKeyWay();
  const { balance } = useCkbWallet();
  if (!ready) return <p>Loading KeyWay...</p>;
  if (!authenticated) return null;
  return balance === undefined ? <p>Loading balance...</p> : <p>{balance.toString()} shannons</p>;
}
```

`KeyWayLoginButton` opens the built-in email OTP modal. Login recovers the CKB identity without starting Fiber. Use `connect()` from `useFiber()` or `KeyWayConnectButton` when needed. Channel activation uses a built-in funding confirmation. Use `login()` and `logout()` from `useKeyWay()` for custom buttons.

### React API

| API | Purpose |
| --- | --- |
| `KeyWayProvider` | Owns email OTP, wallet recovery, Fiber startup, and funding confirmation |
| `KeyWayLoginButton` | Opens the email OTP modal and logs out an authenticated user |
| `KeyWayConnectButton` | Manually starts or stops Fiber when `autoConnect` is disabled |
| `useKeyWay()` | Authentication readiness, user, login, and logout |
| `useCkbWallet()` | Account, address, independent balance, refresh, and errors |
| `useFiber()` | Explicit connection, channels, invoices, preflight, and settled payments |

The SDK uses KeyWay's managed backend. `appId` identifies the registered application and enforces origins. `appName` brands the modal; `theme` accepts light or dark; `confirmFunding` can replace funding confirmation. From 0.1.0, `autoConnect` defaults to false. `nodeMode` defaults to managed; use browser for local WASM. Authentication, account recovery, and Fiber readiness have separate hooks. Backend URLs and credentials are absent from provider configuration.

`appName` changes the modal. Emails use the registered application's name and the existing neutral template through Resend. OTP records and sessions are isolated by application; the same email in another application gets a different permanent KeyWay account and wallet. The server binds session scope using Better Auth's `databaseHooks.session.create.before` hook.

Successful OTP recovers the CKB account without a node. `useCkbWallet()` reads its balance independently. `useFiber().connect()` starts or attaches to Fiber. Browser mode restores any claimed backup before WASM startup. Opt into automatic connection with `autoConnect`. Disconnecting a managed client does not stop the persistent server node.

In browser mode, explicit `logout()` is transactional after a Fiber connection exists: KeyWay stops the node while retaining its device lease, snapshots only that wallet's IndexedDB databases, derives an AES-256-GCM backup key from the Lit-recovered Fiber key with HKDF-SHA256, and uploads ciphertext to the managed backend. Authentication and ownership are cleared only after the backend independently verifies and stores the ciphertext. A new device claims and restores that one-use backup before Fiber starts. If backup or restoration fails, KeyWay does not release or consume the only recoverable state. Managed logout does not stop the persistent node.

The same package exports the headless connection API:

```ts
import { connectManagedKeyWay } from "@ckb-keyway/react";

const connected = await connectManagedKeyWay({
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

Managed mode implements the same high-level channel, invoice, payment preflight, payment, and balance methods without starting WASM in the consuming page. It uses an isolated persistent native Fiber process and data directory for each user, subject to host capacity limits. Select `<KeyWayProvider nodeMode="browser">` for local WASM; the demo retains it at `/app?mode=browser`. Switching modes does not migrate channels: native and browser nodes have separate identities and state. Existing dedicated-node assignments are preserved.

Channel activation also accepts configuration while retaining the 1,000 CKB default:

```ts
await connected.keyway.activateCkbChannel({
  fundingAmount: 500n * 100_000_000n,
  peer: optionalPeerPublicKey,
  public: true,
});
```

Use `preflightPayment()` before asking the user to confirm a payment. It performs Fiber's dry run and returns a typed, retryable failure instead of requiring string parsing. `getChannels()` returns normalized lifecycle state plus local, remote, and total balances; `closeChannel()` wraps cooperative or forced shutdown with typed errors. The original raw Fiber methods remain available for advanced use.

Browser mode additionally exposes direct peer/channel operations and Fiber's route inspection surface: `connectPeer`, `openFundedChannel`, `graphNodes`, `graphChannels`, `buildRouter`, and `sendPaymentWithRouter`. Use the shared `preflightPayment()` method to check current route readiness without sending.

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

The developer console supports disabling applications, removing origins, setting OTP limits, viewing sanitized usage and checking API health. Its session scope is separate from SDK application sessions. Consumers need no authentication-provider credentials.

Build the distributable React SDK with:

```sh
npm run build:package
```

The private standalone backend runs with `npm run api` and requires `DATABASE_URL`, `KEYWAY_ALLOWED_ORIGINS`, `KEYWAY_RATE_LIMIT_SECRET`, Better Auth/Resend server credentials, and the Lit server credentials from `.env.example`. It is deployed by CKB KeyWay and is not exported by the public SDK. The Next.js reference app has no API routes: it imports the published `@ckb-keyway/react` package, and both it and external consumers use the same SDK-managed Railway endpoint.

See [`examples/browser-wallet.ts`](examples/browser-wallet.ts) for a complete minimal lifecycle. The repository package is private. `npm run pack:sdk` stages and packs only `package.sdk.json`, the React/browser build, README, and license. Server-only `postgres`, `pg`, `better-auth`, and `resend` dependencies, Railway code, and Lit Actions are excluded. Releases use npm Trusted Publishing: an explicit `v<package-version>` tag triggers `.github/workflows/publish.yml`, which runs the full suite with disposable Postgres, checks types, builds the public package, and publishes through OIDC. Ordinary commits do not publish an npm version.

The public package pins its tested Fiber WASM version. Node upgrades require explicit compatibility and recovery verification; they must not happen silently during dependency resolution.

## Security model

- The Lit PKP private key is not returned to the browser or KeyWay backend.
- The backend accepts a complete CKB transaction, enforces testnet funding and fee limits, computes CCC's exact sighash, and invokes only a pinned Lit Action.
- The stored Fiber identity key is encrypted at rest. The backend can observe it during recovery. Browser mode loads it into WASM memory; managed mode trusts the host with the native node's operational keys and channel state.
- Web Locks, `BroadcastChannel`, and an atomic Postgres lease enforce one active browser node.
- Fiber state backups are encrypted in the browser and stored as ciphertext. Explicit logout appends an immutable generation; only the newest can be auto-claimed, older generations stay for rollback, and a restore refuses to overwrite Fiber state that already exists on the device.
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
- Cross-device Fiber state migration currently requires explicit logout. A crash, lost device, force-closed tab, or interrupted browser cannot create a fresh checkpoint, so background snapshots still need an upstream-safe database flush boundary.
- Channel balances and channel shutdown are available through `connection.keyway`. The reference wallet renders both sides of each channel and can close one after an explicit confirmation; a cooperative close settles the latest balance back on CKB.
- The backend is trusted to authorize Lit operations and can observe the decrypted Fiber key.
- The reference wallet uses fixed activation and maximum-payment-fee limits for a predictable demo; SDK consumers can configure channel funding and preflight payment fees.
- CKB balance is an indexer-derived sum of live cells, not an account field. The reference wallet polls it every ten seconds, so a newly mined or faucet-created cell can still appear after indexer delay.
- Lit, Fiber WASM, public peers, Resend, and the CKB testnet RPC remain external availability dependencies.
- Managed mode remains experimental testnet infrastructure. Every account is mapped to a dedicated native node on a persistent volume, with node/channel capacity limits. Authenticated operators can snapshot and restore state; current backups share the host volume and are not off-volume disaster recovery. Separate staging credentials are deferred to mainnet preparation. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) and the funded recovery evidence.

## Upstream foundations

- `@nervosnetwork/fiber-js` `0.9.0-rc7`
- `@fiber-pay/sdk` `0.2.7`
- `@ckb-ccc/core` `1.16.1`
- Better Auth `1.7.7` and Resend `6.32.1` (private backend only)
- Lit Chipotle Actions pinned by immutable IPFS CID

CKB KeyWay is independent experimental infrastructure and is not affiliated with or endorsed by these projects.

## License

CKB KeyWay is released under the [MIT License](LICENSE).
