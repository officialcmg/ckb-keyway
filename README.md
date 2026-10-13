# CKB KeyWay

> The Better Auth/Resend backend and updated demo are deployed. Use SDK 0.2.0; authentication in 0.1.0 is incompatible with the replacement backend. Real OTP delivery, two-device managed wallet recovery, Lit funding, bidirectional Fiber payments and cooperative test-channel closure passed. Legacy test-data deletion remains blocked by the execution safety reviewer; see [operator status](docs/AUTH_REPLACEMENT.md).

CKB KeyWay is reusable email-authenticated wallet infrastructure for Fiber Network. It combines Better Auth email OTP and Resend delivery, a Lit Chipotle PKP, CCC transaction construction, and a hosted or browser Fiber node so an application can recover a stable CKB identity and externally fund Fiber channels without exporting the PKP private key.

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
3. A hosted node is the user's persistent native Fiber node on KeyWay's servers. An optional browser node recovers its separate Fiber identity and loads a WASM node.
4. The selected node connects to Fiber testnet peers.
5. Fiber and the peer collaboratively construct an unsigned funding transaction.
6. The backend validates the complete transaction and computes only the KeyWay lock group's CKB sighash.
7. A pinned Lit Action signs that digest. KeyWay verifies the recovered public key and inserts only its witness.
8. Fiber submits the signed transaction, waits for `ChannelReady`, and can send or receive invoices.
9. Logout with a hosted node clears the SDK session while the native node stays online. Browser logout stops Fiber and uploads an encrypted wallet-scoped IndexedDB backup before releasing device ownership.

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

The public package owns email OTP, the login modal, wallet provisioning, a CCC signer, and the user's Fiber node behind one provider. The node is hosted by KeyWay by default (`fiberNode="hosted"`); a browser node (`fiberNode="browser"`) is an explicit option.

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

`KeyWayLoginButton` opens the built-in email OTP modal. Login recovers the CKB identity without starting Fiber. Use `start()` from `useFiber()` or `KeyWayFiberButton` when needed. Opening a channel uses a built-in approval dialog. Use `login()` and `logout()` from `useKeyWay()` for custom buttons.

### React API

| API | Purpose |
| --- | --- |
| `KeyWayProvider` | Owns email OTP, wallet recovery, Fiber startup, and the approval dialogs |
| `KeyWayLoginButton` | Opens the email OTP modal and logs out an authenticated user |
| `KeyWayFiberButton` | Starts or stops Fiber when `autoStartFiber` is off |
| `useKeyWay()` | Authentication readiness, user, login, and logout |
| `useCkbWallet()` | Status, CCC signer, address, public key, independent balance, refresh, and errors |
| `useFiber()` | Start and stop, the user's Fiber node (`node`), channels, invoices, payment estimates, and settled payments |

The SDK uses KeyWay's managed backend. `appId` identifies the registered application and enforces origins. `appName` brands the dialogs; `theme` accepts light or dark; `approveFiberChannelOpen`, `approveFiberChannelClose`, `approveFiberPeerConnect`, `approveFiberChannelSettings`, `approveCkbTransaction` and `approveCkbMessage` can replace the built-in dialogs, and `approveFiberPayment` adds a payment confirmation. `autoStartFiber` defaults to false. `fiberNode` defaults to hosted; use browser to run the node in the page. Authentication, account recovery, and Fiber readiness have separate hooks. Backend URLs and credentials are absent from provider configuration.

`appName` changes the modal. Emails use the registered application's name and the existing neutral template through Resend. OTP records and sessions are isolated by application; the same email in another application gets a different permanent KeyWay account and wallet. The server binds session scope using Better Auth's `databaseHooks.session.create.before` hook.

Successful OTP recovers the CKB account without a node. `useCkbWallet()` reads its balance independently. `useFiber().start()` starts the browser node or connects to the hosted one. A browser node restores any claimed backup before WASM startup. Opt into automatic startup with `autoStartFiber`. `stop()` does not stop a hosted node.

In browser mode, explicit `logout()` is transactional after a Fiber connection exists: KeyWay stops the node while retaining its device lease, snapshots only that wallet's IndexedDB databases, derives an AES-256-GCM backup key from the Lit-recovered Fiber key with HKDF-SHA256, and uploads ciphertext to the managed backend. Authentication and ownership are cleared only after the backend independently verifies and stores the ciphertext. A new device claims and restores that one-use backup before Fiber starts. If backup or restoration fails, KeyWay does not release or consume the only recoverable state. Logout does not stop a hosted node.

`useFiber().node` is the user's Fiber node with fiber-js's official method names and parameters, the same for hosted and browser nodes:

```ts
const { node } = useFiber();
if (!node) throw new Error("Start Fiber first");

const { channels } = await node.listChannels({});
const { invoice_address } = await node.newInvoice({ amount: "0x5f5e100", description: "Coffee" });
await node.sendPayment({ invoice: fiberInvoice }); // no dialog; may ask for the emailed code
const { payments } = await node.listPayments({});
```

Every method is classified. Reads and invoices are free. `sendPayment` and `sendPaymentWithRouter` have no built-in dialog (apps can pass `approveFiberPayment`) and, on a hosted node, count toward the user's 24-hour email-confirmation total. Opening and closing channels, connecting and disconnecting peers, and `updateChannel` show a dialog the app can replace. `openChannel`, `acceptChannel` and `abandonChannel` are blocked, and anything unclassified is refused with `UNSUPPORTED_METHOD`. Hosted nodes enforce this on KeyWay's backend; browser nodes enforce it in the SDK. See the [Fiber node docs](https://docs.ckbkeyway.dev/fiber-node).

The higher-level helpers cover the common flow:

```ts
const fiber = useFiber();
await fiber.start();

await fiber.openChannel({ fundingAmount: 500n * 100_000_000n, public: true });

const estimate = await fiber.estimatePayment({ invoice: fiberInvoice, max_fee_amount: "0x5f5e100" });
if (estimate.routable) await fiber.payInvoice(fiberInvoice, { max_fee_amount: "0x5f5e100" });
```

`openChannel()` defaults to 1,000 CKB, accepts `peer`, and opens a token channel (for example RUSD) with `udtTypeScript` and `fundingAmount`. Channel funding doesn't count toward the email-confirmation total. `estimatePayment()` performs Fiber's dry run and returns `{ routable, fee }` or a typed, retryable `KeyWayError`. `fiber.channels` lists each channel's `canSend`, `canReceive`, `capacity` and `asset`. `closeChannel()` closes after the user approves.

A hosted node runs on KeyWay's servers, which hold its key, in an isolated persistent native Fiber process and data directory for each user, subject to host capacity limits. Select `<KeyWayProvider fiberNode="browser">` to run the node in the page; the demo retains it at `/app?mode=browser`. Switching modes does not migrate channels: hosted and browser nodes have separate identities and state. Existing dedicated-node assignments are preserved.

`fiber.channels` reports off-chain allocations inside each channel, not the wallet's on-chain CKB balance. The reference app presents the sum of ready-channel `canSend` as the primary Fiber balance, keeps loose on-chain CKB separate, and lists every non-closed channel with explicit user-side and peer-side balances.

A cooperative close requires the peer to participate and pays the user's side to their own address. `force: true` closes without the peer after the channel's commitment delay, about 4 hours. In Fiber 0.9.1 a force-closed channel is settled to the node's own key rather than the channel's shutdown script. As an interim measure until Fiber pays settlements to the close address, KeyWay sweeps them to the user's address: a browser node settles to a key derived from its Fiber key and the SDK sweeps it when the node starts and every 10 minutes while it runs; a hosted node's settlement is swept by KeyWay the next time the user uses Fiber. Prefer cooperative closes.

```ts
await fiber.closeChannel(channelId, { force: true });
```

Closing consumes the channel's on-chain funding cell and settles the final channel allocation back into normal CKB cells. The `channel_outpoint` shown by diagnostics is that funding cell's unique CKB reference: the funding transaction hash plus its output index. It is the channel's on-chain anchor, not the channel ID or a balance.

The consuming React application does not need Next.js or backend configuration. Applications use `KeyWayProvider` and never handle the session token.

The developer console supports disabling applications, removing origins, setting OTP limits, viewing sanitized usage and checking API health. Its session scope is separate from SDK application sessions. Consumers need no authentication-provider credentials.

Build the distributable React SDK with:

```sh
npm run build:package
```

The private standalone backend runs with `npm run api` and requires `DATABASE_URL`, `KEYWAY_ALLOWED_ORIGINS`, `KEYWAY_RATE_LIMIT_SECRET`, Better Auth/Resend server credentials, and the Lit server credentials from `.env.example`. It is deployed by CKB KeyWay and is not exported by the public SDK. The Next.js reference app has no API routes: it imports the published `@ckb-keyway/react` package, and both it and external consumers use the same SDK-managed Railway endpoint.

The repository package is private. `npm run pack:sdk` stages and packs only `package.sdk.json`, the React/browser build, README, and license. Server-only `postgres`, `pg`, `better-auth`, and `resend` dependencies, Railway code, and Lit Actions are excluded. Releases use npm Trusted Publishing: an explicit `v<package-version>` tag triggers `.github/workflows/publish.yml`, which runs the full suite with disposable Postgres, checks types, builds the public package, and publishes through OIDC. Ordinary commits do not publish an npm version.

The public package pins its tested Fiber WASM version. Node upgrades require explicit compatibility and recovery verification; they must not happen silently during dependency resolution.

## Security model

- The Lit PKP private key is not returned to the browser or KeyWay backend by KeyWay's Actions. Lit Chipotle is a single attested TEE: any Action allow-listed in the KeyWay Lit group can read the key inside it, and KeyWay's Lit admin credential controls that allow-list.
- The backend accepts a complete CKB transaction, enforces testnet funding and fee limits, computes CCC's exact sighash, and invokes only a pinned Lit Action: the backend refuses to send Action code whose IPFS CID differs from the configured one, and Lit runs only CIDs allow-listed in the KeyWay group.
- The stored Fiber identity key is encrypted at rest. For a browser node, Lit creates the key and re-encrypts it to a one-time key generated in the user's browser, so KeyWay's backend relays only ciphertext and never receives the key in normal operation; the backend remains trusted to authorize Lit to release it. A hosted node runs on KeyWay's servers, which hold that node's operational keys and channel state.
- Web Locks, `BroadcastChannel`, and an atomic Postgres lease enforce one active browser node.
- Fiber state backups are encrypted in the browser and stored as ciphertext. Explicit logout appends an immutable generation; only the newest can be auto-claimed, older generations stay for rollback, and a restore refuses to overwrite Fiber state that already exists on the device.
- Session bearer tokens live in the embedding app's `localStorage`, so an XSS bug in that app can read them.
- `useCkbWallet().signer` is a CCC signer. The backend signs only the user's own lock, only the exact transaction it decoded and showed in the approval dialog, with a size-based fee cap and rate limits. Users can require an emailed code once a daily amount per asset (CKB and each token) leaves the account within 24 hours; hosted-node Fiber payments count toward it. The dialog runs in the embedding app's page, so a compromised page can approve transactions below that amount, and apps can replace the dialogs (including approving silently).
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

- Testnet only (Fiber currency `Fibt`). CKB and tokens (xUDT, including RUSD) are supported; swaps, merchant checkout, and mainnet are out of scope.
- Cross-device Fiber state migration currently requires explicit logout. A crash, lost device, force-closed tab, or interrupted browser cannot create a fresh checkpoint, so background snapshots still need an upstream-safe database flush boundary.
- Channel balances and channel shutdown are available through `useFiber()`. The reference wallet renders both sides of each channel and can close one after an explicit confirmation; a cooperative close settles the latest balance back on CKB.
- The backend is trusted to authorize Lit operations. It holds hosted nodes' keys; it doesn't receive browser nodes' Fiber keys in normal operation.
- Browser-node Fiber payments don't pass through KeyWay's backend, so they aren't counted toward the daily email-confirmation amount, and the method rules are enforced only in the SDK.
- The reference wallet uses fixed activation and maximum-payment-fee limits for a predictable demo; SDK consumers can configure channel funding and estimate payment fees.
- CKB balance is an indexer-derived sum of live cells, not an account field. The reference wallet polls it every ten seconds, so a newly mined or faucet-created cell can still appear after indexer delay.
- Lit, Fiber WASM, public peers, Resend, and the CKB testnet RPC remain external availability dependencies.
- Hosted nodes remain experimental testnet infrastructure. Every account is mapped to a dedicated native node on a persistent volume, with a host node-capacity limit. Authenticated operators can snapshot and restore state; current backups share the host volume and are not off-volume disaster recovery. Separate staging credentials are deferred to mainnet preparation. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) and the funded recovery evidence.

## Upstream foundations

- `@nervosnetwork/fiber-js` `0.9.0-rc7`
- `@fiber-pay/sdk` `0.2.7`
- `@ckb-ccc/core` `1.16.1`
- Better Auth `1.7.7` and Resend `6.32.1` (private backend only)
- Lit Chipotle Actions pinned by IPFS CID (checked by the backend and allow-listed in the KeyWay Lit group)

CKB KeyWay is independent experimental infrastructure and is not affiliated with or endorsed by these projects.

## License

CKB KeyWay is released under the [MIT License](LICENSE).
