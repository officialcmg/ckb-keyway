# Architecture

## Key separation

CKB KeyWay deliberately uses two unrelated secp256k1 identities.

| Identity | Responsibility | Custody in the MVP |
| --- | --- | --- |
| Lit PKP | CKB cells and on-chain channel funding witness | Private key remains inside Lit; KeyWay receives signatures |
| Fiber node key | P2P identity and off-chain channel-state signing | Encrypted at rest; recovered through the backend into browser/WASM memory |

The Fiber key is never derived from the PKP, an OTP, or an ECDSA signature.

## Runtime path

```text
KeyWay React OTP modal
       |
       v
managed KeyWay backend -- server-side Stytch OTP/session
       |
       +------------------------ Railway Postgres wallet metadata
       |                                  |
       |                                  +-- one Lit PKP per user
       |                                  +-- encrypted Fiber key
       v
pinned Lit Chipotle Actions
       |
       +-- sign validated CKB sighash
       +-- encrypt/decrypt Fiber key

Browser
  Web Lock + backend lease
       |
       v
FiberBrowserNode / fiber-js / IndexedDB
       |
       +-- peers and gossip
       +-- collaborative external funding
       +-- channels, invoices, routes, and payments
```

The public SDK targets `https://keyway-api-production.up.railway.app` internally. Consumers neither provide an API URL nor import server code; CKB KeyWay operates this backend as part of the service.

The Next.js reference app imports only the published `@ckb-keyway/react` package, which re-exports the lower-level browser API. It contains no `app/api` routes and is not the backend. `server/index.ts` and `src/server` build and deploy independently to Railway; neither is included in the npm package.

## External funding boundary

1. Fiber negotiates a collaborative transaction with the selected peer.
2. CCC converts the transaction into KeyWay's signer representation.
3. `/api/keyway/sign-transaction` resolves every input cell and requires at least one KeyWay-controlled input.
4. Policy requires exactly one testnet Fiber FundingLock output, no UDT outputs, at most 1,000 CKB of KeyWay funding, and at most 1 CKB total fee.
5. CCC identifies exactly one KeyWay signing group and computes its CKB sighash.
6. The pinned Lit Action signs the 32-byte digest. The backend recovers and compares the PKP public key.
7. KeyWay inserts only that group's witness. Fiber verifies the transaction structure is otherwise unchanged and submits it.

Peer-owned inputs and peer change are expected because Fiber funding is collaborative. They are included in total fee accounting but are never presented as KeyWay-owned funds.

## Recovery and concurrency

The Stytch-backed identity, PKP, CKB address, and encrypted Fiber key can be recovered after login. The browser never receives Stytch credentials or configures a domain with Stytch; it calls KeyWay's `send-code`, `verify-code`, `session`, and `logout` API routes. The channel database cannot yet be safely moved between browsers. Once a wallet has opened a channel, a different device receives `CHANNEL_STATE_DEVICE_BOUND` and cannot start that Fiber identity.

Within the primary browser, a Web Lock and `BroadcastChannel` prevent duplicate tabs. A short atomic Postgres lease prevents a second browser process from using the same identity concurrently.

`KeyWayProvider` starts Fiber automatically after OTP when `autoConnect` is true. Startup recovers the wallet, acquires the browser lock and backend lease, decrypts the Fiber key, starts the WASM node, connects testnet relays, and reads the initial CKB balance. `disconnect()`, logout, provider unmount, and page refresh stop the running instance; the browser process also disappears when its tab closes, while IndexedDB channel state remains. A rejected lease heartbeat now stops the node and surfaces an SDK error instead of leaving a stale instance running.

Relay connections provide P2P reachability and gossip; they are not payment channels. The reference activation flow opens a public channel with an official browser-reachable testnet channel provider (`bottle` or `bracer`). Each node builds routes from its gossiped network graph, so two KeyWay users can pay through a shared routing provider without having a direct channel. The exact balance split of remote channels is not globally reliable, so `dry_run` can test a requested amount but cannot promise a stable sender-to-recipient maximum.

`listChannels` exposes local, remote, offered-TLC, and received-TLC balances for channels known to the browser node. A channel's `channel_outpoint` is the CKB funding cell reference (`tx_hash` plus output `index`) that anchors the off-chain state. Cooperative or forced `shutdownChannel` eventually consumes that funding cell and creates settlement cells from the latest enforceable allocation; forced settlement may remain pending for the negotiated commitment delay.

The reference wallet lives at `/app`; `/` is the pitch-oriented project landing page. The wallet treats ready-channel `local_balance` values as the user's Fiber balance and displays the on-chain CKB cell balance separately. Its transit-map channel list includes every non-closed channel and renders `local_balance` as "You" and `remote_balance` as "Peer", so pending lifecycle states and both sides of each channel remain visible.

## Trust boundaries

- Stytch proves control of the configured email account behind the managed backend.
- The KeyWay backend is trusted to map users to PKPs, enforce transaction policy, hold provider credentials, and authorize Lit calls.
- Lit protects PKP key material and executes only configured Actions for the permitted account resources.
- The backend can observe the Fiber key during the current decrypt flow.
- `fiber-js` owns live channel-state correctness and local persistence.
- CKB enforces the final funding and settlement scripts.
