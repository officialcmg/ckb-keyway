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
Stytch email OTP
       |
       v
authenticated KeyWay backend ---- Railway Postgres wallet metadata
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

The Stytch identity, PKP, CKB address, and encrypted Fiber key can be recovered after login. The channel database cannot yet be safely moved between browsers. Once a wallet has opened a channel, a different device receives `CHANNEL_STATE_DEVICE_BOUND` and cannot start that Fiber identity.

Within the primary browser, a Web Lock and `BroadcastChannel` prevent duplicate tabs. A short atomic Postgres lease prevents a second browser process from using the same identity concurrently.

## Trust boundaries

- Stytch proves control of the configured email account.
- The KeyWay backend is trusted to map users to PKPs, enforce transaction policy, hold provider credentials, and authorize Lit calls.
- Lit protects PKP key material and executes only configured Actions for the permitted account resources.
- The backend can observe the Fiber key during the current decrypt flow.
- `fiber-js` owns live channel-state correctness and local persistence.
- CKB enforces the final funding and settlement scripts.
