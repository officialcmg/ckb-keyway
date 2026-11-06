# Browser-mode force close: why the user's share was never claimed, and the fix

All times UTC. Sources: Fiber `v0.9.1` (commit `9a561b3e`), `@nervosnetwork/fiber-js` 0.9.1 and `@fiber-pay/sdk`
0.2.7 as installed by `npm ci` on `main` (`d381a13`).

## Root cause

**Fiber's browser build has no watchtower, and only the watchtower claims force-closed funds.**

1. In Fiber 0.9.1, nothing but the watchtower builds the transaction that claims a party's share from a
   commitment cell (`build_settlement_tx`, `crates/fiber-lib/src/watchtower/actor.rs:1102`, called from
   `run_periodic_check` → `try_settle_commitment_tx`, `actor.rs:256` / `:523`). The channel actor only waits for it:
   after a force close the channel sits in `CLOSED | WAITING_ONCHAIN_SETTLEMENT` (`fiber/channel.rs:10171`) until the
   commitment cells are spent.
2. The native node starts that watchtower: `crates/fiber-bin/src/main.rs:335-356` spawns `WatchtowerActor` (unless
   `disable_built_in_watchtower`) with a 60 s `PeriodicCheck`, and `main.rs:416-417` forwards every channel event to it
   (`forward_event_to_actor`, `main.rs:561-640`). That is why the hosted node claims correctly.
3. The browser build does not. `crates/fiber-wasm/Cargo.toml:8` depends on fiber-lib with `default-features = false`,
   and fiber-lib's `watchtower` module is behind the default `watchtower` feature (`crates/fiber-lib/Cargo.toml:117,123`,
   `src/lib.rs:28-29`), so it is not even compiled. `crates/fiber-wasm/src/lib.rs:238-296` never spawns a watchtower:
   its event loop only forwards events to a *standalone* watchtower over JSON-RPC, and only if
   `fiber.standalone_watchtower_rpc_url` is set (`lib.rs:248-260`, `:275-286`). With no URL every event is dropped
   silently. The start-up guard at `lib.rs:239-246` only rejects `disable_built_in_watchtower: true` without a URL, so
   the default config (watchtower "enabled", none present) starts without a word.
4. KeyWay's browser config never set that URL. `@fiber-pay/sdk` builds the YAML in
   `dist/browser/index.js` `ConfigBuilder.build` (`fiber:` has `listening_addr`, `bootnode_addrs`,
   `announce_listening_addr`, `chain`, `scripts`; nothing about a watchtower), and `src/sdk/browser/fiber-wasm.ts` on
   `main` only swapped the ckb_auth cell dep.

So the browser node force-closed, put its commitment on-chain, and then had nothing that would ever claim the user's
share. It was broken, not slow, and because no watchtower code ran there was nothing to log (run 2's console was silent
for 11 hours).

### Candidates ruled out
- **Fee reserve on the wrong key**: no. The watchtower pays fees from, and pays the claim to, the Secp256k1 lock of the
  node's own CKB key (`actor.rs:1146-1149` `fee_provider_lock_script = Secp256k1Lock(signer.pubkey_hash())`, with
  `signer` from `config.read_secret_key()`, `actor.rs:132-137`). KeyWay gives the WASM node `deriveSettlementKey(fiberKey)`
  (`credential-provider.ts:29-31` → `@fiber-pay/sdk` `FiberBrowserNode.start` → `fiber.start(..., ckbSecretKey)`), and the
  reserve goes to that same key's lock (`create-keyway.ts`, `createFeeReserve({ lock })`). The key was right; nothing used it.
- **Settlement tx built but failing to broadcast (cell deps)**: no transaction was ever built. The commitment lock's
  deps do need the testnet ckb_auth cell `0x12c569a2…:0` (the peer's run-2 settlement uses it), which the fix includes.
- **Errors hidden by the old harness's console filter**: there were none to hide; the new harness logs every console
  line from the page and both Fiber workers (`.evidence/settlement-console.log`).

### What run 2 actually left behind
The peer's settlement `0x32ebef7c…90f1` unlocked its own slot (`0xFF`) and left the user's 499.99999544 CKB in a
successor commitment cell `0x32ebef7c…90f1:0`. A follow-up settlement carries no `since` (`actor.rs:1542-1557`: only the
first settlement waits), so that cell was claimable straight away by the run-2 channel's **settlement key**. That key
lived only in the run-2 browser node's IndexedDB and in watchtower events that were dropped; the account's credentials
were in the old harness's gitignored `.evidence/` and the container that held it is gone. Neither the account nor the
key can be recovered, so `0x32ebef7c…90f1:0` (499.99999544 CKB) and the 62 CKB reserve `0x158925a8…d710:0` remain
live and unclaimable.

## Fix (KeyWay-side)

A hosted standalone watchtower is not an option: Fiber's watchtower pays the claimed share to *its own* key
(`actor.rs:1690-1691`), so pointing browser nodes at a KeyWay-run watchtower would make KeyWay custodian of every
force-closed balance. The browser node instead gets a watchtower inside the page:

- `src/sdk/browser/watchtower-bridge.ts`: the node's config names `standalone_watchtower_rpc_url:
  ws://keyway-watchtower.invalid/`. A shim loaded into Fiber's workers before Fiber answers the WebSocket for that one
  address (all other addresses use the real WebSocket) and passes each JSON-RPC call to the page over a
  BroadcastChannel; the reply is sent only after the page has stored the data, so a storage failure reaches Fiber as an
  RPC error that Fiber logs. Nothing leaves the device (`.invalid` never resolves).
- `src/sdk/browser/watchtower-store.ts`: stores what Fiber's watchtower stores (settlement key, funding keys,
  local/remote/pending settlement data, revocation data, preimages) in IndexedDB as `<node prefix>-keyway-watchtower`,
  so the encrypted node backup carries it with the channel database.
- `src/sdk/browser/watchtower-settle.ts`: a TypeScript port of the watchtower's settlement for channels without pending
  TLCs. Every 60 s while the node runs (`create-keyway.ts` `watchNow`), for each watched channel: find the transaction
  that spent the funding cell; if it is a commitment, follow settlements to the live commitment cell; pick the
  settlement data whose witness hash matches the lock args (Fiber's `verify_and_select_settlement_data`); once
  `commitment epoch + delay <= tip epoch`, build the same transaction Fiber builds (witness = xUDT header ‖ unlock count ‖
  settlement witness ‖ unlock `0xFE`/`0xFF` with a signature over the tx hash without cell deps, successor commitment
  cell for the peer's part, fee from at least one plain cell of the node key, claim paid to the node key), sign it with
  the channel's settlement key and send it. The existing settlement sweep then moves it to the user's address.
- `src/sdk/browser/fiber-wasm.ts`: injects the config and the shim when the node starts.

Not covered by the in-page watchtower (Fiber's watchtower does these; the upstream issue asks for them): claiming
pending TLCs with preimages or after expiry, token (xUDT) channels, and the revocation transaction that punishes a peer
who publishes a revoked commitment. A channel in any of these states is reported in the console and left for a later
version of the in-page watchtower. Punishing revoked commitments of CKB channels (CKB testnet only) is now done by
KeyWay's own watchtower, once it is configured and the SDK has sent it the channel's revocation data: see
[`research/browser-watchtower`](../browser-watchtower/README.md).

## Live proof (CKB testnet, production API, fixed SDK)

**Result: DONE.** A browser-mode node running this branch claimed the user's share by itself after the delay, and the
SDK swept it to the user's own address. Disposable account (temp-mail OTP) on the production API, user address
`ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqtm8ww9j4w2uu0fdf9as5ffqp2cz4mvtpg0cyz4l`, funded with 10,000
CKB from the Nervos testnet faucet, channel `0xbd3d33a2ad1213e27a4a6c27a9df43838dce436db888245cbf26b3eb4f59f07f`
(500 CKB from the user, 250 CKB from the peer). Times are block timestamps from CKB RPC (`testnet.ckb.dev`), 2026-11-06 UTC.

| Step | Transaction | Block | Time (UTC) |
|---|---|---|---|
| Funding (750 CKB channel) | `0x01ded4e7d32e615f92383fcb2499f579eafe52044b94cc8b145d4e1f0d72b0de` | 22984760 | 16:46:43 |
| Fee reserve, 62 CKB to the node key (first open) | `0xa9a5b084ed9d78866a13fb3b3d0a2c111dccbb6b510171c7b804da6e7bdd5883` | 22984763 | 16:47:15 |
| Force close requested from the browser node | n/a | n/a | 16:47:26 |
| Commitment (749.99999544 CKB, 1-epoch delay) | `0x461d050f91bfb6eb82e3570d27321259e7348852f96dc9342d032b4a00335a7b` | 22984768 | 16:47:59 |
| **Node's claim** of the user's share (unlock `0xFE`, `since` `0xa000010000000001`, fee from the reserve): 249.99999544 CKB left in a successor commitment cell for the peer, 561.99999216 CKB to the node key | `0x321662fafdc0ba1ad9cfb75b161117c9fdf06e116be65cfe7262d378b243844b` | 22986580 | 21:07:25 (sent 21:05:56) |
| **SDK sweep** to the user's own address: 499.99993111 CKB to the user, 62 CKB kept as the reserve while the peer's part is unsettled | `0xa253b8f7a695f995809783ba66e0e486efe07ad96d2e870c4564cdb885cb80cb` | 22986587 | 21:08:23 |

From force close to the user's address: 4 h 21 min, of which about 4 h 18 min is the commitment delay (epoch 14142
index ~1673 to epoch 14143 index 1673). The claim went out on the first watchtower pass after the delay.

Notes:
- The in-page watchtower received `create_watch_channel`, `update_local_settlement` and
  `update_pending_remote_settlement` from the WASM node within 2 s of the channel opening (console:
  `[keyway] watchtower: stored ...`), and the data survived seven page reloads (the page was reloaded with each
  review fix to the SDK; the node restarted each time and the watchtower reported `waiting for the commitment delay`).
- Before the delay passed, the same claim built against the live commitment passed CKB `estimate_cycles` (0x302209
  cycles), i.e. Fiber's commitment lock accepted the witness and signature.
- Two harmless rejections in the console after the claim: a pass one minute later rebuilt the claim while the first
  was still in the mempool (`PoolRejectedRBF ... unconfirmed inputs`), and the periodic sweep and the post-claim sweep
  raced (`PoolRejectedDuplicatedTransaction`). Neither sent anything twice.
- The peer had not claimed its 249.99999544 CKB by 21:10; that is its own watchtower's job.
- Everything the page and both Fiber workers printed is in the run's console log (kept with the disposable account's
  credentials in the gitignored `research/e2e/.evidence/`).

### Run 2's stuck cells
Still live at 21:10 on 2026-11-06: `0x32ebef7c…90f1:0` (499.99999544 CKB, the run-2 user's share) and the 62 CKB
reserve `0x158925a8…d710:0`. They cannot be claimed: see "What run 2 actually left behind".

## Upstream issue text (nervosnetwork/fiber)

> **fiber-wasm: browser nodes have no watchtower, so force-closed funds are never claimed (and revoked commitments are never punished)**
>
> **Version:** 0.9.1 (`@nervosnetwork/fiber-js` 0.9.1)
>
> `crates/fiber-wasm` depends on `fnn` with `default-features = false`, so the `watchtower` feature and module are not
> compiled, and `crates/fiber-wasm/src/lib.rs` never starts a `WatchtowerActor`. Its event loop only forwards watchtower
> events when `fiber.standalone_watchtower_rpc_url` is set and otherwise drops them. Since only the watchtower builds
> settlement transactions (`watchtower/actor.rs` `build_settlement_tx`), a browser node that force-closes (or whose
> peer force-closes) never claims its own share: the channel stays `CLOSED | WAITING_ONCHAIN_SETTLEMENT` forever, and
> nothing is logged. Likewise, a revoked commitment published by the peer is never punished.
>
> The start-up check at `lib.rs:239` only rejects `disable_built_in_watchtower: true` without a standalone URL, so the
> default browser config starts as if a built-in watchtower were running.
>
> Reproduction (testnet): start a browser node with `getDefaultConfig("testnet", …)`, open a channel, `shutdown_channel`
> with `force: true`, keep the node running. The peer claims its part after the delay; the browser node never
> claims its own. Observed 2026-10-28: commitment `0xfa3427cd841e6881b3f5f604cfb573a7b1e31c7fece5256a684c3e8c94308802`,
> peer settlement `0x32ebef7c483c6a8370e80393e5dc4a46bc667a73d27dd764e22b6206055290f1`, browser share
> `0x32ebef7c…:0` never claimed.
>
> A standalone watchtower is not a substitute for a self-custodial browser wallet: the watchtower pays claims to its
> own key (`fee_provider_lock_script`), so it takes custody of the user's share.
>
> **Asks:**
> 1. A watchtower for the WASM build: e.g. make the settlement/revocation logic usable with the async WASM RPC client
>    and run a `PeriodicCheck` from the browser event loop, paying to the node's own key as the native node does.
> 2. Until then, refuse to start (or log an error) when the WASM node has neither a standalone watchtower URL nor a
>    built-in one, instead of silently dropping the events.
> 3. Optionally, let the watchtower pay claims to the channel's shutdown/close script rather than the node key, so a
>    third-party watchtower can claim without taking custody.
>
> (KeyWay works around it by answering `standalone_watchtower_rpc_url` inside the page and porting the no-TLC part of
> `build_settlement_tx` to TypeScript.)
