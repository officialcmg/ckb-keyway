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

Not covered (Fiber's watchtower does these; the upstream issue asks for them): claiming pending TLCs with preimages or
after expiry, token (xUDT) channels, and the revocation transaction that punishes a peer who publishes a revoked
commitment. A channel in any of these states is reported in the console and left for a later version. The revocation
gap is the one that can lose funds (a cheating peer is not punished); it existed before this change too.

## Live proof (CKB testnet, production API, fixed SDK)

_In progress; filled in below._

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
