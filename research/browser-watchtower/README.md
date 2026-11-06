# A KeyWay watchtower for browser nodes

All times UTC. CKB testnet only. Sources: Fiber `v0.9.1` (commit `9a561b3e`, crates under `crates/`),
fiber-scripts at `e3bf1e9` ("deploy to testnet"), `@fiber-pay/sdk` 0.2.7 and `@nervosnetwork/fiber-js` 0.9.1 as
installed by `npm ci`. Builds on PR #4 (`browser-settlement`), which gave browser nodes an in-page watchtower.

## Summary

- **Fiber 0.9.1 has a remote ("standalone") watchtower protocol, but it is not safe to point a self-custodial browser
  node at it as is**: its registration call carries the channel's settlement *private* key, every settlement update
  carries the TLC private keys, and the watchtower pays what it claims to its own key.
- **The part that matters while the tab is closed, punishing a revoked commitment, needs no key at all.** The
  revocation data Fiber produces after every payment is a signature both parties made over one output that pays the
  whole channel to the user's own shutdown script. Anyone can broadcast it, adding their own cell for the fee, and
  nobody can change where the money goes.
- So KeyWay runs a **penalty-only watchtower**: the browser SDK sends it, per channel, the two funding public keys
  and the newest revocation data, nothing else. Claiming the user's share after an honest force close stays in the
  page (PR #4); it has no deadline.
- **Proven on testnet** (below): a real fiber-wasm node in Chromium registered its channel and revocations through the
  SDK, the tab was closed, and the watchtower kept following the channel; and with two FNN nodes, a peer that
  published a revoked commitment while the victim was offline was punished 43 s later, the whole 1,098.99999544 CKB
  going to the victim's own address and 0.00000711 CKB of fee paid by the watchtower. After an independent review
  the run was repeated with the fixed code (65 s, same result).

## 1. What Fiber 0.9.1 offers

### The standalone watchtower protocol
- Seven JSON-RPC methods: `create_watch_channel`, `remove_watch_channel`, `update_revocation`,
  `update_pending_remote_settlement`, `update_local_settlement`, `create_preimage`, `remove_preimage`
  (`fiber-lib/src/rpc/watchtower.rs:22-79`). The server side is behind fiber-lib's default `watchtower` feature
  (`fiber-lib/Cargo.toml:117,123`) and enabled with the `watchtower` RPC module.
- A node sends them when its config has `standalone_watchtower_rpc_url` (optionally `standalone_watchtower_token`,
  sent as a Bearer header; `fiber-bin/src/main.rs:307-330`). fiber-bin can also turn off its own watchtower with
  `disable_built_in_watchtower` (`main.rs:298-303,335`). fiber-wasm has no built-in watchtower and forwards events only
  to a standalone URL (`fiber-wasm/src/lib.rs:239-296`; see PR #4's write-up). Both builds use the same forwarding code,
  `forward_event_to_client` (`fiber-lib/src/event_handler.rs:36-140`).
- Per-node separation on the server: each call gets the caller's node ID from a Biscuit token
  (`rpc/middleware.rs:47-90`, `rpc/biscuit.rs:269`). There is no standalone "watchtower-only" FNN mode: the module runs
  inside a full node.
- `@fiber-pay/sdk` 0.2.7 only knows the methods' Biscuit permissions (`dist/chunk-N74KPXKF.js:407-433`) and their
  types (`dist/crypto-B4KHtU1S.d.ts:524-530`); it has no watchtower code.

### What each call carries, and what can spend what

| Call (event) | Fields | Secret? |
| --- | --- | --- |
| `create_watch_channel` (funding done, `RemoteTxComplete`) | channel ID, token script, **`local_settlement_key` (private)**, remote settlement pubkey, both funding pubkeys, settlement data | **yes**: `event_handler.rs:55` sends `local_settlement_key.0.secret_bytes()`; it signs the claim of the user's share of a commitment cell (`watchtower/actor.rs:1930-1940`) |
| `update_local_settlement`, `update_pending_remote_settlement` | settlement data | **yes**: each TLC carries `local_key: Privkey` (`fiber-json-types/src/watchtower.rs:49`) |
| `create_preimage` | payment hash, preimage | yes (claims a TLC) |
| `update_revocation` (`RevokeAndAckReceived`) | revocation data + settlement data | revocation data: **no**; the settlement data next to it: yes |
| `remove_watch_channel` (`ChannelClosed`, `ChannelAbandon`, `ChannelFundingAborted`) | channel ID | no |

And Fiber's watchtower pays every settlement claim and revocation change to its **own** key
(`actor.rs:431-432,1146-1147`: `fee_provider_lock_script = Secp256k1Lock(signer.pubkey_hash())`). Pointing browser
nodes at a stock FNN watchtower would hand KeyWay keys that spend users' channel balances and make it custodian of
every force-closed balance. That rules it out: the watchtower must never receive the node key, only per-channel data, and the same goes for
any key that can spend user funds.

### Why revocation data is safe to hand over
- Fiber builds it in `handle_revoke_and_ack_peer_message` (`fiber/channel.rs:8682-8752`): output = the **whole
  channel** (total minus the commitment fee) locked by `get_local_shutdown_script()` (`channel.rs:8698`), i.e. the
  user's own address in KeyWay (the SDK sets `shutdown_script` to the funding address); the signature is a MuSig2
  aggregate of both funding keys over `blake2b(output ‖ output_data ‖ commitment lock args prefix ‖ commitment number)`
  (`channel.rs:8737-8745`).
- The commitment lock's revocation path (`fiber-scripts/contracts/commitment-lock/src/main.rs:233-279`) checks only:
  one commitment input (`:212-213`), `new_version >= current_version` (`:239`), and that signature over **output 0**,
  its data and the lock args (`:244-257`, Schnorr via ckb_auth). Inputs and other outputs are free, so a third party
  can add its own fee cell, but output 0 is fixed: the watchtower can only pay the user.
- Because the check is `>=`, the newest revocation covers every older commitment: one record per channel is enough.
- Fiber's own watchtower does exactly this (`actor.rs:301-358` recognises the peer's commitment by its key hash and
  compares commitment numbers; `build_revocation_tx`, `actor.rs:415-521`: witness = header ‖ `0x00` ‖ commitment
  number ‖ x-only aggregated key ‖ signature; fee at 1000 shannons/KB from its own cells).
- It can be sent without anything else from the channel: to find the channel on-chain the watchtower needs only the
  two funding public keys (funding lock args = blake160 of the BIP327 aggregate of both keys, sorted,
  `watchtower/store.rs:121-131`; the peer's commitment lock key = aggregate of [local, remote],
  `channel.rs:10020-10031`).

### Who pays the fee
The penalty transaction's fee comes from the watchtower's own plain cells (as in Fiber, `actor.rs:430-512`); the
revocation output is exactly the commitment cell's capacity, so it cannot pay its own fee. KeyWay therefore keeps a
small hot key (`KEYWAY_WATCHTOWER_FEE_KEY`) holding only a fee float. One penalty cost 711 shannons on testnet; the
key needs at least one plain cell above 61 CKB (the change output). Settlement claims after an honest close are paid
by the user's own node key from its fee reserve (PR #4), as before.

## 2. Design

```
browser tab (fiber-wasm)                          KeyWay API (Railway)                     CKB
  Fiber events ──shim──► in-page store (PR #4)      POST /api/v1/keyway/watchtower          
                  │  keeps keys, settlement data    ├ session auth, 240 updates/min/user    
                  └► watchtower-remote.ts ─────────►├ validate, store newest revocation  ──► indexer: funding cell
                     funding pubkeys + newest       │  (keyway_v2_watchtower_channels)        spent? by what?
                     revocation only, coalesced,    └ runner (60 s, one instance by          revoked peer commitment
                     retried                           pg advisory lock) ── penalty tx ───────► whole channel → user
```

**Browser SDK** (`src/sdk/browser/watchtower-remote.ts`, wired in `create-keyway.ts`)
- `remoteWatchUpdate()` builds each request from an allow-list: `watch` (channel ID, both funding pubkeys, token
  script), `revoke` (commitment number, aggregated signature, output, output data), `unwatch` (channel ID).
  `update_local_settlement`, `update_pending_remote_settlement`, preimages and every private key stay in the page
  (tests assert no key reaches a request).
- A per-channel queue keeps only the newest revocation and sends watch → revoke → unwatch in order. A channel whose
  update fails waits for a retry (15 s, doubling to 5 min) without holding up the others; an update KeyWay refuses
  for good (4xx other than 401/429, e.g. a token channel) is dropped, with the channel's later updates; a channel
  KeyWay doesn't know is re-registered from the in-page store. At each start the page resends every stored
  channel (idempotent), which also registers channels opened before this version.
- While anything is unsent, `beforeunload` asks before the tab closes; `watchtowerPending()` and
  `watchtowerStatus()` expose the queue and KeyWay's view to apps. Stopping the node waits up to 10 s for the queue.

**API** (`src/server/watchtower.ts`, route in `http.ts`, migration 19)
- Session-authenticated like every wallet route (`authenticateUser`); rate limits per user of 240 updates/min and,
  separately, 30 status reads/min; at most 64 unresolved channels per user; strict hex/point/molecule validation; a
  channel's funding keys can't be replaced; a revocation is stored only if newer. Token (UDT) channels are refused for
  now: their penalty needs the token's cell deps and was not tested live.
- Each user sees and changes only their own rows (primary key `(user_id, channel_id)`).
- Stored per channel: the two funding pubkeys, the derived funding lock args and peer commitment key, newest
  revocation, state (`watching`, `penalty-sent`, `penalized`, `closed`, `missed`, `invalid`), attempts, and the
  closing/penalty transactions. No private key, settlement data or preimage.
- `unwatch` (Fiber's `remove_watch_channel` on close) only marks the row: the record stays until the watchtower has
  seen how the channel closed, because a revoked commitment can itself be what closed it. Rows that are resolved are
  deleted after 30 days; channels never funded after 14 days (or at once after `unwatch`).

**Runner** (`startWatchtower`, started by `server/index.ts` when `KEYWAY_WATCHTOWER_FEE_KEY` is set)
- Every 60 s (like Fiber's), whichever API instance holds `pg_try_advisory_lock('keyway-watchtower')` checks up to
  500 unresolved channels, oldest check first: funding cell (by lock) live → `open`; spent by an uncommitted tx →
  wait; by anything other than a single commitment-lock output → `closed cooperatively`; by the user's own commitment
  or the peer's current one → `closed` (the in-page watchtower claims the user's share whenever the wallet next runs;
  there is no deadline); by a peer commitment whose number ≤ the newest revocation → verify the revocation signature
  exactly as the lock will (BIP340 by the peer-commitment key over blake2b(output ‖ u32le(len) ‖ data ‖ on-chain
  args[0..28] ‖ number)); if it doesn't verify → `invalid`, never sent; else build and send the penalty and follow it
  to `penalized`. A failed build/send is retried after 1, 2, 4 … minutes (at most every 5 min). If the revoked
  commitment was already spent by something else: `missed`.
- The penalty builder requires the revocation output to equal the commitment cell's capacity (Fiber makes them
  equal), takes fee cells only from the fee key's plain cells with at least 62 CKB to spare, and checks that its change
  equals its own inputs less a fee of at most 0.001 CKB: the watchtower can't take from the channel or be made to pay
  more than a fee.
- Anyone can create cells under the funding lock (only spending needs both parties), so a peer could pad its
  history; each padded cell locks 61 CKB for good. The history is read by two scans, each resuming from a position
  saved with the channel, and stops at the first spend, which only the 2-of-2 can make; the funding outpoint reported
  is the cell that spend consumed, never a guess from the outputs.
  - The recent scan reads everything added since the channel was first checked, newest first, up to 20 s per
    channel per pass. A range it can't finish resumes from its saved position next pass, after first reading
    everything added above that range (within the same 20 s), so a new spend never waits behind an old range.
    Each range also re-reads the last 24 blocks it had already read, so a reorganization that puts a spend into
    those blocks doesn't hide it.
  - The backlog scan reads what was there before, oldest first.
- Reorganizations: a saved spend whose transaction leaves the chain is forgotten and the scan looks again. A
  channel resolved as `closed` or `penalized` in the last 30 minutes is confirmed again every pass; if its closing
  transaction (or penalty) has left the chain, it goes back to `watching` (or `penalty-sent`, so the penalty is
  sent again if needed).
- Each pass checks every channel whose funding has been seen (recent scan, one backlog page, and the penalty if
  one is due), 8 at a time, before anything else. Channels never seen funded can't have been closed; at most 200 of
  them are checked per pass, least recently checked first, so registrations from many accounts can't slow the
  funded channels' checks. Only then do the channels still catching up on a backlog share a 2-minute catch-up
  budget equally; catch-up reads only the backlog, since the recent scan already ran. Passes start every 60 s (one
  that runs longer is followed at once).
- So, for a funded channel:
  - a spend made while it is watched is acted on in the first pass after the spend is committed, whatever the other
    channels' backlogs, unless the peer pads more cells after it than a pass reads in 20 s (thousands, at 61 CKB
    each), which only adds passes;
  - a spend already buried in a backlog when the channel was first checked (possible only for a channel registered
    after it was closed, e.g. re-registered from an older SDK) is reached at 2 minutes of reading per pass, shared
    by the channels catching up.
- Measured (`timing.ts`, evidence/timing.txt): the real pass and scans against Postgres and a simulated indexer with
  100 ms per request, 600 channels, 10 of them padded with 100,000 cells each, and a revoked commitment buried under
  40,000 cells before its first check and 300 after. See the evidence file for the time to the penalty, against a
  commitment delay of about 4 h. Tests cover a spend buried under 1,000 later cells, a spend made while an old
  range is resumed, a recent range longer than a pass, a reorganized spend, a dropped close, the catch-up order and
  funded-before-unfunded checks.
- The advisory lock is re-asked every pass (re-entrant for the holder), so an instance whose connection was replaced
  stops when another holds it; on any error the instance unlocks and releases the connection.

**What the watchtower can and can't do**
- Can: broadcast the penalty (pays the user), learn the user's channels, their capacity, commitment count and the
  user's address (which KeyWay already knows), and, by staying silent or down, fail to protect.
- Can't: move the user's funds anywhere else, claim the user's share, settle TLCs, or act for another user. A leaked
  database gives an attacker the same powers (publish penalties that pay users). A stolen session can `unwatch` a
  channel only in the sense above (the record stays until the close is resolved) or register junk under its own
  account (bounded by the limits; a revocation whose signature doesn't verify is never sent, and one that would
  move more than a fee is refused).
- If KeyWay's watchtower is down: nothing is lost unless a peer cheats *and* the outage outlasts the commitment delay
  (1 epoch, about 4 h). Monitor the `[watchtower]` log and the fee key balance; a second API replica takes over the
  advisory lock if the first dies.

**Not covered**: TLCs that expire while the tab is closed (claiming them needs preimages or TLC keys, which stay on
the device), token channels (neither penalised by KeyWay nor settled in the page), and force-closed channels stay in
the in-page store, so each start re-registers them (the API keeps their resolved row 30 days; afterwards one pass
marks them closed again). Browser mode still needs the user to open the wallet to
claim their share after an honest force close; the docs and SDK say so.

## 3. Live proof (CKB testnet, 2026-11-06)

Throwaway keys, faucet CKB, local Postgres, harness in this folder; logs in `evidence/*.txt` (field names, hashes and
public addresses only). The runner was the shipped `startWatchtower` with a 20 s interval.

### A. Real browser node registers, the tab closes, the watchtower follows (`browser-proof.ts`)
fiber-wasm 0.9.1 in headless Chromium with PR #4's shim/bridge/store and this change's `watchtower-remote.ts`; the
relay's `/sdk` endpoint stands in for `POST /api/v1/keyway/watchtower` (same parser and store, no session).
- 18:28:28 the browser node opened a 500 CKB channel `0x4b8fb9ee…1730` to a native peer P over WebSocket;
  18:28:37 the SDK sent `watch {channelId, fundingUdtTypeScript, localFundingPubkey, remoteFundingPubkey}`.
- The watchtower derived the funding lock from the two pubkeys alone and found funding `0xddfab24e…498b:0`
  (block 22985583), the outpoint Fiber reports: state `open`.
- 18:39:10 the browser paid P 100 CKB; the SDK sent `revoke` for commitments 1 and 2; queue empty; tab closed.
- With the tab closed, P force-closed with the current state: commitment `0x2601c684…015a` (block 22985674,
  commitment number 3 > revocation 2). The watchtower recognised it as the peer's current commitment, sent nothing,
  and recorded "the peer force-closed with the current state; the wallet claims the user's share when it next runs".

### B. A cheating peer is punished while the victim is offline (`relay-and-watch.ts`, `fnn.sh`)
Victim V = FNN 0.9.1 with `--fiber-disable-built-in-watchtower` and its watchtower URL pointed at the relay, i.e. the
same calls fiber-wasm sends to the page (same `forward_event_to_client`); each call went through the SDK's
`remoteWatchUpdate` and the API's parser/store. Cheater C = FNN 0.9.1.
1. 18:22 C opened a 1,000 CKB channel `0xead63244…ae97` to V (V auto-accepted 99 CKB): funding `0xf0a9859f…36ac:0`,
   block 22985533. The relay log shows `create_watch_channel {…local_settlement_key…settlement_data}` arriving and
   only `{channelId, fundingUdtTypeScript, localFundingPubkey, remoteFundingPubkey}` reaching KeyWay.
2. C's store was copied at this state (C: 901 CKB, V: 0 spendable). C paid V 300 CKB; V's node sent revocations 1
   and 2, which KeyWay stored.
3. V stopped ("tab closed"). C was restored to the copy and force-closed: revoked commitment
   `0x35749a98996416485aae08ae89aefaa9147801bd3e071cb107acbac0cba0e4cb` (commitment number 1), block 22985547,
   18:24:54.
4. The watchtower saw it on its next pass and sent penalty
   `0xefd241da113a7319114a05d08fe5871fd6dd2965d5bb122053e6660f144dcf69`, block 22985550, 18:25:37:
   - in: the revoked commitment cell (1,098.99999544 CKB) and one fee-key cell (10,000 CKB);
   - out 0: **1,098.99999544 CKB to V's own lock** (`0x18f0c6ee…ab0b`), the entire channel including the 601 CKB that
     were C's;
   - out 1: 9,999.99999289 CKB change to the fee key (fee 711 shannons).
   The row moved `watching → penalty-sent → penalized`. V's node was never restarted.

### C. Repeated after the review, with the fixed code
Same setup, new channel `0xa609458f…8be7` (C paid V 700 CKB; revocations 1 and 2 stored; V stopped; C restored and
force-closed): revoked commitment `0x75000a9c71b2f4ee242a6263ebbe270b3da90085185caea520e45ed234dec35c` (commitment
number 1), block 22985878, 19:11:11; penalty `0x6c1aa0bfb54edab72b885ed32fc2a3a12ac425c753298a58c6312c68f180169a`,
block 22985882, 19:12:16: 1,098.99999544 CKB to V's lock `0x18f0c6ee…ab0b`, change 9,999.99998578 CKB to the fee key
(fee 711 shannons). Logs: `evidence/*-run2.txt`. (A first attempt at this run lost the channel's events because the
proof database's old table had been renamed without its index, so the watchtower migration failed; Fiber logs a failed forward
and doesn't retry it. In the browser the in-page store keeps the data and the SDK queue retries, so this only
affects the native harness.)

`tests/fixtures/watchtower-testnet-proof.json` keeps the public data of both channels; a test checks that the
watchtower's key derivation reproduces their on-chain funding and commitment locks, and that the real revocation
signature verifies against the revoked commitment's on-chain args (and not against anything else) (in both channels the local key
happened to sort first, so the funding and peer-commitment hashes coincide; unit tests cover the other order).

Reproduce: `PROOF=<dir with C/ckb/key, V/ckb/key, keys.json>`, `FNN`, `CONFIG` (FNN 0.9.1 testnet config),
`FIBER_SECRET_KEY_PASSWORD`, `DATABASE_URL`, `KEYWAY_WATCHTOWER_FEE_KEY`; run `relay-and-watch.ts`, `fnn.sh start C|V`,
then the RPC steps above; for A, a native peer listening on `/ip4/127.0.0.1/tcp/8258/ws` and
`browser-proof.ts fund|start|pay`.

## 4. Deploy steps for the founder

No managed-host (Railway `managed-host`) change: hosted nodes keep Fiber's built-in watchtower.

1. Merge PR #4 first; this branch is based on it.
2. Create the fee key: a fresh secp256k1 key used for nothing else. Fund its testnet address with ~1,000 CKB (a
   penalty costs well under 0.001 CKB; one plain cell above 61 CKB is required).
3. On the Railway **API** service: add the secret `KEYWAY_WATCHTOWER_FEE_KEY=0x…`. Optional:
   `KEYWAY_WATCHTOWER_CKB_RPC_URL` (default: CCC's public testnet RPC) and `KEYWAY_WATCHTOWER_INTERVAL_SECONDS`
   (default 60). Without the key the API runs as before and logs that the watchtower is off.
4. Run the migration before the new API starts (production refuses to start on an old schema):
   `npm run migrate:production` (adds migration 19, `keyway_v2_watchtower_channels`).
5. Deploy the API. Check the log for `[watchtower] running; fee address ckt1…` on exactly one instance.
6. Release the SDK (your call and version number): browser apps send watch data only from that version on; at first
   start the SDK registers channels opened earlier.
7. Watch: `[watchtower]` log lines, the fee key's balance, and `select state, count(*) from
   keyway_v2_watchtower_channels group by 1`.

## 5. Independent review (Fable) and what changed

The reviewer read the diff and the Fiber/fiber-scripts sources without these conclusions. Fixed:
- **High: fee key drain.** A user controlling both sides of a channel could sign a revocation output larger than the
  commitment cell and make the watchtower pay the difference. Now the output must equal the commitment cell and the
  change must equal the watchtower's inputs less a small fee.
- **High: bogus revocations retried forever.** Signatures are now verified before anything is built (`invalid`
  state), and failures back off.
- **High: token-channel penalties lacked the token's cell dep.** Token channels are refused until supported.
- **Medium:** advisory lock left held on a pooled connection after an error, and not re-checked after a reconnect;
  browser queue head-of-line blocking and an endless `beforeunload` prompt for refused updates; a flush on stop that
  did nothing while a retry was waiting (the new test found that a flush during a pass in progress also returned
  early); change cell possibly below 61 CKB.
- **Low:** connection leak if the lock query throws, `NaN` interval, shared rate limit for status and updates, empty
  `returnValue`.
- Tests added: penalty builder with a stub client (change = inputs − fee; inflated, shrunk and too-small-fee cases),
  signature verification against the live revocation, queue isolation/refusal/flush, invalid and backoff passes.

Left as is: the remote queue stays stopped after logout (each sign-in makes a new client); re-registration churn of
resolved channels described above.

## 6. Upstream issue text (nervosnetwork/fiber)

> **Watchtower: a revocation-only registration so third-party watchtowers don't need settlement or TLC private keys**
>
> **Version:** 0.9.1
>
> A node that can't watch its own channels (a browser node, a phone) needs a remote watchtower, and Fiber's standalone
> watchtower protocol is the natural fit. But today registering with one gives it keys that spend the user's funds:
>
> - `create_watch_channel` carries `local_settlement_key` as a private key (`event_handler.rs:55`), which unlocks the
>   user's share of every commitment cell;
> - every `SettlementData` (in `create_watch_channel`, `update_revocation`, `update_local_settlement`,
>   `update_pending_remote_settlement`) carries `SettlementTlc.local_key: Privkey` for each pending TLC;
> - the watchtower pays settlement claims and revocation change to its own key (`watchtower/actor.rs:431,1146`).
>
> The penalty, the one job that has a deadline, needs none of this: `RevocationData` is a two-party signature over an
> output that already pays the whole channel to the user's shutdown script, and the commitment lock checks only that
> output (commitment-lock `auth()`), so anyone can add a fee cell and broadcast it.
>
> **Asks:**
> 1. A watch-only registration: `create_watch_channel` without `local_settlement_key`/settlement data (or a flag), and
>    `update_revocation` without settlement data, for which the watchtower only builds revocation transactions.
> 2. A node option to forward only those (e.g. `standalone_watchtower_mode: revocation_only`), so a node can use a
>    third-party watchtower without handing it keys.
> 3. Optionally, settlement claims that pay the channel's shutdown script instead of the watchtower's key, so a
>    third-party watchtower could also claim after an honest force close without taking custody.
>
> (KeyWay implements (1) on its side: its SDK filters the forwarded calls and its own watchtower ports
> `build_revocation_tx`.)
