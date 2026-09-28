# Testnet Evidence

Verification date: July 13, 2026

Environment:

- Production reference app: `https://ckb-keyway.vercel.app`
- CKB Pudge testnet
- Fiber WASM `0.9.0-rc7`
- Independent receiver: the public Fiber Checkout testnet demo

## Channel activation

The disposable wallet authenticated by email, recovered the same CKB address after logout, connected to Fiber testnet, approved the funding preview, and reached `ChannelReady`.

- Funding transaction: `0x6cbe309c362fca8df9d9d57359ccedb5f31691e265abbfc32d3a4c5e5527c319`
- Channel ID: `0xfb2ed16a558fd89565c6b3d14596eff90228e11c91a579c25a58c5ae8d4a0ed9`
- Funding outpoint: `0x6cbe309c362fca8df9d9d57359ccedb5f31691e265abbfc32d3a4c5e5527c319:0x0`
- Fiber packed outpoint: `0x6cbe309c362fca8df9d9d57359ccedb5f31691e265abbfc32d3a4c5e5527c31900000000`
- Block: `21735029`
- KeyWay contribution shown before approval: `999.99999754 CKB`
- Total transaction fee shown before approval: `0.0000071 CKB`
- Collaborative FundingLock output: `1,250 CKB`
- KeyWay on-chain change: `8,999.99999536 CKB`

Explorer: [view the funding transaction](https://testnet.explorer.nervos.org/transaction/0x6cbe309c362fca8df9d9d57359ccedb5f31691e265abbfc32d3a4c5e5527c319).

The transaction has two inputs and three outputs: one KeyWay input, one peer input, the Fiber FundingLock output, and change for both parties. This is why the signing policy validates KeyWay's own debit while permitting peer-owned collaborative inputs.

## Fiber payment

The independent receiver generated a fixed 1 CKB invoice. The recovered KeyWay wallet parsed it, displayed an explicit confirmation, submitted it through Fiber, and reported settlement. The receiver independently changed from `Waiting for payment` to `Payment confirmed`.

- Amount: `1 CKB`
- Payment hash: `0x705dae6371d3b2b10e417bf18b9cac0235e654eb59ffd8a1432e0cf3250d472b`
- Sender state: settled
- Receiver state: payment confirmed
- Sender console errors: none
- Receiver console errors: none

Fiber payments are off-chain, so this payment does not have a separate CKB transaction hash.

## Automated checks

The same release passed:

```text
npm run typecheck
npm test
npm run build
```

Automated coverage includes PKP recovery, signature formatting, Lit Action boundaries, encrypted Fiber-key round trips, device leases, collaborative funding policy, CCC-to-RPC transaction serialization, peer selection, and actionable error mapping.

## September 28 Verification

The current testnet release uses the existing deployment and newly created disposable accounts. Separate staging identity-provider credentials are deferred until mainnet preparation; existing users' wallet metadata, keys, and channel databases must remain untouched.

- Full local suite against disposable Postgres: 82 passed, 0 failed, 0 skipped. The temporary Postgres server was stopped afterward. Coverage includes native TCP bootstrap, strict funding serialization, and failed IndexedDB import cleanup, in addition to the managed-host restore safeguards.
- API build, SDK build, typecheck, and Next.js production build passed.
- Production demo deployment `dpl_3bZABTfBFWntzTueGtoD2HWqGGAz` is ready. `/app` remains browser mode; `/app?mode=managed` is explicit opt-in.
- A new disposable mailbox received a real OTP from the existing API. Verification and session validation returned 200, logout returned 204, and the revoked session was rejected with 401. No mailbox credentials or session tokens are recorded here.
- The wallet recovery check exposed a missing `/app/lit-actions/decrypt-fiber-key.js` file in the API runtime image. The Dockerfile now copies all three Lit Actions into the runtime image, with a regression test. API deployment `9dbf81b2-ea63-488b-b66c-9224ec37511b` succeeded, and a new disposable wallet was subsequently provisioned through Lit.
- The disposable managed node reported Fiber 0.9.0, two peers, and no channels. Its CKB wallet received 10,000 faucet CKB in transaction `0x9b4123f2578a2581fa81f399fa11c6ceee580fd7d8945810f6031e0ce3f8df83`; the real SDK read the resulting 10,000 CKB balance.
- The real funding test exposed an asynchronous peer-handshake race. The API now waits for the requested peer to appear in `listPeers` before negotiation, with a regression test. API deployment `6d37db9e-bcfa-4938-bf87-9812e77d0133` succeeded. The next test failed safely because the selected peer was not reachable within the handshake deadline; no funding confirmation, signature, or transaction submission occurred. A separate retry failed on a network timeout during the initial channel read.
- The owner-approved managed backup encryption key was configured on the production testnet host. A Git-ignored recovery copy has permission 0600; no key value is recorded in this document. Host deployment `9a5b7e1d-4e72-4663-89cf-8fd6182552b0` succeeded with encrypted backups, serialized database operations, and a fail-closed interrupted-restore guard. Restore keeps the previous database until the replacement succeeds; a leftover `.previous` directory requires operator recovery before startup.
- Native TCP peer resolution worked once gossip was available, but fresh nodes had no matching address. The gateway now prefers pubkey-based TCP resolution and falls back to a verified Bottle bootstrap address, requiring the expected pubkey in `listPeers` before negotiation. Browser WSS behavior is unchanged.
- A real signed funding transaction exposed strict native RPC rejection of CCC's cached input fields. Both SDK modes now use CCC's JSON-RPC transformer; the managed gateway also cleans older SDK payloads without changing transaction hashes or witnesses. API deployment `99002e2a-1d27-44fd-bf94-94a5114842d8` succeeded with this fix and fresh-node bootstrap.
- Two new disposable accounts completed OTP delivery, Lit wallet provisioning, faucet funding, funding confirmation, signing, and native submission. CKB independently reports both funding transactions committed: `0xff1801ab16f85ecbc57232b76b36cdda3c7c4c34bca2f192fe371af4490153c4` (channel `0x88fa80f766bd35bb3ccdd0c43407d102b4f0880ae5bf6cf34cdbe59c692090b0`) and `0x5040294c51ee6c14dccb1c080793131f4a23f28b1eff2301b48e9d1aba64e8cc` (channel `0xcc57351d5e1215ae01e39af4de07323e3349962035a4a1086f48c5aaf24bd088`). Each preview showed `999.99999702 CKB` funding and `0.00000762 CKB` total transaction fee.
- Both disposable channels reached `CHANNEL_READY`, each initially exposing 901 CKB local and 151 CKB remote liquidity. A 1 CKB payment settled successfully with hash `0xe41104e39d7a0830c628f1e49d392e4bf7fa93517494254970f797fad547cf7a`; the receiver independently reported `Paid` and its local balance increased to 902 CKB. A reverse 1 CKB payment using installed `@ckb-keyway/react@0.0.5` also settled successfully, with hash `0x5221ce6a0e119344de041f93c589a1cf21444af1f2a517383542cf2fb447108c`. Each route charged 0.001 CKB. The tests used the real SDK and API, with curl as the transport because Node connection establishment was intermittently timing out; they do not substitute for browser UI verification.
- Native logs show an initial broadcast rejection of the partial transaction before peer witnesses arrived. Both exact transaction hashes later committed and both channels became ready. The observed error alone was not proof of final channel failure; no duplicate funding was submitted.
- Funded-channel restore and cross-browser migration still require verification for this release. The unfunded staging restore does not substitute for funded recovery. Managed mode must remain opt-in.

### Browser verification in progress

- A new disposable account completed real Chrome OTP login, Lit wallet recovery, browser WASM startup, faucet funding, and channel funding confirmation through the production demo using SDK 0.0.5.
- Funding transaction: `0xfd2877fdeabf110cd7e092515d31ed61c5e0b0ce65930eb01789a0047526949c`; channel: `0x00fe8b37564d93c95a7292ef63ca178ea2f408b716ca0768c15f191c235ddef9`. The UI reached Ready with 901 CKB local and 151 CKB remote liquidity. Fiber identity: `0347f7a3b00f36082204dbbf942d170224ec7bf4bd863c20d290691e018f425fe7`.
- A 1 CKB browser-to-managed payment preflight reported no available route; no payment was submitted. This flow still requires successful settlement verification.
- Recovery hardening now validates all archive schemas before writing, refuses pre-existing databases, and cleans up only databases created by a failed import. Tests also reject modified salt, IV, ciphertext, and digest before creating local state.
- The in-app browser blocks the Railway API with `ERR_BLOCKED_BY_CLIENT`; Chrome was used instead. An independent incognito handoff remains in progress. Neither this browser funding check nor local archive tests prove funded cross-device recovery.
