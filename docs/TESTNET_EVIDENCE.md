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
- Funded managed-node restore still requires verification for this release. The unfunded staging restore does not substitute for funded managed recovery. Managed mode must remain opt-in.

### Browser verification in progress

- A new disposable account completed real Chrome OTP login, Lit wallet recovery, browser WASM startup, faucet funding, and channel funding confirmation through the production demo using SDK 0.0.5.
- Funding transaction: `0xfd2877fdeabf110cd7e092515d31ed61c5e0b0ce65930eb01789a0047526949c`; channel: `0x00fe8b37564d93c95a7292ef63ca178ea2f408b716ca0768c15f191c235ddef9`. The UI reached Ready with 901 CKB local and 151 CKB remote liquidity. Fiber identity: `0347f7a3b00f36082204dbbf942d170224ec7bf4bd863c20d290691e018f425fe7`.
- A 1 CKB browser-to-managed payment preflight reported no available route; no payment was submitted. This flow still requires successful settlement verification.
- Recovery hardening now validates all archive schemas before writing, refuses pre-existing databases, and cleans up only databases created by a failed import. Tests also reject modified salt, IV, ciphertext, and digest before creating local state.
- The in-app browser blocks the Railway API with `ERR_BLOCKED_BY_CLIENT`; Chrome was used for funding. Owner-authorized headless Playwright then verified two independent, private browser profiles without accessing the owner's normal Chrome profile. The app remained cross-origin isolated and the real API was reachable.
- The funded Chrome wallet explicitly logged out, then the same account authenticated by fresh OTP in headless profile A. Backup load returned 200, restore confirmation returned 204, and the UI showed the exact same Fiber identity, channel ID, and 901 CKB balance. Profile A's subsequent logout saved a new backup (200), released its lease (204), and revoked its session (204), in that order.
- A second isolated headless profile B independently repeated the login, authenticated restore, unchanged funded-channel checks, and transactional logout. Both private test profiles are retained outside the repository. This proves explicit-logout funded database handoff; it does not prove recovery after an unexpected close or successful payment settlement after restore.

### Post-Restore Payments

- A subsequent fresh headless profile restored the same funded browser identity and channel. Its graph contained 875 public channels, including both its own Bottle channel and the disposable managed receiver's Bottle channel. All three expected browser peers were connected.
- The earlier no-route preflight was transient: once the receiver's channel appeared in gossip, the ordinary SDK preflight succeeded without a node-version upgrade or a manual route override.
- Browser to managed: 1 CKB settled with payment hash `0xcf4b854b99d20ac73900dbceceaa2bd373074d3d44533f64790d538f425fbcca`. The managed receiver independently reported `Paid`; the fee was 0.001 CKB.
- Managed to restored browser: 1 CKB settled with payment hash `0x701e83a2d5c8214fd4cdfc3bb7e06162003117bec88036186f7a48373d2f87d7`. The browser receiver independently reported `Paid`; the fee was 0.001 CKB.
- Both accounts then completed explicit logout. The private browser profile is retained outside Git, and its latest encrypted database backup was saved by the SDK. No test credentials, payment preimages, or full invoices are recorded here.
- This verifies real send and receive after explicit-logout recovery using published SDK 0.0.5. Funded managed snapshot/restore and unexpected-close recovery remain separate, unproven gates.

### SDK 0.0.6 Release

- [Trusted Publishing run 36445023342](https://github.com/officialcmg/ckb-keyway/actions/runs/36445023342) passed all 82 tests with zero skips against disposable Postgres, typechecked, built the public package, and published `@ckb-keyway/react@0.0.6` through OIDC.
- This patch includes failed-import cleanup and archive schema validation. It pins the tested Fiber WASM runtime to `0.9.0-rc7`; no funded node database is upgraded by this release.
- The reference app now imports npm SDK 0.0.6. Local typecheck, backup/package regression tests, and its production build pass. Browser mode remains the default, with managed mode explicitly opt-in.
- Dependency inspection reports one unpatched low-severity [elliptic advisory](https://github.com/advisories/GHSA-848j-6mx2-7j84), propagated into five npm findings through CCC/JoyID dependencies. KeyWay has no direct elliptic/JoyID call sites; this does not establish that every transitive execution path is unaffected. No forced dependency replacement was applied.

### September 29 Production Smoke Checks

- Production deployment `dpl_2cE815o9iGhYFRdtDLwxN831QTcy` is ready at the canonical demo URL and uses npm SDK 0.0.6. Browser mode remains the default.
- A new disposable account completed dashboard OTP login, application creation, and origin registration. App-aware OTP returned 200 for the registered origin. Disabling the application and removing its origin each produced an independently verified 403. The test application was left disabled with no registered origins, and dashboard logout succeeded.
- An isolated headless browser completed real OTP login, wallet recovery, WASM startup, encrypted backup upload, lease release, and session revocation using SDK 0.0.6. This account was unfunded; it does not substitute for the earlier funded-channel tests.
- The initial second-profile attempt reached the intended five-OTP-per-email, ten-minute limit and returned 429 before authentication. Verification respects the cooldown rather than weakening abuse controls.
- After the cooldown, two fresh isolated headless profiles completed real OTP login and restored the same CKB and Fiber identities. Each backup load returned 200 and restore confirmation returned 204 before WASM readiness. Each explicit logout then saved the encrypted backup (200), released the lease (204), and revoked the session (204). Both browser contexts were closed afterward; their private temporary profiles were retained outside Git.

### Funded Managed Recovery

- Commit `11712be` prevents snapshot/restore from returning success when the subsequent node restart fails. All 83 tests passed against disposable local Postgres, with zero skips; typecheck passed. Host deployment `dcc34967-5084-4a2f-9e59-8917953edd4e` succeeded, using the unchanged Fiber 0.9.0 image and existing volume. The redundant queued upload was cancelled; no active deployment or volume was removed.
- The existing authenticated HTTPS operator endpoint was used; no SSH key was registered. Only the two previously verified disposable accounts were selected, by their known opaque directory hashes. No wallet metadata or keys were replaced.
- Both test channels were ready, with explicitly zero pending TLCs and zero offered/received TLC balances. The latest AES-GCM snapshot `snap-1790698790215` was immediately restored to the disposable source node. Its digest matched, and its public identity, channel `0xcc57351d5e1215ae01e39af4de07323e3349962035a4a1086f48c5aaf24bd088`, and exact local/remote balances were unchanged before any new payment.
- After restoration, 1 CKB settled from source to receiver with payment hash `0x2fe3632f0e95a93eb931eb1b701b5e0354b239c3e8c9d7b4c9375dff864d416b`. A reverse 1 CKB settled with hash `0xa0bf45386de546e9b93e9f035b85f60aaa99e3d0fb131faa1fa2218b435a9ebe`. Both senders reported Success and both receivers independently reported Paid; each fee was 0.001 CKB.
- This verifies native funded-state snapshot/restore and post-restore payments through authenticated operator/native RPC. It is not a browser UI test, arbitrary-old-state rollback test, or off-volume disaster-recovery test. Snapshots remain on the same Railway volume.

### Managed Production Headless Checks

- Published SDK 0.0.6 completed fresh OTP login and managed-node connection in two isolated headless Chrome profiles using the same disposable account. Both reported Ready with the same managed node identity, then revoked their sessions on explicit logout. The account was unfunded; funded payment/recovery evidence is recorded separately above.
- Two further isolated headless profiles repeated the flow with COOP/COEP headers removed only from their intercepted test responses. Each asserted `window.crossOriginIsolated === false`, connected successfully, recovered the same managed identity, and logged out. Production headers were not changed.
- No personal Chrome profile, GUI window, existing user's state, or provider credential was accessed by these tests. This completes the managed-default testnet gate; crash-safe browser checkpoints and off-volume managed disaster recovery remain future work.

### SDK 0.0.7 Release And Production Default

- [Trusted Publishing run 36598684045](https://github.com/officialcmg/ckb-keyway/actions/runs/36598684045) passed the full 84-test suite with disposable Postgres, typecheck, package build, and OIDC publish. npm serves `@ckb-keyway/react@0.0.7` with provenance. The reference app pins that exact published version; its local typecheck and production build passed.
- Production deployment `dpl_6y9gQnF5FKCwy1LLxxSTGYuwmeLv` reached Ready and received the canonical `ckb-keyway.vercel.app` alias. Canonical `/app` renders the managed-node demo; `/app?mode=browser` remains explicit and warns that switching modes does not migrate channels.
- Two fresh, isolated headless Chrome profiles logged into canonical `/app` using the same disposable account and published SDK 0.0.7. Each reached Ready with the same managed node identity and completed logout. Each browser asserted `window.crossOriginIsolated === false` after isolation headers were stripped only from its intercepted test responses. OTP send/verify, bootstrap, and managed-node API calls returned 200; logout returned 204. The profiles were closed and retained outside Git.
- Updated Mintlify docs passed build validation and broken-link checks; its accessibility check found no missing media alt text and only non-failing color-contrast improvement warnings. The independent docs production deployment `dpl_7BdwwhM1rcFAL6GrfTbp5qnj9REg` is Ready and its canonical quickstart returns HTTP 200.
- The SDK 0.0.7 headless smoke used an unfunded disposable account. Funded browser and managed post-restore payments are proven separately above. Neither the smoke nor operator recovery proves arbitrary-old-state rollback, unexpected-close browser recovery, off-volume disaster recovery, or mainnet readiness.

### SDK 0.1.0 Account-First API (October 6, 2026)

- Published `@ckb-keyway/react@0.1.0` through [trusted publishing run 37490938782](https://github.com/officialcmg/ckb-keyway/actions/runs/37490938782). The demo pins the published npm package. All 86 tests passed against disposable local Postgres with no skips; typecheck, SDK package build, and production Next.js build passed.
- Seven isolated headless browser scenarios passed: default wallet-only login, wallet-only login with browser mode selected, automatic connection opt-in, recovery failure, balance failure, logout during recovery, and successful payment despite a subsequent channel-refresh failure. Immediate `await fiber.connect(); await fiber.refreshChannels()` also passed. These scenarios mock external services.
- Real temporary mailboxes verified OTP delivery and authentication for two disposable accounts. Each logged in on two isolated devices, recovered the same CKB address and exact managed Fiber public key, read on-chain balance without any managed-node requests before explicit connection, connected, and logged out. No personal browser profile or existing user wallet was accessed.
- Both disposable accounts were funded from the official CKB testnet faucet and opened public channels through the new `useFiber().openChannel()` API and built-in funding confirmation modal. Both reached readiness. A routed 1 CKB payment settled in each direction through `useFiber().payInvoice()`. Sender Success and receiver Paid were checked independently. Payment hashes: `0x7c769f9e5426a3288ed65952ee556eea64d212e91cf9f30073e24df7753daa20` and `0xa2167bf0344db23e1b66b28acd46f9eb23b90b15334c57f9faea483c4f66adef`.
- Added `https://ckbkeyway.dev` to the existing Railway API origin allowlist while retaining previous origins. The API hostname is unchanged. The docs were validated and exported with Mintlify, then deployed to the existing Wildcard Labs project serving `docs.ckbkeyway.dev`.
- OTP template HTML/plaintext generation is tested but not enabled for live delivery. Sender-domain verification, the Stytch branding add-on, and login/signup template configuration remain operator setup. This verification does not claim mainnet readiness, unexpected-close browser recovery, or off-volume managed disaster recovery.
- Canonical production `/app` was checked separately with a disposable funded account using the actual deployed npm SDK: account-only login issued session/bootstrap requests but no managed-node requests; the explicit Connect Fiber button displayed its ready channel; logout returned 204 and the login UI reappeared. Production app deployment `dpl_Fk3XdjK35KiDBKbXHxXiDfCgqKGk` and final docs deployment `dpl_8e6zhzHtUanzTkEHFivXhrtM6QY8` reached Ready. The generated email HTML was visually inspected at 390px width, with a visible code and no horizontal overflow; Gmail/Outlook delivery rendering remains unverified until templates are configured.
