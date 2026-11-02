# JoyID redirect mode under cross-origin isolation

Research only. Nothing in product code changed. Researched 2026-11-02 against the versions this repo locks:
`@ckb-ccc/joy-id` 1.1.3, `@ckb-ccc/core` 1.16.1, `@joyid/ckb` 1.1.4, `@joyid/common` 0.2.2 (`package.json`,
`package-lock.json:1225`; the installed `node_modules/@joyid/common/dist/index.js` is byte-identical to the
`npm pack` tarball). JoyID's web app is closed source, so its behaviour comes from its live JavaScript bundles.
`evidence/joyid-app-excerpts.txt` holds the excerpts with URLs, sha256 hashes and offsets, and
`proofs/joyid-bundle-excerpts.sh` regenerates them.

Citation keys used below:

- **common** = `@joyid/common@0.2.2/dist/index.js` (line numbers from the published file)
- **common-types** = `@joyid/common@0.2.2/src/types/dapp.ts`
- **joyid-ckb** = `@joyid/ckb@1.1.4/src/index.ts`
- **ccc-joyid** = `@ckb-ccc/joy-id@1.1.3/dist/barrel.mjs` and `dist/connectionsStorage-BloUSPun.mjs`. These are minified to one line each, so they're cited by symbol.
- **ccc-core** = `@ckb-ccc/core@1.16.1/src/...`
- **JoyID-app** = `evidence/joyid-app-excerpts.txt`, which covers the testnet bundle `index-KHmlX32p.js` (sha256 `1f91e61a…4c31`), the testnet sign-message chunk `index-DBbMSMVu.js` (sha256 `a44605e9…0721`) and the mainnet bundle `index-CTCvN3gI.js` (sha256 `9ea3918e…b1e6`).
- **P1** = `proofs/redirect-equivalence.ts` → `proofs/redirect-equivalence.output.txt` (Node)
- **P2** = `proofs/coop-browser.ts` → `proofs/coop-browser.output.txt` (headless Chromium 153, Playwright 1.63)

## Verdict

**Redirect mode is a sound fix.** For signing a text, JoyID produces the same WebAuthn assertion whichever way
it delivers it. The JoyID page runs one signing path for both modes. The mode only picks the last step: send
the result with `window.opener.postMessage`, or put it in the return URL's query and call `location.replace`
(JoyID-app `sendMessageToDapp`). P1 shows that the redirect-decoded result matches the popup result field for
field and byte for byte. It also passes KeyWay's `parseJoyIdSignature`, `verifyWebAuthn` and
`verifyBackupOwnership` unchanged. P2 shows that under KeyWay's exact production headers (COOP same-origin,
COEP require-corp, the proxy.ts CSP, X-Frame-Options DENY, Referrer-Policy strict-origin-when-cross-origin):

- the popup loses `window.opener`, and the opener's window handle reports `closed === true` at once;
- a top-level redirect round trip works, and the page comes back cross-origin isolated with sessionStorage intact.

**Better still:** P2 also shows a *hybrid* in Chromium. A same-origin helper window runs JoyID's redirect mode,
then relays the result to the main tab over `BroadcastChannel` and closes itself. That works under COOP
same-origin, and the main tab and its Fiber node never unload. I recommend the hybrid as the default, with a
full-page redirect as the fallback. See §8.

Caveats that keep this short of certain:

- JoyID needs the JoyID address before it can sign, so the first backup costs two round trips (auth, then sign).
- The result travels in the **query string**, so it reaches the app's server and its logs.
- Firefox, Safari, mobile, PWAs and in-app browsers weren't run here. They are on the hand-test list at the end.

---

## 1. The redirect API in the versions KeyWay uses

| Package | Redirect support | Source |
| --- | --- | --- |
| `@joyid/common` 0.2.2 | `authWithRedirect(request)` and `signMessageWithRedirect(request)` call `window.location.assign(buildJoyIDURL(request, "redirect", "/auth" \| "/sign-message"))`. `getRedirectResponse(uri?)`, `authCallback` and `signMessageCallback` read the result. `isRedirectFromJoyID(uri?)` detects a return. `buildJoyIDURL`, `encodeSearch` and `decodeSearch` are also exported. | common:546-548, 571-573, 322-333, 567, 591, 352-359, 334-351, 119-120 |
| `@joyid/ckb` 1.1.4 | **None.** `connect`, `signChallenge`, `signTransaction`, `signCotaNFTTx` and `signRawTransaction` are popup-only (`authWithPopup`, `signMessageWithPopup`, or `buildJoyIDURL(..., 'popup', ...)` plus `runPopup`). | joyid-ckb:83-95, 97-118, 120-153, 193-247 |
| `@ckb-ccc/joy-id` 1.1.3 | **None.** `CkbSigner.connect` and `signMessageRaw` call `createPopup(buildJoyIDURL(e, "popup", "/auth" \| "/sign-message"), …)`. Every signer hard-codes `"popup"`. | ccc-joyid `barrel.mjs` class `l` (CkbSigner); `connectionsStorage` `createPopup` |
| JoyID app, transactions | `/sign-ckb`, `/sign-cota-nft` and `/sign-ckb-raw-tx` always answer with `DappCommunicationType.Popup`, so **transaction signing has no redirect mode**. KeyWay only signs messages with JoyID, so this doesn't matter here. | JoyID-app "sign-ckb-raw-tx delivery is hard-coded popup" |

**Request URL.** `buildJoyIDURL` (common:334-351) builds `<joyidAppURL><path>?type=redirect&_data_=<encodeSearch(request)>`.
In redirect mode it first appends `joyid-redirect=true` to `redirectURL`. That is the only request difference
from popup mode. P1 §1 shows `request fields that differ: [ 'redirectURL' ]`, with `challenge` and
`isData:false` identical. CCC sends `{redirectURL: location.href, joyidAppURL, name, logo, challenge, isData, address}`
with **no `requestNetwork`** (ccc-joyid CkbSigner `getConfig` / `signMessageRaw`). A KeyWay redirect should
send exactly the same fields, so that JoyID's page takes the same branch.

**Where JoyID returns.** It returns to `redirectURL` exactly, the app's own `location.href` plus
`joyid-redirect=true`. JoyID's page sets `url.searchParams.set("_data_", encodeSearch(message))` and calls
`location.replace(url.href)` (JoyID-app `sendMessageToDapp`, identical in the testnet and mainnet bundles).
So the result is in the **query**, not the fragment. P1 §3 shows query keys `[tab, joyid-redirect, _data_]`
and fragment `""`. `getRedirectResponse` reads `url.searchParams.get("_data_")` (common:322-333).

JoyID's page refuses a redirect whose `redirectURL` origin differs from `document.referrer`'s origin, and
accepts only `https:`, `http:` and `tap3:` (JoyID-app `useGuardRedirectUri` and the SignMessage route). KeyWay
sends `Referrer-Policy: strict-origin-when-cross-origin` (next.config.ts:23), so the referrer is the app's
origin and the check passes. P2 shows the wallet stand-in saw `referrer: "http://localhost:4100/"`.

**Fields returned** (JoyID-app `sendSignedMessageToDapp` / `sendRawAuthMessageToDapp`; common-types:88-135):

- SignMessage: `{ type: "SignMessage", data: { signature, message, challenge, alg, pubkey, keyType, state }, state }`.
  - `signature` is base64url DER.
  - `message` is base64url(authenticatorData ‖ clientDataJSON).
  - `challenge` is the original text.
  - `pubkey` is hex without 0x for a main key (`cn.pubkey.slice(2)`).
  - Session keys also get `attestation`.
- Auth: `{ type: "Auth", data: { address, ethAddress, keyType, alg, nostrPubkey, pubkey, nativeSegwit, taproot, btcAddressType }, state }`.
  Here `state` is **only at the top level**.
- Reject or error: `{ error: "User Rejected", type, state }`. `getRedirectResponse` throws `RedirectErrorWithState(error, state)` (common:329-331, P1 §6).

**How `state` round-trips.** `state` is a request field, so it travels to JoyID inside `_data_` (it's visible
in JoyID's URL) and comes back at the top level. For SignMessage it also comes back in `data.state`.
`getRedirectResponse` returns only `res.data`, **so for Auth the state is lost** (P1 §6:
`Auth via getRedirectResponse has state? false`). KeyWay must read the top-level `state` itself with
`decodeSearch(url.searchParams.get("_data_"))`. The qss decoder coerces numeric and boolean *strings*
(common:38-47), but `encodeSearch` JSON-quotes them first, so `"12345"`, `"true"` and `{id:"007"}` all survive
(P1 §6). Use an object such as `{ v: 1, id: <128-bit random> }` anyway.

## 2. Is the redirect signature the same assertion as the popup one?

**Yes, byte for byte.** Both modes take this path on JoyID's page (JoyID-app, with the call sites in that file):

1. The SignMessage route reads `type` from the URL, defaulting to `"redirect"`, and renders **one** component `b` with `type` passed through.
2. Confirm calls `useSendSignedMessageToDapp(SignMessage)(request, account, type)`.
3. For a request that isn't `ethereum` and isn't `btc-*` (CCC's CKB request has no `requestNetwork`):
   - `isData` true: `useSignMessage(hexToArrayBuffer, …)`;
   - `isData` false: `useSignMessage(utf8StringToBuffer, t => bufferToBase64URLString(utf8StringToBuffer(t)))`.
   That is `startAuthentication({ challenge: base64url(utf8(text)), userVerification: "required", allowCredentials: [this credential] })`.
4. `generateSignedInfo` sets `message = base64url(authenticatorData ‖ clientDataJSON)` and `signature = response.signature`.
5. `sendSignedMessageToDapp` builds the result object above, the same object for both modes.
6. `sendMessageToDapp(message, redirectURL, type)` is the **only** branch on mode: postMessage the object, or encodeSearch it into `_data_`.

On the dapp side:

- **Popup:** `runPopup` / `createPopup` resolve `e.data.data` (common:396-416; ccc-joyid `createPopup`).
  CCC's `signMessageRaw` returns `JSON.stringify({signature, alg, message})`, and
  `Signer.signMessage` adds `identity = JSON.stringify({keyType, publicKey})` (ccc-core `signer/signer/index.ts:392-398`).
- **Redirect:** `getRedirectResponse` → `decodeSearch` → `JSON.parse` of `data` returns the same object.
  `alg` stays the number `-7` (P1 §4).

**Challenge encoding:** KeyWay passes a string, so CCC sends `isData: false` (`isData: typeof e != "string"`),
and JoyID's page signs base64url(UTF-8 text). That is exactly `webAuthnChallenge` (src/sdk/browser/webauthn.ts:42-45)
and what `contracts/joyid-webauthn` rebuilds (contracts/joyid-webauthn/src/lib.rs:7-9, 133-136). P1 asserts
`bufferToBase64URLString(utf8StringToBuffer(text)) === webAuthnChallenge(text)`. A KeyWay redirect must set
`isData: false` or leave it out; JoyID treats a missing value as false.

The verifier checks neither rpIdHash nor the clientDataJSON origin (lib.rs:167-177; webauthn.ts:67-77, 98-115).
Even so, the origin is JoyID's page in both modes.

**Don't use Auth's `challenge` option to save a round trip.** With a challenge, Auth signs
`` `JoyID authorize prefix:\n${challenge}` `` (JoyID-app `AUTH_MESSAGE_PREFIX`, `au`). KeyWay's verifier would reject that.

**P1 result:**

- a real P-256 assertion, made the way JoyID's code makes it, delivered both ways: `signature JSON identical: true`;
- field-by-field equal;
- `verifyWebAuthn(redirect): true`;
- `verifyBackupOwnership(redirect) -> joyid (address matches)`.

UNVERIFIED: I couldn't run a real passkey in JoyID's page. The claim rests on JoyID's shipped code (above) plus
P1's reconstruction. Founder test 1 closes it.

## 3. Does navigation work under COOP same-origin + COEP require-corp?

**Yes. P2, run against KeyWay's real CSP (`contentSecurityPolicy()` from proxy.ts):**

| Case | Result (P2) |
| --- | --- |
| Popup from a COOP same-origin / COEP require-corp page | The popup sees `openerIsNull: true`. The opener's handle reports `popupHandleClosed: true` and `received: null`. CCC's `createPopup` polls `popup.closed` every second and rejects with `PopupCancelledError` ("Popup closed"). JoyID's page posts nothing (`window.opener && …`), and after 5 s its `useSdkPopupGuard` warns that the dapp window was closed. |
| The same with COOP same-origin-allow-popups / COEP unsafe-none (today's `/rescue`) | `openerIsNull: false`, and the message arrives. But `crossOriginIsolated: false` and `SharedArrayBuffer` is undefined, so there's no Fiber node. |
| Full-page redirect round trip | Back on the app, `crossOriginIsolated: true`, `SharedArrayBuffer` is a function, sessionStorage and localStorage both survive, the result decodes, and the Fiber Web Lock can be re-acquired (`fiberLockReacquired: true`). |
| Hybrid helper window (§8) | The result arrives over BroadcastChannel, the helper closes itself (`helperClosed: true`) and the main tab stays isolated. |

**Why** ([MDN COOP](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cross-Origin-Opener-Policy)):

- "When navigating between documents, the new document is opened in the same BCG if the two documents have 'matching coop policies', and otherwise into a new BCG."
- "When opened in a new BCG, any references between the new document and its opener are severed … any object opened by your document in a new BCG can't access it using `window.opener`."

COOP changes which browsing context group a navigation lands in. It doesn't block the navigation. COEP governs
what a document loads: "The policy applies to loaded resources, and resources in `<iframe>`s and nested frames"
([MDN COEP](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cross-Origin-Embedder-Policy)).
After navigating, JoyID's page is its own document with its own headers. JoyID sends no COOP, COEP or CSP, only
X-Frame-Options DENY and HSTS (evidence, headers section), so its resources aren't subject to KeyWay's COEP.

**KeyWay's CSP, X-Frame-Options and Referrer-Policy:**

- The CSP (proxy.ts:20-36) has no directive that limits top-level navigation. `form-action 'self'` only covers form submissions, and `buildJoyIDURL` uses `location.assign`.
- `frame-ancestors 'none'` and X-Frame-Options only matter when framed, and nothing is framed here.
- P2 ran with the real CSP and the round trip worked.
- One catch: the redirect must be **started from SDK code**, which the nonce plus `'strict-dynamic'` allows (P2's code is a nonce'd module).
- The proxy's matcher covers the return URL (proxy.ts:38-48), so the returning page gets a nonce'd CSP like any other page.
- In P2, `connect-src` gained the local `http://` wallet origin, only for the Referer probe, because production `connect-src` allows `https:` and the test ran over http.

## 4. Security of a signature in the URL

**Measured (P2):**

- The return request line, with the full `_data_`, reaches the app's server (`serverLog`: `app GET /wallet?tab=recovery&joyid-redirect=true&_data_=…`).
- Before `replaceState`, a **same-origin** fetch sent `Referer` with the full `_data_` URL. A cross-origin fetch sent only `http://localhost:4100/`, because of strict-origin-when-cross-origin.
- `history.replaceState` cleaned the visible URL (`urlAfterReplace: http://localhost:4100/wallet`).
- JoyID's `location.replace` means Back skips JoyID's page and returns to the pre-redirect app page (`after history.back()`).
- Sizes: the request URL is about 1.2 KB and the return URL about 2.5 KB for a real backup challenge (P1), well under Vercel's 14 KB CDN URL limit ([Vercel URL_TOO_LONG](https://vercel.com/docs/errors/URL_TOO_LONG)).

**What leaks:**

- the signed text (KeyWay account address, JoyID address, nonce, expiry);
- the JoyID public key and the assertion.

The *request* side already leaks the same text today: popup mode also puts it in JoyID's URL query
(common:334-351, same builder). The new exposure is the response in the app's own:

- server or CDN request logs: Vercel logging the query is UNVERIFIED. I found no Vercel doc saying whether request logs keep query strings; check the dashboard (founder test 9);
- browser history and sync;
- extensions with tab access;
- same-origin Referers sent before cleanup.

**Replay value is negligible:**

- **Backup proof:** the nonce is `<expiry>.<random>.<HMAC(user.id, expiry, random)>`, accepted only for that user and for 15 minutes (src/server/recovery.ts:187-201; recovery-backups.ts:164-171). The text names the account and *this* JoyID (recovery-backups.ts:177-188). A leaked proof can only add the JoyID the user approved, to the user's own account, and only with the user's session token plus the emailed code (account-recovery.ts:144-160, `changeRecoveryBackup` → `withEmailCode` at line 158). The real harm is privacy: it links the KeyWay address to the JoyID address.
- **Rescue:** the signed text is bound to one transaction sighash and one destination (recovery-backups.ts:12-15; contracts/joyid-webauthn). Replaying it can only broadcast the rescue the user signed. Rescue keeps popup mode anyway (§8).

**The real risk is injection, not replay.** A crafted URL `…?joyid-redirect=true&_data_=…` carrying an
*attacker's* JoyID signature over the victim's challenge would verify on the server. `verifyBackupOwnership`
checks that whoever signed holds the JoyID named in the text, and the text names the attacker's JoyID. This
needs the victim's nonce, which leaks only through the victim's own URLs. The defence is the state binding in
§5: a result is accepted only if this tab started that exact request, for that JoyID address and nonce. The
add-backup dialog and the email code stay as further gates.

**Mitigations (all required):**

1. On load, parse `_data_`, then call `history.replaceState` **synchronously, before any fetch, analytics or render**.
2. Keep `Referrer-Policy: strict-origin-when-cross-origin` or stricter. With `no-referrer`, JoyID's referrer check is skipped (`if (document.referrer)`), and the redirect still works.
3. Use a dedicated, minimal return path with no third-party scripts.
4. Don't log query strings on that path. Next/Vercel functions don't log URLs on their own; the proxy middleware runs, but it doesn't log.
5. A fragment isn't an option: JoyID always writes `_data_` into the query.

## 5. What to persist, and how to resume

**Today's reload behaviour:**

- The session is a bearer token in **localStorage**, under `ckb-keyway.session.v2:<appId>`. It's restored on mount and validated with `api.session` (keyway-provider.tsx:341-366, 921-948), so it survives the round trip (P2 also shows localStorage kept).
- With `autoStartFiber`, the provider calls `connect()` once authenticated (keyway-provider.tsx:409-444). The browser node restarts from IndexedDB on return.
- The node's Web Lock is released when the page unloads (P2 `fiberLockReacquired: true`).
- The server lease lets the **same device** re-acquire before expiry (src/server/device-lease.ts:20-35).
- The node is killed **without `stop()`** and is offline while the user is at JoyID.

**Persist** in sessionStorage, keyed `keyway:joyid:<state.id>`. sessionStorage is tab-scoped, so another tab
can't consume the record. It survived the COOP browsing-context-group switch (P2). Firefox and Safari:
UNVERIFIED (founder test 4). Store `{ v, id (128-bit random), op: "backup-add" | "backup-enable", step: "auth" | "sign", appId, userId, account, joyIdAddress?, challengeNonce?, expiresAt, returnPath, otherProofs? }`.
There are no secrets in it: `otherProofs` are the EVM backup proofs gathered for `enable([...])`.

**Resume** (provider mount, before Fiber autostart):

1. Return early unless `isRedirectFromJoyID()` is true.
2. Decode the top-level `_data_` with `decodeSearch`, then `replaceState` at once.
3. Load the record by `state.id`. **Delete it before using it**, so it's one-time.
4. Require all of these, or discard the result with an error:
   - the record exists;
   - `now < expiresAt`;
   - `userId` matches the restored session;
   - `type` matches `step`;
   - for sign: `data.challenge === recoveryBackupChallenge(account, { kind: "joyid", address: joyIdAddress }, challengeNonce)`;
   - `keyType === "main_key"` and `alg === -7`;
   - `verifyBackupOwnership` passes locally.
5. A `RedirectErrorWithState` "User Rejected" becomes a cancel.
6. The proof then enters the normal `addBackup` / `enable` flow: preview dialog plus emailed code.

Before navigating away with a browser node running:

- `await keyway.stop()`;
- refuse to leave, or warn, while a payment or channel operation is in flight.

Ask for the nonce *right before* the sign step, so the 15-minute window covers JoyID's two passkey prompts.

## 6. UX facts

- **Two passkey prompts, as with popup.** JoyID's sign page needs `address` (common-types:150-155, 173-176), and KeyWay's text contains the JoyID address. So a first-time user does Auth (one round trip), then sign (a second). Auth without a challenge runs `useVerifyAccount` (one passkey prompt), and sign is another, just as CCC's popup `connect()` then `signMessage` does today (account-recovery.ts:68-74). Skip Auth when a JoyID connection is already stored. CCC keeps it in localStorage `ccc-joy-id-signer` (ccc-joyid `ConnectionsRepoLocalStorage`).
- **Same sign screen** (JoyID-app sign-message chunk). One component for both modes shows the app logo, "Sign {name}", the host from `document.referrer || redirectURL`, and the message text. The referrer is the app's origin in both modes (P2 `walletSaw.referrer`, popup and redirect), so the host shown is identical.
- **JoyID docs** ([docs.joyid.dev/guide/applications/webdapp](https://docs.joyid.dev/guide/applications/webdapp)): "Popup invocation is ideal for desktop applications…", "Redirect invocation is well-suited for mobile applications…", and "Browser restrictions may affect popup usage, with some browsers blocking popups or permitting only one browser tab." The PWA page is "under construction" ([pwa](https://docs.joyid.dev/guide/applications/pwa)). I found no other stated limits.
- **Standalone PWAs:** popup mode refuses outright. `runPopup` and CCC's `createPopup` reject with `PopupNotSupportedError` when `isStandaloneBrowser()` (common:198-200, 375-377).
- **CCC's own position:** `getJoyIdSigners` replaces every JoyID signer with `SignerAlwaysError("JoyID can only be used with standard browsers")` in standalone mode or a webview UA (`isWebview`, ccc-core `utils/index.ts:184-186`). KeyWay builds `CkbSigner` directly (rescue-view.tsx:97-98), which bypasses that check.
- **Redirect inside a PWA or an in-app browser:** UNVERIFIED. Leaving the PWA's scope may open a separate browser surface, which wouldn't return to the PWA's tab or sessionStorage (founder tests 5-6).
- **Mobile Safari / Chrome:** UNVERIFIED by run. This environment has only Chromium.

## 7. Alternatives

| Option | Fiber node (needs `crossOriginIsolated`) | JoyID popup | Evidence |
| --- | --- | --- | --- |
| **Document-Isolation-Policy** instead of COOP+COEP | Chrome/Edge 137+ desktop, Chrome Android 146+. **Not supported in Firefox or Safari** (desktop or iOS); bugs 2063367 and webkit 325516. | Works: "Documents with Document Isolation Policy can open cross-origin popups and communicate with them." | [web-features](https://web-platform-dx.github.io/web-features-explorer/features/document-isolation-policy/), [Chrome blog](https://developer.chrome.com/blog/document-isolation-policy) |
| COEP `credentialless` | Still needs COOP same-origin for isolation ("set the COOP header to `same-origin` and … COEP … `require-corp` (or `credentialless`)"). | Broken, same as today | [MDN COOP](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cross-Origin-Opener-Policy). Safari support for `credentialless`: UNVERIFIED (MDN compat table not retrieved). |
| Helper window on the app's origin + BroadcastChannel (the hybrid) | Main tab keeps running | Not needed: the helper uses JoyID's redirect mode | P2 HYBRID (Chromium). Other browsers UNVERIFIED. |
| Relay through KeyWay's server | n/a | Doesn't help. JoyID returns only to a `redirectURL` on the referrer's origin (JoyID-app guard), so the browser still has to come back to the app. A server hop only adds another place that sees signatures. | JoyID-app `useGuardRedirectUri` |
| Popup with `same-origin-allow-popups` (today's `/rescue`) | No (`crossOriginIsolated: false`) | Works | P2 |

DIP alone isn't cross-browser. Sending COOP as well brings the popup problem back, so using DIP would mean
choosing headers per user agent. Redirect, or the hybrid, is the only fix that works in every browser.

## 8. Recommended design (not implemented)

**Browser SDK** (`src/sdk/browser/joyid-redirect.ts`, new). It uses `@joyid/common` directly, builds the same
request fields CCC sends, and has three transports:

- `"popup"`: today's CCC `CkbSigner`.
- `"window"`: the hybrid. Synchronously on the user's click, `window.open("<returnPath>?keyway-joyid=<id>")` on the app's own origin. That page calls `signMessageWithRedirect` / `authWithRedirect` with `redirectURL = <origin><returnPath>`. On return it validates `state.id`, posts `{id, result}` on `BroadcastChannel("keyway:joyid")` and calls `window.close()`. The opener waits with a timeout and falls back if `window.open` returned `null`.
- `"redirect"`: a full-page `location.assign`, with resume as in §5.
- `transport: "auto"` (default):
  - not `crossOriginIsolated`: `"popup"`;
  - isolated: `"window"`, falling back to `"redirect"` when the window can't open (blocked, or standalone PWA).

**React** (`createJoyIdBackup(signer?, { transport })` in wallet-hooks.ts:81-83):

- With "popup" or "window" it resolves with the proof, as today.
- With "redirect" it persists the intent and navigates, and its promise never resolves.
- **KeyWayProvider** runs resume on mount *before* Fiber autostart. It exposes `recovery.pendingJoyIdBackup` (proof or error) and, for `op`, continues with `addBackup` / `enable` (the user still approves and enters the code).
- In a `keyway-joyid` helper window, the provider must **not** start Fiber or bootstrap. Otherwise the helper would try to take the device lock (device-lock.ts:12-23).
- Optional `joyIdReturnPath` prop, defaulting to the current path.

**Rescue page:** keep the popup (next.config.ts:29-35, no Fiber node). Support for the hybrid is optional, for
popup-blocked mobile browsers. Don't use full-page redirect there: the signed text is bound to a transaction
built from live cells. Resuming would mean persisting the serialized transaction and re-running
`checkRescueTransaction` (src/rescue/rescue.ts:374), and a moved cell invalidates the signature.

**Docs:**

- quickstart.mdx "Optional browser node": warn that `Cross-Origin-Opener-Policy: same-origin` cuts off any cross-origin wallet window, including JoyID and EVM wallet sites. With KeyWay's SDK, JoyID backups switch to the helper-window or redirect flow automatically.
- troubleshooting.mdx, new section "A wallet window closes immediately or never returns": the cause, the `crossOriginIsolated` check, and the `transport` option.
- account-recovery.mdx: the `transport` option, the two-step first use, and the resume API.

**Test plan:**

1. Unit tests (`node:test`): turn P1 into a test. Add resume validation that rejects each of: unknown or consumed state, expiry, a different user, a step/type mismatch, a challenge mismatch, a different JoyID address, a session key or sub key, and a user rejection. Cover the qss round trip of `state`.
2. Playwright e2e: turn P2 into a test with a fake JoyID origin, run against `next build && next start` with the real next.config.ts and proxy.ts headers. Cover popup failure detection, hybrid, redirect plus resume, URL cleaned before the first fetch, a Fiber restart after redirect, and a blocked `window.open` falling back to redirect.
3. Manual tests with real JoyID (below).

## What the founder must confirm by hand

1. Desktop Chrome, demo `/wallet` (COOP same-origin): a real JoyID redirect sign returns to `…?joyid-redirect=true&_data_=…`, and the server accepts the backup. This is UNVERIFIED here because there's no real passkey in the cloud.
2. Same with the hybrid helper window: JoyID's page works in the helper and the helper closes itself.
3. iOS Safari and Android Chrome: both transports. Does `window.close()` close the helper tab? Does sessionStorage survive the redirect?
4. Firefox and Safari desktop: sessionStorage and BroadcastChannel across the COOP browsing-context-group switch.
5. Installed PWA (iOS home screen, Android): what happens on redirect and in the hybrid.
6. In-app browsers (social or chat apps): whether JoyID's passkey works at all.
7. JoyID's screen shows the same app name, host and message in both modes.
8. A backup added through redirect later signs a rescue that the chain accepts (testnet, once it commits).
9. Whether Vercel request logs keep query strings on the return path.
10. A browser Fiber node restarts after the round trip, with channels intact and no lease error.

## Files

- `proofs/redirect-equivalence.ts` + `.output.txt`: request diff, a mode-equivalent assertion, KeyWay's verifiers, `state` behaviour. Run: `node --import tsx research/joyid-redirect/proofs/redirect-equivalence.ts`.
- `proofs/coop-browser.ts` + `.output.txt`: popup, popup-allowed control, hybrid and redirect under KeyWay's headers. Run: `NODE_PATH=$(npm root -g) NODE_ENV=production node --import tsx research/joyid-redirect/proofs/coop-browser.ts`.
- `proofs/joyid-bundle-excerpts.sh` → `evidence/joyid-app-excerpts.txt`: JoyID app bundle excerpts, hashes and headers.
