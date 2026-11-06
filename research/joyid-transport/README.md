# JoyID transports: implementation notes

Implements section 8 ("Recommended design") of `research/joyid-redirect/README.md` (branch
`research/joyid-redirect`). This note records what was built, how it was tested, where it departs from or corrects
the research, and the independent review.

## What was built

- `src/sdk/browser/joyid-redirect.ts` (new). Uses `@joyid/common` 0.2.2 directly (now an explicit dependency of the
  SDK, the version CCC's JoyID packages already install). Requests carry exactly CCC's `CkbSigner` fields
  (`redirectURL`, `joyidAppURL` for the client's network, `name`, `logo`, and for signing `challenge`,
  `isData: false`, `address`) plus `state`. Transports:
  - `"popup"`: JoyID's own window (`authWithPopup` / `signMessageWithPopup`), or the app's CCC signer as before.
  - `"window"`: `window.open("<returnPath>?keyway-joyid=<id>")` synchronously on the click. The helper page (the
    app's page with `KeyWayProvider`, which renders only a status card there) says `ready` on
    `BroadcastChannel("keyway:joyid")`, takes each request (`go`), records it in its own `sessionStorage`, runs
    JoyID's redirect mode, and posts JoyID's answer back. The opening tab checks it against the request it holds in
    memory, then sends the next step or `close`.
  - `"redirect"`: records the request in `sessionStorage` and `location.assign`s to JoyID. The provider resumes.
  - `"auto"`: `crossOriginIsolated` false → popup; true → window, or redirect in a standalone app or when
    `window.open` returns `null` or a closed window.
- First use: Auth without a challenge, then sign. Auth is skipped when CCC's JoyID connection store
  (`localStorage["ccc-joy-id-signer"]`) has a main-key connection for the JoyID app; KeyWay writes the connection
  there after Auth, in CCC's format. The nonce is requested right before the sign step.
- Checks (`checkJoyIdResponse`): `state` `{ v: 1, id: 32 hex }` equals the recorded id; signed-in user equals the
  record's; JoyID's `error` → `JoyIdCancelledError` when it is a rejection; unexpired; `type` matches the step;
  Auth: main key, ES256, address is a JoyID main-key lock on the network whose args hash the returned key; Sign:
  `data.challenge` equals the exact challenge text, main key, `alg === -7`, and `verifyBackupOwnership` passes.
  Records are one-time (`takeJoyIdRecord` deletes before parsing) and validated on read; the return path must be a
  same-site path (`/x`, never `//host` or `/\host`).
- URL hygiene: the SDK strips `_data_` and `joyid-redirect` with `history.replaceState` when its module loads,
  then again in the provider's layout effect and once more after the router mounts (see "Corrections" below).
  Only answers with KeyWay's state shape, or in a KeyWay helper window, are touched; other JoyID integrations on the
  same page are left alone.
- React: `useCkbWallet().recovery.createJoyIdBackup(signer?, options?)` (`transport`, `onStage`, `signal`,
  `afterRedirect`, `otherBackups`), `pendingJoyIdBackup`, `dismissPendingJoyIdBackup()`; provider prop
  `joyIdReturnPath`. The provider takes the record on mount, holds Fiber autostart and bootstrap until the answer
  is checked, continues Auth → sign with a fresh state, then runs the normal `enable` / `addBackup` flow (preview
  dialog + emailed code). In a helper window it skips session restore, bootstrap and Fiber entirely, so it never
  takes the device lock. `useFiber()`'s `openChannel`, `closeChannel` and `payInvoice` are counted; a full-page
  redirect with a browser node refuses while any runs or a Fiber approval dialog is open, waits for a start in
  progress, then calls `stop()` (`stopBrowserNodeForRedirect`).
- Rescue page: unchanged. It keeps JoyID's own window (it doesn't send COOP same-origin) and gets no full-page
  redirect, as the research recommends.
- Demo `/app`: "Turn on with JoyID" and "Add JoyID" next to the EVM wallet buttons, with "Connecting JoyID…",
  "Waiting for JoyID…", "Opening JoyID…", a Cancel link, "Cancelled. Nothing changed.", failures, and the status
  after a redirect. It detects the new SDK by `recovery.dismissPendingJoyIdBackup`, so it compiles and runs against
  the pinned 0.2.6 (JoyID button hidden) and the new SDK (`KEYWAY_LOCAL_SDK=1`; typechecked both ways).
- Docs: quickstart (browser node callout), troubleshooting ("A wallet window closes at once or never returns"),
  account recovery ("JoyID on a cross-origin isolated page"), React SDK (`joyIdReturnPath`). Release notes draft:
  `research/release-notes-0.2.7.md`.

## Tests

- `tests/joyid-redirect.test.ts` (node:test, 11 tests): P1 as a test (a redirect-delivered answer equals the
  window-delivered one field by field, passes `verifyWebAuthn` and `verifyBackupOwnership`, and becomes the same
  proof CCC's signer gives); request fields equal CCC's; `state` round trip through `encodeSearch`/`decodeSearch`
  (also Auth, top level); one-time records; resume rejects unknown/consumed state, a mismatched id, expiry, a
  different user, no user, step/type mismatch, challenge mismatch (nonce, trailing space), another JoyID's
  signature, sub key, main and sub session keys, RS256 and other algs, a bad signature; rejection → cancel; Auth
  checks; redirect Auth → sign continuation (fresh state, nonce asked then, connection stored); URL capture at load
  (and foreign JoyID answers left alone); transport choice; return-path validation; stopping a browser node before
  leaving and refusing mid-payment.
- `e2e.ts` → `e2e.output.txt` (Playwright, Chromium 153): `next build` with the local SDK, `next start` with the
  real `next.config.ts` headers and `proxy.ts` CSP; a fake KeyWay API (routes `keyway-api-production…`, issues
  nonces and runs `verifyBackupOwnership` on every proof) and a fake JoyID origin (routes `testnet.joyid.dev`;
  referrer guard, real P-256 assertions, `_data_` in the query, `location.replace`). 22 checks:
  1. window transport, first use: Auth then sign in one helper window; JoyID saw the app's origin as referrer; the
     server verified the proof; preview + emailed code turned recovery on; the main tab never reloaded and stayed
     cross-origin isolated; the helper stripped `_data_` and closed itself;
  2. a known JoyID connection skips Auth; a rejection in JoyID shows "Cancelled. Nothing changed.", nothing is
     previewed, the helper closes;
  3. `window.open` blocked → full-page redirect (Auth and sign round trips) on `/app?mode=browser`, resume, preview
     + code; no `fetch` ran while the answer was in the URL; the address bar is clean; no cross-origin request
     carried the answer in `Referer`; cross-origin isolated again; a Web Lock held like the Fiber device lock is
     free again after return;
  4. a crafted `_data_` URL with no matching request: stripped before any fetch, refused with a plain message,
     nothing reached the recovery API.
- `screenshots/`: the recovery card off, waiting for JoyID, cancelled, back from JoyID, and on; desktop and 360px;
  light and dark color schemes (the demo site is light-only, `color-scheme: light`, so both look the same).
- Not covered by a real run: a real JoyID passkey (no passkey here), a real browser Fiber node being stopped before
  a redirect (needs Lit and testnet peers; the logic is unit-tested, and e2e shows isolation and the lock come
  back), Firefox, Safari, mobile, installed apps. These are on the founder's hand-test list.

## Corrections to the research

- **Next.js puts the answer back in the address bar.** The research (§4) says to `replaceState` synchronously on
  load. That alone isn't enough under Next.js's app router: its `HistoryUpdater` (an insertion effect) replaces the
  URL with the canonical URL from the server-rendered payload during hydration, `_data_` included. The first e2e run
  caught it: the provider's first `fetch` ran with `…&joyid-redirect=true&_data_=…` back in `location.href`. Next
  also skips history calls carrying its own `__NA` marker and only syncs its router from history calls after its
  own passive effect has patched `history.replaceState`. The fix strips three times: at SDK load (before the app's
  scripts can read it), in the provider's layout effect (after the router's insertion effect, before any passive
  effect fetches), and from a timer after the router has mounted, without the `__NA` marker, so the router's own
  state forgets the old URL. The e2e navigation logs in `e2e.output.txt` show the sequence.
- **Same-origin Referer before scripts run.** The HTML's own subresources (fonts, CSS, script chunks) are requested
  before any script can strip the URL, so they carry the full return URL in `Referer` to the app's own origin
  (`requestsWithTheAnswerInReferer` in `e2e.output.txt`). The app's server already received that URL as the
  document request, so this adds no new party; cross-origin requests get only the origin. It is another reason not
  to log query strings (or Referer) on the return path.
- **The helper's window handle can't tell "closed by the user" once it reaches JoyID.** The research's hybrid proof
  only checked the handle after the result. Under COOP same-origin the handle reports `closed` as soon as the helper
  navigates to JoyID (another browsing context group), so the opening tab watches `closed` only until the helper
  leaves for JoyID, and after that waits until the request expires (10 minutes for connect, the challenge's expiry
  for signing), with a Cancel link and `signal` for the user and app.

## Independent review (Fable)

An independent reviewer (Fable model) read `git diff origin/main...HEAD`, the research README (§1-5, §8) and its
proofs, without these notes. It found no high-severity issue and confirmed that a crafted `_data_` URL or
BroadcastChannel message can't get a foreign JoyID accepted. Findings and outcomes:

| # | Severity | Finding | Outcome |
| --- | --- | --- | --- |
| 1 | Medium | The opening tab can't tell the JoyID window was closed or reloaded (Back from JoyID's page) and waits until the request expires. | Fixed. The window posts `gone` on `pagehide` unless it is leaving for JoyID or was told to close; a second `ready` while an answer is due means it reloaded. Either ends the wait as a cancel. Closing it *while JoyID's page shows* still can't be seen (no KeyWay code runs there); the Cancel link and `signal` cover that. Unit-tested. |
| 2 | Medium | Scripts on the return page that run before the SDK can read `_data_`; the design asks for a minimal return path. | Fixed in docs: a warning callout in Account recovery recommending a `joyIdReturnPath` without third-party scripts. The demo `/app` has none, so it keeps the default. |
| 3 | Medium | The window protocol has no test run by `npm test`. | Fixed: node:test with a fake BroadcastChannel covers ignoring another window's `go`/`close`, a full-page record, a non-JoyID app URL, recording once, the JoyID URL, `gone` on close and not when leaving for JoyID; plus return-URL tests. The e2e stays a research harness (it needs the environment's Playwright). |
| 4 | Medium | Explicit `transport: "popup"` on an isolated page reports "cancelled". | Fixed: refused up front with a plain message; documented. |
| 5 | Low | The app's page mounts once in the JoyID window before the helper screen replaces it. | Documented. `connect()` now refuses in the JoyID window as a second guard (session restore and bootstrap were already skipped, so it had no token). |
| 6 | Low | Back to a bfcache-restored page after a full-page redirect leaves the promise pending forever. | Fixed: `pageshow` with `persisted` rejects it as a cancel. A browser node stopped for the redirect stays stopped until started again (or restarts with `autoStartFiber` on a normal load); documented. |
| 7 | Low | `JoyIdCancelledError` isn't exported. | Not changed: the package's runtime exports are pinned by `tests/package-surface.test.ts`, and adding one is a public-API decision for the founder. The error's `name` is `JoyIdCancelledError`, now documented. |
| 8 | Low | The JoyID window navigates to any http(s) `joyIdAppURL` in a `go` message. | Fixed: records must name `https://app.joy.id` or `https://testnet.joyid.dev`; `appId` and `otherProofs` shapes are checked too. |
| 9 | Low | A rejection after the session expired shows "Sign in again"; a crafted link fires `onError`. | Fixed: a rejection is a cancel before any other check; an answer with no record behind it no longer calls `onError`. |
| 10 | Low | `useLayoutEffect` warns in React 18 SSR. | Fixed: layout effect in the browser, plain effect on the server. |
| 11 | Low | The router-synced strip on `setTimeout(0)` may run before Next.js hooks history. | Fixed: it runs again after 300 ms. |
| 12 | Low | Default return path drops the hash; direct `node.sendPayment` calls aren't counted; a custom JoyID app URI on a CCC signer is ignored; no docs sentence on manual node restart. | Hash kept; docs now say only `useFiber()` payments and channel changes are counted, and cover the restart. The custom app URI is left out on purpose: JoyID requests go only to JoyID's two apps (see 8). |

Backward compatibility and UX copy: the reviewer found no issue. After the fixes every check was re-run: both
typechecks, `npm test` (242 tests: 225 pass, 0 fail, 17 skipped by their own environment gates; 13 JoyID tests),
the Postgres suite (43/43), `next build` against the pinned 0.2.6 and the local SDK, the demo typecheck against the
new SDK, the docs build, the release workflow steps, and the e2e (22/22).
