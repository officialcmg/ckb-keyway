# @ckb-keyway/react 0.2.7 (draft)

## JoyID backups work on cross-origin isolated pages

Apps that run the browser Fiber node send `Cross-Origin-Opener-Policy: same-origin`. That cuts the link to JoyID's
own window, so a JoyID backup never got its signature back on those pages. `createJoyIdBackup` now reaches JoyID in
a way the page allows:

- On a page that isn't cross-origin isolated: JoyID's own window, as before.
- On a cross-origin isolated page: a window on your own site that goes to JoyID and hands the result back. Your page,
  and a browser node in it, keeps running.
- When the browser blocks that window, or the app runs as an installed app: a full-page redirect. A browser node is
  stopped cleanly first, and KeyWay won't leave while a payment or channel change is running. The provider finishes
  the backup when the page returns, with the usual dialog and emailed code.

Choose one yourself with `createJoyIdBackup(signer?, { transport: "popup" | "window" | "redirect" })`.

## Changes

- `useCkbWallet().recovery.createJoyIdBackup(signer?, options?)`: the CCC JoyID signer is now optional. Call it
  straight from the user's click. Options: `transport` (default `"auto"`), `onStage`, `signal`, `afterRedirect`,
  `otherBackups`.
- New `recovery.pendingJoyIdBackup` and `recovery.dismissPendingJoyIdBackup()`: how a backup finished after a
  full-page redirect.
- New `KeyWayProvider` prop `joyIdReturnPath`: the page JoyID returns to (defaults to the current page). It must
  render `KeyWayProvider`.
- A first-time JoyID connects, then signs (two passkey prompts, as with CCC's signer). The connection is remembered
  where CCC's JoyID signer keeps it.
- New types: `JoyIdTransport`, `JoyIdBackupOptions`, `JoyIdBackupStage`, `PendingJoyIdBackup`.
- New dependency: `@joyid/common` 0.2.2, the version CCC's JoyID packages already install.

## Security

- Each JoyID request carries a fresh 128-bit `state`, recorded once in the tab's `sessionStorage` and deleted before
  use. An answer is accepted only in the tab that asked, once, unexpired, for the signed-in user, for the step asked,
  over the exact challenge text, from a JoyID main key (ES256), and only if KeyWay's own signature check passes.
- JoyID writes its answer into the return URL's query. The SDK removes it from the address bar as soon as it loads,
  and again after the router hydrates (Next.js puts the served URL back), before the page fetches anything. Don't log
  query strings on the return page.
- A window KeyWay opens for JoyID doesn't restore the session, start Fiber or take the device lock.

## Compatibility

- Apps that pass a CCC JoyID signer on a page that isn't cross-origin isolated behave exactly as before.
- No server change and no migration.

## Docs

Quickstart (browser node: cross-origin wallet windows), Troubleshooting ("A wallet window closes at once or never
returns"), Account recovery ("JoyID on a cross-origin isolated page"), React SDK (`joyIdReturnPath`).
