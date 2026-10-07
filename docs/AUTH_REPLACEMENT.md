# Authentication replacement: operator release checklist

## Current status (2026-10-07)

Better Auth 1.7.7 and Resend 6.32.1 are deployed on the production API. SDK 0.2.0 is staged but not published; the production demo currently builds the local SDK using an explicit deployment build override. Railway authentication configuration and production additive migrations are complete. Real Resend delivery from `login@auth.ckbkeyway.dev`, public OTP verification, database-backed session validation and logout revocation passed against the deployed API with a disposable inbox. Funded wallet acceptance remains in progress. No legacy account, channel database or backup has been deleted. Eight obsolete managed nodes remain retired, and the empty dedicated-node deployment remains stopped.

On October 8 the owner explicitly confirmed that no browser channels remain open. The complete reset report validated 41 legacy Stytch test accounts and three preserved disabled application registrations. The irreversible deletion command was blocked by the execution safety reviewer, so the reset has not executed. This is an execution-policy block, not a claim that browser channels remain open. Do not claim the legacy reset is complete or silently bypass the block.

Real PostgreSQL HTTP endpoint tests verify independent application OTPs, resend isolation, atomic one-use consumption across two auth instances, app-bound sessions, dashboard access, renewal, revocation, expiry, attempts, delivery failures, and durable concurrent limits. The full suite passed 89 tests without skips; seven headless React scenarios passed. Light/dark email and OTP modals match the Git baseline at 360px and 1280px (less than 0.1% pixel variance). SDK, API and demo builds and typecheck passed.

The real delivery test exposed a consumed-request-body bug after OTP verification. Session validation now constructs a fresh bodyless request. A regression exercises the public verification handler with a JSON POST body, rather than only calling the internal auth function.

## Release order

1. Complete Resend setup in `email-branding.mdx`. Keep credentials server-only.
2. Inspect and cooperatively close legacy channels. Do not delete inaccessible or unsettled channel databases. Complete the reset only after final on-chain settlement.
3. Configure BETTER_AUTH_SECRET (32+ random characters), BETTER_AUTH_URL, RESEND_API_KEY, KEYWAY_AUTH_EMAIL_FROM and KEYWAY_DASHBOARD_ORIGINS. Set KEYWAY_TRUST_PROXY=railway only after verifying edge forwarding behavior.
4. Run `npm run migrate` in an explicit release step. Versions 8 and 9 are additive. Production startup checks the migration version and never changes the schema.
5. Sign in to the replacement dashboard. Use `scripts/assign-application-owner.ts <app-id> <dashboard-KeyWay-user-id>` for explicit ownership assignment, never automatic email matching. Set NEXT_PUBLIC_KEYWAY_APP_ID for the demo.
6. Deploy the backend, publish a new SDK version and update the demo package pin together. Old tokens/challenge IDs are unsupported. KEYWAY_LOCAL_SDK=1 verifies the local SDK without publishing.
7. Complete disposable-account real testnet funding, payments and recovery before declaring release complete. Historical wallet evidence does not prove the replacement.
8. Remove obsolete Stytch variables only after supported-API user deletion. Preserve Lit resources, application registrations, origins, deployment configuration and unrelated data.

Do not publish an npm tag before backend/email readiness. Do not roll back by resurrecting revoked sessions or deleted accounts.

## Complete reset scope

Read-only production inventory: 40 Stytch test users; 29 wallet mappings; 10 leases; 7 backup rows; 110 idempotency records; no signing or managed-confirmation rows. Preserve three application registrations. Some wallets report previously opened channels; flags cannot establish settlement.

`scripts/inventory-legacy.ts` reads the configured Stytch test project and legacy rows without migrations or node startup. Repeat for staging and any legacy service. Save inventories privately without credentials.

Reset all obsolete KeyWay test users, including auth-only users, their provider sessions, wallet mappings, leases, nonces, node/channel databases and backups. Do not delete unrelated users in a shared provider project, entire volumes, applications, Lit PKPs or unrelated deployment configuration.

Record each node's channels, pending payments, close transactions and final settlement. Force-close needs separate approval. Preserve state throughout settlement, retire the node against automatic restart, then delete only its exact directory/backups. `scripts/reset-legacy.ts --report <private-report>` validates complete scope without deletion; `--execute` also requires an explicit legacy-auth freeze and replacement migrations. It refuses a selected subset, unknown browser state or missing settlement evidence. The Stytch supported API is used, not the removed SDK dependency. Browser deletion uses settlement-approved rows in `keyway_legacy_cleanup`, scoped to the returning origin and exact wallet prefix. The table is empty until reviewed closure evidence is inserted. Non-returning devices cannot be remotely erased.

## Managed channel closure evidence

All four existing host channels closed cooperatively. Their funding-spend transactions were committed with 97 confirmations at inspection and payouts to the previously recorded CKB wallet locks:

- `0x6f6dc2b3c5347252fac2975910e686f59c03034399cdd88afe836ddcbfd7dcb9`
- `0xe40fed7162bf09b94e56c10a7de5b9712c7c832574f885a7a2a370d687a0439e`
- `0x9d0eb71c4036fa027b24b0c922fbe28eb139ce0a66276e141bcc91ed5d1bd4d8`
- `0xe83fcf95ef17bba7ee1a98f2748dd8ef24600ec5662db92092155c1150b05e8c`

Eight host nodes are retired; `/readyz` confirms zero running processes. The separate dedicated node had no channels and its active deployment was stopped. All databases/backups remain preserved pending completion of the browser-state inventory. The temporary Railway SSH registration was removed after inspection.

## Verification

```sh
KEYWAY_AUTH_TEST_DATABASE_URL=postgres://.../disposable npm run test:auth:postgres
DATABASE_URL=postgres://.../disposable KEYWAY_AUTH_TEST_DATABASE_URL=postgres://.../disposable npm test
npm run typecheck
npm run build:sdk
npm run build:api
KEYWAY_LOCAL_SDK=1 npm run build
```

The database must be disposable. The dedicated auth command refuses to silently skip without its URL. Actual Better Auth HTTP handlers and PostgreSQL run in the integration test; only email delivery is intercepted. Never log captured codes/tokens.

Bearer tokens stored in localStorage are exposed to XSS in a consuming application. Public app IDs and CORS are not substitutes for session authorization.
