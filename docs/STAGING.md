# Staging Runbook

Historical Stytch notes below describe the previous release. The local Better Auth/Resend replacement and cutover gates are in `AUTH_REPLACEMENT.md`; do not create another Stytch project for the replacement.

Staging exists to prove a change before production and to host the two-account Fiber test without touching production wallets. This file is repository-only; it is not part of the published Mintlify site.

## Current state

Product decision (2026-09-28): KeyWay remains testnet-only. Keep this staging infrastructure, but separate Stytch/Lit credentials and full staging isolation are deferred to mainnet preparation and are not release gates. Verify with disposable accounts only; never overwrite existing users' metadata, keys, or channel databases.

Update (2026-09-29): funded payment and recovery verification has passed in both modes (see `TESTNET_EVIDENCE.md`). SDK 0.0.7 and its reference app select managed mode by default; browser mode remains at `/app?mode=browser`. Switching modes does not migrate existing channels. The older staging checklist below is retained for future isolated verification, not as a testnet release requirement.

The Railway project `ckb-keyway` has two environments:

| Environment | Services |
| --- | --- |
| production | `keyway-api`, `keyway-managed-host-production`, `keyway-managed-fnn`, `Postgres` |
| staging | `keyway-api-staging`, `keyway-managed-host`, `keyway-managed-fnn-staging`, `Postgres-oF2n` |

The separate frontend is deployed at `https://ckb-keyway-staging.vercel.app`. Staging has its own `DATABASE_URL`, `KEYWAY_*` credentials, managed-host token, and managed Fiber state. Its API allows the staging frontend origin and `http://localhost:3000`. It cannot access production identities because it holds no usable identity provider credentials.

Staging is currently missing:

```text
STYTCH_PROJECT_ID
STYTCH_SECRET
LIT_USAGE_API_KEY
LIT_PROVISIONING_API_KEY
```

The three public, pinned Lit Action CIDs are already configured on staging. Without the four private credentials above, `keyway-api-staging` serves `/healthz` and `/readyz` but cannot send OTP codes or authorize Lit operations, so the two-account Fiber test cannot run there yet.

Before deploying managed-host backup encryption, set `KEYWAY_MANAGED_BACKUP_KEY` on the target managed host to a random 32-byte hex key (for example, `openssl rand -hex 32`). Preserve the key outside Railway as part of disaster recovery: losing it makes that environment's encrypted snapshots unrestorable. Existing plaintext snapshot generations remain restorable during migration, but must be removed after encrypted generations are verified. This runtime encryption key is required for the host being deployed; configuring another environment is not a release gate.

Historical rollout (2026-09-27): staging has its own backup key. Deployment `6cdf544e-fd32-476f-b77f-94bbcef61f2e` includes whole-archive authentication before extraction and passed authenticated readiness. A disposable, unfunded native node successfully restored snapshot `snap-1790530413595`, preserving public key `020c2b2988b2571f98cdfde6549123c7efe7ff5c898cc568ceb72de811a1cdc18d`. The restored directory digest was `0075354d2130ae44dd571cc4efc83f0c24de3ec954cc13a2534b0194b821d8f8`. This verifies native-node identity recovery, not funded-channel recovery or payments.

Production testnet rollout (2026-09-28): the owner-approved backup key is configured, with a private Git-ignored 0600 recovery copy. Host deployment `9a5b7e1d-4e72-4663-89cf-8fd6182552b0` succeeded with encryption and interrupted-restore safeguards. The disposable test node retained its public key after deployment. Funded-channel restore and subsequent payment still require live verification; managed mode remains opt-in.

Deployment `bd74819f-c6d3-42fc-9cc1-02226c39fa85` additionally serializes RPC, snapshot, restore, and automatic restart operations per user, and waits for process exit before touching its database. Concurrent backup and node-info requests passed against the same disposable node, producing `snap-1790530717510` with its identity unchanged. Local checks: 64 tests passed, 11 database-gated tests skipped, and typecheck passed. Staging Stytch/Lit credentials were rechecked and remain absent.

The full suite was subsequently run against a fresh disposable localhost Postgres cluster: **75 passed, 0 failed, 0 skipped**. This includes application isolation, OTP limits, advisory locks, device leases, idempotency, backup state transitions and retention, and transaction-bound signing confirmations. The temporary server was stopped afterward. These tests use synthetic data and do not prove real Stytch/Lit authentication or funded Fiber payment recovery.

The npm SDK always targets the production API. For staging only, run `npm run build:staging`. This compiles a separate local SDK bundle with the staging API URL and aliases the demo's `@ckb-keyway/react` import to that bundle. The production `npm run build:sdk` explicitly compiles the production URL; no provider API URL prop is exposed. The separate `ckb-keyway-staging` Vercel project uses `vercel.staging.json` to run that build. The staging API already allows its origin.

The staging Vercel project has no Git connection. Deploy from a clean temporary copy so the checkout's existing `.vercel` link keeps pointing at production:

```sh
rsync -a --exclude='.git' --exclude='.vercel' --exclude='.next' --exclude='node_modules' --exclude='dist' --exclude='.env*' --exclude='.railway' ./ /tmp/ckb-keyway-staging/
vercel link --yes --project ckb-keyway-staging --cwd /tmp/ckb-keyway-staging
vercel deploy --prod --yes -A /tmp/ckb-keyway-staging/vercel.staging.json --cwd /tmp/ckb-keyway-staging
```

Verify that `https://ckb-keyway-staging.vercel.app/app` loads and that an `OPTIONS` request from this origin to `https://keyway-api-staging-staging.up.railway.app/api/v1/keyway/auth/send-code` receives `Access-Control-Allow-Origin: https://ckb-keyway-staging.vercel.app`.

## Remaining setup

The following setup is deferred until mainnet preparation. Do not spend additional time configuring it for the current testnet release.

1. Create a second Stytch Consumer project in the test environment, dedicated to staging.
2. Set `STYTCH_PROJECT_ID` and `STYTCH_SECRET` on `keyway-api-staging` from that project, and keep `STYTCH_ENVIRONMENT=test`.
3. Create a second Lit Chipotle account, or a second API key on a separate Lit billing boundary, for staging.
4. Set `LIT_USAGE_API_KEY` and `LIT_PROVISIONING_API_KEY` on `keyway-api-staging`. The pinned Action CIDs are public IPFS content and already configured on staging.
5. Keep `KEYWAY_ALLOWED_ORIGINS` limited to the staging frontend origin, and confirm it does not list `https://ckb-keyway.vercel.app`.
6. Generate a distinct `KEYWAY_MANAGED_FIBER_HOST_TOKEN` for `keyway-managed-host`, and a distinct `KEYWAY_MANAGED_FIBER_RPC_TOKEN` for `keyway-managed-fnn-staging`.
7. Confirm every staging secret differs from production. Compare fingerprints with:

```sh
diff <(railway variables -s keyway-api -e production --json | jq -S 'with_entries(select(.key|startswith("STYTCH") or startswith("LIT")))') \
     <(railway variables -s keyway-api-staging -e staging --json | jq -S 'with_entries(select(.key|startswith("STYTCH") or startswith("LIT")))')
```

The command must report a difference. Identical values mean staging can mutate production identities and must not be used for testing.

## Two-account Fiber test

For the current release, use `https://ckb-keyway.vercel.app` and fresh disposable accounts. The staging-specific steps below are retained for later isolated verification; missing staging credentials must not block testnet verification.

Run the same flow used for the original testnet evidence in both node modes:

1. Open the current testnet app in two isolated browser profiles and authenticate two newly created disposable email accounts.
2. Activate a channel in each profile and wait for `CHANNEL_READY`.
3. Create a small invoice in profile B and pay it from profile A, confirming the preflight, the routed payment, and the settled payment hash.
4. Log out in profile A, log in with the same account in a third profile, and confirm the encrypted handoff restores the same channel.
5. Repeat the payment step with `/app?mode=managed` on both profiles and confirm the same result and the same public lifecycle surface. `/app` exercises browser mode. Use different fresh accounts for each mode to avoid converting an existing wallet or channel database.

Record the payment hashes, channel IDs, and recovery results under `docs/TESTNET_EVIDENCE.md`. Do not record OTPs, sessions, keys, or mailbox credentials.
