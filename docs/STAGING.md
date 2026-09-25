# Staging Runbook

Staging exists to prove a change before production and to host the two-account Fiber test without touching production wallets. This file is repository-only; it is not part of the published Mintlify site.

## Current state

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
LIT_SIGN_ACTION_CID
LIT_ENCRYPT_ACTION_CID
LIT_DECRYPT_ACTION_CID
```

Without them, `keyway-api-staging` serves `/healthz` and `/readyz` but cannot send OTP codes or authorize Lit operations, so the two-account Fiber test cannot run there yet.

The npm SDK always targets the production API. For staging only, run `npm run build:staging`. This compiles a separate local SDK bundle with the staging API URL and aliases the demo's `@ckb-keyway/react` import to that bundle. The production `npm run build:sdk` explicitly compiles the production URL; no provider API URL prop is exposed. The separate `ckb-keyway-staging` Vercel project uses `vercel.staging.json` to run that build. The staging API already allows its origin.

The staging Vercel project has no Git connection. Deploy from a clean temporary copy so the checkout's existing `.vercel` link keeps pointing at production:

```sh
rsync -a --exclude='.git' --exclude='.vercel' --exclude='.next' --exclude='node_modules' --exclude='dist' --exclude='.env*' --exclude='.railway' ./ /tmp/ckb-keyway-staging/
vercel link --yes --project ckb-keyway-staging --cwd /tmp/ckb-keyway-staging
vercel deploy --prod --yes -A /tmp/ckb-keyway-staging/vercel.staging.json --cwd /tmp/ckb-keyway-staging
```

Verify that `https://ckb-keyway-staging.vercel.app/app` loads and that an `OPTIONS` request from this origin to `https://keyway-api-staging-staging.up.railway.app/api/v1/keyway/auth/send-code` receives `Access-Control-Allow-Origin: https://ckb-keyway-staging.vercel.app`.

## Remaining setup

1. Create a second Stytch Consumer project in the test environment, dedicated to staging.
2. Set `STYTCH_PROJECT_ID` and `STYTCH_SECRET` on `keyway-api-staging` from that project, and keep `STYTCH_ENVIRONMENT=test`.
3. Create a second Lit Chipotle account, or a second API key on a separate Lit billing boundary, for staging.
4. Set `LIT_USAGE_API_KEY` and `LIT_PROVISIONING_API_KEY` on `keyway-api-staging`. The pinned Action CIDs are public IPFS content and may be copied from production, or republished under the staging account.
5. Keep `KEYWAY_ALLOWED_ORIGINS` limited to the staging frontend origin, and confirm it does not list `https://ckb-keyway.vercel.app`.
6. Generate a distinct `KEYWAY_MANAGED_FIBER_HOST_TOKEN` for `keyway-managed-host`, and a distinct `KEYWAY_MANAGED_FIBER_RPC_TOKEN` for `keyway-managed-fnn-staging`.
7. Confirm every staging secret differs from production. Compare fingerprints with:

```sh
diff <(railway variables -s keyway-api -e production --json | jq -S 'with_entries(select(.key|startswith("STYTCH") or startswith("LIT")))') \
     <(railway variables -s keyway-api-staging -e staging --json | jq -S 'with_entries(select(.key|startswith("STYTCH") or startswith("LIT")))')
```

The command must report a difference. Identical values mean staging can mutate production identities and must not be used for testing.

## Two-account Fiber test

After the credentials exist, run the same flow used for the original testnet evidence in both node modes:

1. Open the staging app in two isolated browser profiles and authenticate two different email accounts.
2. Activate a channel in each profile and wait for `CHANNEL_READY`.
3. Create a small invoice in profile B and pay it from profile A, confirming the preflight, the routed payment, and the settled payment hash.
4. Log out in profile A, log in with the same account in a third profile, and confirm the encrypted handoff restores the same channel.
5. Repeat the payment step with `/app?mode=managed` on both profiles and confirm the same result and the same public lifecycle surface. `/app` exercises browser mode. The query switch is enabled only in the staging build.

Record the two payment hashes and the channel IDs under `docs/TESTNET_EVIDENCE.md` when staging is no longer ephemeral.
