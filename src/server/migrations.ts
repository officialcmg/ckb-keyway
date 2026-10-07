import type { DatabaseSql } from "./database";
import { authSchemaSql } from "./auth-schema.ts";

export const migrations: Array<{
  version: number;
  name: string;
  up: (sql: DatabaseSql) => Promise<unknown>;
}> = [
  {
    version: 1,
    name: "wallets-and-leases",
    up: async (sql) => {
      await sql`
        create table if not exists keyway_wallets (
          stytch_user_id text primary key,
          wallet jsonb not null,
          updated_at timestamptz not null default now()
        )
      `;
      await sql`
        create table if not exists keyway_device_leases (
          stytch_user_id text primary key,
          device_id_hash text not null,
          lease_id uuid not null,
          expires_at timestamptz not null
        )
      `;
      await sql`
        create table if not exists keyway_signing_confirmations (
          stytch_user_id text primary key,
          nonce uuid not null,
          transaction_digest text not null,
          expires_at timestamptz not null
        )
      `;
    },
  },
  {
    version: 2,
    name: "encrypted-node-backups",
    up: (sql) => sql`
      create table if not exists keyway_node_backups (
        stytch_user_id text primary key,
        generation bigint not null,
        format_version integer not null,
        database_prefix text not null,
        salt text not null,
        iv text not null,
        ciphertext bytea not null,
        digest text not null,
        source_device_id_hash text not null,
        status text not null check (status in ('available', 'claimed', 'consumed')),
        claimed_device_id_hash text,
        claim_expires_at timestamptz,
        created_at timestamptz not null default now(),
        updated_at timestamptz not null default now()
      )
    `,
  },
  {
    version: 3,
    name: "developer-applications",
    up: async (sql) => {
      await sql`
        create table if not exists keyway_applications (
          app_id text primary key,
          owner_stytch_user_id text not null,
          name text not null,
          disabled boolean not null default false,
          otp_login_template_id text,
          otp_signup_template_id text,
          otp_limit_per_minute integer not null default 30 check (otp_limit_per_minute between 1 and 120),
          created_at timestamptz not null default now(),
          updated_at timestamptz not null default now()
        )
      `;
      await sql`
        create index if not exists keyway_applications_owner_idx
        on keyway_applications (owner_stytch_user_id)
      `;
      await sql`
        create table if not exists keyway_application_origins (
          app_id text not null references keyway_applications(app_id) on delete cascade,
          origin text not null,
          environment text not null check (environment in ('development', 'production')),
          created_at timestamptz not null default now(),
          primary key (app_id, origin)
        )
      `;
      await sql`
        create table if not exists keyway_otp_events (
          id bigint generated always as identity primary key,
          app_id text not null,
          email_hash text not null,
          ip_hash text not null,
          outcome text not null check (outcome in (
            'requested', 'sent', 'send_failed', 'verified', 'verify_failed', 'rate_limited'
          )),
          created_at timestamptz not null default now()
        )
      `;
      await sql`
        create index if not exists keyway_otp_events_limits_idx
        on keyway_otp_events (outcome, created_at, app_id, email_hash, ip_hash)
      `;
      await sql`
        create table if not exists keyway_otp_methods (
          method_id text primary key,
          app_id text not null,
          email_hash text not null,
          ip_hash text not null,
          created_at timestamptz not null default now()
        )
      `;
    },
  },
  {
    version: 4,
    name: "managed-node-confirmations",
    up: (sql) => sql`
      create table if not exists keyway_managed_confirmations (
        stytch_user_id text not null,
        purpose text not null check (purpose in ('payment', 'channel_close')),
        nonce uuid not null,
        operation_digest text not null,
        expires_at timestamptz not null,
        primary key (stytch_user_id, purpose)
      )
    `,
  },
  {
    version: 5,
    name: "idempotent-mutations",
    up: async (sql) => {
      await sql`
        create table if not exists keyway_idempotency_keys (
          stytch_user_id text not null,
          operation text not null,
          idempotency_key text not null,
          request_digest text not null,
          status text not null check (status in ('running', 'completed', 'failed')),
          response jsonb,
          error_message text,
          expires_at timestamptz not null,
          created_at timestamptz not null default now(),
          updated_at timestamptz not null default now(),
          primary key (stytch_user_id, operation, idempotency_key)
        )
      `;
      await sql`
        create index if not exists keyway_idempotency_expiry_idx
        on keyway_idempotency_keys (expires_at)
      `;
    },
  },
  {
    version: 6,
    name: "security-events",
    up: async (sql) => {
      await sql`
        create table if not exists keyway_security_events (
          id bigint generated always as identity primary key,
          kind text not null,
          subject_hash text not null,
          created_at timestamptz not null default now()
        )
      `;
      await sql`
        create index if not exists keyway_security_events_window_idx
        on keyway_security_events (kind, created_at)
      `;
    },
  },
  {
    version: 7,
    name: "node-backup-generations",
    up: async (sql) => {
      await sql`alter table keyway_node_backups drop constraint if exists keyway_node_backups_pkey`;
      await sql`alter table keyway_node_backups add primary key (stytch_user_id, generation)`;
      await sql`
        create index if not exists keyway_node_backups_latest_idx
        on keyway_node_backups (stytch_user_id, generation desc)
      `;
    },
  },
  {
    version: 8,
    name: "application-scoped-authentication",
    up: async (sql) => {
      await sql`create table keyway_users (
        id uuid primary key, auth_user_id uuid not null, scope_id text not null,
        created_at timestamptz not null default now(), unique (auth_user_id, scope_id)
      )`;
      await sql`alter table keyway_applications alter column owner_stytch_user_id drop not null`;
      await sql`alter table keyway_applications add column owner_user_id uuid`;
      for (const suffix of ["wallets", "device_leases", "signing_confirmations", "node_backups", "managed_confirmations", "idempotency_keys"]) {
        await sql.unsafe(`create table keyway_v2_${suffix} (like keyway_${suffix} including all)`);
        await sql.unsafe(`alter table keyway_v2_${suffix} rename column stytch_user_id to user_id`);
      }
      await sql`create table keyway_auth_challenges (
        id uuid primary key, scope_id text not null, email text not null,
        expires_at timestamptz not null, created_at timestamptz not null default now(),
        status text not null check (status in ('pending', 'sent', 'failed', 'consumed', 'superseded'))
      )`;
      await sql`create index keyway_auth_challenge_subject on keyway_auth_challenges (scope_id, email, created_at desc)`;
      await sql`create table keyway_auth_rate_limits (key text primary key, count integer not null, starts_at timestamptz not null)`;
    },
  },
  { version: 9, name: "better-auth-1.7.7-schema", up: (sql) => sql.unsafe(authSchemaSql) },
  {
    version: 10, name: "settlement-approved-browser-cleanup",
    up: (sql) => sql`create table keyway_legacy_cleanup (
      origin text not null, database_prefix text not null, epoch text not null,
      settlement_evidence jsonb not null, approved_at timestamptz not null default now(),
      primary key (origin, database_prefix)
    )`,
  },
];
