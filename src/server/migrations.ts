import type { DatabaseSql } from "./database";

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
];
