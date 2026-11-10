-- Alpha Bros enterprise layer — Postgres migration 0001 (squashed).
--
-- One file for a Postgres database: this package's own 3 tables (mirrors
-- `src/schema/pg/index.ts`) and the `studio_ref` column better-auth's "user"
-- and organization tables carry to link back to a studio product's own
-- records. It is the SQLite 0001 + 0002 end state. Every statement is
-- idempotent on its own (`IF NOT EXISTS` on tables, indexes and columns), so
-- a product's drizzle journal, `psql -f` or `applyMigrationPg` can all run it
-- more than once.
--
-- Not carried over from the SQLite chain: the legacy `scim_group` table and
-- the `0003_require2fa` onset bump. A Postgres database never held a 1.0.x
-- install, so there is no legacy data to preserve or to re-time.
--
-- `audit_event.metadata` is `json`, NOT `jsonb`: the audit hash chain covers
-- the serialised row, so the bytes read back must equal the bytes written.
-- `jsonb` re-orders object keys and would break chain verification.
--
-- The two ALTER TABLE statements need better-auth's "user" and organization
-- tables to exist; run this after the product's own migrations (applyMigrationPg
-- skips them with a warning when a table is missing, and `verifyDatabase`
-- then reports the column).

CREATE TABLE IF NOT EXISTS org_policy (
  id text PRIMARY KEY,
  org_id text NOT NULL UNIQUE,
  require_2fa boolean NOT NULL DEFAULT false,
  sso_enforced boolean NOT NULL DEFAULT false,
  break_glass_user_id text,
  session_max_age_s integer,
  allowed_methods text[] NOT NULL DEFAULT ARRAY['sso','magic_link','google','github','linkedin','microsoft','password','passkey']::text[],
  group_role_map jsonb NOT NULL DEFAULT '{}'::jsonb,
  updated_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_event (
  id text PRIMARY KEY,
  org_id text NOT NULL,
  seq integer NOT NULL,
  actor_type text NOT NULL,
  actor_id text,
  action text NOT NULL,
  target_type text NOT NULL,
  target_id text,
  ip text,
  user_agent text,
  metadata json NOT NULL DEFAULT '{}'::json,
  created_at timestamptz NOT NULL,
  prev_hash text NOT NULL,
  hash text NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS audit_event_org_seq ON audit_event (org_id, seq);

CREATE INDEX IF NOT EXISTS audit_event_org_created ON audit_event (org_id, created_at);

CREATE TABLE IF NOT EXISTS enterprise_scim_member (
  id text PRIMARY KEY NOT NULL,
  org_id text NOT NULL,
  user_id text NOT NULL,
  member_id text NOT NULL UNIQUE,
  last_role text NOT NULL
);

ALTER TABLE "user" ADD COLUMN IF NOT EXISTS studio_ref text;

ALTER TABLE organization ADD COLUMN IF NOT EXISTS studio_ref text;
