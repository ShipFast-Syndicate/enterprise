-- Alpha Bros enterprise layer — migration 0001.
--
-- Creates this package's own 3 tables (mirrors `src/schema/index.ts`
-- exactly) and adds the `studio_ref` column better-auth's `user` and
-- `organization` tables need to link back to a studio product's own
-- records. Every statement here is safe to re-run: the `CREATE TABLE`/
-- `CREATE INDEX` statements use `IF NOT EXISTS`, and the two `ALTER TABLE`
-- statements are re-run only by `applyMigration` (`src/schema/migrate.ts`),
-- which guards each one with `PRAGMA table_info` first — SQLite has no
-- `ADD COLUMN IF NOT EXISTS`, so running this file's raw SQL a second time
-- through any other tool (e.g. the product's own drizzle migration runner)
-- will fail on the `ALTER TABLE` lines if they already applied. That's
-- expected of a plain migration file: `applyMigration` is what's idempotent.

CREATE TABLE IF NOT EXISTS org_policy (
  org_id TEXT PRIMARY KEY,
  require_2fa INTEGER NOT NULL DEFAULT 0,
  sso_enforced INTEGER NOT NULL DEFAULT 0,
  break_glass_user_id TEXT,
  session_max_age_s INTEGER,
  allowed_methods TEXT NOT NULL DEFAULT '["sso","magic_link","google","github","linkedin","microsoft","password","passkey"]',
  group_role_map TEXT NOT NULL DEFAULT '{}',
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_event (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  seq INTEGER NOT NULL,
  actor_type TEXT NOT NULL,
  actor_id TEXT,
  action TEXT NOT NULL,
  target_type TEXT NOT NULL,
  target_id TEXT,
  ip TEXT,
  user_agent TEXT,
  metadata TEXT NOT NULL DEFAULT '{}',
  created_at INTEGER NOT NULL,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS audit_event_org_seq ON audit_event (org_id, seq);

CREATE INDEX IF NOT EXISTS audit_event_org_created ON audit_event (org_id, created_at);

CREATE TABLE IF NOT EXISTS scim_group (
  team_id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  external_id TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS scim_group_org ON scim_group (org_id);

CREATE UNIQUE INDEX IF NOT EXISTS scim_group_org_external ON scim_group (org_id, external_id);

ALTER TABLE user ADD COLUMN studio_ref TEXT;

ALTER TABLE organization ADD COLUMN studio_ref TEXT;
