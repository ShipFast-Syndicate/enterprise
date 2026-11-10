-- Alpha Bros enterprise layer — Postgres migration 0002 (OPTIONAL: staff-managed entitlements).
--
-- Only for a deployment that sets `entitlements: { store: "table" }`; the
-- Postgres counterpart of SQLite `0004_org_entitlement.sql`. Not part of the
-- default set: `applyMigrationPg()` runs it only with `{ entitlements: true }`
-- and `verifyDatabase()` expects the table only with `{ entitlements: true }`.
--
-- `org_entitlement` holds, per organization, the features it is entitled to.
-- Only platform staff write it (`setEntitlements()` / `POST
-- /enterprise/entitlements/set`); it replaces `organization.metadata` as the
-- entitlement source because an organization's owner can write that. A missing
-- row means no features.
--
-- Idempotent like 0001 (`IF NOT EXISTS`); same concurrency note: run it once
-- per deploy, not from two runners at the same time.

CREATE TABLE IF NOT EXISTS org_entitlement (
  id text PRIMARY KEY,
  org_id text NOT NULL UNIQUE,
  features text[] NOT NULL DEFAULT ARRAY[]::text[],
  updated_at timestamptz NOT NULL,
  updated_by text
);
