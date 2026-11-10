-- Alpha Bros enterprise layer — migration 0004 (OPTIONAL: staff-managed entitlements).
--
-- Only for a deployment that sets `entitlements: { store: "table" }`. It is not
-- part of the default migration set: `applyMigration()` runs it only with
-- `{ entitlements: true }`, `ab-enterprise migrate` writes it only with
-- `--entitlements` or `--from 0004`, and `verifyDatabase()` expects the table
-- only with `{ entitlements: true }` (`ab-enterprise verify --entitlements`) —
-- so a deployment that does not opt in neither gets the table nor fails verify.
--
-- `org_entitlement` holds, per organization, the features it is entitled to
-- (a JSON array of `Feature` names). Only platform staff write it
-- (`setEntitlements()` / `POST /enterprise/entitlements/set`); it replaces
-- `organization.metadata` as the entitlement source because an organization's
-- owner can write that. A missing row means no features.
--
-- Safe to re-run (`CREATE TABLE IF NOT EXISTS`); it touches no existing table.

CREATE TABLE IF NOT EXISTS org_entitlement (
  id TEXT PRIMARY KEY NOT NULL,
  org_id TEXT NOT NULL UNIQUE,
  features TEXT NOT NULL DEFAULT '[]',
  updated_at INTEGER NOT NULL,
  updated_by TEXT
);
