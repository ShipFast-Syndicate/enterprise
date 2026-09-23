-- Add the adapter ID missing from the original natural-key policy table.
-- applyMigration guards ADD COLUMN; existing organization policies are preserved.
ALTER TABLE org_policy ADD COLUMN id TEXT;
UPDATE org_policy SET id = org_id WHERE id IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS org_policy_id ON org_policy (id);
CREATE TABLE IF NOT EXISTS enterprise_scim_member (
  id TEXT PRIMARY KEY NOT NULL,
  org_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  member_id TEXT NOT NULL UNIQUE,
  last_role TEXT NOT NULL
);
-- Legacy scim_group and scimProvider are intentionally retained, but no longer
-- read. Regenerate upstream auth tables for 1.7.5 and reprovision SCIM clients.
