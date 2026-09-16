// Alpha Bros enterprise layer — static snapshot of the tables/columns
// `verifyDatabase` (`./verify.ts`) checks for.
//
// The upstream portion (every key below except `org_policy`, `audit_event`,
// `scim_group`) is a snapshot of `getAuthTables()` with the Task 2 preset
// (`enterprisePreset`) mounted — the same introspection `better-auth
// generate`/`getMigrations` are themselves built on. Column order and
// spelling are exactly what that call returns: `field.fieldName ?? key` for
// each field, `id` first — better-auth does not snake_case its own default
// field names (confirmed directly against the DDL `test/helpers/auth.ts`'s
// `buildDynamicSchema` generates, which uses that same `field.fieldName ??
// key` expression to build `CREATE TABLE` column lists), so most of these
// are camelCase (`emailVerified`, `twoFactorEnabled`, `organizationId`, …)
// and several model/table names are too (`teamMember`, `ssoProvider`,
// `scimProvider`). `test/schema/verify.test.ts`'s "EXPECTED_TABLES drift
// guard" asserts this literal still matches a live `getAuthTables()` call,
// so a better-auth upgrade that adds, removes, or renames a field fails CI
// instead of drifting silently.
//
// `session`, `account`, and `verification` are core better-auth tables that
// exist in any working better-auth deployment independent of this
// package's plugins — deliberately not tracked here; `verifyDatabase` only
// guards the tables/columns *this* package's plugins and migration
// actually require.
//
// `user` and `organization` additionally carry `studio_ref` — the column
// `0001_enterprise.sql`'s `ALTER TABLE` statements add (linking each row
// back to the studio product's own record), not part of better-auth's own
// field set.
export const EXPECTED_TABLES: Record<string, string[]> = {
  user: [
    "id",
    "name",
    "email",
    "emailVerified",
    "image",
    "createdAt",
    "updatedAt",
    "role",
    "banned",
    "banReason",
    "banExpires",
    "twoFactorEnabled",
    "studio_ref",
  ],
  organization: ["id", "name", "slug", "logo", "createdAt", "metadata", "studio_ref"],
  member: ["id", "organizationId", "userId", "role", "createdAt"],
  team: ["id", "name", "organizationId", "createdAt", "updatedAt"],
  teamMember: ["id", "teamId", "userId", "createdAt"],
  invitation: [
    "id",
    "organizationId",
    "email",
    "role",
    "teamId",
    "status",
    "expiresAt",
    "createdAt",
    "inviterId",
  ],
  ssoProvider: [
    "id",
    "issuer",
    "oidcConfig",
    "samlConfig",
    "userId",
    "providerId",
    "organizationId",
    "domain",
    "domainVerified",
  ],
  scimProvider: ["id", "providerId", "scimToken", "organizationId", "userId"],
  twoFactor: [
    "id",
    "secret",
    "backupCodes",
    "userId",
    "verified",
    "failedVerificationCount",
    "lockedUntil",
  ],
  passkey: [
    "id",
    "name",
    "publicKey",
    "userId",
    "credentialID",
    "counter",
    "deviceType",
    "backedUp",
    "transports",
    "createdAt",
    "aaguid",
  ],
  apikey: [
    "id",
    "configId",
    "name",
    "start",
    "referenceId",
    "prefix",
    "key",
    "refillInterval",
    "refillAmount",
    "lastRefillAt",
    "enabled",
    "rateLimitEnabled",
    "rateLimitTimeWindow",
    "rateLimitMax",
    "requestCount",
    "remaining",
    "lastRequest",
    "expiresAt",
    "createdAt",
    "updatedAt",
    "permissions",
    "metadata",
  ],
  org_policy: [
    "org_id",
    "require_2fa",
    "sso_enforced",
    "break_glass_user_id",
    "session_max_age_s",
    "allowed_methods",
    "group_role_map",
    "updated_at",
  ],
  audit_event: [
    "id",
    "org_id",
    "seq",
    "actor_type",
    "actor_id",
    "action",
    "target_type",
    "target_id",
    "ip",
    "user_agent",
    "metadata",
    "created_at",
    "prev_hash",
    "hash",
  ],
  scim_group: ["team_id", "org_id", "external_id", "created_at", "updated_at"],
};
