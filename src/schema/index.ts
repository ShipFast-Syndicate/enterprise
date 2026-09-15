// Alpha Bros enterprise layer — schema entry point.
//
// Drizzle sqlite table definitions for the enterprise layer's own tables
// (org security policy, the tamper-evident audit log, and our SCIM Groups
// mapping — better-auth 1.6 has no SCIM Groups). Task 3 adds the matching
// SQL migration under `src/schema/sql/`, a `verify` check, and the
// `ab-enterprise` CLI; this task only defines the tables so
// `test/helpers/auth.ts` can create them for tests.

import { sqliteTable, text, integer, index, uniqueIndex } from "drizzle-orm/sqlite-core";

export const orgPolicy = sqliteTable("org_policy", {
  orgId: text("org_id").primaryKey(),
  require2fa: integer("require_2fa", { mode: "boolean" }).notNull().default(false),
  ssoEnforced: integer("sso_enforced", { mode: "boolean" }).notNull().default(false),
  breakGlassUserId: text("break_glass_user_id"),
  sessionMaxAgeS: integer("session_max_age_s"),
  allowedMethods: text("allowed_methods")
    .notNull()
    .default('["sso","magic_link","google","github","linkedin","microsoft","password","passkey"]'),
  groupRoleMap: text("group_role_map").notNull().default("{}"),
  updatedAt: integer("updated_at", { mode: "timestamp_ms" }).notNull(),
});

export const auditEvent = sqliteTable(
  "audit_event",
  {
    id: text("id").primaryKey(),
    orgId: text("org_id").notNull(),
    seq: integer("seq").notNull(),
    actorType: text("actor_type").notNull(),
    actorId: text("actor_id"),
    action: text("action").notNull(),
    targetType: text("target_type").notNull(),
    targetId: text("target_id"),
    ip: text("ip"),
    userAgent: text("user_agent"),
    metadata: text("metadata").notNull().default("{}"),
    createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
    prevHash: text("prev_hash").notNull(),
    hash: text("hash").notNull(),
  },
  (t) => [
    uniqueIndex("audit_event_org_seq").on(t.orgId, t.seq),
    index("audit_event_org_created").on(t.orgId, t.createdAt),
  ],
);

export const scimGroup = sqliteTable(
  "scim_group",
  {
    teamId: text("team_id").primaryKey(),
    orgId: text("org_id").notNull(),
    externalId: text("external_id"),
    createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
    updatedAt: integer("updated_at", { mode: "timestamp_ms" }).notNull(),
  },
  (t) => [
    index("scim_group_org").on(t.orgId),
    uniqueIndex("scim_group_org_external").on(t.orgId, t.externalId),
  ],
);

export const enterpriseSchema = { orgPolicy, auditEvent, scimGroup };
