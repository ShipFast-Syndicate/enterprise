// Enterprise-owned SQLite models. Native SCIM models come from Better Auth (1.7.19 in the test suite).
// SQL migrations preserve legacy tables and add the projection ownership marker.

import { sqliteTable, text, integer, index, uniqueIndex } from "drizzle-orm/sqlite-core";

export const orgPolicy = sqliteTable("org_policy", {
  id: text("id").primaryKey(),
  orgId: text("org_id").notNull().unique(),
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

export const enterpriseScimMember = sqliteTable("enterprise_scim_member", {
  id: text("id").primaryKey(),
  orgId: text("org_id").notNull(),
  userId: text("user_id").notNull(),
  memberId: text("member_id").notNull().unique(),
  lastRole: text("last_role").notNull(),
});

// Optional (`entitlements: { store: "table" }`; migration `0004`). Not part of
// `enterpriseSchema`, so a product that did not opt in does not get a table
// in its drizzle schema either — spread `orgEntitlementSchema` in when it does.
export const orgEntitlement = sqliteTable("org_entitlement", {
  id: text("id").primaryKey(),
  orgId: text("org_id").notNull().unique(),
  features: text("features").notNull().default("[]"),
  updatedAt: integer("updated_at", { mode: "timestamp_ms" }).notNull(),
  updatedBy: text("updated_by"),
});

export const enterpriseSchema = { orgPolicy, auditEvent, enterpriseScimMember };
export const orgEntitlementSchema = { orgEntitlement };

export { EXPECTED_TABLES, EXPECTED_ENTITLEMENT_TABLES } from "./expected";
export { verifyDatabase, type MissingItem, type VerifyOptions, type VerifyResult } from "./verify";
export { applyMigration, type ApplyMigrationOptions } from "./migrate";
export { applyMigrationPg, type ApplyMigrationPgOptions } from "./migrate-pg";
export type { PgClient } from "./pg-client";
