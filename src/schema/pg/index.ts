// Enterprise-owned Postgres models (`@alphabros/enterprise/schema/pg`).
// Mirrors `../index.ts` (SQLite) and `../sql/pg/0001_enterprise.sql`.
//
// Do NOT regenerate these with `@better-auth/cli generate`: for a `json`
// field it emits `jsonb`, and `jsonb` re-orders object keys. The audit hash
// chain covers the serialised row, so `audit_event.metadata` must be `json`
// (text-preserving) or `verifyChain` rejects honest rows. `verifyDatabase`
// fails on a `jsonb` column for that reason.
//
// better-auth's drizzle adapter on `pg` hands arrays and objects to the
// driver as-is (`supportsJSON`/`supportsArrays`), so `allowed_methods` is a
// native `text[]` and `group_role_map` a `jsonb` object; timestamps are
// `timestamptz` read back as `Date`.

import {
  boolean,
  index,
  integer,
  json,
  jsonb,
  pgTable,
  text,
  timestamp,
  uniqueIndex,
} from "drizzle-orm/pg-core";

export const orgPolicy = pgTable("org_policy", {
  id: text("id").primaryKey(),
  orgId: text("org_id").notNull().unique(),
  require2fa: boolean("require_2fa").notNull().default(false),
  ssoEnforced: boolean("sso_enforced").notNull().default(false),
  breakGlassUserId: text("break_glass_user_id"),
  sessionMaxAgeS: integer("session_max_age_s"),
  allowedMethods: text("allowed_methods")
    .array()
    .notNull()
    .default([
      "sso",
      "magic_link",
      "google",
      "github",
      "linkedin",
      "microsoft",
      "password",
      "passkey",
    ]),
  groupRoleMap: jsonb("group_role_map").notNull().default({}),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull(),
});

export const auditEvent = pgTable(
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
    // `json`, never `jsonb`: see the header.
    metadata: json("metadata").notNull().default({}),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull(),
    prevHash: text("prev_hash").notNull(),
    hash: text("hash").notNull(),
  },
  (t) => [
    uniqueIndex("audit_event_org_seq").on(t.orgId, t.seq),
    index("audit_event_org_created").on(t.orgId, t.createdAt),
  ],
);

export const enterpriseScimMember = pgTable("enterprise_scim_member", {
  id: text("id").primaryKey(),
  orgId: text("org_id").notNull(),
  userId: text("user_id").notNull(),
  memberId: text("member_id").notNull().unique(),
  lastRole: text("last_role").notNull(),
});

/**
 * The `studio_ref` column this package adds to better-auth's `user` and
 * `organization` tables (nullable text, as in the SQLite migration). Spread
 * it into the product's own table definitions so drizzle knows the column:
 *
 *   pgTable("user", { ...baseColumns, ...studioRefColumns() })
 *
 * A function, so each table gets its own column builder.
 */
export function studioRefColumns() {
  return { studioRef: text("studio_ref") };
}

export const enterpriseSchema = { orgPolicy, auditEvent, enterpriseScimMember };
