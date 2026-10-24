// A product-shaped test deployment: the same preset and handler as
// `makeAuth` (`./auth.ts`), but with the `session`, `member` and `org_policy`
// Drizzle tables written by hand the way every product that embeds this
// package maintains them — not derived from the plugins' declared schema.
//
// `makeAuth` builds its Drizzle schema from `getAuthTables(options)`, so any
// field a plugin declares on a core model exists in the test database by
// construction; a plugin that starts writing a new `session` column passes
// there and throws in production, where upstream's Drizzle adapter refuses a
// value key its hand-written table does not have. This harness is the
// production shape:
//
// - `session` — a product's session table: snake_case columns,
//   `created_at`/`updated_at`/`expires_at` in **seconds**
//   (`mode: "timestamp"`), and no column beyond the upstream/organization/
//   admin ones.
// - `member` and `org_policy` — a product with hand-maintained member and
//   org_policy tables: `enterprise_member` with a millisecond `createdAt`, and
//   `org_policy` keyed by its snake_case field names with a millisecond
//   `updated_at` (the physical table is the package's own `0001`/`0002`).
//
// The mixed units (a seconds `session.created_at` next to millisecond policy
// and membership stamps) are deliberate: products in the field mix them.
import { index, integer, sqliteTable, text, uniqueIndex } from "drizzle-orm/sqlite-core";
import type { DynamicSchema } from "./auth";
import { makeAuth, type TestAuth } from "./auth";

const productSession = sqliteTable("session", {
  id: text("id").primaryKey(),
  expiresAt: integer("expires_at", { mode: "timestamp" }).notNull(),
  token: text("token").notNull().unique(),
  createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
  updatedAt: integer("updated_at", { mode: "timestamp" }).notNull(),
  ipAddress: text("ip_address"),
  userAgent: text("user_agent"),
  activeOrganizationId: text("activeOrganizationId"),
  activeTeamId: text("activeTeamId"),
  impersonatedBy: text("impersonatedBy"),
  userId: text("user_id").notNull(),
});

const productMember = sqliteTable(
  "enterprise_member",
  {
    id: text("id").primaryKey(),
    organizationId: text("organizationId").notNull(),
    userId: text("userId").notNull(),
    role: text("role").notNull().default("member"),
    createdAt: integer("createdAt", { mode: "timestamp_ms" }).notNull(),
  },
  (t) => [
    uniqueIndex("enterprise_member_org_user").on(t.organizationId, t.userId),
    index("enterprise_member_user").on(t.userId),
  ],
);

const productOrgPolicy = sqliteTable("org_policy", {
  id: text("id").unique(),
  org_id: text("org_id").primaryKey(),
  require_2fa: integer("require_2fa", { mode: "boolean" }).notNull(),
  sso_enforced: integer("sso_enforced", { mode: "boolean" }).notNull(),
  break_glass_user_id: text("break_glass_user_id"),
  session_max_age_s: integer("session_max_age_s"),
  allowed_methods: text("allowed_methods").notNull(),
  group_role_map: text("group_role_map").notNull(),
  updated_at: integer("updated_at", { mode: "timestamp_ms" }).notNull(),
});

const PRODUCT_DDL = [
  `CREATE TABLE IF NOT EXISTS "session" (
  "id" TEXT PRIMARY KEY NOT NULL,
  "expires_at" INTEGER NOT NULL,
  "token" TEXT NOT NULL UNIQUE,
  "created_at" INTEGER NOT NULL,
  "updated_at" INTEGER NOT NULL,
  "ip_address" TEXT,
  "user_agent" TEXT,
  "activeOrganizationId" TEXT,
  "activeTeamId" TEXT,
  "impersonatedBy" TEXT,
  "user_id" TEXT NOT NULL
)`,
  `CREATE TABLE IF NOT EXISTS "enterprise_member" (
  "id" TEXT PRIMARY KEY NOT NULL,
  "organizationId" TEXT NOT NULL,
  "userId" TEXT NOT NULL,
  "role" TEXT NOT NULL DEFAULT 'member',
  "createdAt" INTEGER NOT NULL
)`,
  `CREATE UNIQUE INDEX IF NOT EXISTS "enterprise_member_org_user" ON "enterprise_member" ("organizationId", "userId")`,
  `CREATE INDEX IF NOT EXISTS "enterprise_member_user" ON "enterprise_member" ("userId")`,
];

/** Drops the derived `session`/`member`/`org_policy` tables and puts the hand-written product ones in their place. */
function productTables(built: DynamicSchema): DynamicSchema {
  const replaced = /^CREATE TABLE IF NOT EXISTS "(session|member|org_policy)" /;
  return {
    drizzleSchema: {
      ...built.drizzleSchema,
      session: productSession,
      member: productMember,
      org_policy: productOrgPolicy,
    },
    // `org_policy` is created by the package's own migration (`applyMigration`,
    // run by `makeAuth` after this DDL), exactly as in a product.
    ddl: [...built.ddl.filter((statement) => !replaced.test(statement)), ...PRODUCT_DDL],
  };
}

export async function makeProductAuth(
  overrides: Parameters<typeof makeAuth>[0] = {},
): Promise<TestAuth> {
  return makeAuth({ ...overrides, tables: productTables });
}

/** A raw membership row in the product-shaped `enterprise_member` table (millisecond `createdAt`). */
export async function insertProductMember(
  t: TestAuth,
  orgId: string,
  userId: string,
  role = "member",
  createdAtMs = Date.now(),
): Promise<void> {
  await t.client.execute({
    sql: `INSERT INTO enterprise_member (id, organizationId, userId, role, createdAt) VALUES (?, ?, ?, ?, ?)`,
    args: [`member_${userId}_${orgId}`, orgId, userId, role, createdAtMs],
  });
}

/**
 * A signed session cookie over a raw row in the product-shaped `session`
 * table (second-precision timestamps), minted at `createdAtMs` — a session
 * that no request of this deployment created.
 */
export async function insertProductSessionCookie(
  t: TestAuth,
  userId: string,
  createdAtMs = Date.now(),
): Promise<string> {
  const token = `product_session_${userId}_${Math.random().toString(36).slice(2)}`;
  const seconds = Math.floor(createdAtMs / 1000);
  await t.client.execute({
    sql: `INSERT INTO session (id, expires_at, token, created_at, updated_at, user_id) VALUES (?, ?, ?, ?, ?, ?)`,
    args: [`sess_${token}`, seconds + 24 * 60 * 60, token, seconds, seconds, userId],
  });
  const secret = (t.auth.options as { secret: string }).secret;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(token));
  const base64 = btoa(String.fromCharCode(...new Uint8Array(signature)));
  return `better-auth.session_token=${encodeURIComponent(`${token}.${base64}`)}`;
}
