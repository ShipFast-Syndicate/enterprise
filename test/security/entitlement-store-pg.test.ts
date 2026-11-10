// The Postgres runtime path of the entitlement table, end to end: the real
// store (`setEntitlements`, the resolver's table read, the audit append) run
// through better-auth's drizzle adapter on `pg` against PGlite, with the shipped
// `sql/pg/0002_org_entitlement.sql`. `features` is a
// native `text[]` there, which only an adapter that hands arrays to the driver
// as-is (drizzle's) can write — the same assumption `org_policy.allowed_methods`
// already makes — so this pins the supported combination.

import { PGlite } from "@electric-sql/pglite";
import { betterAuth } from "better-auth";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import { drizzle } from "drizzle-orm/pglite";
import { boolean, integer, json, pgTable, text, timestamp } from "drizzle-orm/pg-core";
import { afterEach, describe, expect, it } from "vitest";
import { applyMigrationPg } from "../../src/schema";
import { readEntitlementRow, setEntitlements } from "../../src/server/entitlement-store";
import { enterprisePreset } from "../../src/server/preset";

const user = pgTable("user", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  email: text("email").notNull(),
  emailVerified: boolean("emailVerified").notNull(),
  image: text("image"),
  createdAt: timestamp("createdAt").notNull(),
  updatedAt: timestamp("updatedAt").notNull(),
  role: text("role"),
  banned: boolean("banned"),
  banReason: text("banReason"),
  banExpires: timestamp("banExpires"),
  studioRef: text("studio_ref"),
});

const organization = pgTable("organization", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  slug: text("slug").notNull(),
  logo: text("logo"),
  createdAt: timestamp("createdAt").notNull(),
  metadata: text("metadata"),
  studioRef: text("studio_ref"),
});

// The drizzle adapter finds a model's table by its model name and a column by
// the plugin-declared field name, so these two carry the physical column names
// as keys (the shipped `./schema/pg` tables carry camelCase keys for queries).
const orgEntitlement = pgTable("org_entitlement", {
  id: text("id").primaryKey(),
  org_id: text("org_id").notNull().unique(),
  features: text("features").array().notNull(),
  updated_at: timestamp("updated_at", { withTimezone: true }).notNull(),
  updated_by: text("updated_by"),
});

const auditEvent = pgTable("audit_event", {
  id: text("id").primaryKey(),
  org_id: text("org_id").notNull(),
  seq: integer("seq").notNull(),
  actor_type: text("actor_type").notNull(),
  actor_id: text("actor_id"),
  action: text("action").notNull(),
  target_type: text("target_type").notNull(),
  target_id: text("target_id"),
  ip: text("ip"),
  user_agent: text("user_agent"),
  metadata: json("metadata").notNull(),
  created_at: timestamp("created_at", { withTimezone: true }).notNull(),
  prev_hash: text("prev_hash").notNull(),
  hash: text("hash").notNull(),
});

let pg: PGlite | undefined;
afterEach(async () => {
  await pg?.close();
  pg = undefined;
});

async function makePgAuth() {
  pg = new PGlite();
  await pg.exec(`
    CREATE TABLE "user" (
      id text PRIMARY KEY, name text NOT NULL, email text NOT NULL,
      "emailVerified" boolean NOT NULL, image text,
      "createdAt" timestamp NOT NULL, "updatedAt" timestamp NOT NULL,
      role text, banned boolean, "banReason" text, "banExpires" timestamp
    );
    CREATE TABLE organization (
      id text PRIMARY KEY, name text NOT NULL, slug text NOT NULL,
      logo text, "createdAt" timestamp NOT NULL, metadata text
    );
  `);
  await applyMigrationPg(pg, { entitlements: true });
  await pg.exec(`
    INSERT INTO "user" (id, name, email, "emailVerified", "createdAt", "updatedAt", role)
      VALUES ('staff_1', 'Staff', 'staff@platform.test', true, now(), now(), 'admin'),
             ('owner_1', 'Owner', 'owner@acme.test', true, now(), now(), NULL);
    INSERT INTO organization (id, name, slug, "createdAt") VALUES ('org_1', 'Acme', 'acme', now());
  `);
  const db = drizzle(pg, {
    schema: { user, organization, audit_event: auditEvent, org_entitlement: orgEntitlement },
  });
  const auth = betterAuth({
    database: drizzleAdapter(db, { provider: "pg", transaction: true }),
    secret: "x".repeat(32),
    baseURL: "http://localhost:3000",
    emailAndPassword: { enabled: true },
    plugins: enterprisePreset({
      product: "test",
      secretsKey: "s".repeat(32),
      scimCredentialHashSecret: "catalog-test-key-".repeat(3),
      entitlements: { store: "table" },
    }),
  });
  return { auth, pg };
}

describe("entitlement table on Postgres (drizzle adapter)", () => {
  it("setEntitlements writes the text[] column, the resolver reads it back, the audit row lands", async () => {
    const { auth, pg } = await makePgAuth();

    const first = await setEntitlements(auth, "org_1", ["scim", "sso"], { userId: "staff_1" });
    expect(first).toEqual({ features: ["sso", "scim"], previousFeatures: [] });

    const context = await auth.$context;
    const adapter = context.adapter as unknown as Parameters<typeof readEntitlementRow>[0];
    expect(await readEntitlementRow(adapter, "org_1")).toEqual(["sso", "scim"]);
    const stored = await pg.query<{ features: string[] }>(
      `SELECT features FROM org_entitlement WHERE org_id = 'org_1'`,
    );
    expect(stored.rows[0]!.features).toEqual(["sso", "scim"]);

    const second = await setEntitlements(auth, "org_1", ["audit_log"], { userId: "staff_1" });
    expect(second).toEqual({ features: ["audit_log"], previousFeatures: ["sso", "scim"] });
    expect(await readEntitlementRow(adapter, "org_1")).toEqual(["audit_log"]);
    const rows = await pg.query<{ n: number | string }>(
      `SELECT count(*) AS n FROM org_entitlement WHERE org_id = 'org_1'`,
    );
    expect(Number(rows.rows[0]!.n)).toBe(1);

    const audit = await pg.query<{ action: string; seq: number }>(
      `SELECT action, seq FROM audit_event WHERE org_id = 'org_1' ORDER BY seq`,
    );
    expect(audit.rows.map((r) => r.action)).toEqual(["entitlement.changed", "entitlement.changed"]);
  });

  it("refuses a non-staff user and an unknown organization, writing nothing", async () => {
    const { auth, pg } = await makePgAuth();

    await expect(
      setEntitlements(auth, "org_1", ["sso"], { userId: "owner_1" }),
    ).rejects.toMatchObject({ body: { code: "NOT_PLATFORM_STAFF" } });
    await expect(
      setEntitlements(auth, "org_missing", ["sso"], { userId: "staff_1" }),
    ).rejects.toMatchObject({ body: { code: "ORG_NOT_FOUND" } });

    const rows = await pg.query(`SELECT 1 FROM org_entitlement`);
    expect(rows.rows).toEqual([]);
  });
});
