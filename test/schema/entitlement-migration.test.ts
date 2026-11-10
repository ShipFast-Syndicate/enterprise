// The optional `org_entitlement` migration (SQLite 0004, Postgres 0002) is
// opt-in: the default `applyMigration*` and `verifyDatabase` neither create nor
// expect it, so a deployment that never opts in cannot start failing verify.

import { PGlite } from "@electric-sql/pglite";
import { eq } from "drizzle-orm";
import { drizzle as drizzlePg } from "drizzle-orm/pglite";
import { drizzle } from "drizzle-orm/libsql";
import { createClient } from "@libsql/client";
import { afterEach, describe, expect, it } from "vitest";
import {
  EXPECTED_ENTITLEMENT_TABLES,
  EXPECTED_TABLES,
  applyMigration,
  applyMigrationPg,
  orgEntitlement,
  verifyDatabase,
} from "../../src/schema";
import { orgEntitlement as orgEntitlementPg } from "../../src/schema/pg";
import { MIGRATION_FILES, OPTIONAL_MIGRATION_FILES } from "../../src/schema/migrate";
import { OPTIONAL_PG_MIGRATION_FILES, PG_MIGRATION_FILES } from "../../src/schema/migrate-pg";
import { baseAuthOptions, runMigrations } from "../helpers/auth";

describe("SQLite 0004_org_entitlement", () => {
  it("is not part of the default migration set or the default verify contract", () => {
    expect(MIGRATION_FILES).not.toContain("0004_org_entitlement.sql");
    expect(OPTIONAL_MIGRATION_FILES).toEqual(["0004_org_entitlement.sql"]);
    expect(Object.keys(EXPECTED_TABLES)).not.toContain("org_entitlement");
  });

  it("the default migration leaves verify ok without the table; opting in creates it and verifies it", async () => {
    const client = createClient({ url: ":memory:" });
    await runMigrations({ options: baseAuthOptions() }, client);
    await applyMigration(client);

    expect(await verifyDatabase(client)).toEqual({ ok: true, missing: [] });
    expect(await verifyDatabase(client, { entitlements: true })).toEqual({
      ok: false,
      missing: [{ table: "org_entitlement" }],
    });

    await applyMigration(client, { entitlements: true });
    expect(await verifyDatabase(client, { entitlements: true })).toEqual({ ok: true, missing: [] });
    // Still ok for a consumer that never opted in.
    expect(await verifyDatabase(client)).toEqual({ ok: true, missing: [] });
  });

  it("is idempotent and reports a missing column", async () => {
    const client = createClient({ url: ":memory:" });
    await runMigrations({ options: baseAuthOptions() }, client);
    await applyMigration(client, { entitlements: true });
    await expect(applyMigration(client, { entitlements: true })).resolves.toBeUndefined();

    await client.execute("ALTER TABLE org_entitlement DROP COLUMN updated_by");
    expect((await verifyDatabase(client, { entitlements: true })).missing).toEqual([
      { table: "org_entitlement", column: "updated_by" },
    ]);
  });

  it("matches the drizzle table and EXPECTED_ENTITLEMENT_TABLES, one row per organization", async () => {
    const client = createClient({ url: ":memory:" });
    await applyMigration(client, { entitlements: true });
    const info = await client.execute(`PRAGMA table_info("org_entitlement")`);
    expect(info.rows.map((row) => String(row.name))).toEqual(
      EXPECTED_ENTITLEMENT_TABLES.org_entitlement,
    );

    const db = drizzle(client);
    const updatedAt = new Date();
    await db
      .insert(orgEntitlement)
      .values({ id: "e1", orgId: "org_1", features: '["sso"]', updatedAt, updatedBy: "u1" });
    expect((await db.select().from(orgEntitlement))[0]).toMatchObject({
      orgId: "org_1",
      features: '["sso"]',
    });
    await expect(
      db.insert(orgEntitlement).values({ id: "e2", orgId: "org_1", features: "[]", updatedAt }),
    ).rejects.toThrow();
  });
});

describe("Postgres 0002_org_entitlement", () => {
  let db: PGlite | undefined;
  afterEach(async () => {
    await db?.close();
  });

  async function pgWithBetterAuthTables(): Promise<PGlite> {
    db = new PGlite();
    for (const [table, columns] of Object.entries(EXPECTED_TABLES)) {
      if (["audit_event", "org_policy", "enterprise_scim_member"].includes(table)) continue;
      const defs = columns.filter((c) => c !== "studio_ref").map((c) => `"${c}" text`);
      await db.exec(`CREATE TABLE "${table}" (${defs.join(", ")})`);
    }
    return db;
  }

  it("is not part of the default set; opt-in creates, verifies and is idempotent", async () => {
    expect(PG_MIGRATION_FILES).not.toContain("0002_org_entitlement.sql");
    expect(OPTIONAL_PG_MIGRATION_FILES).toEqual(["0002_org_entitlement.sql"]);
    const pg = await pgWithBetterAuthTables();

    await applyMigrationPg(pg);
    expect(await verifyDatabase(pg)).toEqual({ ok: true, missing: [] });
    expect((await verifyDatabase(pg, { entitlements: true })).missing).toEqual([
      { table: "org_entitlement" },
    ]);

    await applyMigrationPg(pg, { entitlements: true });
    await applyMigrationPg(pg, { entitlements: true });
    expect(await verifyDatabase(pg, { entitlements: true })).toEqual({ ok: true, missing: [] });
    expect(await verifyDatabase(pg)).toEqual({ ok: true, missing: [] });
  });

  it("requires the unique index on org_id, and the drizzle table round-trips features", async () => {
    const pg = await pgWithBetterAuthTables();
    await applyMigrationPg(pg);
    // A product-made table without the unique index verifies clean on columns
    // alone; the uniqueness check catches it.
    await pg.exec(
      `CREATE TABLE org_entitlement (id text PRIMARY KEY, org_id text NOT NULL, features text[] NOT NULL, updated_at timestamptz NOT NULL, updated_by text)`,
    );
    expect((await verifyDatabase(pg, { entitlements: true })).missing).toEqual([
      { table: "org_entitlement", reason: "no unique index on (org_id)" },
    ]);
    await pg.exec(`DROP TABLE org_entitlement`);
    await applyMigrationPg(pg, { entitlements: true });

    const orm = drizzlePg(pg);
    await orm.insert(orgEntitlementPg).values({
      id: "e1",
      orgId: "org_1",
      features: ["sso", "scim"],
      updatedAt: new Date(),
    });
    const [row] = await orm
      .select()
      .from(orgEntitlementPg)
      .where(eq(orgEntitlementPg.orgId, "org_1"));
    expect(row!.features).toEqual(["sso", "scim"]);
  });
});
