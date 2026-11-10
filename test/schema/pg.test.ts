// Postgres schema support, run against PGlite (in-process Postgres, no
// Docker): `applyMigrationPg`, the `./schema/pg` drizzle tables, and the
// Postgres branch of `verifyDatabase`. The SQLite path is covered by
// verify.test.ts and the CLI tests, which this change leaves untouched.
import { PGlite } from "@electric-sql/pglite";
import { eq } from "drizzle-orm";
import { drizzle } from "drizzle-orm/pglite";
import { getTableConfig, pgTable, text } from "drizzle-orm/pg-core";
import { readFileSync } from "node:fs";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { EXPECTED_TABLES, applyMigrationPg, verifyDatabase, type PgClient } from "../../src/schema";
import { pgMigrationFilePath } from "../../src/schema/migrate-pg";
import { splitStatements } from "../../src/schema/migrate";
import {
  auditEvent,
  enterpriseSchema,
  enterpriseScimMember,
  orgPolicy,
  studioRefColumns,
} from "../../src/schema/pg";

const OWN_TABLES = new Set(["audit_event", "org_policy", "enterprise_scim_member"]);

function snake(name: string): string {
  return name.replace(/([a-z0-9])([A-Z])/g, "$1_$2").toLowerCase();
}

// Stands in for the product's own better-auth tables (this package does not
// ship them): every non-enterprise `EXPECTED_TABLES` entry, minus the
// `studio_ref` column the migration adds, with text columns. `naming`
// picks the camelCase (quoted) or snake_case spelling a product might use.
async function createBetterAuthTables(db: PGlite, naming: "camel" | "snake") {
  for (const [table, columns] of Object.entries(EXPECTED_TABLES)) {
    if (OWN_TABLES.has(table)) continue;
    const tableName = naming === "snake" ? snake(table) : table;
    const defs = columns
      .filter((column) => column !== "studio_ref")
      .map((column) => `"${naming === "snake" ? snake(column) : column}" text`);
    await db.exec(`CREATE TABLE "${tableName}" (${defs.join(", ")})`);
  }
}

let db: PGlite;

beforeEach(async () => {
  db = new PGlite();
});

afterEach(async () => {
  await db.close();
});

describe("applyMigrationPg + verifyDatabase (pg)", () => {
  it("applies on top of the product's better-auth tables and verifies ok", async () => {
    await createBetterAuthTables(db, "camel");
    expect((await verifyDatabase(db)).ok).toBe(false);

    await applyMigrationPg(db);

    expect(await verifyDatabase(db)).toEqual({ ok: true, missing: [] });
  });

  it("is idempotent: a second and third apply change nothing", async () => {
    await createBetterAuthTables(db, "camel");
    await applyMigrationPg(db);
    const snapshot = JSON.stringify(
      (
        await db.query(
          "SELECT table_name, column_name, data_type FROM information_schema.columns WHERE table_schema = current_schema() ORDER BY 1, 2",
        )
      ).rows,
    );

    await expect(applyMigrationPg(db)).resolves.toBeUndefined();
    await expect(applyMigrationPg(db)).resolves.toBeUndefined();

    const after = JSON.stringify(
      (
        await db.query(
          "SELECT table_name, column_name, data_type FROM information_schema.columns WHERE table_schema = current_schema() ORDER BY 1, 2",
        )
      ).rows,
    );
    expect(after).toBe(snapshot);
    expect((await verifyDatabase(db)).ok).toBe(true);
  });

  it("tolerates snake_case table and column names", async () => {
    await createBetterAuthTables(db, "snake");
    await applyMigrationPg(db);

    expect(await verifyDatabase(db)).toEqual({ ok: true, missing: [] });
  });

  it("reports every missing table on an empty database", async () => {
    const { ok, missing } = await verifyDatabase(db);

    expect(ok).toBe(false);
    expect(missing.map((m) => m.table).sort()).toEqual(Object.keys(EXPECTED_TABLES).sort());
    expect(missing.every((m) => m.column === undefined)).toBe(true);
  });

  it("reports a missing column on a present table", async () => {
    await createBetterAuthTables(db, "camel");
    await applyMigrationPg(db);
    await db.exec('ALTER TABLE "user" DROP COLUMN studio_ref');

    expect((await verifyDatabase(db)).missing).toEqual([{ table: "user", column: "studio_ref" }]);
  });

  it("skips studio_ref with a warning when the base tables do not exist yet", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      await expect(applyMigrationPg(db)).resolves.toBeUndefined();
      expect(warn).toHaveBeenCalledTimes(2);
    } finally {
      warn.mockRestore();
    }
    const tables = (await verifyDatabase(db)).missing.map((m) => m.table);
    expect(tables).not.toContain("org_policy");
    expect(tables).not.toContain("audit_event");
    expect(tables).not.toContain("enterprise_scim_member");

    // Once the product's tables exist, re-running completes the job.
    await createBetterAuthTables(db, "camel");
    await applyMigrationPg(db);
    expect((await verifyDatabase(db)).ok).toBe(true);
  });

  it("FAILS verification when audit_event.metadata is jsonb", async () => {
    await createBetterAuthTables(db, "camel");
    await applyMigrationPg(db);
    await db.exec("ALTER TABLE audit_event ALTER COLUMN metadata TYPE jsonb");

    const { ok, missing } = await verifyDatabase(db);

    expect(ok).toBe(false);
    expect(missing).toEqual([
      { table: "audit_event", column: "metadata", reason: expect.stringContaining("jsonb") },
    ]);
  });

  it("fails when a pre-existing jsonb audit_event survives the migration", async () => {
    await createBetterAuthTables(db, "camel");
    // A product that generated the table with the better-auth CLI.
    await db.exec(`CREATE TABLE audit_event (
      id text PRIMARY KEY, org_id text NOT NULL, seq integer NOT NULL, actor_type text NOT NULL,
      actor_id text, action text NOT NULL, target_type text NOT NULL, target_id text, ip text,
      user_agent text, metadata jsonb NOT NULL, created_at timestamptz NOT NULL,
      prev_hash text NOT NULL, hash text NOT NULL)`);
    await applyMigrationPg(db);

    const { ok, missing } = await verifyDatabase(db);

    expect(ok).toBe(false);
    expect(missing).toHaveLength(1);
    expect(missing[0]).toMatchObject({ table: "audit_event", column: "metadata" });
  });

  it("accepts any PgClient shape (query + rows)", async () => {
    const calls: string[] = [];
    const client: PgClient = {
      async query(sql) {
        calls.push(sql);
        return { rows: [] };
      },
    };
    const { ok } = await verifyDatabase(client);
    expect(ok).toBe(false);
    expect(calls).toHaveLength(1);
  });
});

describe("pg migration file", () => {
  const sql = readFileSync(pgMigrationFilePath(), "utf8");
  const statements = splitStatements(sql);

  it("is idempotent by construction: no DO blocks, every statement guarded", () => {
    expect(sql).not.toMatch(/\bDO\s+\$/i);
    for (const statement of statements) {
      if (/^CREATE (UNIQUE )?INDEX/i.test(statement)) expect(statement).toMatch(/IF NOT EXISTS/i);
      else if (/^CREATE TABLE/i.test(statement)) expect(statement).toMatch(/IF NOT EXISTS/i);
      else if (/^ALTER TABLE/i.test(statement))
        expect(statement).toMatch(/ADD COLUMN IF NOT EXISTS/i);
      else throw new Error(`unexpected statement: ${statement}`);
    }
    expect(sql).toContain('ALTER TABLE "user" ADD COLUMN IF NOT EXISTS studio_ref text');
  });

  it("declares audit_event.metadata as json, not jsonb", () => {
    const audit = statements.find((s) => s.startsWith("CREATE TABLE IF NOT EXISTS audit_event"))!;
    expect(audit).toMatch(/metadata json NOT NULL/);
    expect(audit).not.toMatch(/metadata jsonb/);
  });

  it("has the sqlite-equivalent indexes and uniques", async () => {
    await createBetterAuthTables(db, "camel");
    await applyMigrationPg(db);
    const { rows } = await db.query<{ indexdef: string }>(
      "SELECT indexdef FROM pg_indexes WHERE schemaname = current_schema()",
    );
    const defs = rows.map((r) => r.indexdef);
    expect(defs).toEqual(
      expect.arrayContaining([
        expect.stringMatching(/UNIQUE INDEX audit_event_org_seq .*\(org_id, seq\)/),
        expect.stringMatching(/INDEX audit_event_org_created .*\(org_id, created_at\)/),
        expect.stringMatching(/UNIQUE INDEX org_policy_org_id_key .*\(org_id\)/),
        expect.stringMatching(/UNIQUE INDEX enterprise_scim_member_member_id_key .*\(member_id\)/),
      ]),
    );
  });
});

describe("./schema/pg drizzle tables", () => {
  it("match the migration: same columns and types as the live tables", async () => {
    await createBetterAuthTables(db, "camel");
    await applyMigrationPg(db);
    const { rows } = await db.query<{ table_name: string; column_name: string; data_type: string }>(
      "SELECT table_name, column_name, data_type FROM information_schema.columns WHERE table_schema = current_schema()",
    );
    const live = (table: string) =>
      Object.fromEntries(
        rows.filter((r) => r.table_name === table).map((r) => [r.column_name, r.data_type]),
      );

    for (const table of [orgPolicy, auditEvent, enterpriseScimMember]) {
      const config = getTableConfig(table);
      expect(config.columns.map((c) => c.name).sort()).toEqual(
        Object.keys(live(config.name)).sort(),
      );
    }
    expect(
      getTableConfig(auditEvent)
        .columns.find((c) => c.name === "metadata")!
        .getSQLType(),
    ).toBe("json");
    expect(live("audit_event").metadata).toBe("json");
    expect(live("org_policy").allowed_methods).toBe("ARRAY");
    expect(live("org_policy").group_role_map).toBe("jsonb");
    expect(live("org_policy").updated_at).toBe("timestamp with time zone");
    expect(Object.keys(enterpriseSchema)).toEqual([
      "orgPolicy",
      "auditEvent",
      "enterpriseScimMember",
    ]);
  });

  it("studioRefColumns() yields a fresh nullable text studio_ref column each call", () => {
    expect(studioRefColumns().studioRef).not.toBe(studioRefColumns().studioRef);
    for (const name of ["user", "organization"]) {
      const table = pgTable(name, { id: text("id").primaryKey(), ...studioRefColumns() });
      const column = getTableConfig(table).columns.find((c) => c.name === "studio_ref")!;
      expect(column.getSQLType()).toBe("text");
      expect(column.notNull).toBe(false);
    }
  });

  it("round-trips rows: defaults, Date timestamps, json metadata key order preserved", async () => {
    await applyMigrationPg(db);
    const orm = drizzle(db);
    const now = new Date("2026-11-10T10:00:00.123Z");

    await orm.insert(orgPolicy).values({ id: "p1", orgId: "o1", updatedAt: now });
    const [policy] = await orm.select().from(orgPolicy).where(eq(orgPolicy.orgId, "o1"));
    expect(policy).toMatchObject({
      require2fa: false,
      ssoEnforced: false,
      groupRoleMap: {},
      allowedMethods: [
        "sso",
        "magic_link",
        "google",
        "github",
        "linkedin",
        "microsoft",
        "password",
        "passkey",
      ],
    });
    expect(policy.updatedAt.getTime()).toBe(now.getTime());

    // Keys deliberately not in jsonb order (jsonb sorts shorter keys first).
    const metadata = { zzzzzz: 1, a: 2, mmm: { yy: 1, b: 2 } };
    await orm.insert(auditEvent).values({
      id: "e1",
      orgId: "o1",
      seq: 1,
      actorType: "user",
      action: "x",
      targetType: "org",
      metadata,
      createdAt: now,
      prevHash: "p",
      hash: "h",
    });
    const raw = await db.query<{ metadata: unknown }>("SELECT metadata FROM audit_event");
    expect(JSON.stringify(raw.rows[0].metadata)).toBe(JSON.stringify(metadata));
    const [row] = await orm.select().from(auditEvent);
    expect(JSON.stringify(row.metadata)).toBe(JSON.stringify(metadata));
    // The same value through jsonb loses the order: why the column is json.
    const viaJsonb = await db.query<{ m: unknown }>("SELECT metadata::jsonb AS m FROM audit_event");
    expect(JSON.stringify(viaJsonb.rows[0].m)).not.toBe(JSON.stringify(metadata));
  });

  it("enforces unique (org_id, seq) on audit_event and unique member_id", async () => {
    await applyMigrationPg(db);
    const orm = drizzle(db);
    const event = {
      orgId: "o1",
      seq: 1,
      actorType: "user",
      action: "x",
      targetType: "org",
      createdAt: new Date(),
      prevHash: "p",
      hash: "h",
    };
    await orm.insert(auditEvent).values({ ...event, id: "e1" });
    await expect(orm.insert(auditEvent).values({ ...event, id: "e2" })).rejects.toThrow();
    await orm.insert(auditEvent).values({ ...event, id: "e3", orgId: "o2" });

    const member = { orgId: "o1", userId: "u1", memberId: "m1", lastRole: "member" };
    await orm.insert(enterpriseScimMember).values({ ...member, id: "s1" });
    await expect(
      orm.insert(enterpriseScimMember).values({ ...member, id: "s2" }),
    ).rejects.toThrow();
  });
});

describe("package surface", () => {
  const pkg = JSON.parse(readFileSync("package.json", "utf8")) as {
    exports: Record<string, { types: string; import: string }>;
    files: string[];
  };

  it("exports ./schema/pg next to the unchanged existing entries", () => {
    expect(pkg.exports["./schema/pg"]).toEqual({
      types: "./dist/schema/pg/index.d.ts",
      import: "./dist/schema/pg/index.js",
    });
    expect(pkg.exports["./schema"].import).toBe("./dist/schema/index.js");
    expect(pkg.files).toContain("sql");
  });
});
