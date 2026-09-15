// Task 3 — `verifyDatabase` / `applyMigration` behaviour, plus the drift
// guard for `EXPECTED_TABLES` (ruling (b): the static literal must track a
// live `getAuthTables()` derivation so a better-auth upgrade that adds,
// removes, or renames a field fails CI instead of silently going stale).
import { describe, it, expect } from "vitest";
import { getAuthTables } from "better-auth/db";
import { createClient } from "@libsql/client";
import { verifyDatabase, applyMigration, EXPECTED_TABLES } from "../../src/schema";
import { baseAuthOptions as baseOptions, runMigrations } from "../helpers/auth";

describe("verifyDatabase", () => {
  it("reports every missing enterprise table/column on a fresh better-auth db", async () => {
    const client = createClient({ url: ":memory:" });
    await runMigrations({ options: baseOptions() }, client);

    const { ok, missing } = await verifyDatabase(client);

    expect(ok).toBe(false);
    const keys = missing.map((m) => (m.column ? `${m.table}.${m.column}` : m.table));
    // `audit_event` is *not* expected here (unlike `org_policy`/`scim_group`,
    // still plugin-less as of this task): Task 4's `auditLog` plugin
    // declares a `schema` for it (`src/server/audit/plugin.ts`), so
    // `runMigrations` above — which derives its DDL from `getAuthTables()`,
    // the same introspection a real `better-auth generate`/migration run
    // uses — already creates it, the same way it already creates `user`/
    // `organization` before this package's own migration adds `studio_ref`.
    expect(keys).toEqual(
      expect.arrayContaining([
        "org_policy",
        "scim_group",
        "user.studio_ref",
        "organization.studio_ref",
      ]),
    );
    expect(keys).not.toContain("audit_event");
    // and nothing else besides studio_ref is missing off `user`/`organization`
    // — the base upstream DDL already has every other tracked column.
    expect(missing.filter((m) => m.table === "user")).toEqual([
      { table: "user", column: "studio_ref" },
    ]);
  });

  it("reports ok:true once applyMigration has run on top of the upstream tables", async () => {
    const client = createClient({ url: ":memory:" });
    await runMigrations({ options: baseOptions() }, client);
    await applyMigration(client);

    const result = await verifyDatabase(client);

    expect(result).toEqual({ ok: true, missing: [] });
  });

  it("reports the 3 enterprise tables missing (not user/organization) on a totally empty db", async () => {
    const client = createClient({ url: ":memory:" });

    const { ok, missing } = await verifyDatabase(client);

    expect(ok).toBe(false);
    const tables = missing.map((m) => m.table);
    expect(tables).toEqual(
      expect.arrayContaining(["user", "organization", "org_policy", "audit_event", "scim_group"]),
    );
  });
});

describe("applyMigration", () => {
  it("is idempotent — running it twice does not throw and stays ok", async () => {
    const client = createClient({ url: ":memory:" });
    await runMigrations({ options: baseOptions() }, client);

    await expect(applyMigration(client)).resolves.toBeUndefined();
    await expect(applyMigration(client)).resolves.toBeUndefined();

    expect((await verifyDatabase(client)).ok).toBe(true);
  });

  it("does not throw when user/organization do not exist yet (skips the ALTER TABLE)", async () => {
    const client = createClient({ url: ":memory:" });

    await expect(applyMigration(client)).resolves.toBeUndefined();

    // our 3 own tables still get created even though user/organization don't exist
    const { missing } = await verifyDatabase(client);
    const tables = missing.map((m) => m.table);
    expect(tables).not.toContain("org_policy");
    expect(tables).not.toContain("audit_event");
    expect(tables).not.toContain("scim_group");
  });
});

describe("EXPECTED_TABLES drift guard", () => {
  // Tables that exist in any working better-auth deployment independent of
  // this package's plugins — deliberately not tracked by `verifyDatabase`
  // (see `src/schema/expected.ts`).
  const UNTRACKED_UPSTREAM_TABLES = new Set(["session", "account", "verification"]);

  it("matches a live getAuthTables() derivation, column-for-column", () => {
    const tables = getAuthTables(baseOptions());
    const live: Record<string, string[]> = {};
    for (const table of Object.values(tables)) {
      const cols = ["id"];
      for (const [key, field] of Object.entries(table.fields)) {
        cols.push(field.fieldName ?? key);
      }
      live[table.modelName] = cols;
    }

    const liveTrackedTableNames = Object.keys(live).filter(
      (t) => !UNTRACKED_UPSTREAM_TABLES.has(t),
    );
    const expectedUpstreamTableNames = Object.keys(EXPECTED_TABLES).filter((t) => t in live);
    expect(new Set(expectedUpstreamTableNames)).toEqual(new Set(liveTrackedTableNames));

    for (const table of expectedUpstreamTableNames) {
      // `user`/`organization` additionally carry `studio_ref` — our own
      // migration's column, not part of better-auth's field set.
      const expectedCols = EXPECTED_TABLES[table].filter((c) => c !== "studio_ref");
      expect(expectedCols).toEqual(live[table]);
    }
  });
});
