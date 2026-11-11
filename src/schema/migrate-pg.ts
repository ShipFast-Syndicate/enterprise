// Alpha Bros enterprise layer — Postgres migration runner.
//
// `applyMigrationPg` runs every `PG_MIGRATION_FILES` statement, in order,
// against a live Postgres client (`./pg-client`). The file is idempotent on
// its own (`IF NOT EXISTS` everywhere, no PRAGMA-style guard needed), so
// re-running it is a no-op. The one thing guarded here mirrors the SQLite
// runner: an `ALTER TABLE … ADD COLUMN` whose base table (`"user"`,
// `organization`) does not exist yet is skipped with a warning — this package
// layers onto an existing better-auth deployment — and `verifyDatabase`
// reports the missing column until the runner is re-run.
//
// Not transactional and not safe to run concurrently: see the header of
// `sql/pg/0001_enterprise.sql`. Run it once per deploy.
//
// `pgMigrationFilePath()` finds the SQL the same two ways `migrationFilePath`
// does: `src/schema/sql/pg/…` from source, `<pkg root>/sql/pg/…` once built.
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { splitStatements } from "./migrate";
import type { PgClient } from "./pg-client";

/** Every Postgres migration this package ships, in the order they apply. */
export const PG_MIGRATION_FILES = ["0001_enterprise.sql"] as const;

/**
 * Postgres migrations applied only on opt-in: `0002_org_entitlement.sql`, for
 * `entitlements: { store: "table" }` (`applyMigrationPg(client, { entitlements:
 * true })`). Not in `PG_MIGRATION_FILES`, so a deployment that does not opt in
 * is never asked to apply or verify it.
 */
export const OPTIONAL_PG_MIGRATION_FILES = ["0002_org_entitlement.sql"] as const;

export interface ApplyMigrationPgOptions {
  /** Also create `org_entitlement` (`0002`) — for `entitlements: { store: "table" }`. */
  entitlements?: boolean;
}

export function pgMigrationFilePath(file: string = PG_MIGRATION_FILES[0]): string {
  const here = dirname(fileURLToPath(import.meta.url));
  const candidates = [join(here, "sql", "pg", file), join(here, "..", "..", "sql", "pg", file)];
  const found = candidates.find((candidate) => existsSync(candidate));
  if (!found) {
    throw new Error(`pg/${file} not found (looked in: ${candidates.join(", ")})`);
  }
  return found;
}

const ADD_COLUMN_STATEMENT = /^ALTER TABLE\s+"?(\w+)"?\s+ADD COLUMN/i;

async function tableExists(client: PgClient, table: string): Promise<boolean> {
  const result = await client.query(
    "SELECT 1 FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = $1",
    [table],
  );
  return result.rows.length > 0;
}

export async function applyMigrationPg(
  client: PgClient,
  options: ApplyMigrationPgOptions = {},
): Promise<void> {
  const files = options.entitlements
    ? [...PG_MIGRATION_FILES, ...OPTIONAL_PG_MIGRATION_FILES]
    : PG_MIGRATION_FILES;
  const sql = files.map((file) => readFileSync(pgMigrationFilePath(file), "utf8")).join("\n");

  for (const statement of splitStatements(sql)) {
    const addColumn = ADD_COLUMN_STATEMENT.exec(statement);
    if (addColumn && !(await tableExists(client, addColumn[1]))) {
      console.warn(
        `applyMigrationPg: skipping "${statement}" — table "${addColumn[1]}" does not exist yet`,
      );
      continue;
    }
    await client.query(statement);
  }
}
