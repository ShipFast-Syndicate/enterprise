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

export async function applyMigrationPg(client: PgClient): Promise<void> {
  const sql = PG_MIGRATION_FILES.map((file) =>
    readFileSync(pgMigrationFilePath(file), "utf8"),
  ).join("\n");

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
