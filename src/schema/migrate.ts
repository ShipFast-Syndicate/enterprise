// Alpha Bros enterprise layer — migration runner.
//
// `applyMigration` executes `sql/0001_enterprise.sql`'s statements against
// a live client. The `CREATE TABLE`/`CREATE INDEX` statements are plain
// `IF NOT EXISTS` and safe to re-run as-is; the two `ALTER TABLE … ADD
// COLUMN studio_ref` statements are not — SQLite has no `ADD COLUMN IF NOT
// EXISTS` — so each is guarded here with a `PRAGMA table_info` check first
// (ruling (d)). The same guard covers a base table (`user`/`organization`)
// not existing yet: this package layers onto an existing better-auth
// deployment, so its own migrations may run before the app's; that's not a
// failure, just a statement to skip until the app's migrations create the
// table and `applyMigration` is re-run.
//
// `migrationFilePath()` locates the checked-in SQL file at runtime from
// either layout the package can be loaded from: `src/schema/sql/…` when
// this module runs straight from source (tests, via vitest's TS
// resolution) or `<pkg root>/sql/…` once built — `tsup` bundles this
// module into `dist/schema/index.js` and `dist/cli/index.js`, and `pnpm
// build`'s `cp -R src/schema/sql sql` step (see package.json) places the
// SQL file at the package root, two directories up from either bundle
// (`dist/schema/../..` / `dist/cli/../..`). Both candidates are checked
// rather than branching on an environment flag, so this keeps working
// regardless of how the module got loaded.
import type { Client } from "@libsql/client";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export function migrationFilePath(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  const candidates = [
    join(here, "sql", "0001_enterprise.sql"),
    join(here, "..", "..", "sql", "0001_enterprise.sql"),
  ];
  const found = candidates.find((candidate) => existsSync(candidate));
  if (!found) {
    throw new Error(`0001_enterprise.sql not found (looked in: ${candidates.join(", ")})`);
  }
  return found;
}

const ADD_COLUMN_STATEMENT = /^ALTER TABLE\s+"?(\w+)"?\s+ADD COLUMN\s+"?(\w+)"?/i;

function stripLineComments(sql: string): string {
  return sql
    .split("\n")
    .filter((line) => !line.trim().startsWith("--"))
    .join("\n");
}

function splitStatements(sql: string): string[] {
  return stripLineComments(sql)
    .split(";")
    .map((statement) => statement.trim())
    .filter((statement) => statement.length > 0);
}

async function tableInfo(client: Client, table: string) {
  const result = await client.execute(`PRAGMA table_info("${table}")`);
  return result.rows;
}

export async function applyMigration(client: Client): Promise<void> {
  const sql = readFileSync(migrationFilePath(), "utf8");

  for (const statement of splitStatements(sql)) {
    const addColumn = ADD_COLUMN_STATEMENT.exec(statement);
    if (!addColumn) {
      await client.execute(statement);
      continue;
    }

    const [, table, column] = addColumn;
    const rows = await tableInfo(client, table);
    if (rows.length === 0) {
      // Base table doesn't exist yet — not this package's job to create it.
      console.warn(`applyMigration: skipping "${statement}" — table "${table}" does not exist yet`);
      continue;
    }
    const alreadyApplied = rows.some((row) => String(row.name) === column);
    if (alreadyApplied) {
      continue;
    }
    await client.execute(statement);
  }
}
