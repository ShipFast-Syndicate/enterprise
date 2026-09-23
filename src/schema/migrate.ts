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

export function migrationFilePath(file = "0001_enterprise.sql"): string {
  const here = dirname(fileURLToPath(import.meta.url));
  const candidates = [join(here, "sql", file), join(here, "..", "..", "sql", file)];
  const found = candidates.find((candidate) => existsSync(candidate));
  if (!found) {
    throw new Error(`${file} not found (looked in: ${candidates.join(", ")})`);
  }
  return found;
}

const ADD_COLUMN_STATEMENT = /^ALTER TABLE\s+"?(\w+)"?\s+ADD COLUMN\s+"?(\w+)"?/i;

type ScanState = "code" | "line-comment" | "block-comment" | "string";

// SQL-aware statement splitter: a small character scanner rather than
// regex-and-split, so it isn't fooled by a `;` (or `--`/`/*`) that's really
// inside a `--` line comment, a `/* ... */` block comment, or a
// single-quoted string literal (including a `''`-escaped quote within one)
// — all of which a future `NNNN_*.sql` migration could plausibly contain.
// Comments are dropped entirely from the returned statement text (not just
// ignored for splitting purposes) — cheap to do in the same pass, and it
// keeps `applyMigration`'s `ADD_COLUMN_STATEMENT` regex match (which
// assumes the statement starts with real SQL, not a comment) robust
// regardless of where a comment appears in the source file.
export function splitStatements(sql: string): string[] {
  const statements: string[] = [];
  let buf = "";
  let state: ScanState = "code";

  for (let i = 0; i < sql.length; i++) {
    const ch = sql[i];
    const next = sql[i + 1];

    if (state === "line-comment") {
      if (ch === "\n") state = "code";
      continue;
    }
    if (state === "block-comment") {
      if (ch === "*" && next === "/") {
        state = "code";
        i++;
      }
      continue;
    }
    if (state === "string") {
      buf += ch;
      if (ch === "'") {
        if (next === "'") {
          buf += next;
          i++;
        } else {
          state = "code";
        }
      }
      continue;
    }

    // state === "code"
    if (ch === "-" && next === "-") {
      state = "line-comment";
      i++;
      continue;
    }
    if (ch === "/" && next === "*") {
      state = "block-comment";
      i++;
      continue;
    }
    if (ch === "'") {
      state = "string";
      buf += ch;
      continue;
    }
    if (ch === ";") {
      const trimmed = buf.trim();
      if (trimmed.length > 0) statements.push(trimmed);
      buf = "";
      continue;
    }
    buf += ch;
  }

  const trailing = buf.trim();
  if (trailing.length > 0) statements.push(trailing);
  return statements;
}

async function tableInfo(client: Client, table: string) {
  const result = await client.execute(`PRAGMA table_info("${table}")`);
  return result.rows;
}

export async function applyMigration(client: Client): Promise<void> {
  const sql = ["0001_enterprise.sql", "0002_scim_1_7.sql"]
    .map((file) => readFileSync(migrationFilePath(file), "utf8"))
    .join("\n");

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
