// A throwaway Postgres for one `makeAuth()` (./auth.ts), plus the thin
// libsql-shaped client the suites' raw SQL runs through.
//
// Two backends behind one surface:
// - PGlite (default): a fresh in-process database per call.
// - a real Postgres (`TEST_DATABASE_URL`): a fresh schema per call, selected
//   with the connection's `search_path`, dropped on close. The pool allows
//   concurrent connections on purpose: the audit concurrency test needs
//   writers on separate connections.
//
// The raw-SQL client (`TestSqlClient`) keeps the suites' SQLite-written
// statements working unchanged where the meaning is the same on both engines:
//   - `?` placeholders become `$1, $2, …`;
//   - identifiers Postgres would fold to lower case (`"activeOrganizationId"`,
//     `scimManagedCredential`) or refuses bare (`user`) are quoted;
//   - result values come back in the shape SQLite gives: timestamps as epoch
//     milliseconds, booleans as 0/1, JSON and array columns as JSON text,
//     bigint as number.
// Anything the dialects genuinely disagree on (an integer bound to a
// `timestamptz`, a JSON string bound to a `text[]`) is handled in the suite
// itself with `ts()` / `isPg` from ./dialect.
import { randomUUID } from "node:crypto";
import { PGlite } from "@electric-sql/pglite";
import { drizzle as drizzleNodePostgres } from "drizzle-orm/node-postgres";
import { drizzle as drizzlePglite } from "drizzle-orm/pglite";
import pg from "pg";

export interface SqlStatement {
  sql: string;
  args?: unknown[];
}

export interface SqlResult {
  rows: Record<string, unknown>[];
  rowsAffected: number;
}

/** The slice of libsql's `Client` the suites use, answered by Postgres. */
export interface TestSqlClient {
  execute(statement: string | SqlStatement): Promise<SqlResult>;
  batch(statements: (string | SqlStatement)[], mode?: string): Promise<SqlResult[]>;
  close(): void;
}

interface RawResult {
  rows: Record<string, unknown>[];
  affected: number;
}

interface Runner {
  query(sql: string, params: unknown[]): Promise<RawResult>;
  /** Runs `body` on one connection inside BEGIN/COMMIT. */
  transaction<T>(body: (run: Runner["query"]) => Promise<T>): Promise<T>;
}

export interface PgTestDatabase {
  kind: "pglite" | "postgres";
  /** The raw driver, for `drizzle()`; a `PGlite` or a `pg.Pool`. */
  driver: PGlite | pg.Pool;
  /** `applyMigrationPg` / `verifyDatabase` client. */
  query(sql: string, params?: unknown[]): Promise<{ rows: unknown[] }>;
  drizzle<S extends Record<string, unknown>>(schema: S): unknown;
  /** Builds the libsql-shaped client over this database. */
  sqlClient(columns: ColumnKinds): TestSqlClient;
  close(): Promise<void>;
}

function normalize(value: unknown): unknown {
  if (value instanceof Date) return value.getTime();
  if (typeof value === "boolean") return value ? 1 : 0;
  if (typeof value === "bigint") return Number(value);
  if (value !== null && typeof value === "object") return JSON.stringify(value);
  return value;
}

function normalizeRows(rows: Record<string, unknown>[]): Record<string, unknown>[] {
  return rows.map((row) =>
    Object.fromEntries(Object.entries(row).map(([key, value]) => [key, normalize(value)])),
  );
}

/**
 * Rewrites one SQLite-flavoured statement for Postgres: `?` → `$n`, and
 * quotes the identifiers in `quoted`. String literals and already-quoted
 * identifiers are copied verbatim.
 */
export function toPostgres(sql: string, quoted: ReadonlySet<string>): string {
  let out = "";
  let param = 0;
  let i = 0;
  while (i < sql.length) {
    const char = sql[i]!;
    if (char === "'" || char === '"') {
      let j = i + 1;
      while (j < sql.length) {
        if (sql[j] === char) {
          if (sql[j + 1] === char) j += 2;
          else break;
        } else j++;
      }
      out += sql.slice(i, j + 1);
      i = j + 1;
    } else if (char === "?") {
      out += `$${++param}`;
      i++;
    } else if (/[A-Za-z_]/.test(char)) {
      let j = i + 1;
      while (j < sql.length && /\w/.test(sql[j]!)) j++;
      const word = sql.slice(i, j);
      out += quoted.has(word) ? `"${word}"` : word;
      i = j;
    } else {
      out += char;
      i++;
    }
  }
  return out;
}

/** What the test client needs to know about the schema to bind SQLite-shaped values. */
export interface ColumnKinds {
  /** Names to quote: mixed-case identifiers and the reserved `user`. */
  identifiers: Iterable<string>;
  /** Column name -> logical type, for the columns whose binding differs from SQLite. */
  kinds: Iterable<[string, "date" | "boolean" | "array"]>;
}

// Splits a VALUES list at its top-level commas.
function splitList(list: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let quote = "";
  let current = "";
  for (const char of list) {
    if (quote) {
      if (char === quote) quote = "";
    } else if (char === "'" || char === '"') quote = char;
    else if (char === "(") depth++;
    else if (char === ")") depth--;
    else if (char === "," && depth === 0) {
      parts.push(current.trim());
      current = "";
      continue;
    }
    current += char;
  }
  parts.push(current.trim());
  return parts;
}

const INSERT_ROW =
  /^\s*INSERT\s+(?:OR\s+\w+\s+)?INTO\s+"?\w+"?\s*\(([^)]*)\)\s*VALUES\s*\((.*)\)\s*$/is;
const COMPARISON = /"?(\w+)"?\s*(?:<=|>=|!=|<>|=|<|>)\s*\$(\d+)/g;

function sqlClientOver(runner: Runner, columns: ColumnKinds): TestSqlClient {
  const quoted = new Set(columns.identifiers);
  const kinds = new Map(columns.kinds);
  const bare = (column: string) => column.trim().replace(/^"|"$/g, "");

  // SQLite binds an epoch-millisecond integer, a 0/1 and a JSON string where
  // Postgres wants a timestamptz, a boolean and a text[]. The column an
  // argument lands in says which: an INSERT's column list, or `column <op> ?`.
  const prepare = (statement: string | SqlStatement) => {
    const { sql, args = [] } = typeof statement === "string" ? { sql: statement } : statement;
    let text = toPostgres(sql, quoted);
    const bound = [...args];
    const adapt = (index: number, kind: string | undefined) => {
      const value = bound[index];
      if (kind === "date" && typeof value === "number") bound[index] = new Date(value);
      else if (kind === "boolean" && typeof value === "number") bound[index] = value !== 0;
      else if (kind === "array" && typeof value === "string") bound[index] = JSON.parse(value);
    };
    const insert = INSERT_ROW.exec(text);
    if (insert) {
      const names = splitList(insert[1]!).map(bare);
      const values = splitList(insert[2]!);
      const rewritten = values.map((value, i) => {
        const kind = kinds.get(names[i] ?? "");
        const param = /^\$(\d+)$/.exec(value);
        if (param) adapt(Number(param[1]) - 1, kind);
        else if (kind === "boolean" && (value === "0" || value === "1")) {
          return value === "1" ? "true" : "false";
        }
        return value;
      });
      text = text.replace(insert[2]!, rewritten.join(", "));
    }
    for (const match of text.matchAll(COMPARISON)) {
      adapt(Number(match[2]) - 1, kinds.get(match[1]!));
    }
    // `boolean_column = 1` / `= 0` literals.
    for (const [name, kind] of kinds) {
      if (kind !== "boolean") continue;
      text = text.replace(
        new RegExp(String.raw`("?\b${name}\b"?\s*=\s*)([01])(?![\w.$])`, "g"),
        (_all, lhs: string, bit: string) => `${lhs}${bit === "1" ? "true" : "false"}`,
      );
    }
    return { text, args: bound };
  };
  const finish = (raw: RawResult): SqlResult => ({
    rows: normalizeRows(raw.rows),
    rowsAffected: raw.affected,
  });
  return {
    async execute(statement) {
      const { text, args } = prepare(statement);
      return finish(await runner.query(text, args));
    },
    async batch(statements) {
      const prepared = statements.map(prepare);
      return runner.transaction(async (run) => {
        const results: SqlResult[] = [];
        for (const { text, args } of prepared) results.push(finish(await run(text, args)));
        return results;
      });
    },
    close() {},
  };
}

function pgliteRunner(db: PGlite): Runner {
  const query = async (sql: string, params: unknown[]): Promise<RawResult> => {
    const result = await db.query<Record<string, unknown>>(sql, params);
    return { rows: result.rows, affected: result.affectedRows ?? 0 };
  };
  return {
    query,
    async transaction(body) {
      return db.transaction(async (tx) =>
        body(async (sql, params) => {
          const result = await tx.query<Record<string, unknown>>(sql, params);
          return { rows: result.rows, affected: result.affectedRows ?? 0 };
        }),
      );
    },
  };
}

function poolRunner(pool: pg.Pool): Runner {
  const fromResult = (result: pg.QueryResult): RawResult => ({
    rows: result.rows as Record<string, unknown>[],
    affected: result.rowCount ?? 0,
  });
  return {
    query: async (sql, params) => fromResult(await pool.query(sql, params)),
    async transaction(body) {
      const connection = await pool.connect();
      try {
        await connection.query("BEGIN");
        const result = await body(async (sql, params) =>
          fromResult(await connection.query(sql, params)),
        );
        await connection.query("COMMIT");
        return result;
      } catch (error) {
        await connection.query("ROLLBACK").catch(() => undefined);
        throw error;
      } finally {
        connection.release();
      }
    },
  };
}

// Booting a PGlite (WASM Postgres) costs ~0.7 s alone and several seconds when
// every worker of a full run does it at once, which is most of a suite's time.
// One instance per test file is kept and wiped between `makeAuth()` calls
// instead: dropping and recreating the `public` schema takes milliseconds. A
// second database opened while the first is still in use gets its own
// instance, so a test that builds two auth instances keeps them apart.
const idleInstances: PGlite[] = [];

async function resetPglite(db: PGlite): Promise<void> {
  await db.exec("DROP SCHEMA public CASCADE; CREATE SCHEMA public;");
}

async function openPglite(): Promise<PgTestDatabase> {
  const db = idleInstances.pop() ?? new PGlite();
  await db.waitReady;
  const runner = pgliteRunner(db);
  return {
    kind: "pglite",
    driver: db,
    query: async (sql, params = []) => ({ rows: (await runner.query(sql, params)).rows }),
    drizzle: (schema) => drizzlePglite(db, { schema }),
    sqlClient: (columns) => sqlClientOver(runner, columns),
    async close() {
      try {
        await resetPglite(db);
      } catch {
        // A database that cannot be wiped is not reused.
        await db.close().catch(() => undefined);
        return;
      }
      if (idleInstances.length === 0) idleInstances.push(db);
      else await db.close();
    },
  };
}

async function openPostgres(url: string): Promise<PgTestDatabase> {
  const schemaName = `ab_test_${randomUUID().replaceAll("-", "")}`;
  const admin = new pg.Pool({ connectionString: url, max: 1 });
  await admin.query(`CREATE SCHEMA "${schemaName}"`);
  const pool = new pg.Pool({
    connectionString: url,
    max: 12,
    options: `-c search_path=${schemaName}`,
  });
  const runner = poolRunner(pool);
  return {
    kind: "postgres",
    driver: pool,
    query: async (sql, params = []) => ({ rows: (await runner.query(sql, params)).rows }),
    drizzle: (schema) => drizzleNodePostgres({ client: pool, schema }),
    sqlClient: (columns) => sqlClientOver(runner, columns),
    async close() {
      await pool.end();
      try {
        await admin.query(`DROP SCHEMA "${schemaName}" CASCADE`);
      } finally {
        await admin.end();
      }
    },
  };
}

export function openPgTestDatabase(url: string | undefined): Promise<PgTestDatabase> {
  return url ? openPostgres(url) : openPglite();
}
