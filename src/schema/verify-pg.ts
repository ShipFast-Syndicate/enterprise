// Alpha Bros enterprise layer — Postgres database verification.
//
// Same contract as the SQLite `verifyDatabase`, read from
// `information_schema.columns` for the connection's current schema. A product
// may name its better-auth tables and columns camelCase or snake_case
// (drizzle `casing: "snake_case"`, the better-auth CLI), so each expected
// name matches as-is, snake_cased, or lower-cased. Reported items always use
// the `EXPECTED_TABLES` name.
//
// One type check on top of presence: `audit_event.metadata` must be `json`.
// `jsonb` re-orders keys, which breaks the audit hash chain, and a product
// that regenerates its schema with the better-auth CLI gets `jsonb` back
// without noticing.
//
// And one uniqueness check: the unique indexes the migration creates
// (`audit_event (org_id, seq)`, `org_policy (org_id)`,
// `enterprise_scim_member (member_id)`) must exist. The audit hash chain
// depends on `(org_id, seq)` being unique; a product that created the table
// itself without the index would otherwise verify clean. Any non-partial
// unique index or constraint over exactly those columns counts, whatever its name.
import { EXPECTED_TABLES } from "./expected";
import type { PgClient } from "./pg-client";
import type { VerifyResult, MissingItem } from "./verify";

function snakeCase(name: string): string {
  return name.replace(/([a-z0-9])([A-Z])/g, "$1_$2").toLowerCase();
}

function candidates(name: string): string[] {
  return [...new Set([name, snakeCase(name), name.toLowerCase()])];
}

interface ColumnRow {
  table_name: string;
  column_name: string;
  data_type: string;
}

/** Unique indexes the migration creates; a missing one is reported with a `reason`. */
const EXPECTED_UNIQUES: ReadonlyArray<{ table: string; columns: readonly string[] }> = [
  { table: "audit_event", columns: ["org_id", "seq"] },
  { table: "org_policy", columns: ["org_id"] },
  { table: "enterprise_scim_member", columns: ["member_id"] },
];

interface UniqueRow {
  table_name: string;
  cols: string;
}

const UNIQUES_QUERY = `SELECT t.relname AS table_name, string_agg(a.attname, ',' ORDER BY k.ord) AS cols
FROM pg_index i
JOIN pg_class t ON t.oid = i.indrelid
JOIN pg_namespace n ON n.oid = t.relnamespace
CROSS JOIN LATERAL unnest(i.indkey) WITH ORDINALITY AS k(attnum, ord)
JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = k.attnum
WHERE i.indisunique AND i.indpred IS NULL AND n.nspname = current_schema()
GROUP BY i.indexrelid, t.relname`;

export async function verifyDatabasePg(client: PgClient): Promise<VerifyResult> {
  const { rows } = await client.query(
    "SELECT table_name, column_name, data_type FROM information_schema.columns WHERE table_schema = current_schema()",
  );
  const tables = new Map<string, Map<string, string>>();
  for (const row of rows as ColumnRow[]) {
    const columns = tables.get(row.table_name) ?? new Map<string, string>();
    columns.set(row.column_name, row.data_type);
    tables.set(row.table_name, columns);
  }

  const missing: MissingItem[] = [];
  for (const [table, expected] of Object.entries(EXPECTED_TABLES)) {
    const found = candidates(table).find((name) => tables.has(name));
    const existing = found ? tables.get(found) : undefined;
    if (!existing) {
      missing.push({ table });
      continue;
    }
    for (const column of expected) {
      const name = candidates(column).find((candidate) => existing.has(candidate));
      if (!name) {
        missing.push({ table, column });
      } else if (
        table === "audit_event" &&
        column === "metadata" &&
        existing.get(name) !== "json"
      ) {
        missing.push({
          table,
          column,
          reason: `type is ${existing.get(name)}, expected json (jsonb re-orders keys and breaks the audit hash chain)`,
        });
      }
    }
  }

  const { rows: uniqueRows } = await client.query(UNIQUES_QUERY);
  const uniques = new Map<string, Set<string>>();
  for (const row of uniqueRows as UniqueRow[]) {
    const set = uniques.get(row.table_name) ?? new Set<string>();
    set.add(row.cols);
    uniques.set(row.table_name, set);
  }
  for (const { table, columns } of EXPECTED_UNIQUES) {
    const found = candidates(table).find((name) => tables.has(name));
    if (!found) continue; // already reported as a missing table
    const existing = tables.get(found)!;
    const resolved = columns.map(
      (column) => candidates(column).find((candidate) => existing.has(candidate)) ?? column,
    );
    if (!uniques.get(found)?.has(resolved.join(","))) {
      missing.push({
        table,
        reason: `no unique index on (${columns.join(", ")})${
          table === "audit_event" ? ", which the audit hash chain depends on" : ""
        }`,
      });
    }
  }

  return { ok: missing.length === 0, missing };
}
