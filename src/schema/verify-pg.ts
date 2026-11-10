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

  return { ok: missing.length === 0, missing };
}
