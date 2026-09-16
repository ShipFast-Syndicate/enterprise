// Alpha Bros enterprise layer — database verification.
//
// Checks a live database against `EXPECTED_TABLES` via `PRAGMA
// table_info(<table>)`: a table with 0 rows back doesn't exist (SQLite
// returns an empty result set rather than an error for an unknown table,
// which is what lets this stay a plain read instead of needing try/catch
// per table); ruling (c) — a missing table reports `{ table }` only (column
// checks are skipped, there's nothing to check them against), a present
// table missing one of its tracked columns reports `{ table, column }` per
// missing column.
import type { Client } from "@libsql/client";
import { EXPECTED_TABLES } from "./expected";

export interface MissingItem {
  table: string;
  column?: string;
}

export interface VerifyResult {
  ok: boolean;
  missing: MissingItem[];
}

export async function verifyDatabase(client: Client): Promise<VerifyResult> {
  const missing: MissingItem[] = [];

  for (const [table, columns] of Object.entries(EXPECTED_TABLES)) {
    const info = await client.execute(`PRAGMA table_info("${table}")`);
    if (info.rows.length === 0) {
      missing.push({ table });
      continue;
    }
    const existingColumns = new Set(info.rows.map((row) => String(row.name)));
    for (const column of columns) {
      if (!existingColumns.has(column)) {
        missing.push({ table, column });
      }
    }
  }

  return { ok: missing.length === 0, missing };
}
