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
import { expectedTables } from "./expected";

import type { PgClient } from "./pg-client";
import { verifyDatabasePg } from "./verify-pg";

export interface MissingItem {
  table: string;
  column?: string;
  /** Postgres only: the column exists but is wrong (e.g. `jsonb` audit metadata). */
  reason?: string;
}

export interface VerifyResult {
  ok: boolean;
  missing: MissingItem[];
}

export interface VerifyOptions {
  /**
   * Also expect `org_entitlement` (optional migration `0004` / Postgres
   * `0002`) — for a deployment with `entitlements: { store: "table" }`.
   * Off by default, so a deployment that did not opt in verifies as before.
   */
  entitlements?: boolean;
}

/**
 * Verifies a SQLite/libSQL `Client` (unchanged) or, given a Postgres client
 * (anything with `query()` and no `execute()`: `pg`, PGlite), the same
 * contract through `information_schema` — see `verifyDatabasePg`.
 */
export async function verifyDatabase(
  client: Client,
  options?: VerifyOptions,
): Promise<VerifyResult>;
export async function verifyDatabase(
  client: PgClient,
  options?: VerifyOptions,
): Promise<VerifyResult>;
export async function verifyDatabase(
  client: Client | PgClient,
  options: VerifyOptions = {},
): Promise<VerifyResult> {
  if (!("execute" in client)) return verifyDatabasePg(client, options);
  const missing: MissingItem[] = [];

  for (const [table, columns] of Object.entries(expectedTables(options))) {
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
