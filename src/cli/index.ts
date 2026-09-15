// Alpha Bros enterprise layer — CLI entry point (ab-enterprise bin). tsup
// injects the `#!/usr/bin/env node` banner for this entry only (see
// tsup.config.ts). No CLI framework — `node:util`'s `parseArgs` per ruling
// (e).
//
// Commands:
//   ab-enterprise migrate --out <dir>   copy 0001_enterprise.sql into a
//                                        product's drizzle migrations folder
//                                        as the next-numbered NNNN_enterprise.sql
//   ab-enterprise verify [--url] [--token]
//                                        check a live database against
//                                        EXPECTED_TABLES, one line per
//                                        missing table/column; exit 1 if
//                                        anything is missing
//   ab-enterprise audit-verify --org <id> [--url] [--token]
//                                        verify an org's audit_event hash
//                                        chain; exit 0 if it verifies, 1 if
//                                        broken (prints brokenAtSeq)
import { parseArgs } from "node:util";
import { copyFileSync, existsSync, mkdirSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { createClient, type Row } from "@libsql/client";
import { verifyDatabase } from "../schema/verify";
import { migrationFilePath } from "../schema/migrate";
import { verifyChain, type AuditRow } from "../server/audit/chain";

const MIGRATION_FILE_RE = /^(\d{4})_.*\.sql$/;

function nextMigrationNumber(dir: string): string {
  if (!existsSync(dir)) {
    return "0000";
  }
  let highest = -1;
  for (const entry of readdirSync(dir)) {
    const match = MIGRATION_FILE_RE.exec(entry);
    if (match) {
      highest = Math.max(highest, Number(match[1]));
    }
  }
  return String(highest + 1).padStart(4, "0");
}

function cmdMigrate(argv: string[]): number {
  const { values } = parseArgs({
    args: argv,
    options: { out: { type: "string" } },
  });
  if (!values.out) {
    console.error("ab-enterprise migrate: --out <dir> is required");
    return 1;
  }
  const outDir = values.out;
  mkdirSync(outDir, { recursive: true });
  const dest = join(outDir, `${nextMigrationNumber(outDir)}_enterprise.sql`);
  copyFileSync(migrationFilePath(), dest);
  console.log(`ab-enterprise migrate: wrote ${dest}`);
  return 0;
}

async function cmdVerify(argv: string[]): Promise<number> {
  const { values } = parseArgs({
    args: argv,
    options: {
      url: { type: "string" },
      token: { type: "string" },
    },
  });
  const url = values.url ?? process.env.TURSO_DATABASE_URL;
  const token = values.token ?? process.env.TURSO_AUTH_TOKEN;
  if (!url) {
    console.error(
      "ab-enterprise verify: --url or TURSO_DATABASE_URL is required (auth token: --token or TURSO_AUTH_TOKEN)",
    );
    return 1;
  }

  const client = createClient(token ? { url, authToken: token } : { url });
  try {
    const { ok, missing } = await verifyDatabase(client);
    for (const item of missing) {
      console.log(
        item.column
          ? `missing column: ${item.table}.${item.column}`
          : `missing table: ${item.table}`,
      );
    }
    return ok ? 0 : 1;
  } finally {
    client.close();
  }
}

function rowToAuditRow(row: Row): AuditRow {
  return {
    id: String(row.id),
    orgId: String(row.org_id),
    seq: Number(row.seq),
    actorType: String(row.actor_type),
    actorId: row.actor_id === null ? null : String(row.actor_id),
    action: String(row.action),
    targetType: String(row.target_type),
    targetId: row.target_id === null ? null : String(row.target_id),
    ip: row.ip === null ? null : String(row.ip),
    userAgent: row.user_agent === null ? null : String(row.user_agent),
    metadata: JSON.parse(String(row.metadata ?? "{}")) as Record<string, unknown>,
    createdAt: Number(row.created_at),
    prevHash: String(row.prev_hash),
    hash: String(row.hash),
  };
}

async function cmdAuditVerify(argv: string[]): Promise<number> {
  const { values } = parseArgs({
    args: argv,
    options: {
      org: { type: "string" },
      url: { type: "string" },
      token: { type: "string" },
    },
  });
  if (!values.org) {
    console.error("ab-enterprise audit-verify: --org <id> is required");
    return 1;
  }
  const url = values.url ?? process.env.TURSO_DATABASE_URL;
  const token = values.token ?? process.env.TURSO_AUTH_TOKEN;
  if (!url) {
    console.error(
      "ab-enterprise audit-verify: --url or TURSO_DATABASE_URL is required (auth token: --token or TURSO_AUTH_TOKEN)",
    );
    return 1;
  }

  const client = createClient(token ? { url, authToken: token } : { url });
  try {
    const result = await client.execute({
      sql: `SELECT id, org_id, seq, actor_type, actor_id, action, target_type, target_id, ip, user_agent, metadata, created_at, prev_hash, hash FROM audit_event WHERE org_id = ? ORDER BY seq ASC`,
      args: [values.org],
    });
    const rows = result.rows.map(rowToAuditRow);
    const verdict = await verifyChain(rows);
    if (verdict.ok) {
      console.log(`audit-verify: chain ok (${rows.length} rows)`);
      return 0;
    }
    console.log(`audit-verify: chain broken at seq ${verdict.brokenAtSeq}`);
    return 1;
  } finally {
    client.close();
  }
}

async function main(): Promise<number> {
  const [command, ...rest] = process.argv.slice(2);
  switch (command) {
    case "migrate":
      return cmdMigrate(rest);
    case "verify":
      return cmdVerify(rest);
    case "audit-verify":
      return cmdAuditVerify(rest);
    case undefined:
      console.error("ab-enterprise: no command given");
      console.error(
        "usage: ab-enterprise migrate --out <dir> | verify [--url <url>] [--token <t>] | audit-verify --org <id> [--url <url>] [--token <t>]",
      );
      return 1;
    default:
      console.error(`ab-enterprise: unknown command "${command}"`);
      console.error(
        "usage: ab-enterprise migrate --out <dir> | verify [--url <url>] [--token <t>] | audit-verify --org <id> [--url <url>] [--token <t>]",
      );
      return 1;
  }
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (err: unknown) => {
    console.error(err instanceof Error ? err.message : String(err));
    process.exitCode = 1;
  },
);
