#!/usr/bin/env node
// Alpha Bros enterprise layer — CLI entry point (ab-enterprise bin). The
// `#!/usr/bin/env node` line above is part of this source file (esbuild
// preserves an entry point's hashbang verbatim) rather than a tsup `banner`,
// because `banner` is per-config and having a second tsup config object just
// for this entry raced with the first one's DTS pass — `dist/cli/index.d.ts`
// went missing from finished builds at random (see tsup.config.ts). No CLI
// framework — `node:util`'s `parseArgs` per ruling (e).
//
// Commands:
//   ab-enterprise migrate --out <dir>   write 0001_enterprise.sql into a
//                                        product's drizzle migrations folder
//                                        as the next-numbered NNNN_enterprise.sql,
//                                        and register it in meta/_journal.json
//                                        if the folder has one
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
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
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

// `--token` is visible in `ps` output and in shell history on any shared or
// CI host (L-06). It stays supported (some environments genuinely cannot set
// an env var), but every use now says so once, on stderr, so it never passes
// unnoticed in a CI log.
function resolveAuthToken(flagToken: string | undefined): string | undefined {
  if (flagToken) {
    console.error(
      "ab-enterprise: warning — --token is visible to other processes (ps) and in shell history; prefer TURSO_AUTH_TOKEN.",
    );
    return flagToken;
  }
  return process.env.TURSO_AUTH_TOKEN;
}

const STATEMENT_BREAKPOINT = "--> statement-breakpoint";

/**
 * Inserts drizzle's `--> statement-breakpoint` marker after every top-level
 * `;` (I-6).
 *
 * `drizzle-kit migrate` hands each `--> statement-breakpoint`-separated chunk
 * of a migration file to the driver as **one** statement
 * (`readMigrationFiles` in `node_modules/drizzle-orm/migrator.js` splits on
 * exactly that string, and the dialect then runs each piece through
 * `session.run(sql.raw(stmt))`). Without the markers the whole file arrives as
 * a single statement and libsql rejects it, so writing `breakpoints: true`
 * into the journal without them would be an over-claim.
 *
 * The marker is an ordinary SQL line comment, so the written file stays valid
 * for every other application path too — `applyMigration()` drops it in its
 * own splitter, and `turso db shell` ignores it.
 *
 * This is a scanner rather than `splitStatements()` (`../schema/migrate.ts`)
 * because that one *strips* comments by design, which would throw away the
 * migration file's own header explaining the `ALTER TABLE` re-run caveat. It
 * has to be comment- and string-aware for the same reason that one is: a `;`
 * inside a line comment, a block comment or a quoted literal is not a
 * statement terminator.
 */
export function insertStatementBreakpoints(sql: string): string {
  let out = "";
  let state: "code" | "line-comment" | "block-comment" | "string" = "code";

  for (let i = 0; i < sql.length; i++) {
    const ch = sql[i] as string;
    const next = sql[i + 1];
    out += ch;

    if (state === "line-comment") {
      if (ch === "\n") state = "code";
      continue;
    }
    if (state === "block-comment") {
      if (ch === "*" && next === "/") {
        out += next;
        i++;
        state = "code";
      }
      continue;
    }
    if (state === "string") {
      if (ch === "'") {
        if (next === "'") {
          out += next;
          i++;
        } else {
          state = "code";
        }
      }
      continue;
    }

    if (ch === "-" && next === "-") {
      out += next;
      i++;
      state = "line-comment";
      continue;
    }
    if (ch === "/" && next === "*") {
      out += next;
      i++;
      state = "block-comment";
      continue;
    }
    if (ch === "'") {
      state = "string";
      continue;
    }
    if (ch === ";") out += `\n${STATEMENT_BREAKPOINT}`;
  }

  // A marker after the *last* statement would leave drizzle with a trailing
  // whitespace-only chunk, which the driver rejects as an empty statement.
  return out.replace(new RegExp(`\\n${STATEMENT_BREAKPOINT}(\\s*)$`), "$1");
}

interface JournalEntry {
  idx: number;
  version: string;
  when: number;
  tag: string;
  breakpoints: boolean;
}

interface DrizzleJournal {
  entries?: JournalEntry[];
  [key: string]: unknown;
}

/**
 * Registers `tag` in a drizzle `meta/_journal.json`, if the target directory
 * has one (I-6).
 *
 * `drizzle-kit migrate` decides what to apply purely from that journal — it
 * reads `entries[].tag`, loads `<tag>.sql` next to it, and applies any entry
 * whose `when` is newer than the newest `created_at` already in
 * `__drizzle_migrations` (`node_modules/drizzle-orm/migrator.js` +
 * `sqlite-core/dialect.js`). A hand-dropped `.sql` with no journal entry is
 * silently skipped, which given the fleet's history of migrations not reaching
 * Turso is exactly the failure this package's `verify` command exists to
 * catch. Nothing in the migrator reads `meta/<NNNN>_snapshot.json` — that file
 * is `drizzle-kit generate`'s own input for diffing the next migration, not a
 * requirement for `migrate` — so none is written.
 *
 * Returns the journal path if an entry was added, else `null`.
 */
function appendJournalEntry(outDir: string, tag: string): string | null {
  const journalPath = join(outDir, "meta", "_journal.json");
  if (!existsSync(journalPath)) return null;

  const journal = JSON.parse(readFileSync(journalPath, "utf8")) as DrizzleJournal;
  const entries = Array.isArray(journal.entries) ? journal.entries : [];
  if (entries.some((entry) => entry.tag === tag)) return null;

  const highestIdx = entries.reduce(
    (max, entry) => (typeof entry.idx === "number" ? Math.max(max, entry.idx) : max),
    -1,
  );
  entries.push({
    idx: highestIdx + 1,
    // drizzle's sqlite snapshot version. The migrator never reads it (only
    // `tag` and `when`); it is written so the entry matches the shape
    // `drizzle-kit` itself produces and its own tooling stays happy.
    version: "6",
    // Newer than every `created_at` already recorded in
    // `__drizzle_migrations`, which is what makes the migrator pick it up.
    when: Date.now(),
    tag,
    breakpoints: true,
  });
  journal.entries = entries;
  writeFileSync(journalPath, `${JSON.stringify(journal, null, 2)}\n`);
  return journalPath;
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
  const tag = `${nextMigrationNumber(outDir)}_enterprise`;
  const dest = join(outDir, `${tag}.sql`);
  writeFileSync(dest, insertStatementBreakpoints(readFileSync(migrationFilePath(), "utf8")));
  console.log(`ab-enterprise migrate: wrote ${dest}`);

  const journalPath = appendJournalEntry(outDir, tag);
  if (journalPath) {
    console.log(`ab-enterprise migrate: registered ${tag} in ${journalPath}`);
  } else {
    console.log(
      `ab-enterprise migrate: no drizzle meta/_journal.json in ${outDir} — apply it with applyMigration() from @alphabros/enterprise/schema, or your own SQL runner`,
    );
  }
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
  const token = resolveAuthToken(values.token);
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
  const token = resolveAuthToken(values.token);
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
