// Alpha Bros enterprise layer — the ab-enterprise commands. `./index.ts` is
// the bin entry point (it carries the `#!/usr/bin/env node` line, which
// esbuild preserves verbatim for an entry point rather than a tsup `banner`:
// `banner` is per-config and having a second tsup config object just for the
// CLI raced with the first one's DTS pass — `dist/cli/index.d.ts` went missing
// from finished builds at random, see tsup.config.ts) and only runs `main()`;
// the commands live here so a test can call `main()` in process. No CLI
// framework — `node:util`'s `parseArgs` per ruling (e).
//
// Commands:
//   --dialect sqlite|pg (every command; default sqlite): pg runs the Postgres
//                                        variant. A postgres:// / postgresql:// URL
//                                        in --url / TURSO_DATABASE_URL (or, with
//                                        neither set, AB_DATABASE_URL /
//                                        DATABASE_URL) selects pg by itself. The
//                                        Postgres URL carries credentials, so it
//                                        is read from AB_DATABASE_URL, DATABASE_URL
//                                        or TURSO_DATABASE_URL and never from argv
//                                        (--url is accepted only without a
//                                        password); with --dialect pg and no URL
//                                        the PG* variables apply. Needs the `pg`
//                                        package (an optional peer). pg migrate
//                                        emits sql/pg (0001; --entitlements adds
//                                        0002 org_entitlement); pg verify also
//                                        checks audit_event.metadata is json and
//                                        the unique indexes; pg audit-verify reads
//                                        json metadata as objects and timestamptz
//                                        created_at as Dates.
//   ab-enterprise migrate --out <dir> [--from <NNNN>] [--entitlements]
//                                        write every package migration the
//                                        folder does not hold yet (0001, 0002,
//                                        0003, ...; with --from, only those
//                                        numbered NNNN or later) into a
//                                        product's drizzle migrations folder
//                                        as next-numbered NNNN_enterprise*.sql
//                                        files, and register each in
//                                        meta/_journal.json if the folder has
//                                        one; a folder an earlier release
//                                        wrote (0001 only) needs --from 0003
//                                        (from 1.0.x) or --from 0002 (from
//                                        0.1.x without 0002 applied).
//                                        --entitlements (or --from 0004) also
//                                        writes the optional 0004
//                                        (org_entitlement), for a deployment
//                                        with entitlements: { store: "table" };
//                                        a plain run, and --from 0003, never do
//   ab-enterprise verify [--url] [--token] [--entitlements]
//                                        check a live database against
//                                        EXPECTED_TABLES, one line per
//                                        missing table/column; exit 1 if
//                                        anything is missing. --entitlements
//                                        also expects org_entitlement
//   ab-enterprise audit-verify --org <id> [--url] [--token]
//                              [--expect-head <seq>:<hash> | <head JSON>]
//                                        verify an org's audit_event hash
//                                        chain; exit 0 if it verifies, 1 if
//                                        broken (prints brokenAtSeq). A keyed
//                                        chain (audit.chainKey) is verified
//                                        with the key from AB_AUDIT_CHAIN_KEY
//                                        (never argv). --expect-head: the
//                                        chain must still hold the row an
//                                        earlier GET /enterprise/audit/head
//                                        reported (same seq, same hash;
//                                        with its signature checked under
//                                        the key when one is given)
import { parseArgs } from "node:util";
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createClient, type Row } from "@libsql/client";
import { verifyDatabase } from "../schema/verify";
import { MIGRATION_FILES, OPTIONAL_MIGRATION_FILES, migrationFilePath } from "../schema/migrate";
import {
  OPTIONAL_PG_MIGRATION_FILES,
  PG_MIGRATION_FILES,
  pgMigrationFilePath,
} from "../schema/migrate-pg";
import { verifyDatabasePg } from "../schema/verify-pg";
import {
  AUDIT_ROWS_SQL_PG,
  AUDIT_ROWS_SQL_SQLITE,
  prepareExpectedHead,
  toAuditRow,
  verifyAuditRows,
  type AuditVerifyOutcome,
} from "./audit";
import { openPgClient, selectDialect, type CliDialect, type OpenPgClient } from "./pg";

/**
 * The migrations of one dialect: the files `migrate` emits (optional ones
 * last — only a plain `migrate` / `verify` leaves them out, `--entitlements`
 * opts in), where each is read from, and the drizzle snapshot version its
 * journal entries carry.
 */
interface MigrationSet {
  dialect: CliDialect;
  files: readonly string[];
  optional: readonly string[];
  all: readonly string[];
  pathOf: (file: string) => string;
  journalVersion: string;
}

const SQLITE_SET: MigrationSet = {
  dialect: "sqlite",
  files: MIGRATION_FILES,
  optional: OPTIONAL_MIGRATION_FILES,
  all: [...MIGRATION_FILES, ...OPTIONAL_MIGRATION_FILES],
  pathOf: migrationFilePath,
  journalVersion: "6",
};

const PG_SET: MigrationSet = {
  dialect: "pg",
  files: PG_MIGRATION_FILES,
  optional: OPTIONAL_PG_MIGRATION_FILES,
  all: [...PG_MIGRATION_FILES, ...OPTIONAL_PG_MIGRATION_FILES],
  pathOf: pgMigrationFilePath,
  journalVersion: "7",
};

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
function resolveAuthToken(
  flagToken: string | undefined,
  env: NodeJS.ProcessEnv,
): string | undefined {
  if (flagToken) {
    console.error(
      "ab-enterprise: warning — --token is visible to other processes (ps) and in shell history; prefer TURSO_AUTH_TOKEN.",
    );
    return flagToken;
  }
  return env.TURSO_AUTH_TOKEN;
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
  // chunk holding no statement — whitespace, or only comments (`0002` ends
  // with a note) — which the driver rejects as an empty statement.
  const marker = `\n${STATEMENT_BREAKPOINT}`;
  const last = out.lastIndexOf(marker);
  if (last === -1) return out;
  const tail = out.slice(last + marker.length);
  const tailCode = tail
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/--[^\n]*/g, "")
    .trim();
  return tailCode === "" ? out.slice(0, last) + tail : out;
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
function appendJournalEntry(
  outDir: string,
  tag: string,
  when: number,
  version: string,
): string | null {
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
    // drizzle's snapshot version for the dialect ("6" sqlite, "7" pg). The
    // migrator never reads it (only `tag` and `when`); it is written so the
    // entry matches the shape `drizzle-kit` itself produces and its own
    // tooling stays happy.
    version,
    // Newer than every `created_at` already recorded in
    // `__drizzle_migrations`, which is what makes the migrator pick it up
    // (and strictly increasing across the files one run writes).
    when,
    tag,
    breakpoints: true,
  });
  journal.entries = entries;
  writeFileSync(journalPath, `${JSON.stringify(journal, null, 2)}\n`);
  return journalPath;
}

/**
 * The newest `when` in the folder's drizzle journal (`-Infinity` without
 * one). The migrator applies an entry only when its `when` is newer than the
 * newest migration it has already recorded, and a product's journal can hold
 * hand-set `when` values ahead of the clock — so the entries this command
 * adds start after the newest one there, not merely at "now".
 */
function newestJournalWhen(outDir: string): number {
  const journalPath = join(outDir, "meta", "_journal.json");
  if (!existsSync(journalPath)) return -Infinity;
  const journal = JSON.parse(readFileSync(journalPath, "utf8")) as DrizzleJournal;
  const entries = Array.isArray(journal.entries) ? journal.entries : [];
  return entries.reduce(
    (max, entry) => (typeof entry.when === "number" ? Math.max(max, entry.when) : max),
    -Infinity,
  );
}

/**
 * The name suffix a package migration is emitted under, after the target
 * folder's next free `NNNN_` prefix. `0001` keeps the historic bare
 * `enterprise` suffix — the only file earlier releases of this command wrote —
 * so a folder that already holds it is recognised; the later ones carry their
 * own file stem (`enterprise_0002_scim_1_7`, `enterprise_0003_require2fa`).
 */
function emittedSuffix(file: string, set: MigrationSet): string {
  return file === set.files[0] ? "enterprise" : `enterprise_${file.replace(/\.sql$/, "")}`;
}

/** A package migration's own number — the `NNNN` of `NNNN_name.sql`. */
function migrationNumber(file: string): string {
  return file.slice(0, 4);
}

/**
 * Whether `entry` carries the name this command gives package migration
 * `file`: `NNNN_<emittedSuffix>.sql`, the suffix compared exactly.
 */
function hasEmittedName(entry: string, file: string, set: MigrationSet): boolean {
  const match = /^\d{4}_(.+)\.sql$/.exec(entry);
  return match !== null && match[1] === emittedSuffix(file, set);
}

/** A migration's text with drizzle's breakpoint markers removed — what this command inserted them into. */
function withoutBreakpoints(sql: string): string {
  return sql.split(`\n${STATEMENT_BREAKPOINT}`).join("").trimEnd();
}

/**
 * Whether `entry` (a file in the target folder) is **provably** package
 * migration `file` as this command writes it: its name is the one this
 * command gives that migration (`NNNN_<emittedSuffix>.sql`) **and** its
 * content, breakpoint markers aside, is the package file's own. Every release
 * of this command wrote exactly that (`0001` has not changed since 0.1.0), so
 * a folder it wrote into is recognised; nothing else is — not a product's own
 * migration that created the same tables under another name (a product's
 * own `NNNN_enterprise_pilot.sql`), not a hand-edited copy under the emitted
 * name. The command cannot prove what such a file applied, so it never
 * guesses: see `cmdMigrate` for what it does instead.
 */
function isEmissionOf(outDir: string, entry: string, file: string, set: MigrationSet): boolean {
  if (!hasEmittedName(entry, file, set)) return false;
  const emitted = readFileSync(join(outDir, entry), "utf8");
  const source = readFileSync(set.pathOf(file), "utf8");
  return withoutBreakpoints(emitted) === withoutBreakpoints(source);
}

type EmissionState =
  { kind: "absent" } | { kind: "present"; entry: string } | { kind: "conflict"; entry: string };

/**
 * `present` when the folder holds a proven emission of `file`
 * (`isEmissionOf`); `conflict` when a file carries the name this command
 * gives `file` but not its content (hand-edited, or not written by this
 * command) — the command stops rather than guess; `absent` otherwise.
 */
function emissionState(outDir: string, file: string, set: MigrationSet): EmissionState {
  if (!existsSync(outDir)) return { kind: "absent" };
  const named = readdirSync(outDir).filter((entry) => hasEmittedName(entry, file, set));
  const proven = named.find((entry) => isEmissionOf(outDir, entry, file, set));
  if (proven) return { kind: "present", entry: proven };
  if (named[0]) return { kind: "conflict", entry: named[0] };
  return { kind: "absent" };
}

/**
 * `.sql` files in the folder whose name mentions `enterprise` but that are
 * not a proven emission of any package migration — typically the migration
 * a product wrote itself when it first adopted this package (e.g. a
 * hand-written `NNNN_enterprise_pilot.sql`, possibly followed by its own copy
 * of `0002`). Its tables are already in the database; emitting `0001`/`0002` next to
 * it would re-run their `ALTER TABLE`s and fail the product's migrator.
 */
function unprovenEnterpriseFiles(outDir: string, set: MigrationSet): string[] {
  if (!existsSync(outDir)) return [];
  return readdirSync(outDir).filter(
    (entry) =>
      /\.sql$/.test(entry) &&
      /enterprise/i.test(entry) &&
      !set.all.some((file) => isEmissionOf(outDir, entry, file, set)),
  );
}

/**
 * Writes the package migrations (`MIGRATION_FILES`) the folder does not hold
 * yet, each as its own next-numbered file registered in the drizzle journal,
 * in order — so running it again after an upgrade adds exactly the
 * migrations that release brought, and a second run writes nothing.
 *
 * `--from <NNNN>` limits the run to package migrations numbered `NNNN` or
 * later. It is how a product whose package tables came from **its own**
 * migration upgrades: it already holds what `0001`/`0002` create, under a
 * name this command cannot prove (`isEmissionOf`), so it runs
 * `--from 0003` and gets exactly the one file it lacks.
 *
 * Without `--from`, a folder holding such an unproven `*enterprise*.sql` file
 * is refused (exit 1, nothing written): the command recognises nothing it
 * cannot prove, and emitting every migration next to that file would fail
 * the product's migrator on the first `ALTER TABLE` it re-runs. A file under
 * the emitted name but with other content is refused whatever `--from` says.
 *
 * Without `--from`, a folder holding a proven emission of `0001` but none of
 * `0002` is refused too (exit 1, nothing written). Releases up to 1.0.x
 * wrote `0001` only, and the 1.0.0 upgrade guide (`docs/migration-1-7.md`
 * step 4) had `0002` applied outside this folder — through `applyMigration()`
 * or a product migration of its own name — so the folder cannot show whether
 * `0002`'s `ALTER TABLE org_policy ADD COLUMN id` already ran. From 1.0.x it
 * did: `--from 0003`. From 0.1.x, where it never ran: `--from 0002`.
 */
function cmdMigrate(argv: string[]): number {
  const { values } = parseArgs({
    args: argv,
    options: {
      out: { type: "string" },
      from: { type: "string" },
      entitlements: { type: "boolean" },
      dialect: { type: "string" },
    },
  });
  if (!values.out) {
    console.error("ab-enterprise migrate: --out <dir> is required");
    return 1;
  }
  const requested = values.dialect === "postgres" ? "pg" : values.dialect;
  if (requested !== undefined && requested !== "sqlite" && requested !== "pg") {
    console.error(
      `ab-enterprise migrate: --dialect must be "sqlite" or "pg" (got "${values.dialect}")`,
    );
    return 1;
  }
  const set = requested === "pg" ? PG_SET : SQLITE_SET;
  const numbers = set.files.map(migrationNumber);
  const optionalNumbers: readonly string[] = set.optional.map(migrationNumber);
  const from = values.from;
  if (from !== undefined && !numbers.includes(from) && !optionalNumbers.includes(from)) {
    console.error(
      `ab-enterprise migrate: --from must be one of this package's migration numbers (${numbers.join(", ")}), or an optional one (${optionalNumbers.join(", ")}), got "${from}"`,
    );
    return 1;
  }
  const outDir = values.out;
  mkdirSync(outDir, { recursive: true });

  // The optional migrations are written only on request: `--entitlements`, or
  // a `--from` that names an optional migration itself (`--from 0004`). A
  // `--from 0003` upgrade from 1.0.x does not pick them up.
  const withOptional =
    values.entitlements === true || (from !== undefined && optionalNumbers.includes(from));
  const selected = set.all.filter(
    (file) =>
      (from === undefined || migrationNumber(file) >= from) &&
      (withOptional || !optionalNumbers.includes(migrationNumber(file))),
  );
  for (const file of selected) {
    const state = emissionState(outDir, file, set);
    if (state.kind === "conflict") {
      console.error(
        `ab-enterprise migrate: ${state.entry} has the name this command gives ${file} but not its content — nothing written. Restore it from this package or remove it (and its meta/_journal.json entry) before running again.`,
      );
      return 1;
    }
  }

  if (from === undefined) {
    const unproven = unprovenEnterpriseFiles(outDir, set);
    if (unproven.length > 0) {
      console.error(
        `ab-enterprise migrate: ${outDir} holds ${unproven.join(", ")}, which this command did not write — it cannot tell which package migrations that applied. Nothing written. If it created the package tables (a product's own enterprise migration), run again with --from <the first package migration it lacks>, e.g. --from ${numbers[numbers.length - 1]}.`,
      );
      return 1;
    }

    // SQLite only: Postgres has no release that wrote 0001 alone, and its 0002
    // is the optional entitlement table, not a core migration.
    if (set === SQLITE_SET) {
      const first = emissionState(outDir, MIGRATION_FILES[0], set);
      const second = emissionState(outDir, MIGRATION_FILES[1], set);
      if (first.kind === "present" && second.kind === "absent") {
        console.error(
          `ab-enterprise migrate: ${outDir} holds ${first.entry}, this command's emission of package migration 0001, but no emission of 0002 — releases up to 1.0.x wrote 0001 only, and the 1.0.0 upgrade guide applied 0002 through applyMigration() or a product migration, so this folder cannot show whether it ran. Nothing written. Upgrading from 1.0.x: run again with --from 0003. Upgrading from 0.1.x, where 0002 was never applied: run again with --from 0002.`,
        );
        return 1;
      }
    }
  }

  let when = Math.max(Date.now(), newestJournalWhen(outDir) + 1);
  let written = 0;
  let journalPath: string | null = null;
  for (const file of selected) {
    const state = emissionState(outDir, file, set);
    if (state.kind === "present") {
      console.log(`ab-enterprise migrate: ${file} already present as ${state.entry} — skipped`);
      continue;
    }
    const tag = `${nextMigrationNumber(outDir)}_${emittedSuffix(file, set)}`;
    const dest = join(outDir, `${tag}.sql`);
    writeFileSync(dest, insertStatementBreakpoints(readFileSync(set.pathOf(file), "utf8")));
    console.log(`ab-enterprise migrate: wrote ${dest}`);
    const registered = appendJournalEntry(outDir, tag, when++, set.journalVersion);
    if (registered) {
      journalPath = registered;
      console.log(`ab-enterprise migrate: registered ${tag} in ${registered}`);
    }
    written++;
  }

  if (written === 0) {
    console.log(
      `ab-enterprise migrate: ${outDir} already holds every migration${from === undefined ? "" : ` from ${from}`} — nothing written`,
    );
  } else if (!journalPath) {
    console.log(
      `ab-enterprise migrate: no drizzle meta/_journal.json in ${outDir} — apply the files in order with ${set === PG_SET ? "applyMigrationPg()" : "applyMigration()"} from @alphabros/enterprise/schema, or your own SQL runner`,
    );
  }
  return 0;
}

/** A `--token` has no meaning for Postgres: its credentials are in the URL, from the environment. */
function refusePgToken(command: string, token: string | undefined): string | null {
  return token === undefined
    ? null
    : `ab-enterprise ${command}: --token is for libSQL/Turso; a Postgres URL carries its own credentials (from the environment)`;
}

async function cmdVerify(argv: string[], deps: CliDeps): Promise<number> {
  const { values } = parseArgs({
    args: argv,
    options: {
      url: { type: "string" },
      token: { type: "string" },
      entitlements: { type: "boolean" },
      dialect: { type: "string" },
    },
  });
  const selection = selectDialect("verify", values, deps.env);
  if ("error" in selection) {
    console.error(selection.error);
    return 1;
  }
  if (selection.dialect === "pg") {
    const refused = refusePgToken("verify", values.token);
    if (refused) {
      console.error(refused);
      return 1;
    }
    const client = await deps.openPg(selection.url);
    try {
      const { ok, missing } = await verifyDatabasePg(client, {
        entitlements: values.entitlements === true,
      });
      for (const item of missing) {
        const subject = item.column ? `${item.table}.${item.column}` : item.table;
        console.log(
          item.reason
            ? `problem: ${subject}: ${item.reason}`
            : item.column
              ? `missing column: ${subject}`
              : `missing table: ${item.table}`,
        );
      }
      return ok ? 0 : 1;
    } finally {
      await client.close();
    }
  }

  const url = selection.url;
  const token = resolveAuthToken(values.token, deps.env);
  if (!url) {
    console.error(
      "ab-enterprise verify: --url or TURSO_DATABASE_URL is required (auth token: --token or TURSO_AUTH_TOKEN)",
    );
    return 1;
  }

  const client = createClient(token ? { url, authToken: token } : { url });
  try {
    const { ok, missing } = await verifyDatabase(client, {
      entitlements: values.entitlements === true,
    });
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

function printOutcome(outcome: AuditVerifyOutcome): number {
  if (outcome.usage) console.error(outcome.message);
  else console.log(outcome.message);
  return outcome.code;
}

async function cmdAuditVerify(argv: string[], deps: CliDeps): Promise<number> {
  const { values } = parseArgs({
    args: argv,
    options: {
      org: { type: "string" },
      url: { type: "string" },
      token: { type: "string" },
      "expect-head": { type: "string" },
      dialect: { type: "string" },
    },
  });
  if (!values.org) {
    console.error("ab-enterprise audit-verify: --org <id> is required");
    return 1;
  }
  const org = values.org;
  const selection = selectDialect("audit-verify", values, deps.env);
  if ("error" in selection) {
    console.error(selection.error);
    return 1;
  }
  const pg = selection.dialect === "pg";
  if (pg) {
    const refused = refusePgToken("audit-verify", values.token);
    if (refused) {
      console.error(refused);
      return 1;
    }
  }
  const token = pg ? undefined : resolveAuthToken(values.token, deps.env);
  const url = selection.url;
  if (!url && !pg) {
    console.error(
      "ab-enterprise audit-verify: --url or TURSO_DATABASE_URL is required (auth token: --token or TURSO_AUTH_TOKEN)",
    );
    return 1;
  }
  // The chain key is a secret: environment only, like TURSO_AUTH_TOKEN
  // without the argv fallback.
  const chainKey = deps.env.AB_AUDIT_CHAIN_KEY || undefined;
  const prepared = await prepareExpectedHead(values["expect-head"], org, chainKey);
  if (prepared.failure) return printOutcome(prepared.failure);

  if (pg) {
    const client = await deps.openPg(url);
    try {
      // Postgres hands `json` back parsed and `timestamptz` as a Date;
      // `toAuditRow` takes both (and the SQLite shapes).
      const result = await client.query(AUDIT_ROWS_SQL_PG, [org]);
      const rows = (result.rows as Record<string, unknown>[]).map(toAuditRow);
      return printOutcome(await verifyAuditRows(rows, chainKey, prepared.expected));
    } finally {
      await client.close();
    }
  }

  const client = createClient(token ? { url: url!, authToken: token } : { url: url! });
  try {
    const result = await client.execute({
      sql: AUDIT_ROWS_SQL_SQLITE,
      args: [org],
    });
    const rows = result.rows.map((row: Row) =>
      toAuditRow(row as unknown as Record<string, unknown>),
    );
    return printOutcome(await verifyAuditRows(rows, chainKey, prepared.expected));
  } finally {
    client.close();
  }
}

const USAGE =
  "usage: ab-enterprise migrate --out <dir> [--from <NNNN>] [--entitlements] [--dialect sqlite|pg] | verify [--url <url>] [--token <t>] [--entitlements] [--dialect sqlite|pg] | audit-verify --org <id> [--url <url>] [--token <t>] [--expect-head <seq>:<hash>] [--dialect sqlite|pg]";

/** What the commands read from outside the process — replaceable by a test. */
export interface CliDeps {
  env: NodeJS.ProcessEnv;
  /** Opens a Postgres connection (`undefined`: the `PG*` variables decide). */
  openPg: (url: string | undefined) => Promise<OpenPgClient>;
}

export async function main(
  argv: string[] = process.argv.slice(2),
  overrides: Partial<CliDeps> = {},
): Promise<number> {
  const deps: CliDeps = { env: process.env, openPg: openPgClient, ...overrides };
  const [command, ...rest] = argv;
  switch (command) {
    case "migrate":
      return cmdMigrate(rest);
    case "verify":
      return cmdVerify(rest, deps);
    case "audit-verify":
      return cmdAuditVerify(rest, deps);
    case "--help":
    case "-h":
    case "help":
      console.log(USAGE);
      return 0;
    case undefined:
      console.error("ab-enterprise: no command given");
      console.error(USAGE);
      return 1;
    default:
      console.error(`ab-enterprise: unknown command "${command}"`);
      console.error(USAGE);
      return 1;
  }
}
