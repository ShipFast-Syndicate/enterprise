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
//   ab-enterprise migrate --out <dir> [--from <NNNN>]
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
//                                        0.1.x without 0002 applied)
//   ab-enterprise verify [--url] [--token]
//                                        check a live database against
//                                        EXPECTED_TABLES, one line per
//                                        missing table/column; exit 1 if
//                                        anything is missing
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
import { MIGRATION_FILES, migrationFilePath } from "../schema/migrate";
import {
  RETENTION_COMPACTED_ACTION,
  RETENTION_COMPACTING_ACTION,
  verifyChain,
  verifyChainHeadSignature,
  type AuditRow,
} from "../server/audit/chain";

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
function appendJournalEntry(outDir: string, tag: string, when: number): string | null {
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
function emittedSuffix(file: string): string {
  return file === MIGRATION_FILES[0] ? "enterprise" : `enterprise_${file.replace(/\.sql$/, "")}`;
}

/** A package migration's own number — the `NNNN` of `NNNN_name.sql`. */
function migrationNumber(file: string): string {
  return file.slice(0, 4);
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
function isEmissionOf(outDir: string, entry: string, file: string): boolean {
  if (!new RegExp(`^\\d{4}_${emittedSuffix(file)}\\.sql$`).test(entry)) return false;
  const emitted = readFileSync(join(outDir, entry), "utf8");
  const source = readFileSync(migrationFilePath(file), "utf8");
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
function emissionState(outDir: string, file: string): EmissionState {
  if (!existsSync(outDir)) return { kind: "absent" };
  const pattern = new RegExp(`^\\d{4}_${emittedSuffix(file)}\\.sql$`);
  const named = readdirSync(outDir).filter((entry) => pattern.test(entry));
  const proven = named.find((entry) => isEmissionOf(outDir, entry, file));
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
function unprovenEnterpriseFiles(outDir: string): string[] {
  if (!existsSync(outDir)) return [];
  return readdirSync(outDir).filter(
    (entry) =>
      /\.sql$/.test(entry) &&
      /enterprise/i.test(entry) &&
      !MIGRATION_FILES.some((file) => isEmissionOf(outDir, entry, file)),
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
    options: { out: { type: "string" }, from: { type: "string" } },
  });
  if (!values.out) {
    console.error("ab-enterprise migrate: --out <dir> is required");
    return 1;
  }
  const numbers = MIGRATION_FILES.map(migrationNumber);
  const from = values.from;
  if (from !== undefined && !numbers.includes(from)) {
    console.error(
      `ab-enterprise migrate: --from must be one of this package's migration numbers (${numbers.join(", ")}), got "${from}"`,
    );
    return 1;
  }
  const outDir = values.out;
  mkdirSync(outDir, { recursive: true });

  const selected = MIGRATION_FILES.filter(
    (file) => from === undefined || migrationNumber(file) >= from,
  );
  for (const file of selected) {
    const state = emissionState(outDir, file);
    if (state.kind === "conflict") {
      console.error(
        `ab-enterprise migrate: ${state.entry} has the name this command gives ${file} but not its content — nothing written. Restore it from this package or remove it (and its meta/_journal.json entry) before running again.`,
      );
      return 1;
    }
  }

  if (from === undefined) {
    const unproven = unprovenEnterpriseFiles(outDir);
    if (unproven.length > 0) {
      console.error(
        `ab-enterprise migrate: ${outDir} holds ${unproven.join(", ")}, which this command did not write — it cannot tell which package migrations that applied. Nothing written. If it created the package tables (a product's own enterprise migration), run again with --from <the first package migration it lacks>, e.g. --from ${numbers[numbers.length - 1]}.`,
      );
      return 1;
    }

    const first = emissionState(outDir, MIGRATION_FILES[0]);
    const second = emissionState(outDir, MIGRATION_FILES[1]);
    if (first.kind === "present" && second.kind === "absent") {
      console.error(
        `ab-enterprise migrate: ${outDir} holds ${first.entry}, this command's emission of package migration 0001, but no emission of 0002 — releases up to 1.0.x wrote 0001 only, and the 1.0.0 upgrade guide applied 0002 through applyMigration() or a product migration, so this folder cannot show whether it ran. Nothing written. Upgrading from 1.0.x: run again with --from 0003. Upgrading from 0.1.x, where 0002 was never applied: run again with --from 0002.`,
      );
      return 1;
    }
  }

  let when = Math.max(Date.now(), newestJournalWhen(outDir) + 1);
  let written = 0;
  let journalPath: string | null = null;
  for (const file of selected) {
    const state = emissionState(outDir, file);
    if (state.kind === "present") {
      console.log(`ab-enterprise migrate: ${file} already present as ${state.entry} — skipped`);
      continue;
    }
    const tag = `${nextMigrationNumber(outDir)}_${emittedSuffix(file)}`;
    const dest = join(outDir, `${tag}.sql`);
    writeFileSync(dest, insertStatementBreakpoints(readFileSync(migrationFilePath(file), "utf8")));
    console.log(`ab-enterprise migrate: wrote ${dest}`);
    const registered = appendJournalEntry(outDir, tag, when++);
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
      `ab-enterprise migrate: no drizzle meta/_journal.json in ${outDir} — apply the files in order with applyMigration() from @alphabros/enterprise/schema, or your own SQL runner`,
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

interface ExpectedHead {
  seq: number;
  hash: string;
  orgId?: string;
  signature?: string | null;
}

/**
 * `--expect-head` accepts `<seq>:<hash>` or the JSON `GET
 * /enterprise/audit/head` answered (`{ head: { orgId, seq, hash }, signature }`,
 * or just its `head` object with an optional `signature`).
 */
function parseExpectedHead(raw: string): ExpectedHead | null {
  const trimmed = raw.trim();
  if (trimmed.startsWith("{")) {
    try {
      const parsed = JSON.parse(trimmed) as {
        head?: { orgId?: unknown; seq?: unknown; hash?: unknown } | null;
        orgId?: unknown;
        seq?: unknown;
        hash?: unknown;
        signature?: unknown;
      };
      const head = parsed.head ?? parsed;
      if (typeof head.seq !== "number" || typeof head.hash !== "string") return null;
      return {
        seq: head.seq,
        hash: head.hash,
        orgId: typeof head.orgId === "string" ? head.orgId : undefined,
        signature: typeof parsed.signature === "string" ? parsed.signature : null,
      };
    } catch {
      return null;
    }
  }
  const match = /^(-?\d+):(\S+)$/.exec(trimmed);
  if (!match) return null;
  return { seq: Number(match[1]), hash: match[2]! };
}

async function cmdAuditVerify(argv: string[]): Promise<number> {
  const { values } = parseArgs({
    args: argv,
    options: {
      org: { type: "string" },
      url: { type: "string" },
      token: { type: "string" },
      "expect-head": { type: "string" },
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
  // The chain key is a secret: environment only, like TURSO_AUTH_TOKEN
  // without the argv fallback.
  const chainKey = process.env.AB_AUDIT_CHAIN_KEY || undefined;
  let expected: ExpectedHead | null = null;
  if (values["expect-head"] !== undefined) {
    expected = parseExpectedHead(values["expect-head"]);
    if (!expected) {
      console.error(
        "ab-enterprise audit-verify: --expect-head takes <seq>:<hash> or the JSON GET /enterprise/audit/head returned",
      );
      return 1;
    }
    if (expected.orgId !== undefined && expected.orgId !== values.org) {
      console.log(
        `audit-verify: expected head belongs to org ${expected.orgId}, not ${values.org}`,
      );
      return 1;
    }
    if (expected.signature) {
      if (!chainKey) {
        console.log(
          "audit-verify: the expected head is signed; set AB_AUDIT_CHAIN_KEY to check its signature",
        );
        return 1;
      }
      const valid = await verifyChainHeadSignature(
        chainKey,
        { orgId: values.org, seq: expected.seq, hash: expected.hash },
        expected.signature,
      );
      if (!valid) {
        console.log(
          "audit-verify: the expected head's signature does not verify under AB_AUDIT_CHAIN_KEY",
        );
        return 1;
      }
    }
  }

  const client = createClient(token ? { url, authToken: token } : { url });
  try {
    const result = await client.execute({
      sql: `SELECT id, org_id, seq, actor_type, actor_id, action, target_type, target_id, ip, user_agent, metadata, created_at, prev_hash, hash FROM audit_event WHERE org_id = ? ORDER BY seq ASC`,
      args: [values.org],
    });
    const rows = result.rows.map(rowToAuditRow);
    const verdict = await verifyChain(rows, chainKey);
    if (!verdict.ok) {
      console.log(
        verdict.reason === "keyed_row_without_key"
          ? `audit-verify: chain is keyed from seq ${verdict.brokenAtSeq}; set AB_AUDIT_CHAIN_KEY to verify it`
          : `audit-verify: chain broken at seq ${verdict.brokenAtSeq}`,
      );
      return 1;
    }
    if (expected) {
      const row = rows.find((r) => r.seq === expected.seq);
      if (row) {
        if (row.hash !== expected.hash) {
          console.log(
            `audit-verify: the row at seq ${expected.seq} no longer carries the expected head hash — the chain was rewritten`,
          );
          return 1;
        }
      } else {
        // Gone: compacted away (the anchor records the hash of the last
        // compacted row only), or truncated. Either way the head cannot be
        // confirmed — fail closed.
        const anchor = rows.find(
          (r) =>
            (r.action === RETENTION_COMPACTED_ACTION || r.action === RETENTION_COMPACTING_ACTION) &&
            (r.metadata as { compactedThroughSeq?: unknown }).compactedThroughSeq === expected.seq,
        );
        if (!anchor || (anchor.metadata as { lastHash?: unknown }).lastHash !== expected.hash) {
          console.log(
            `audit-verify: the chain no longer holds the expected head (seq ${expected.seq}) — truncated, or compacted past it`,
          );
          return 1;
        }
      }
      console.log(
        `audit-verify: chain ok (${rows.length} rows), expected head at seq ${expected.seq} present`,
      );
      return 0;
    }
    console.log(`audit-verify: chain ok (${rows.length} rows)`);
    return 0;
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
        "usage: ab-enterprise migrate --out <dir> [--from <NNNN>] | verify [--url <url>] [--token <t>] | audit-verify --org <id> [--url <url>] [--token <t>] [--expect-head <seq>:<hash>]",
      );
      return 1;
    default:
      console.error(`ab-enterprise: unknown command "${command}"`);
      console.error(
        "usage: ab-enterprise migrate --out <dir> [--from <NNNN>] | verify [--url <url>] [--token <t>] | audit-verify --org <id> [--url <url>] [--token <t>] [--expect-head <seq>:<hash>]",
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
