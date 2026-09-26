// Task 3 — `ab-enterprise` CLI, exercised as a real spawned process against
// the built `dist/cli/index.js` (ruling (f)), not by importing `src/cli`
// directly: this is the only test in the suite that proves the shipped
// binary — shebang, bundling, `@libsql/client` resolving at runtime — works
// end to end, not just the TS source.
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createClient } from "@libsql/client";
import { drizzle } from "drizzle-orm/libsql";
import { migrate } from "drizzle-orm/libsql/migrator";
import { applyMigration } from "../../src/schema";
import { migrationFilePath, splitStatements } from "../../src/schema/migrate";
import { baseAuthOptions as baseOptions, runMigrations } from "../helpers/auth";
import { hashRow, type AuditRowForHash } from "../../src/server/audit/chain";

const repoRoot = fileURLToPath(new URL("../..", import.meta.url));
const cliPath = join(repoRoot, "dist", "cli", "index.js");

function runCli(args: string[]) {
  return spawnSync(process.execPath, [cliPath, ...args], { encoding: "utf8" });
}

describe("ab-enterprise CLI (built binary)", () => {
  let workDir: string;

  beforeAll(() => {
    const result = spawnSync("pnpm", ["build"], { cwd: repoRoot, stdio: "inherit" });
    if (result.status !== 0) {
      throw new Error(`pnpm build failed with status ${result.status}`);
    }
    workDir = mkdtempSync(join(tmpdir(), "ab-enterprise-cli-"));
  }, 120_000);

  afterAll(() => {
    if (workDir) rmSync(workDir, { recursive: true, force: true });
  });

  // Task 13 leftover: two sibling tsup config objects raced on one `dist/`
  // and `dist/cli/index.d.ts` went missing from finished builds at random,
  // breaking `exports`-resolution for consumers non-deterministically. One
  // config with all five entries fixed it; this asserts the build output the
  // `beforeAll` above just produced actually contains every published entry,
  // types included.
  it("pnpm build emits every dist entry, including dist/cli/index.d.ts", () => {
    for (const entry of [
      "cli/index.js",
      "cli/index.d.ts",
      "server/index.js",
      "server/index.d.ts",
      "schema/index.js",
      "schema/index.d.ts",
      "client/index.js",
      "client/index.d.ts",
      "portal/index.js",
      "portal/index.d.ts",
    ]) {
      expect(existsSync(join(repoRoot, "dist", entry)), entry).toBe(true);
    }
    expect(readFileSync(cliPath, "utf8").startsWith("#!/usr/bin/env node")).toBe(true);
  });

  it("verify exits 1 against an empty database and prints missing items", () => {
    const dbPath = join(workDir, "empty.db");
    const result = runCli(["verify", "--url", `file:${dbPath}`]);

    expect(result.status).toBe(1);
    expect(result.stdout).toMatch(/org_policy/);
  });

  it("verify exits 0 once the upstream DDL and our migration are applied", async () => {
    const dbPath = join(workDir, "migrated.db");
    const client = createClient({ url: `file:${dbPath}` });
    await runMigrations({ options: baseOptions() }, client);
    await applyMigration(client);
    client.close();

    const result = runCli(["verify", "--url", `file:${dbPath}`]);

    expect(result.status).toBe(0);
    expect(result.stdout.trim()).toBe("");
  });

  it("audit-verify requires --org and exits 1 without it", () => {
    const dbPath = join(workDir, "audit-no-org.db");
    const result = runCli(["audit-verify", "--url", `file:${dbPath}`]);

    expect(result.status).toBe(1);
    expect(result.stderr).toMatch(/--org <id> is required/);
  });

  it("audit-verify exits 0 for a valid chain and 1 with brokenAtSeq after a tamper", async () => {
    const dbPath = join(workDir, "audit-verify.db");
    const client = createClient({ url: `file:${dbPath}` });
    await runMigrations({ options: baseOptions() }, client);
    await applyMigration(client);

    const orgId = "org_cli_test";
    let prevHash = "GENESIS";
    for (let seq = 1; seq <= 3; seq++) {
      const row: AuditRowForHash = {
        orgId,
        seq,
        actorType: "user",
        actorId: "user_1",
        action: "member.invited",
        targetType: "member",
        targetId: `inv_${seq}`,
        ip: null,
        userAgent: null,
        metadata: {},
        createdAt: 1_700_000_000_000 + seq,
      };
      const hash = await hashRow(prevHash, row);
      await client.execute({
        sql: `INSERT INTO audit_event (id, org_id, seq, actor_type, actor_id, action, target_type, target_id, ip, user_agent, metadata, created_at, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        args: [
          `evt_${seq}`,
          row.orgId,
          row.seq,
          row.actorType,
          row.actorId,
          row.action,
          row.targetType,
          row.targetId,
          row.ip,
          row.userAgent,
          JSON.stringify(row.metadata),
          row.createdAt,
          prevHash,
          hash,
        ],
      });
      prevHash = hash;
    }

    const ok = runCli(["audit-verify", "--org", orgId, "--url", `file:${dbPath}`]);
    expect(ok.status).toBe(0);
    expect(ok.stdout).toMatch(/chain ok \(3 rows\)/);

    await client.execute({
      sql: `UPDATE audit_event SET metadata = ? WHERE org_id = ? AND seq = 2`,
      args: [JSON.stringify({ tampered: true }), orgId],
    });

    const broken = runCli(["audit-verify", "--org", orgId, "--url", `file:${dbPath}`]);
    expect(broken.status).toBe(1);
    expect(broken.stdout).toMatch(/chain broken at seq 2/);

    client.close();
  });

  it("migrate --out writes every package migration as next-numbered files, and only the missing ones on a later run", () => {
    const outDir = join(workDir, "migrations");
    const first = runCli(["migrate", "--out", outDir]);
    expect(first.status).toBe(0);
    expect(readdirSync(outDir).sort()).toEqual([
      "0000_enterprise.sql",
      "0001_enterprise_0002_scim_1_7.sql",
      "0002_enterprise_0003_require2fa.sql",
    ]);

    // Nothing new to write: a second run (a redeploy) adds no duplicate.
    const second = runCli(["migrate", "--out", outDir]);
    expect(second.status).toBe(0);
    expect(second.stdout).toMatch(/already holds every migration/);
    expect(readdirSync(outDir)).toHaveLength(3);

    // A folder an earlier release wrote 0001 into (its only file, with the
    // content every release wrote for it — 0001 is unchanged since 0.1.0).
    // Releases up to 1.0.x wrote 0001 only and had 0002 applied outside the
    // folder (docs/migration-1-7.md step 4), so the folder cannot show
    // whether 0002 ran: a plain run is refused, writes nothing, and names
    // both answers (PR-5 round 5).
    const upgradeDir = join(workDir, "migrations-upgrade");
    mkdirSync(upgradeDir, { recursive: true });
    const earlier = readFileSync(join(outDir, "0000_enterprise.sql"), "utf8");
    writeFileSync(join(upgradeDir, "0004_enterprise.sql"), earlier);
    const plain = runCli(["migrate", "--out", upgradeDir]);
    expect(plain.status).toBe(1);
    expect(plain.stderr).toMatch(
      /0004_enterprise\.sql, this command's emission of package migration 0001, but no emission of 0002/,
    );
    expect(plain.stderr).toMatch(/Upgrading from 1\.0\.x: run again with --from 0003/);
    expect(plain.stderr).toMatch(
      /Upgrading from 0\.1\.x, where 0002 was never applied: run again with --from 0002/,
    );
    expect(readdirSync(upgradeDir)).toEqual(["0004_enterprise.sql"]);
    // Told which, it gets the rest after it, numbered on from what is there.
    expect(runCli(["migrate", "--out", upgradeDir, "--from", "0002"]).status).toBe(0);
    expect(readdirSync(upgradeDir).sort()).toEqual([
      "0004_enterprise.sql",
      "0005_enterprise_0002_scim_1_7.sql",
      "0006_enterprise_0003_require2fa.sql",
    ]);
    // Once 0002's emission is there, a plain run has nothing left to ask.
    expect(runCli(["migrate", "--out", upgradeDir]).status).toBe(0);
    expect(readdirSync(upgradeDir)).toHaveLength(3);

    // Recognised only on proof: a file under the emitted name whose content
    // is not the package's is refused, and nothing is written.
    const forgedDir = join(workDir, "migrations-forged");
    mkdirSync(forgedDir, { recursive: true });
    writeFileSync(join(forgedDir, "0004_enterprise.sql"), "-- not the package's 0001\n");
    const forged = runCli(["migrate", "--out", forgedDir]);
    expect(forged.status).toBe(1);
    expect(forged.stderr).toMatch(
      /0004_enterprise\.sql has the name this command gives 0001_enterprise\.sql but not its content/,
    );
    expect(readdirSync(forgedDir)).toEqual(["0004_enterprise.sql"]);

    // 0003 is data only: no schema change reaches a product table.
    const require2fa = readFileSync(join(outDir, "0002_enterprise_0003_require2fa.sql"), "utf8")
      .split("\n")
      .filter((line) => !line.trimStart().startsWith("--"))
      .join("\n");
    expect(require2fa).toMatch(/UPDATE org_policy/);
    expect(require2fa).not.toMatch(/\b(ALTER|CREATE|DROP)\b/i);

    const copied = readFileSync(join(outDir, "0000_enterprise.sql"), "utf8");
    expect(copied).toMatch(/CREATE TABLE IF NOT EXISTS org_policy/);
    expect(copied).toMatch(/ALTER TABLE user ADD COLUMN studio_ref TEXT/);
    // The source file's own header survives — the markers are inserted, the
    // file is not regenerated from stripped statements.
    expect(copied).toMatch(/Alpha Bros enterprise layer — migration 0001/);
    // One `--> statement-breakpoint` between statements, none trailing (a
    // trailing one leaves drizzle with an empty statement to run).
    expect(copied.trimEnd().endsWith("--> statement-breakpoint")).toBe(false);
    expect(copied.split("--> statement-breakpoint").length - 1).toBe(copied.split(";").length - 2);

    // With no journal in the target dir, the command says how to apply it.
    expect(first.stdout).toMatch(/no drizzle meta\/_journal\.json/);
  });

  // I-6 — `migrate` used to drop a `.sql` file into the product's migrations
  // folder and write nothing to `meta/_journal.json`, which is the only thing
  // `drizzle-kit migrate` reads to decide what to apply. The file was silently
  // skipped. This drives the real drizzle migrator over a real journal to
  // prove the output is picked up and applied, rather than asserting on the
  // journal's shape alone.
  describe("migrate into a drizzle migrations folder", () => {
    function seedJournalDir(name: string): string {
      const dir = join(workDir, name);
      mkdirSync(join(dir, "meta"), { recursive: true });
      // A stand-in for the product's own first migration. `IF NOT EXISTS`
      // because the apply test below creates the full upstream better-auth
      // schema on the same database first (so `ab-enterprise verify` has
      // something complete to check) and this entry then no-ops.
      writeFileSync(
        join(dir, "0000_base.sql"),
        `CREATE TABLE IF NOT EXISTS user (id TEXT PRIMARY KEY);\n--> statement-breakpoint\nCREATE TABLE IF NOT EXISTS organization (id TEXT PRIMARY KEY);\n`,
      );
      writeFileSync(
        join(dir, "meta", "_journal.json"),
        `${JSON.stringify(
          {
            version: "7",
            dialect: "sqlite",
            entries: [
              {
                idx: 0,
                version: "6",
                when: 1_700_000_000_000,
                tag: "0000_base",
                breakpoints: true,
              },
            ],
          },
          null,
          2,
        )}\n`,
      );
      return dir;
    }

    it("appends a journal entry per migration, in order (and no snapshot, which migrate never reads)", () => {
      const dir = seedJournalDir("drizzle-journal");

      const result = runCli(["migrate", "--out", dir]);
      expect(result.status).toBe(0);
      expect(result.stdout).toMatch(/registered 0001_enterprise in/);

      const journal = JSON.parse(readFileSync(join(dir, "meta", "_journal.json"), "utf8")) as {
        entries: Array<Record<string, unknown>>;
      };
      expect(journal.entries.length).toBe(4);
      expect(journal.entries.slice(1).map((entry) => entry.tag)).toEqual([
        "0001_enterprise",
        "0002_enterprise_0002_scim_1_7",
        "0003_enterprise_0003_require2fa",
      ]);
      expect(journal.entries[1]).toMatchObject({
        idx: 1,
        version: "6",
        tag: "0001_enterprise",
        breakpoints: true,
      });
      expect(typeof journal.entries[1]!.when).toBe("number");
      expect(Number(journal.entries[1]!.when)).toBeGreaterThan(1_700_000_000_000);
      const whens = journal.entries.slice(1).map((entry) => Number(entry.when));
      expect(whens).toEqual([...whens].sort((a, b) => a - b));
      expect(new Set(whens).size).toBe(3);
      expect(existsSync(join(dir, "meta", "0001_snapshot.json"))).toBe(false);

      // Run again: nothing to add, the journal is unchanged.
      expect(runCli(["migrate", "--out", dir]).status).toBe(0);
      const again = JSON.parse(readFileSync(join(dir, "meta", "_journal.json"), "utf8")) as {
        entries: unknown[];
      };
      expect(again.entries.length).toBe(4);
    });

    it("the real drizzle migrator then applies it — ab-enterprise verify exits 0", async () => {
      const dir = seedJournalDir("drizzle-apply");
      expect(runCli(["migrate", "--out", dir]).status).toBe(0);

      // The product's own better-auth schema first — `ab-enterprise verify`
      // checks every EXPECTED_TABLES entry, upstream ones included, so this is
      // what makes its exit code a statement about *our* migration.
      const dbPath = join(workDir, "drizzle-apply.db");
      const client = createClient({ url: `file:${dbPath}` });
      await runMigrations({ options: baseOptions() }, client);
      // `org_policy` is this package's own table: in a product it comes from
      // these migrations (0001 creates it, 0002 adds `id`), not from the
      // better-auth schema derived above, which already carries `id`.
      await client.execute(`DROP TABLE org_policy`);
      // The real drizzle migrator, reading the journal `migrate` just wrote.
      await migrate(drizzle(client), { migrationsFolder: dir });
      const columns = await client.execute(`PRAGMA table_info("user")`);
      expect(columns.rows.some((row) => String(row.name) === "studio_ref")).toBe(true);
      client.close();

      const result = runCli(["verify", "--url", `file:${dbPath}`]);
      expect(result.stdout.trim()).toBe("");
      expect(result.status).toBe(0);
    });
  });

  // PR-5 round 4 — a product whose package tables came from its own
  // migration (every fleet product: klar `0010_enterprise_pilot.sql`, dispatch
  // `0011`, nomi `0023` + `0024_scim_1_7.sql`, rendra `0004`, pagr `0008`,
  // opensalary `0006`, publishr `0014`). A plain `migrate --out` used to write
  // all three package files after it, and the product's migrator then failed
  // on 0001's `ALTER TABLE organization` / 0002's `ALTER TABLE org_policy ADD
  // COLUMN id`. `--from 0003` writes the one file such a product lacks.
  describe("migrate --from into a product's own drizzle folder (klar-shaped fixture)", () => {
    const fixture = join(repoRoot, "test", "cli", "fixtures", "klar-shaped-drizzle");

    function journalOf(dir: string) {
      return JSON.parse(readFileSync(join(dir, "meta", "_journal.json"), "utf8")) as {
        entries: Array<{ idx: number; tag: string; when: number; breakpoints: boolean }>;
      };
    }

    async function productDatabase(name: string) {
      const dir = join(workDir, name);
      cpSync(fixture, dir, { recursive: true });
      const client = createClient({ url: `file:${join(workDir, `${name}.db`)}` });
      // The product's database as it runs today: every product migration
      // applied by the real drizzle migrator, the pilot's package tables
      // included.
      await migrate(drizzle(client), { migrationsFolder: dir });
      await client.execute({
        sql: `INSERT INTO org_policy (id, org_id, require_2fa, updated_at) VALUES ('org_strict', 'org_strict', 1, ?), ('org_open', 'org_open', 0, ?)`,
        args: [1_700_000_000_000, 1_700_000_000_000],
      });
      return { dir, client };
    }

    async function appliedCount(client: ReturnType<typeof createClient>) {
      const rows = await client.execute(`SELECT count(*) AS n FROM __drizzle_migrations`);
      return Number(rows.rows[0]!.n);
    }

    async function updatedAt(client: ReturnType<typeof createClient>, orgId: string) {
      const rows = await client.execute({
        sql: `SELECT updated_at FROM org_policy WHERE org_id = ?`,
        args: [orgId],
      });
      return Number(rows.rows[0]!.updated_at);
    }

    it("without --from, a folder holding a migration this command did not write is refused and left untouched", async () => {
      const { dir, client } = await productDatabase("klar-plain");
      const before = readdirSync(dir).sort();
      const journalBefore = readFileSync(join(dir, "meta", "_journal.json"), "utf8");

      const plain = runCli(["migrate", "--out", dir]);
      expect(plain.status).toBe(1);
      expect(plain.stderr).toMatch(/0010_enterprise_pilot\.sql, which this command did not write/);
      expect(plain.stderr).toMatch(/--from 0003/);
      expect(readdirSync(dir).sort()).toEqual(before);
      expect(readFileSync(join(dir, "meta", "_journal.json"), "utf8")).toBe(journalBefore);
      client.close();
    });

    it("--from 0003 writes exactly one file, registers it after the product's own entries, and the real drizzle libsql migrator applies it once", async () => {
      const { dir, client } = await productDatabase("klar-from");
      expect(await appliedCount(client)).toBe(16);
      const before = readdirSync(dir);

      const run = runCli(["migrate", "--out", dir, "--from", "0003"]);
      expect(run.status, run.stderr).toBe(0);
      const added = readdirSync(dir).filter((entry) => !before.includes(entry));
      expect(added).toEqual(["0015_enterprise_0003_require2fa.sql"]);
      const journal = journalOf(dir);
      expect(journal.entries).toHaveLength(17);
      const entry = journal.entries[16]!;
      expect(entry).toMatchObject({
        idx: 16,
        tag: "0015_enterprise_0003_require2fa",
        breakpoints: true,
      });
      expect(entry.when).toBeGreaterThan(
        Math.max(...journal.entries.slice(0, 16).map((e) => e.when)),
      );

      const upgradeStartedMs = Date.now();
      await migrate(drizzle(client), { migrationsFolder: dir });
      expect(await appliedCount(client)).toBe(17);
      // 0003 moved the requiring org's onset to the upgrade, in the column's
      // own unit (milliseconds here); the other org is untouched.
      const moved = await updatedAt(client, "org_strict");
      expect(moved).toBeGreaterThanOrEqual(upgradeStartedMs);
      expect(moved).toBeLessThan(upgradeStartedMs + 60_000);
      expect(await updatedAt(client, "org_open")).toBe(1_700_000_000_000);

      // Idempotent: a second run (a redeploy) writes nothing, and the
      // migrator has nothing left to apply.
      const again = runCli(["migrate", "--out", dir, "--from", "0003"]);
      expect(again.status).toBe(0);
      expect(again.stdout).toMatch(/already holds every migration from 0003 — nothing written/);
      expect(readdirSync(dir).filter((e) => !before.includes(e))).toEqual(added);
      expect(journalOf(dir).entries).toHaveLength(17);
      await migrate(drizzle(client), { migrationsFolder: dir });
      expect(await appliedCount(client)).toBe(17);
      expect(await updatedAt(client, "org_strict")).toBe(moved);
      // And a plain run is still refused (the pilot file is still unproven);
      // the proven 0003 emission alone would not be.
      expect(runCli(["migrate", "--out", dir]).status).toBe(1);
      client.close();
    });

    it("--from must name one of the package's migrations", () => {
      const dir = join(workDir, "klar-bad-from");
      cpSync(fixture, dir, { recursive: true });
      for (const bad of ["3", "0004", "0000", "latest"]) {
        const result = runCli(["migrate", "--out", dir, "--from", bad]);
        expect(result.status, bad).toBe(1);
        expect(result.stderr, bad).toMatch(
          /--from must be one of this package's migration numbers \(0001, 0002, 0003\)/,
        );
      }
      expect(readdirSync(dir).filter((e) => /enterprise_0/.test(e))).toEqual([]);
    });

    it("journal entries start after the newest `when` already there, even when it is ahead of the clock", () => {
      const dir = join(workDir, "journal-future");
      mkdirSync(join(dir, "meta"), { recursive: true });
      const ahead = Date.now() + 24 * 60 * 60 * 1000;
      writeFileSync(
        join(dir, "meta", "_journal.json"),
        `${JSON.stringify({ version: "7", dialect: "sqlite", entries: [{ idx: 0, version: "7", when: ahead, tag: "0000_base", breakpoints: true }] })}\n`,
      );
      writeFileSync(join(dir, "0000_base.sql"), "CREATE TABLE IF NOT EXISTS t (id TEXT);\n");
      expect(runCli(["migrate", "--out", dir]).status).toBe(0);
      const whens = journalOf(dir).entries.map((e) => e.when);
      expect(whens).toEqual([ahead, ahead + 1, ahead + 2, ahead + 3]);
    });
  });
  // PR-5 round 5 — a folder a 1.0.x install left behind. Every release up to
  // 1.0.x (0.1.0 … 1.0.1) wrote 0001 only, as `NNNN_enterprise.sql`, and the
  // 1.0.0 upgrade guide (docs/migration-1-7.md step 4) had 0002 applied
  // outside this command: through `applyMigration()` or a product migration
  // of its own name. So such a folder holds a proven 0001 and no emission of
  // 0002, while its database already has 0002's `org_policy.id` column. A
  // plain run on 3627619 wrote 0002 and 0003 there and the product's migrator
  // stopped on `duplicate column name: id`.
  //
  // The fixture's `0001_enterprise.sql` and its journal entry are the exact
  // output of the v1.0.1 CLI (`git archive v1.0.1`, `src/cli/index.ts`
  // bundled with esbuild as tsup does, `migrate --out` into a folder holding
  // `0000_base.sql`); `0002_scim_1_7.sql` is the product migration step 4
  // allows (package 0002 with drizzle breakpoints, e.g. nomi's own).
  describe("migrate from a 1.0.x install (the v1.0.1 CLI's exact 0001 output)", () => {
    const fixture = join(repoRoot, "test", "cli", "fixtures", "v1-0-1-drizzle");

    function journalOf(dir: string) {
      return JSON.parse(readFileSync(join(dir, "meta", "_journal.json"), "utf8")) as {
        entries: Array<{ idx: number; tag: string; when: number; breakpoints: boolean }>;
      };
    }

    function withoutProductScimMigration(dir: string) {
      rmSync(join(dir, "0002_scim_1_7.sql"));
      const journal = journalOf(dir);
      journal.entries = journal.entries.filter((entry) => entry.tag !== "0002_scim_1_7");
      writeFileSync(join(dir, "meta", "_journal.json"), `${JSON.stringify(journal, null, 2)}\n`);
    }

    /**
     * `product-migration`: 0002 reached the database through the product's own
     * `0002_scim_1_7.sql`. `applyMigration`: the folder holds 0001 only and
     * 0002 was run the way 1.0.x's `applyMigration()` ran it. `0.1.x`: the
     * folder holds 0001 only and 0002 never ran.
     */
    async function installedDatabase(
      name: string,
      via: "product-migration" | "applyMigration" | "0.1.x",
    ) {
      const dir = join(workDir, name);
      cpSync(fixture, dir, { recursive: true });
      if (via !== "product-migration") withoutProductScimMigration(dir);
      const client = createClient({ url: `file:${join(workDir, `${name}.db`)}` });
      await migrate(drizzle(client), { migrationsFolder: dir });
      if (via === "applyMigration") {
        const scim = readFileSync(migrationFilePath("0002_scim_1_7.sql"), "utf8");
        for (const statement of splitStatements(scim)) await client.execute(statement);
      }
      await client.execute({
        sql: `INSERT INTO org_policy (org_id, require_2fa, updated_at) VALUES ('org_strict', 1, ?), ('org_open', 0, ?)`,
        args: [1_700_000_000_000, 1_700_000_000_000],
      });
      return { dir, client };
    }

    async function appliedCount(client: ReturnType<typeof createClient>) {
      const rows = await client.execute(`SELECT count(*) AS n FROM __drizzle_migrations`);
      return Number(rows.rows[0]!.n);
    }

    async function policyRow(client: ReturnType<typeof createClient>, orgId: string) {
      const rows = await client.execute({
        sql: `SELECT * FROM org_policy WHERE org_id = ?`,
        args: [orgId],
      });
      return rows.rows[0]!;
    }

    it("the fixture's 0001 is the v1.0.1 CLI's output, byte for byte, and this release's own", () => {
      const pinned = readFileSync(join(fixture, "0001_enterprise.sql"));
      expect(createHash("sha1").update(pinned).digest("hex")).toBe(
        "ef570b7dde0189ebbe48739bf3ed6987febaa6f0",
      );
      const emptyDir = join(workDir, "v1-0-1-compare");
      expect(runCli(["migrate", "--out", emptyDir]).status).toBe(0);
      expect(readFileSync(join(emptyDir, "0000_enterprise.sql"))).toEqual(pinned);
    });

    it.each(["product-migration", "applyMigration"] as const)(
      "0002 applied via %s: a plain run is refused and writes nothing; --from 0003 writes one file the real drizzle libsql migrator applies cleanly",
      async (via) => {
        const { dir, client } = await installedDatabase(`v1-0-1-${via}`, via);
        const applied = await appliedCount(client);
        const before = readdirSync(dir).sort();
        const journalBefore = readFileSync(join(dir, "meta", "_journal.json"), "utf8");

        const plain = runCli(["migrate", "--out", dir]);
        expect(plain.status).toBe(1);
        expect(plain.stderr).toMatch(
          /0001_enterprise\.sql, this command's emission of package migration 0001, but no emission of 0002/,
        );
        expect(plain.stderr).toMatch(/--from 0003/);
        expect(plain.stderr).toMatch(/--from 0002/);
        expect(readdirSync(dir).sort()).toEqual(before);
        expect(readFileSync(join(dir, "meta", "_journal.json"), "utf8")).toBe(journalBefore);

        const run = runCli(["migrate", "--out", dir, "--from", "0003"]);
        expect(run.status, run.stderr).toBe(0);
        const added = readdirSync(dir).filter((entry) => !before.includes(entry));
        const tag = `${String(before.length - 1).padStart(4, "0")}_enterprise_0003_require2fa`;
        expect(added).toEqual([`${tag}.sql`]);
        expect(journalOf(dir).entries.at(-1)).toMatchObject({ tag, breakpoints: true });

        const upgradeStartedMs = Date.now();
        await migrate(drizzle(client), { migrationsFolder: dir });
        expect(await appliedCount(client)).toBe(applied + 1);
        const idColumns = await client.execute(`PRAGMA table_info(org_policy)`);
        expect(idColumns.rows.filter((row) => String(row.name) === "id")).toHaveLength(1);
        const strict = await policyRow(client, "org_strict");
        expect(Number(strict.updated_at)).toBeGreaterThanOrEqual(upgradeStartedMs);
        expect(Number(strict.updated_at)).toBeLessThan(upgradeStartedMs + 60_000);
        expect(Number((await policyRow(client, "org_open")).updated_at)).toBe(1_700_000_000_000);

        // A redeploy: nothing written, nothing applied.
        expect(runCli(["migrate", "--out", dir, "--from", "0003"]).status).toBe(0);
        expect(readdirSync(dir).filter((entry) => !before.includes(entry))).toEqual(added);
        await migrate(drizzle(client), { migrationsFolder: dir });
        expect(await appliedCount(client)).toBe(applied + 1);
        client.close();
      },
    );

    it("from 0.1.x, where 0002 never ran: --from 0002 writes 0002 and 0003 and the real drizzle libsql migrator applies both", async () => {
      const { dir, client } = await installedDatabase("v0-1-x", "0.1.x");
      const applied = await appliedCount(client);
      const before = readdirSync(dir);

      expect(runCli(["migrate", "--out", dir]).status).toBe(1);
      expect(readdirSync(dir)).toEqual(before);

      const run = runCli(["migrate", "--out", dir, "--from", "0002"]);
      expect(run.status, run.stderr).toBe(0);
      expect(
        readdirSync(dir)
          .filter((entry) => !before.includes(entry))
          .sort(),
      ).toEqual(["0002_enterprise_0002_scim_1_7.sql", "0003_enterprise_0003_require2fa.sql"]);
      await migrate(drizzle(client), { migrationsFolder: dir });
      expect(await appliedCount(client)).toBe(applied + 2);
      expect((await policyRow(client, "org_open")).id).toBe("org_open");

      // With 0002's emission in the folder, a plain run has nothing to ask.
      const again = runCli(["migrate", "--out", dir]);
      expect(again.status).toBe(0);
      expect(again.stdout).toMatch(/already holds every migration — nothing written/);
      client.close();
    });
  });
});
