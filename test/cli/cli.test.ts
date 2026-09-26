// Task 3 — `ab-enterprise` CLI, exercised as a real spawned process against
// the built `dist/cli/index.js` (ruling (f)), not by importing `src/cli`
// directly: this is the only test in the suite that proves the shipped
// binary — shebang, bundling, `@libsql/client` resolving at runtime — works
// end to end, not just the TS source.
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import {
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

    // A folder an earlier release wrote 0001 into (its only file) gets the
    // rest after it, numbered on from what is there.
    const upgradeDir = join(workDir, "migrations-upgrade");
    mkdirSync(upgradeDir, { recursive: true });
    writeFileSync(join(upgradeDir, "0004_enterprise.sql"), "-- written by an earlier release\n");
    expect(runCli(["migrate", "--out", upgradeDir]).status).toBe(0);
    expect(readdirSync(upgradeDir).sort()).toEqual([
      "0004_enterprise.sql",
      "0005_enterprise_0002_scim_1_7.sql",
      "0006_enterprise_0003_require2fa.sql",
    ]);

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
});
