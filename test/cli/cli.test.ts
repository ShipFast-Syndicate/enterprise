// Task 3 — `ab-enterprise` CLI, exercised as a real spawned process against
// the built `dist/cli/index.js` (ruling (f)), not by importing `src/cli`
// directly: this is the only test in the suite that proves the shipped
// binary — shebang, bundling, `@libsql/client` resolving at runtime — works
// end to end, not just the TS source.
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createClient } from "@libsql/client";
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

  it("migrate --out copies the SQL as the next-numbered migration file", () => {
    const outDir = join(workDir, "migrations");
    const first = runCli(["migrate", "--out", outDir]);
    expect(first.status).toBe(0);
    expect(existsSync(join(outDir, "0000_enterprise.sql"))).toBe(true);

    const second = runCli(["migrate", "--out", outDir]);
    expect(second.status).toBe(0);
    expect(existsSync(join(outDir, "0001_enterprise.sql"))).toBe(true);

    const copied = readFileSync(join(outDir, "0000_enterprise.sql"), "utf8");
    expect(copied).toMatch(/CREATE TABLE IF NOT EXISTS org_policy/);
    expect(copied).toMatch(/ALTER TABLE user ADD COLUMN studio_ref TEXT/);
  });
});
