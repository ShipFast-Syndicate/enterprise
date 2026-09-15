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
import type { BetterAuthOptions } from "better-auth";
import { createClient } from "@libsql/client";
import { applyMigration } from "../../src/schema";
import { enterprisePreset } from "../../src/server/preset";
import { runMigrations } from "../helpers/auth";

const repoRoot = fileURLToPath(new URL("../..", import.meta.url));
const cliPath = join(repoRoot, "dist", "cli", "index.js");

function baseOptions(): BetterAuthOptions {
  return {
    secret: "x".repeat(32),
    baseURL: "http://localhost:3000",
    emailAndPassword: { enabled: true },
    plugins: enterprisePreset({
      product: "test",
      secretsKey: "s".repeat(32),
      resolveEntitlements: async () => new Set(),
    }),
  };
}

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

  it("audit-verify prints the Task 4 placeholder and exits 2", () => {
    const result = runCli(["audit-verify"]);

    expect(result.status).toBe(2);
    expect(result.stdout).toMatch(/not implemented yet \(Task 4\)/);
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
