// `ab-enterprise ... --dialect pg`, run in process through `main()` of
// `src/cli/main.ts` (the spawned-binary suite is `./cli.test.ts`, SQLite).
//
// - Dialect selection and credential handling are pure and run in every
//   project (the Postgres connection is a stub there).
// - The commands against a database run in the `server-pg` project: PGlite
//   by default, or the real server when `TEST_DATABASE_URL` is set. The
//   connection is injected (`main()`'s `openPg`), so PGlite stands in for the
//   `pg` driver; what the two hand back for `json` columns (objects) and
//   `timestamptz` (a Date) is the same.
import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PGlite } from "@electric-sql/pglite";
import type { GenericEndpointContext } from "better-auth";
import { main, type CliDeps } from "../../src/cli/main";
import { epochMs, parseExpectedHead, toAuditRow } from "../../src/cli/audit";
import { isPostgresUrl, selectDialect, urlCarriesPassword } from "../../src/cli/pg";
import { compactChain, writeAudit } from "../../src/server/audit/chain";
import { createOrg, makeAuth, signUpOwner, type TestAuth } from "../helpers/auth";
import { isPg } from "../helpers/dialect";

interface Run {
  code: number;
  out: string;
  err: string;
}

async function runCli(args: string[], deps: Partial<CliDeps> = {}): Promise<Run> {
  const out: string[] = [];
  const err: string[] = [];
  const log = vi.spyOn(console, "log").mockImplementation((...a) => void out.push(a.join(" ")));
  const error = vi.spyOn(console, "error").mockImplementation((...a) => void err.push(a.join(" ")));
  try {
    const code = await main(args, { env: {}, ...deps });
    return { code, out: out.join("\n"), err: err.join("\n") };
  } finally {
    log.mockRestore();
    error.mockRestore();
  }
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("--dialect and the database URL", () => {
  it("recognises postgres:// and postgresql:// URLs only", () => {
    expect(isPostgresUrl("postgres://h/db")).toBe(true);
    expect(isPostgresUrl("PostgreSQL://h/db")).toBe(true);
    expect(isPostgresUrl("libsql://x.turso.io")).toBe(false);
    expect(isPostgresUrl("file:/tmp/a.db")).toBe(false);
    expect(isPostgresUrl(undefined)).toBe(false);
  });

  it("detects a password in a URL's userinfo or query", () => {
    expect(urlCarriesPassword("postgres://user:secret@h/db")).toBe(true);
    expect(urlCarriesPassword("postgres://user@h/db?password=secret")).toBe(true);
    expect(urlCarriesPassword("postgres://user@h/db")).toBe(false);
    expect(urlCarriesPassword("postgres://h/db?sslmode=require")).toBe(false);
  });

  it("keeps the SQLite sources and defaults when nothing says postgres", () => {
    expect(selectDialect("verify", { url: "file:a.db" }, {})).toEqual({
      dialect: "sqlite",
      url: "file:a.db",
    });
    expect(selectDialect("verify", {}, { TURSO_DATABASE_URL: "libsql://x" })).toEqual({
      dialect: "sqlite",
      url: "libsql://x",
    });
    expect(selectDialect("verify", {}, {})).toEqual({ dialect: "sqlite", url: undefined });
    // A DATABASE_URL that is not postgres never changes the SQLite behaviour.
    expect(selectDialect("verify", {}, { DATABASE_URL: "file:other.db" })).toEqual({
      dialect: "sqlite",
      url: undefined,
    });
  });

  it("autodetects postgres from the URL, wherever it comes from", () => {
    expect(selectDialect("verify", {}, { TURSO_DATABASE_URL: "postgres://u:p@h/db" })).toEqual({
      dialect: "pg",
      url: "postgres://u:p@h/db",
    });
    expect(selectDialect("verify", {}, { AB_DATABASE_URL: "postgresql://u:p@h/db" })).toEqual({
      dialect: "pg",
      url: "postgresql://u:p@h/db",
    });
    expect(selectDialect("verify", {}, { DATABASE_URL: "postgres://u:p@h/db" })).toEqual({
      dialect: "pg",
      url: "postgres://u:p@h/db",
    });
    expect(selectDialect("verify", { url: "postgres://u@h/db" }, {})).toEqual({
      dialect: "pg",
      url: "postgres://u@h/db",
    });
  });

  it("never takes a Postgres URL with credentials from argv", () => {
    const selection = selectDialect("verify", { url: "postgres://u:secret@h/db" }, {});
    expect(selection).toMatchObject({ error: expect.stringContaining("never from --url") });
    expect(JSON.stringify(selection)).not.toContain("secret");
    expect(
      selectDialect("verify", { dialect: "pg", url: "postgres://u:secret@h/db" }, {}),
    ).toMatchObject({ error: expect.stringContaining("never from --url") });
  });

  it("--dialect pg: URL from the environment, else the PG* variables, else an error", () => {
    expect(
      selectDialect("verify", { dialect: "pg" }, { AB_DATABASE_URL: "postgres://h/db" }),
    ).toEqual({
      dialect: "pg",
      url: "postgres://h/db",
    });
    expect(selectDialect("verify", { dialect: "pg" }, { PGHOST: "localhost" })).toEqual({
      dialect: "pg",
      url: undefined,
    });
    expect(selectDialect("verify", { dialect: "pg" }, {})).toMatchObject({
      error: expect.stringContaining("connection is required"),
    });
    expect(selectDialect("verify", { dialect: "pg" }, { DATABASE_URL: "file:a.db" })).toMatchObject(
      { error: expect.stringContaining("needs a postgres://") },
    );
  });

  it("rejects a mismatched or unknown --dialect", () => {
    expect(
      selectDialect("verify", { dialect: "sqlite", url: "postgres://h/db" }, {}),
    ).toMatchObject({
      error: expect.stringContaining("--dialect sqlite was given a postgres:// URL"),
    });
    expect(selectDialect("verify", { dialect: "mysql" }, {})).toMatchObject({
      error: expect.stringContaining('--dialect must be "sqlite" or "pg"'),
    });
  });
});

describe("pg commands: refusals before any connection", () => {
  const unreachable = vi.fn(async () => {
    throw new Error("must not connect");
  });

  it("refuses credentials on argv without connecting or echoing them", async () => {
    for (const command of ["verify", "audit-verify --org o1"]) {
      const run = await runCli([...command.split(" "), "--url", "postgres://u:hunter2@h/db"], {
        openPg: unreachable,
      });
      expect(run.code, command).toBe(1);
      expect(run.err).toContain("AB_DATABASE_URL");
      expect(run.err + run.out).not.toContain("hunter2");
    }
    expect(unreachable).not.toHaveBeenCalled();
  });

  it("refuses --token for Postgres", async () => {
    const run = await runCli(["verify", "--dialect", "pg", "--token", "t"], {
      env: { AB_DATABASE_URL: "postgres://h/db" },
      openPg: unreachable,
    });
    expect(run.code).toBe(1);
    expect(run.err).toMatch(/--token is for libSQL/);
    expect(unreachable).not.toHaveBeenCalled();
  });

  it("audit-verify still requires --org first, and a postgres URL does not change the SQLite error", async () => {
    expect(
      (await runCli(["audit-verify", "--dialect", "pg"], { openPg: unreachable })).err,
    ).toMatch(/--org <id> is required/);
    expect((await runCli(["verify"])).err).toMatch(/--url or TURSO_DATABASE_URL is required/);
  });

  it("migrate rejects an unknown --dialect", async () => {
    const run = await runCli(["migrate", "--out", join(tmpdir(), "x"), "--dialect", "oracle"]);
    expect(run.code).toBe(1);
    expect(run.err).toMatch(/--dialect must be "sqlite" or "pg"/);
  });
});

describe("toAuditRow: what each driver hands back", () => {
  const base = {
    id: "e1",
    org_id: "org_1",
    seq: 3,
    actor_type: "user",
    actor_id: "u1",
    action: "member.invited",
    target_type: "member",
    target_id: null,
    ip: null,
    user_agent: null,
    prev_hash: "p",
    hash: "h",
  };

  it("SQLite: JSON text metadata and an epoch-ms number", () => {
    const row = toAuditRow({ ...base, metadata: '{"a":1}', created_at: 1_700_000_000_000 });
    expect(row.metadata).toEqual({ a: 1 });
    expect(row.createdAt).toBe(1_700_000_000_000);
    expect(row.targetId).toBeNull();
  });

  it("Postgres: an already-parsed json object and a Date", () => {
    const at = new Date(1_700_000_000_123);
    const row = toAuditRow({ ...base, metadata: { a: { b: [1, 2] } }, created_at: at });
    expect(row.metadata).toEqual({ a: { b: [1, 2] } });
    expect(row.createdAt).toBe(1_700_000_000_123);
  });

  it("tolerates a missing metadata, bigint/numeric-text/ISO timestamps", () => {
    expect(toAuditRow({ ...base, metadata: null, created_at: 1 }).metadata).toEqual({});
    expect(toAuditRow({ ...base, metadata: "", created_at: 1 }).metadata).toEqual({});
    expect(epochMs(BigInt(5))).toBe(5);
    expect(epochMs("1700000000000")).toBe(1_700_000_000_000);
    expect(epochMs("2023-11-14T22:13:20.000Z")).toBe(1_700_000_000_000);
    expect(() => epochMs("yesterday")).toThrow(/not a timestamp/);
  });

  it("parses --expect-head in both forms", () => {
    expect(parseExpectedHead("4:abc")).toEqual({ seq: 4, hash: "abc" });
    expect(
      parseExpectedHead(
        JSON.stringify({ head: { orgId: "o", seq: 4, hash: "abc" }, signature: "s" }),
      ),
    ).toEqual({ seq: 4, hash: "abc", orgId: "o", signature: "s" });
    expect(parseExpectedHead("nonsense")).toBeNull();
    expect(parseExpectedHead("{not json")).toBeNull();
  });
});

const CHAIN_KEY = "audit-chain-key-for-tests-".repeat(2);

/** The injected connection: PGlite answering as the `pg` driver would. */
function pgDeps(t: TestAuth, env: Record<string, string> = {}): Partial<CliDeps> {
  return {
    env: { AB_DATABASE_URL: "postgres://stub/db", ...env },
    openPg: async () => ({
      query: (sql, params) => t.pg!.query(sql, params),
      close: async () => {},
    }),
  };
}

async function writeChain(t: TestAuth, orgId: string, count: number) {
  const ctx = { context: await t.auth.$context } as unknown as GenericEndpointContext;
  for (let i = 0; i < count; i++) {
    await writeAudit(ctx, {
      orgId,
      actorType: "user",
      actorId: `user_${i}`,
      action: "member.invited",
      targetType: "member",
      targetId: `inv_${i}`,
      metadata: { n: i, nested: { z: 1, a: [i, "x"] } },
    });
  }
  return ctx;
}

async function routeJson(t: TestAuth, path: string, cookie: string) {
  const res = await t.api.get(path, { cookie });
  expect(res.status, path).toBe(200);
  return (await res.json()) as Record<string, unknown>;
}

describe.skipIf(!isPg)("ab-enterprise on Postgres: a chain written by the audit writer", () => {
  it("verifies through the route and the CLI (unkeyed); a tampered row is reported", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);
    await writeChain(t, orgId, 4);

    expect(await routeJson(t, `/enterprise/audit/verify?orgId=${orgId}`, cookie)).toMatchObject({
      ok: true,
    });
    const run = await runCli(["audit-verify", "--org", orgId], pgDeps(t));
    expect(run).toMatchObject({ code: 0 });
    expect(run.out).toMatch(/^audit-verify: chain ok \(\d+ rows\)$/);

    // The rows really came back as the driver's native shapes.
    const raw = await t.pg!.query(
      "SELECT metadata, created_at FROM audit_event WHERE org_id = $1",
      [orgId],
    );
    const first = raw.rows[0] as { metadata: unknown; created_at: unknown };
    expect(typeof first.metadata).toBe("object");
    expect(first.created_at).toBeInstanceOf(Date);

    await t.pg!.query("UPDATE audit_event SET action = 'tampered' WHERE org_id = $1 AND seq = 3", [
      orgId,
    ]);
    const broken = await runCli(["audit-verify", "--org", orgId], pgDeps(t));
    expect(broken.code).toBe(1);
    expect(broken.out).toBe("audit-verify: chain broken at seq 3");
  });

  it("verifies a keyed chain with AB_AUDIT_CHAIN_KEY, and says so without it", async () => {
    const t = await makeAuth({ audit: { chainKey: CHAIN_KEY } });
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);
    await writeChain(t, orgId, 3);

    expect(await routeJson(t, `/enterprise/audit/verify?orgId=${orgId}`, cookie)).toMatchObject({
      ok: true,
      keyed: true,
    });
    const ok = await runCli(
      ["audit-verify", "--org", orgId],
      pgDeps(t, { AB_AUDIT_CHAIN_KEY: CHAIN_KEY }),
    );
    expect(ok.code).toBe(0);

    const without = await runCli(["audit-verify", "--org", orgId], pgDeps(t));
    expect(without.code).toBe(1);
    expect(without.out).toMatch(/chain is keyed from seq \d+; set AB_AUDIT_CHAIN_KEY/);

    const wrong = await runCli(
      ["audit-verify", "--org", orgId],
      pgDeps(t, { AB_AUDIT_CHAIN_KEY: "w".repeat(40) }),
    );
    expect(wrong.code).toBe(1);
    expect(wrong.out).toMatch(/chain broken at seq \d+/);
  });

  it("--expect-head accepts the head the route reported, signed, and fails a truncated chain", async () => {
    const t = await makeAuth({ audit: { chainKey: CHAIN_KEY } });
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);
    await writeChain(t, orgId, 3);

    const head = await routeJson(t, `/enterprise/audit/head?orgId=${orgId}`, cookie);
    const env = { AB_AUDIT_CHAIN_KEY: CHAIN_KEY };
    const ok = await runCli(
      ["audit-verify", "--org", orgId, "--expect-head", JSON.stringify(head)],
      pgDeps(t, env),
    );
    expect(ok.code).toBe(0);
    expect(ok.out).toMatch(/expected head at seq \d+ present/);

    const { seq } = head.head as { seq: number };
    await t.pg!.query("DELETE FROM audit_event WHERE org_id = $1 AND seq = $2", [orgId, seq]);
    const truncated = await runCli(
      ["audit-verify", "--org", orgId, "--expect-head", JSON.stringify(head)],
      pgDeps(t, env),
    );
    expect(truncated.code).toBe(1);
    expect(truncated.out).toMatch(/no longer holds the expected head/);
  });

  it("verifies a compacted chain, keyed and unkeyed", async () => {
    for (const chainKey of [undefined, CHAIN_KEY]) {
      const t = await makeAuth(chainKey ? { audit: { chainKey } } : {});
      const { cookie } = await signUpOwner(t);
      const { orgId } = await createOrg(t, cookie);
      const ctx = await writeChain(t, orgId, 4);
      const compacted = await compactChain(ctx, orgId, new Date(Date.now() + 60_000));
      expect(compacted).not.toBeNull();
      await writeChain(t, orgId, 2);

      expect(await routeJson(t, `/enterprise/audit/verify?orgId=${orgId}`, cookie)).toMatchObject({
        ok: true,
      });
      const run = await runCli(
        ["audit-verify", "--org", orgId],
        pgDeps(t, chainKey ? { AB_AUDIT_CHAIN_KEY: chainKey } : {}),
      );
      expect(run, String(chainKey)).toMatchObject({ code: 0 });
    }
  });

  it("verify: a complete schema is clean; a jsonb audit_event.metadata is reported", async () => {
    const t = await makeAuth();
    const clean = await runCli(["verify"], pgDeps(t));
    expect(clean).toMatchObject({ code: 0, out: "" });

    await t.pg!.query("ALTER TABLE audit_event ALTER COLUMN metadata TYPE jsonb");
    const bad = await runCli(["verify"], pgDeps(t));
    expect(bad.code).toBe(1);
    expect(bad.out).toMatch(/^problem: audit_event\.metadata: type is jsonb, expected json/);
  });

  it("verify --entitlements expects org_entitlement on Postgres", async () => {
    const without = await makeAuth();
    const missing = await runCli(["verify", "--entitlements"], pgDeps(without));
    expect(missing.code).toBe(1);
    expect(missing.out).toContain("missing table: org_entitlement");

    const withTable = await makeAuth({ entitlements: { store: "table" } });
    expect(await runCli(["verify", "--entitlements"], pgDeps(withTable))).toMatchObject({
      code: 0,
    });
  });
});

describe("ab-enterprise migrate --dialect pg", () => {
  const dirs: string[] = [];
  const scratch = () => {
    const dir = mkdtempSync(join(tmpdir(), "ab-enterprise-cli-pg-"));
    dirs.push(dir);
    return dir;
  };
  afterEach(() => {
    for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
  });

  it("emits 0001 (and the optional 0002 on request) with breakpoints and a pg journal entry", async () => {
    const dir = scratch();
    const run = await runCli(["migrate", "--out", dir, "--dialect", "pg"]);
    expect(run.code).toBe(0);
    expect(readdirSync(dir)).toEqual(["0000_enterprise.sql"]);
    const sql = readFileSync(join(dir, "0000_enterprise.sql"), "utf8");
    expect(sql).toContain("CREATE TABLE IF NOT EXISTS audit_event");
    expect(sql).toContain("metadata json NOT NULL");
    expect(sql).toContain("--> statement-breakpoint");
    expect(sql).not.toContain("0002_scim");

    // A second run writes nothing; --entitlements adds the optional table.
    const again = await runCli(["migrate", "--out", dir, "--dialect", "pg"]);
    expect(again.out).toMatch(/already (present|holds)/);
    const withEntitlements = await runCli([
      "migrate",
      "--out",
      dir,
      "--dialect",
      "pg",
      "--entitlements",
    ]);
    expect(withEntitlements.code).toBe(0);
    expect(readdirSync(dir).sort()).toEqual([
      "0000_enterprise.sql",
      "0001_enterprise_0002_org_entitlement.sql",
    ]);
  });

  it("registers entries in an existing drizzle journal with the pg snapshot version", async () => {
    const bare = scratch();
    const noJournal = await runCli(["migrate", "--out", bare, "--dialect", "pg"]);
    expect(noJournal.out).toMatch(/no drizzle meta\/_journal.json/);

    const withJournal = scratch();
    mkdirSync(join(withJournal, "meta"));
    writeFileSync(
      join(withJournal, "meta", "_journal.json"),
      JSON.stringify({ version: "7", dialect: "postgresql", entries: [] }),
    );
    await runCli(["migrate", "--out", withJournal, "--dialect", "pg"]);
    const journal = JSON.parse(
      readFileSync(join(withJournal, "meta", "_journal.json"), "utf8"),
    ) as {
      entries: { idx: number; version: string; tag: string; breakpoints: boolean }[];
    };
    expect(journal.entries).toMatchObject([
      { idx: 0, version: "7", tag: "0000_enterprise", breakpoints: true },
    ]);
  });

  it("refuses a product's own enterprise migration it cannot prove, like the SQLite command", async () => {
    const dir = scratch();
    writeFileSync(join(dir, "0003_enterprise_pilot.sql"), "CREATE TABLE audit_event (id text);");
    const run = await runCli(["migrate", "--out", dir, "--dialect", "pg"]);
    expect(run.code).toBe(1);
    expect(run.err).toMatch(/did not write/);
    expect(readdirSync(dir)).toEqual(["0003_enterprise_pilot.sql"]);
  });

  it("emits SQL that runs on Postgres, statement by statement", async () => {
    const dir = scratch();
    await runCli(["migrate", "--out", dir, "--dialect", "pg", "--entitlements"]);
    const db = new PGlite();
    try {
      await db.exec(
        'CREATE TABLE "user" (id text PRIMARY KEY); CREATE TABLE organization (id text PRIMARY KEY);',
      );
      for (const file of readdirSync(dir).sort()) {
        const statements = readFileSync(join(dir, file), "utf8").split("--> statement-breakpoint");
        for (const statement of statements) await db.exec(statement);
      }
      const tables = await db.query<{ table_name: string }>(
        "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY 1",
      );
      expect(tables.rows.map((r) => r.table_name)).toEqual(
        expect.arrayContaining([
          "audit_event",
          "org_entitlement",
          "org_policy",
          "enterprise_scim_member",
        ]),
      );
    } finally {
      await db.close();
    }
  });
});
