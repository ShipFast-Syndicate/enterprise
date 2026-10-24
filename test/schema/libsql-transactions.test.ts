// @libsql/client 0.18 reworked the local sqlite3 client (a connection pool,
// and the connection handle kept across transactions for `:memory:`). The
// package's own paths run on that client through drizzle and the CLI, so pin
// the three behaviours they rely on: a rolled-back write leaves nothing, a
// committed one persists, and a failing batch is atomic. Run against a file
// database and an in-memory one: 0.15 dropped the `:memory:` database after a
// transaction, so the second case would have failed there.
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createClient, type Client } from "@libsql/client";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

async function count(client: Client): Promise<number> {
  const result = await client.execute("SELECT count(*) AS n FROM t");
  return Number(result.rows[0]?.n);
}

describe.each(["file", "memory"] as const)("libsql transactions (%s database)", (kind) => {
  let workDir: string;
  let client: Client;

  beforeAll(async () => {
    workDir = mkdtempSync(join(tmpdir(), "enterprise-libsql-tx-"));
    client = createClient({
      url: kind === "file" ? `file:${join(workDir, "tx.db")}` : ":memory:",
    });
    await client.execute("CREATE TABLE t (x INTEGER NOT NULL)");
  });

  afterAll(() => {
    client.close();
    rmSync(workDir, { recursive: true, force: true });
  });

  it("rolls back a write transaction", async () => {
    const tx = await client.transaction("write");
    await tx.execute("INSERT INTO t VALUES (1)");
    await tx.rollback();
    expect(await count(client)).toBe(0);
  });

  it("persists a committed write transaction", async () => {
    const tx = await client.transaction("write");
    await tx.execute("INSERT INTO t VALUES (2)");
    await tx.commit();
    expect(await count(client)).toBe(1);
  });

  it("applies a batch atomically: a failing statement rolls the whole batch back", async () => {
    await expect(
      client.batch(["INSERT INTO t VALUES (3)", "INSERT INTO missing_table VALUES (1)"], "write"),
    ).rejects.toThrow();
    expect(await count(client)).toBe(1);
  });
});
