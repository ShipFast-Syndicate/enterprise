// The audit write path on Postgres: unique-violation detection by SQLSTATE
// 23505, and N writers racing for one org still producing a valid hash chain.
//
// - The `isUniqueViolation` cases are pure and run in every project.
// - The adapter case and the barriered race run in the `server-pg` project
//   (PGlite, or the real server when `TEST_DATABASE_URL` is set).
// - The free-running race needs real connections and runs only against a real
//   Postgres: it is skipped when `TEST_DATABASE_URL` is not set.
//
// The per-org lock in `chain.ts` serialises writers inside one process, so a
// race is only visible between *separate* copies of the module — what two
// server instances are. Each writer below gets its own copy (`vi.resetModules`
// + a fresh import), hence its own lock, and all of them share the one
// database through the same auth context.
import { describe, expect, it, vi } from "vitest";
import type { GenericEndpointContext } from "better-auth";
import { getCurrentAdapter, runWithTransaction } from "@better-auth/core/context";
import {
  auditDialectOf,
  isUniqueViolation,
  verifyChain,
  type AuditRow,
} from "../../src/server/audit/chain";
import {
  currentPgTransaction,
  lockOrganizationInTransaction,
  orgLockKey,
  withPgAuditLock,
  type PgTransactionHandle,
} from "../../src/server/audit/pg-lock";
import { makeAuth, type TestAuth } from "../helpers/auth";
import { isPg, realPostgresUrl } from "../helpers/dialect";

type ChainModule = typeof import("../../src/server/audit/chain");

async function freshChainModule(): Promise<ChainModule> {
  vi.resetModules();
  return import("../../src/server/audit/chain");
}

describe("isUniqueViolation: SQLSTATE 23505, wherever in the cause chain the driver put it", () => {
  // drizzle's DrizzleQueryError: its own message is "Failed query: …", the
  // driver's DatabaseError (with the SQLSTATE) is its `cause`.
  const wrapped = (sqlstate: string, driverMessage: string) =>
    Object.assign(new Error("Failed query: insert into audit_event"), {
      cause: Object.assign(new Error(driverMessage), { code: sqlstate }),
    });

  it("recognises 23505 on the error itself and on a wrapped driver error", () => {
    expect(isUniqueViolation(Object.assign(new Error("x"), { code: "23505" }))).toBe(true);
    // The driver message here does not mention "unique": only the code can say so.
    expect(isUniqueViolation(wrapped("23505", "key already present"))).toBe(true);
    expect(
      isUniqueViolation(
        Object.assign(new Error("outer"), { cause: wrapped("23505", "key already present") }),
      ),
    ).toBe(true);
  });

  it("does not take other SQLSTATEs for a unique violation", () => {
    for (const sqlstate of ["23503", "23502", "23514", "25P02", "40001", "40P01", "08006"]) {
      expect(isUniqueViolation(wrapped(sqlstate, "boom")), sqlstate).toBe(false);
    }
    expect(isUniqueViolation(new Error("connection reset"))).toBe(false);
  });

  it("terminates on a cyclic cause chain", () => {
    const a: Error & { cause?: unknown } = new Error("a");
    const b: Error & { cause?: unknown } = new Error("b");
    a.cause = b;
    b.cause = a;
    expect(isUniqueViolation(a)).toBe(false);
  });
});

async function readChain(t: TestAuth, orgId: string): Promise<AuditRow[]> {
  const result = await t.client.execute({
    sql: `SELECT * FROM audit_event WHERE org_id = ? ORDER BY seq ASC`,
    args: [orgId],
  });
  return result.rows.map(
    (r) =>
      ({
        id: String(r.id),
        orgId: String(r.org_id),
        seq: Number(r.seq),
        actorType: String(r.actor_type),
        actorId: r.actor_id === null ? null : String(r.actor_id),
        action: String(r.action),
        targetType: String(r.target_type),
        targetId: r.target_id === null ? null : String(r.target_id),
        ip: r.ip === null ? null : String(r.ip),
        userAgent: r.user_agent === null ? null : String(r.user_agent),
        metadata: JSON.parse(String(r.metadata)) as Record<string, unknown>,
        createdAt: Number(r.created_at),
        prevHash: String(r.prev_hash),
        hash: String(r.hash),
      }) satisfies AuditRow,
  );
}

const input = (orgId: string, writer: number) => ({
  orgId,
  actorType: "user" as const,
  actorId: `user_${writer}`,
  action: "member.invited",
  targetType: "member",
  targetId: `inv_${writer}`,
  metadata: { writer },
});

describe.skipIf(!isPg)("audit write path on Postgres", () => {
  it("a duplicate (org_id, seq) is SQLSTATE 23505, which is what writeAudit's retry keys on", async () => {
    const t = await makeAuth();
    const ctx = await t.auth.$context;
    const row = {
      orgId: "org_dup",
      seq: 1,
      actorType: "system",
      actorId: null,
      action: "x",
      targetType: "org",
      targetId: null,
      ip: null,
      userAgent: null,
      metadata: {},
      createdAt: new Date(),
      prevHash: "GENESIS",
      hash: "h",
    };
    await ctx.adapter.create({ model: "auditEvent", data: row });
    const error = await ctx.adapter.create({ model: "auditEvent", data: row }).then(
      () => null,
      (e: unknown) => e,
    );
    expect(error).not.toBeNull();
    // Through the enterprise adapter wrapper the driver's SQLSTATE survives
    // while the statement and its parameters do not.
    expect(String((error as { code?: unknown }).code)).toBe("23505");
    expect(isUniqueViolation(error)).toBe(true);

    // And straight from the driver, with the constraint it names.
    const raw = await t
      .pg!.query(
        `INSERT INTO audit_event (id, org_id, seq, actor_type, action, target_type, created_at, prev_hash, hash)
       VALUES ('raw_dup', 'org_dup', 1, 'system', 'x', 'org', now(), 'GENESIS', 'h')`,
      )
      .then(
        () => null,
        (e: unknown) => e,
      );
    expect(raw).toMatchObject({ code: "23505", constraint: "audit_event_org_seq" });
    expect(isUniqueViolation(raw)).toBe(true);
  });

  it("a drizzle-wrapped 23505 carries the SQLSTATE on error.cause, which isUniqueViolation reads", async () => {
    const t = await makeAuth();
    const insert = `INSERT INTO audit_event (id, org_id, seq, actor_type, action, target_type, created_at, prev_hash, hash)
      VALUES ('drizzle_dup', 'org_drizzle', 1, 'system', 'x', 'org', now(), 'GENESIS', 'h')`;
    const db = t.db as unknown as { execute(query: string): PromiseLike<unknown> };
    await db.execute(insert);
    const error = await Promise.resolve(db.execute(insert)).then(
      () => null,
      (e: unknown) => e as { message: string; cause?: { code?: string } },
    );
    // drizzle's own error: "Failed query: …" on the outside, the driver's
    // SQLSTATE one level down — never "unique" in the top-level message.
    expect(error).not.toBeNull();
    expect(error!.message).toMatch(/^Failed query/);
    expect(error!.message).not.toMatch(/unique/i);
    expect(error!.cause?.code).toBe("23505");
    expect(isUniqueViolation(error)).toBe(true);
  });

  it("writers that all read the chain before any writes recover through the 23505 retry into a valid chain", async () => {
    const writers = 4;
    // Without the advisory lock (`database` unset): this is the safety net the
    // lock leaves in place, outside a transaction.
    const t = await makeAuth({ database: undefined });
    const base = await t.auth.$context;
    const orgId = "org_barrier";

    // Hold every writer's first read of the chain until all of them have it, so
    // they all compute seq 1 and every one but one hits the unique index.
    let reads = 0;
    let creates = 0;
    let release!: () => void;
    const everyoneRead = new Promise<void>((resolve) => (release = resolve));
    const adapter = new Proxy(base.adapter, {
      get(target, prop, receiver) {
        const value = Reflect.get(target, prop, receiver) as unknown;
        if (typeof value !== "function") return value;
        if (prop === "findMany") {
          return async (args: { model: string }) => {
            const result = await (value as (a: unknown) => Promise<unknown>).call(target, args);
            if (args.model === "auditEvent" && ++reads <= writers) {
              if (reads === writers) release();
              await everyoneRead;
            }
            return result;
          };
        }
        if (prop === "create") {
          return (args: { model: string }) => {
            if (args.model === "auditEvent") creates++;
            return (value as (a: unknown) => Promise<unknown>).call(target, args);
          };
        }
        return (value as (...a: unknown[]) => unknown).bind(target);
      },
    });
    const ctx = { context: { ...base, adapter } } as unknown as GenericEndpointContext;

    const modules = [];
    for (let i = 0; i < writers; i++) modules.push(await freshChainModule());
    const written = await Promise.all(
      modules.map((chain, writer) => chain.writeAudit(ctx, input(orgId, writer))),
    );

    // Every writer got a row, and the losers really did collide and retry.
    expect(written).toHaveLength(writers);
    expect(creates).toBeGreaterThan(writers);
    const chain = await readChain(t, orgId);
    expect(chain.map((r) => r.seq)).toEqual([1, 2, 3, 4]);
    expect(chain[0]!.prevHash).toBe("GENESIS");
    await expect(verifyChain(chain)).resolves.toEqual({ ok: true });
  });

  it("a duplicate (org_id, seq) inside a transaction aborts it (25P02) — what the lock keeps writeAudit out of", async () => {
    const t = await makeAuth({ database: undefined });
    const { adapter } = await t.auth.$context;
    const row = {
      orgId: "org_abort",
      seq: 1,
      actorType: "system",
      actorId: null,
      action: "x",
      targetType: "org",
      targetId: null,
      ip: null,
      userAgent: null,
      metadata: {},
      createdAt: new Date(),
      prevHash: "GENESIS",
      hash: "h",
    };
    await adapter.create({ model: "auditEvent", data: row });
    let failure: unknown = null;
    await runWithTransaction(adapter, async () => {
      const current = await getCurrentAdapter(adapter);
      await current.create({ model: "auditEvent", data: row }).catch(() => undefined);
      // The retry's read, in the same transaction.
      failure = await current
        .findMany({ model: "auditEvent", where: [{ field: "orgId", value: "org_abort" }] })
        .then(
          () => null,
          (e: unknown) => e,
        );
    }).catch(() => undefined); // the aborted transaction cannot commit either
    expect(String((failure as { code?: unknown } | null)?.code)).toBe("25P02");
  });

  it("a SCIM-style write inside a larger transaction succeeds next to concurrent writers", async () => {
    // `database: { dialect: "pg" }` (makeAuth's default here): the lock is
    // taken in the caller's transaction before the chain head is read, so the
    // transaction is never aborted by a unique violation (25P02).
    const t = await makeAuth();
    const context = await t.auth.$context;
    const ctx = { context } as unknown as GenericEndpointContext;
    const orgId = "org_larger_tx";

    const modules = [];
    for (let i = 0; i < 4; i++) modules.push(await freshChainModule());
    const [larger, ...others] = modules as [ChainModule, ...ChainModule[]];

    let lockHeldInside = 0;
    const largerTransaction = runWithTransaction(context.adapter, async () => {
      await larger.writeAudit(ctx, input(orgId, 100));
      // The lock is still held: it lasts until this transaction ends.
      const handle = await currentPgTransaction();
      const held = (await handle!.execute(
        "select count(*)::int as n from pg_locks where locktype = 'advisory' and pid = pg_backend_pid()",
      )) as { rows: { n: number }[] };
      lockHeldInside = held.rows[0]!.n;
      await larger.writeAudit(ctx, input(orgId, 101));
    });
    const concurrent = others.map((chain, writer) => chain.writeAudit(ctx, input(orgId, writer)));
    await expect(Promise.all([largerTransaction, ...concurrent])).resolves.toBeDefined();

    expect(lockHeldInside).toBeGreaterThan(0);
    const chain = await readChain(t, orgId);
    expect(chain.map((r) => r.seq)).toEqual([1, 2, 3, 4, 5]);
    expect(chain[0]!.prevHash).toBe("GENESIS");
    await expect(verifyChain(chain)).resolves.toEqual({ ok: true });
    // The lock ended with the transaction.
    const after = await t.pg!.query(
      "select count(*)::int as n from pg_locks where locktype = 'advisory' and pid = pg_backend_pid()",
    );
    expect((after.rows[0] as { n: number }).n).toBe(0);
  });

  it("a rolled-back transaction leaves no gap and no half-written chain", async () => {
    const t = await makeAuth();
    const context = await t.auth.$context;
    const ctx = { context } as unknown as GenericEndpointContext;
    const orgId = "org_rollback";
    const chainModule = await freshChainModule();

    await chainModule.writeAudit(ctx, input(orgId, 0));
    await expect(
      runWithTransaction(context.adapter, async () => {
        await chainModule.writeAudit(ctx, input(orgId, 1));
        throw new Error("the larger change failed");
      }),
    ).rejects.toThrow("the larger change failed");
    await chainModule.writeAudit(ctx, input(orgId, 2));

    const chain = await readChain(t, orgId);
    expect(chain.map((r) => r.seq)).toEqual([1, 2]);
    await expect(verifyChain(chain)).resolves.toEqual({ ok: true });
  });

  it("a keyed chain written under the lock verifies, through the compaction anchor too", async () => {
    const chainKey = "k".repeat(40);
    const t = await makeAuth({ audit: { chainKey } });
    const context = await t.auth.$context;
    const ctx = { context } as unknown as GenericEndpointContext;
    const orgId = "org_keyed_compacted";
    const chainModule = await freshChainModule();

    for (let writer = 0; writer < 4; writer++) {
      await chainModule.writeAudit(ctx, input(orgId, writer));
    }
    const compacted = await chainModule.compactChain(ctx, orgId, new Date(Date.now() + 60_000));
    expect(compacted?.compactedCount).toBe(4);
    await chainModule.writeAudit(ctx, input(orgId, 4));

    const chain = await readChain(t, orgId);
    expect(chain.some((r) => r.action === "audit.retention_compacted")).toBe(true);
    await expect(verifyChain(chain, chainKey)).resolves.toEqual({ ok: true });
  });
});

describe("withPgAuditLock and the organization lock key", () => {
  it("records the transaction db.transaction opens, for the callback only", async () => {
    const executed: string[] = [];
    const tx: PgTransactionHandle = { execute: async (query) => void executed.push(query) };
    const db = {
      marker: "db",
      transaction: async (callback: (tx: PgTransactionHandle) => Promise<unknown>) => callback(tx),
    };
    const wrapped = withPgAuditLock(db);
    expect(wrapped.marker).toBe("db");

    await expect(lockOrganizationInTransaction("org_a")).resolves.toBe(false);
    await wrapped.transaction(async () => {
      await expect(currentPgTransaction()).resolves.toBe(tx);
      await expect(lockOrganizationInTransaction("org_a")).resolves.toBe(true);
    });
    await expect(currentPgTransaction()).resolves.toBeUndefined();

    expect(executed).toHaveLength(1);
    expect(executed[0]).toMatch(/^select pg_advisory_xact_lock\(\d+, -?\d+\)$/);
  });

  it("keys the lock by organization: stable per id, different between ids", async () => {
    const a = await orgLockKey("org_a");
    expect(await orgLockKey("org_a")).toBe(a);
    expect(Number.isInteger(a)).toBe(true);
    expect(a).toBeGreaterThanOrEqual(-(2 ** 31));
    expect(a).toBeLessThan(2 ** 31);
    expect(await orgLockKey("org_b")).not.toBe(a);
  });

  it("reads database.dialect off the enterprise plugins (sqlite when unset)", () => {
    const withDialect = (dialect: unknown) => ({
      options: { plugins: [{ id: "enterprise-gate", options: { database: { dialect } } }] },
    });
    expect(auditDialectOf(withDialect("pg"))).toBe("pg");
    expect(auditDialectOf(withDialect("sqlite"))).toBe("sqlite");
    expect(auditDialectOf(withDialect(undefined))).toBe("sqlite");
    expect(auditDialectOf({ options: { plugins: [] } })).toBe("sqlite");
    expect(auditDialectOf(null)).toBe("sqlite");
  });
});

describe.skipIf(!realPostgresUrl)("audit chain on a real Postgres: concurrent writers", () => {
  it("N writers on separate connections, one org: every write lands and verifyChain passes", async () => {
    const writers = 12;
    const t = await makeAuth();
    const ctx = { context: await t.auth.$context } as unknown as GenericEndpointContext;
    const orgId = "org_real_concurrent";

    const modules = [];
    for (let i = 0; i < writers; i++) modules.push(await freshChainModule());
    const written = await Promise.all(
      modules.map((chain, writer) => chain.writeAudit(ctx, input(orgId, writer))),
    );

    expect(new Set(written.map((r) => r.seq)).size).toBe(writers);
    const chain = await readChain(t, orgId);
    expect(chain.map((r) => r.seq)).toEqual(Array.from({ length: writers }, (_, i) => i + 1));
    expect(chain[0]!.prevHash).toBe("GENESIS");
    await expect(verifyChain(chain)).resolves.toEqual({ ok: true });
    // Each writer's row is in the chain exactly once.
    expect(
      chain.map((r) => (r.metadata as { writer: number }).writer).sort((a, b) => a - b),
    ).toEqual(Array.from({ length: writers }, (_, i) => i));
  });

  it("N writers, each inside a larger transaction: no 25P02, a gap-free chain that verifies", async () => {
    const writers = 12;
    const t = await makeAuth();
    const context = await t.auth.$context;
    const ctx = { context } as unknown as GenericEndpointContext;
    const orgId = "org_real_larger_tx";

    const modules = [];
    for (let i = 0; i < writers; i++) modules.push(await freshChainModule());
    await Promise.all(
      modules.map((chain, writer) =>
        runWithTransaction(context.adapter, async () => {
          await chain.writeAudit(ctx, input(orgId, writer));
          await chain.writeAudit(ctx, input(orgId, writer + 1000));
        }),
      ),
    );

    const chain = await readChain(t, orgId);
    expect(chain.map((r) => r.seq)).toEqual(Array.from({ length: writers * 2 }, (_, i) => i + 1));
    expect(chain[0]!.prevHash).toBe("GENESIS");
    await expect(verifyChain(chain)).resolves.toEqual({ ok: true });
  });
});
