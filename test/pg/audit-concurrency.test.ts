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
import { isUniqueViolation, verifyChain, type AuditRow } from "../../src/server/audit/chain";
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

  it("writers that all read the chain before any writes recover through the 23505 retry into a valid chain", async () => {
    const writers = 4;
    const t = await makeAuth();
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
});
