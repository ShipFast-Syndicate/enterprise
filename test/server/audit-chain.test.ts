import { describe, expect, it } from "vitest";
import type { GenericEndpointContext } from "better-auth";
import {
  canonical,
  hashRow,
  verifyChain,
  verifyChainPage,
  writeAudit,
  RETENTION_COMPACTED_ACTION,
  type AuditRow,
} from "../../src/server/audit/chain";
import { makeAuth } from "../helpers/auth";

function row(overrides: Partial<AuditRow> = {}): AuditRow {
  return {
    id: "id_1",
    orgId: "org_1",
    seq: 1,
    actorType: "user",
    actorId: "user_1",
    action: "member.invited",
    targetType: "member",
    targetId: "inv_1",
    ip: "127.0.0.1",
    userAgent: "vitest",
    metadata: {},
    createdAt: 1_700_000_000_000,
    prevHash: "GENESIS",
    hash: "",
    ...overrides,
  };
}

async function buildChain(rows: Array<Partial<AuditRow>>): Promise<AuditRow[]> {
  const built: AuditRow[] = [];
  let prevHash = "GENESIS";
  for (const overrides of rows) {
    const candidate = row({ ...overrides, prevHash });
    const hash = await hashRow(prevHash, candidate);
    const withHash = { ...candidate, hash };
    built.push(withHash);
    prevHash = hash;
  }
  return built;
}

describe("canonical", () => {
  it("serializes the hashed fields in the fixed key order, ignoring extra AuditRow fields", () => {
    const r = row({ orgId: "org_1", seq: 3, createdAt: 42 });
    const json = canonical(r);
    expect(json).toBe(
      JSON.stringify({
        orgId: "org_1",
        seq: 3,
        actorType: "user",
        actorId: "user_1",
        action: "member.invited",
        targetType: "member",
        targetId: "inv_1",
        ip: "127.0.0.1",
        userAgent: "vitest",
        metadata: {},
        createdAt: 42,
      }),
    );
  });
});

describe("hashRow", () => {
  it("is deterministic for the same prevHash + row", async () => {
    const r = row();
    const a = await hashRow("GENESIS", r);
    const b = await hashRow("GENESIS", r);
    expect(a).toBe(b);
    expect(a).toMatch(/^[0-9a-f]{64}$/);
  });

  it("changes when prevHash changes", async () => {
    const r = row();
    const a = await hashRow("GENESIS", r);
    const b = await hashRow("some-other-hash", r);
    expect(a).not.toBe(b);
  });

  it("changes when any hashed field changes", async () => {
    const r = row();
    const a = await hashRow("GENESIS", r);
    const b = await hashRow("GENESIS", { ...r, metadata: { tampered: true } });
    expect(a).not.toBe(b);
  });
});

describe("verifyChain", () => {
  it("reports ok:true for a correctly chained set of rows", async () => {
    const rows = await buildChain([
      { seq: 1, action: "member.invited" },
      { seq: 2, action: "member.role_changed" },
      { seq: 3, action: "member.removed" },
    ]);

    await expect(verifyChain(rows)).resolves.toEqual({ ok: true });
  });

  it("tampering row 2's metadata breaks the chain at seq 2", async () => {
    const rows = await buildChain([{ seq: 1 }, { seq: 2 }, { seq: 3 }]);
    const tampered = rows.map((r) => (r.seq === 2 ? { ...r, metadata: { tampered: true } } : r));

    await expect(verifyChain(tampered)).resolves.toEqual({ ok: false, brokenAtSeq: 2 });
  });

  it("deleting the last row keeps the remainder ok:true (documented limit)", async () => {
    const rows = await buildChain([{ seq: 1 }, { seq: 2 }, { seq: 3 }]);
    const truncated = rows.filter((r) => r.seq !== 3);

    await expect(verifyChain(truncated)).resolves.toEqual({ ok: true });
  });

  it("deleting a middle row breaks the chain", async () => {
    const rows = await buildChain([{ seq: 1 }, { seq: 2 }, { seq: 3 }]);
    const withGap = rows.filter((r) => r.seq !== 2);

    const result = await verifyChain(withGap);
    expect(result.ok).toBe(false);
  });

  it("reports ok:true for an empty chain", async () => {
    await expect(verifyChain([])).resolves.toEqual({ ok: true });
  });
});

// I-3 — `/enterprise/audit/verify` walks long chains in bounded pages
// instead of materialising and hashing the whole table at once, so the
// running `prevHash` has to survive the page boundary.
describe("verifyChainPage", () => {
  it("carries prevHash across pages: two halves of one chain verify as one", async () => {
    const rows = await buildChain([{ seq: 1 }, { seq: 2 }, { seq: 3 }, { seq: 4 }]);

    const first = await verifyChainPage(rows.slice(0, 2), null);
    expect(first).toEqual({ ok: true, prevHash: rows[1]!.hash });
    if (!first.ok) throw new Error("unreachable");

    await expect(verifyChainPage(rows.slice(2), first.prevHash)).resolves.toEqual({
      ok: true,
      prevHash: rows[3]!.hash,
    });
  });

  it("catches a tamper in a later page, at that page's own row", async () => {
    const rows = await buildChain([{ seq: 1 }, { seq: 2 }, { seq: 3 }, { seq: 4 }]);
    const first = await verifyChainPage(rows.slice(0, 2), null);
    if (!first.ok) throw new Error("unreachable");

    const tampered = rows.slice(2).map((r) => (r.seq === 3 ? { ...r, metadata: { x: 1 } } : r));
    await expect(verifyChainPage(tampered, first.prevHash)).resolves.toEqual({
      ok: false,
      brokenAtSeq: 3,
    });
  });

  it("a page that does not continue the previous one is broken at its first row", async () => {
    const rows = await buildChain([{ seq: 1 }, { seq: 2 }, { seq: 3 }]);

    await expect(verifyChainPage(rows.slice(1), "not-the-previous-hash")).resolves.toEqual({
      ok: false,
      brokenAtSeq: 2,
    });
  });

  it("only the first page (prevHash === null) may start with a compaction anchor", async () => {
    const rows = await buildChain([{ seq: 1 }, { seq: 2 }]);
    // A non-first page is a plain continuation: an anchor-shaped row there is
    // not re-anchored on, it just fails to chain.
    const anchorLike = { ...rows[0]!, action: RETENTION_COMPACTED_ACTION };
    await expect(verifyChainPage([anchorLike], "GENESIS")).resolves.toEqual({
      ok: false,
      brokenAtSeq: 1,
    });
  });
});

describe("writeAudit — per-org mutex", () => {
  it("serializes two concurrent writes for the same org into a valid seq 1/2 chain", async () => {
    const t = await makeAuth();
    const ctx = { context: await t.auth.$context } as unknown as GenericEndpointContext;
    const input = {
      orgId: "org_concurrent",
      actorType: "user" as const,
      actorId: "user_1",
      action: "member.invited",
      targetType: "member",
      targetId: "inv_1",
    };

    const [a, b] = await Promise.all([writeAudit(ctx, input), writeAudit(ctx, input)]);

    const seqs = [a.seq, b.seq].sort((x, y) => x - y);
    expect(seqs).toEqual([1, 2]);

    const rows = [a, b].sort((x, y) => x.seq - y.seq);
    expect(rows[0]!.prevHash).toBe("GENESIS");
    expect(rows[1]!.prevHash).toBe(rows[0]!.hash);
    await expect(verifyChain(rows)).resolves.toEqual({ ok: true });
  });
});
