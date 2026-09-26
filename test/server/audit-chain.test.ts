import { describe, expect, it } from "vitest";
import type { GenericEndpointContext } from "better-auth";
import {
  canonical,
  compactChain,
  hashRow,
  isKeyedHash,
  verifyChain,
  verifyChainPage,
  writeAudit,
  KEYED_HASH_PREFIX,
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

// `keyFrom(seq)` picks the chain key each row is written under — `undefined`
// for a bare sha256 link — so one helper builds unkeyed, keyed and
// mixed (upgrade-in-the-middle) chains.
async function buildChain(
  rows: Array<Partial<AuditRow>>,
  keyFrom: (seq: number) => string | undefined = () => undefined,
): Promise<AuditRow[]> {
  const built: AuditRow[] = [];
  let prevHash = "GENESIS";
  for (const overrides of rows) {
    const candidate = row({ ...overrides, prevHash });
    const hash = await hashRow(prevHash, candidate, keyFrom(candidate.seq));
    const withHash = { ...candidate, hash };
    built.push(withHash);
    prevHash = hash;
  }
  return built;
}

const CHAIN_KEY = "audit-chain-key-for-tests-".repeat(2);

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

// `audit.chainKey` — keyed (HMAC-SHA256) links, so a database-write holder
// without the key can no longer rewrite an org's chain consistently. Adoption
// is monotonic: unkeyed rows may precede keyed ones (the day the key was
// set), never follow them.
describe("hashRow with a chain key", () => {
  it("is deterministic, prefixed hmac:, and differs from the unkeyed hash and from another key's", async () => {
    const r = row();
    const keyed = await hashRow("GENESIS", r, CHAIN_KEY);
    expect(keyed).toBe(await hashRow("GENESIS", r, CHAIN_KEY));
    expect(keyed).toMatch(/^hmac:[0-9a-f]{64}$/);
    expect(isKeyedHash(keyed)).toBe(true);
    expect(keyed.startsWith(KEYED_HASH_PREFIX)).toBe(true);

    const bare = await hashRow("GENESIS", r);
    expect(isKeyedHash(bare)).toBe(false);
    expect(keyed).not.toBe(`hmac:${bare}`);
    expect(keyed).not.toBe(await hashRow("GENESIS", r, `${CHAIN_KEY}-other`));
  });
});

describe("verifyChain with a chain key", () => {
  it("verifies a fully keyed chain under its key", async () => {
    const rows = await buildChain([{ seq: 1 }, { seq: 2 }, { seq: 3 }], () => CHAIN_KEY);
    await expect(verifyChain(rows, CHAIN_KEY)).resolves.toEqual({ ok: true });
  });

  it("accepts an unkeyed prefix followed by a keyed suffix (the upgrade day)", async () => {
    const rows = await buildChain([{ seq: 1 }, { seq: 2 }, { seq: 3 }, { seq: 4 }], (seq) =>
      seq >= 3 ? CHAIN_KEY : undefined,
    );
    expect(isKeyedHash(rows[1]!.hash)).toBe(false);
    expect(isKeyedHash(rows[2]!.hash)).toBe(true);
    await expect(verifyChain(rows, CHAIN_KEY)).resolves.toEqual({ ok: true });
  });

  it("a bare row after a keyed row breaks the chain at that seq (no downgrade)", async () => {
    const rows = await buildChain([{ seq: 1 }, { seq: 2 }, { seq: 3 }], (seq) =>
      seq === 3 ? undefined : CHAIN_KEY,
    );
    await expect(verifyChain(rows, CHAIN_KEY)).resolves.toEqual({ ok: false, brokenAtSeq: 3 });
  });

  it("a keyed row verified without the key is keyed_row_without_key, never ok", async () => {
    const rows = await buildChain([{ seq: 1 }, { seq: 2 }], (seq) =>
      seq === 2 ? CHAIN_KEY : undefined,
    );
    await expect(verifyChain(rows)).resolves.toEqual({
      ok: false,
      brokenAtSeq: 2,
      reason: "keyed_row_without_key",
    });
  });

  it("a keyed row verified under the wrong key is a plain break (no reason)", async () => {
    const rows = await buildChain([{ seq: 1 }, { seq: 2 }], () => CHAIN_KEY);
    await expect(verifyChain(rows, `${CHAIN_KEY}-other`)).resolves.toEqual({
      ok: false,
      brokenAtSeq: 1,
    });
  });

  it("a tampered keyed row re-hashed with sha256 (the hash an attacker can compute) is detected", async () => {
    const rows = await buildChain([{ seq: 1 }, { seq: 2 }, { seq: 3 }], () => CHAIN_KEY);
    const tamperedRow = { ...rows[1]!, metadata: { tampered: true } };
    const forged = {
      ...tamperedRow,
      hash: await hashRow(tamperedRow.prevHash, tamperedRow), // bare sha256, no key needed
    };
    const tampered = rows.map((r) => (r.seq === 2 ? forged : r));

    await expect(verifyChain(tampered, CHAIN_KEY)).resolves.toEqual({ ok: false, brokenAtSeq: 2 });
  });

  it("a tampered keyed row whose HMAC was not recomputed is detected under the key", async () => {
    const rows = await buildChain([{ seq: 1 }, { seq: 2 }, { seq: 3 }], () => CHAIN_KEY);
    const tampered = rows.map((r) => (r.seq === 2 ? { ...r, metadata: { tampered: true } } : r));

    await expect(verifyChain(tampered, CHAIN_KEY)).resolves.toEqual({ ok: false, brokenAtSeq: 2 });
  });

  it("carries the keyed state across verifyChainPage pages via prevHash", async () => {
    const rows = await buildChain([{ seq: 1 }, { seq: 2 }, { seq: 3 }, { seq: 4 }], (seq) =>
      seq >= 2 ? CHAIN_KEY : undefined,
    );
    const first = await verifyChainPage(rows.slice(0, 2), null, CHAIN_KEY);
    expect(first).toEqual({ ok: true, prevHash: rows[1]!.hash });
    if (!first.ok) throw new Error("unreachable");
    expect(isKeyedHash(first.prevHash)).toBe(true);

    // A bare continuation of a keyed page is refused, even with the key.
    const bareTail = await buildChain([{ seq: 1 }, { seq: 2 }, { seq: 3 }], (seq) =>
      seq >= 2 ? CHAIN_KEY : undefined,
    );
    const bareRow3 = { ...bareTail[2]!, hash: await hashRow(bareTail[2]!.prevHash, bareTail[2]!) };
    await expect(verifyChainPage([bareRow3], first.prevHash, CHAIN_KEY)).resolves.toEqual({
      ok: false,
      brokenAtSeq: 3,
    });
    await expect(verifyChainPage(rows.slice(2), first.prevHash, CHAIN_KEY)).resolves.toEqual({
      ok: true,
      prevHash: rows[3]!.hash,
    });
  });
});

describe("writeAudit / compactChain with a chain key", () => {
  const input = {
    orgId: "org_keyed",
    actorType: "user" as const,
    actorId: "user_1",
    action: "member.invited",
    targetType: "member",
    targetId: "inv_1",
  };

  it("writes keyed links when given { chainKey } and bare links otherwise (byte-identical legacy behaviour)", async () => {
    const t = await makeAuth();
    const ctx = { context: await t.auth.$context } as unknown as GenericEndpointContext;

    const bare = await writeAudit(ctx, input);
    const keyed = await writeAudit(ctx, input, { chainKey: CHAIN_KEY });

    expect(isKeyedHash(bare.hash)).toBe(false);
    expect(bare.hash).toBe(await hashRow("GENESIS", bare));
    expect(isKeyedHash(keyed.hash)).toBe(true);
    expect(keyed.prevHash).toBe(bare.hash);
    expect(keyed.hash).toBe(await hashRow(bare.hash, keyed, CHAIN_KEY));
    await expect(verifyChain([bare, keyed], CHAIN_KEY)).resolves.toEqual({ ok: true });
    await expect(verifyChain([bare, keyed])).resolves.toEqual({
      ok: false,
      brokenAtSeq: 2,
      reason: "keyed_row_without_key",
    });
  });

  it("a compaction anchor written under the key keeps a keyed chain verifiable", async () => {
    const t = await makeAuth();
    const ctx = { context: await t.auth.$context } as unknown as GenericEndpointContext;
    const first = await writeAudit(ctx, input, { chainKey: CHAIN_KEY });
    const second = await writeAudit(ctx, input, { chainKey: CHAIN_KEY });
    // Age the first row past the cutoff.
    await t.client.execute({
      sql: `UPDATE audit_event SET created_at = ? WHERE org_id = ? AND seq = ?`,
      args: [Date.now() - 10 * 24 * 3600 * 1000, input.orgId, first.seq],
    });

    const result = await compactChain(ctx, input.orgId, new Date(Date.now() - 24 * 3600 * 1000), {
      chainKey: CHAIN_KEY,
    });
    expect(result).toEqual({ compactedThroughSeq: 1, compactedCount: 1, lastHash: first.hash });

    const rows = await t.client.execute({
      sql: `SELECT * FROM audit_event WHERE org_id = ? ORDER BY seq ASC`,
      args: [input.orgId],
    });
    const chain = rows.rows.map(
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
    expect(chain.map((r) => r.seq)).toEqual([0, 2]);
    expect(chain[0]!.action).toBe(RETENTION_COMPACTED_ACTION);
    expect(isKeyedHash(chain[0]!.hash)).toBe(true);
    expect(chain[1]!.hash).toBe(second.hash);
    await expect(verifyChain(chain, CHAIN_KEY)).resolves.toEqual({ ok: true });
    // Compacting a keyed chain *without* the key would write a bare anchor
    // after a keyed tail — verify then reports the downgrade.
    await expect(verifyChain(chain)).resolves.toMatchObject({ ok: false, brokenAtSeq: 0 });
  });
});
