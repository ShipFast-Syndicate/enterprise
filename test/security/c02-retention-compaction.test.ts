// C-02 — retention purge silently broke the hash chain (High).
//
// Audit repro: once any row ages past `retentionDays`, the next
// `GET /enterprise/audit/list` deleted it, after which
// `GET /enterprise/audit/verify` returned `{"ok":false,"brokenAtSeq":…}`
// **permanently** — the compliance signal became noise during entirely
// normal operation. Retention is archival compaction now: the expired prefix
// is replaced by one signed `audit.retention_compacted` anchor row, and
// `verifyChain` re-anchors on it.

import { describe, expect, it } from "vitest";
import type { AuthContext } from "better-auth";
import { makeAuth, signUpOwner, createOrg, type TestAuth } from "../helpers/auth";
import { compactChain, hashRow, type AuditRowForHash } from "../../src/server/audit/chain";
import { auditRows } from "./helpers";

const DAY_MS = 24 * 60 * 60 * 1000;

async function inviteMember(t: TestAuth, cookie: string, orgId: string, email: string) {
  const res = await t.api.post(
    "/organization/invite-member",
    { email, role: "member", organizationId: orgId },
    { cookie },
  );
  if (!res.ok) throw new Error(`invite failed: ${res.status} ${await res.text()}`);
}

/** Back-dates every existing row of an org's chain so the next compaction sweeps it. */
async function ageRows(t: TestAuth, orgId: string, days: number, upToSeq: number) {
  await t.client.execute({
    sql: `UPDATE audit_event SET created_at = ? WHERE org_id = ? AND seq <= ?`,
    args: [Date.now() - days * DAY_MS, orgId, upToSeq],
  });
}

async function verify(t: TestAuth, cookie: string, orgId: string) {
  const res = await t.api.get(`/enterprise/audit/verify?orgId=${orgId}`, { cookie });
  return (await res.json()) as { ok: boolean; brokenAtSeq?: number };
}

describe("C-02 — retention compaction keeps the chain verifiable", () => {
  it("rows age out, get compacted on list, and verify still reports ok", async () => {
    const t = await makeAuth({ audit: { retentionDays: 30 } });
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);

    await inviteMember(t, cookie, orgId, "one@acme.test");
    await inviteMember(t, cookie, orgId, "two@acme.test");
    await inviteMember(t, cookie, orgId, "three@acme.test");
    expect((await verify(t, cookie, orgId)).ok).toBe(true);

    // First two rows are now older than the retention window.
    await ageRows(t, orgId, 40, 2);

    const listRes = await t.api.get(`/enterprise/audit/list?orgId=${orgId}`, { cookie });
    expect(listRes.status).toBe(200);

    const rows = await auditRows(t, orgId);
    expect(rows[0]!.action).toBe("audit.retention_compacted");
    expect(rows.length).toBe(2); // one anchor + the one surviving row

    // The whole point of the finding: this used to be {ok:false, brokenAtSeq:3}.
    expect(await verify(t, cookie, orgId)).toEqual({ ok: true });
  });

  it("compacting twice still verifies (the previous anchor is swept with the prefix)", async () => {
    const t = await makeAuth({ audit: { retentionDays: 30 } });
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);

    await inviteMember(t, cookie, orgId, "one@acme.test");
    await inviteMember(t, cookie, orgId, "two@acme.test");
    await ageRows(t, orgId, 40, 1);
    await t.api.post("/enterprise/audit/compact", { orgId }, { cookie });

    await inviteMember(t, cookie, orgId, "three@acme.test");
    await ageRows(t, orgId, 40, 2);
    const second = await t.api.post("/enterprise/audit/compact", { orgId }, { cookie });
    expect(second.status).toBe(200);
    expect(await second.json()).toMatchObject({ compacted: true });

    const rows = await auditRows(t, orgId);
    expect(rows.filter((r) => r.action === "audit.retention_compacted").length).toBe(1);
    expect(await verify(t, cookie, orgId)).toEqual({ ok: true });
  });

  it("a real edit inside the surviving window is still caught after compaction", async () => {
    const t = await makeAuth({ audit: { retentionDays: 30 } });
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);

    await inviteMember(t, cookie, orgId, "one@acme.test");
    await inviteMember(t, cookie, orgId, "two@acme.test");
    await inviteMember(t, cookie, orgId, "three@acme.test");
    await ageRows(t, orgId, 40, 1);
    await t.api.post("/enterprise/audit/compact", { orgId }, { cookie });

    await t.client.execute({
      sql: `UPDATE audit_event SET action = 'member.tampered' WHERE org_id = ? AND seq = 3`,
      args: [orgId],
    });

    const verdict = await verify(t, cookie, orgId);
    expect(verdict.ok).toBe(false);
    expect(verdict.brokenAtSeq).toBe(3);
  });

  // I-4 — C-02's remaining crash window. Compaction used to delete the
  // expired prefix and only then create the anchor: a crash, a request
  // timeout or a throwing `create` in between left the prefix gone with
  // nothing to re-anchor on, and `verify` reported `ok:false` for that org
  // from then on — the same permanent false positive C-02 exists to prevent,
  // reached through a crash instead of through normal operation, with no
  // recovery path and a plain `GET /enterprise/audit/list` as the trigger.
  describe("a crash mid-compaction still leaves a verifiable chain", () => {
    /**
     * The live adapter with one method replaced by a thrower — a crash at that
     * exact step. Cast because `auth.$context`'s adapter is typed against the
     * *inferred* options of this particular instance, while `compactChain`
     * takes the generic `AuthContext["adapter"]`; it is the same object.
     */
    async function adapterThatFailsAt(
      t: TestAuth,
      method: "deleteMany" | "update",
    ): Promise<AuthContext["adapter"]> {
      const { adapter } = await t.auth.$context;
      return new Proxy(adapter, {
        get(target, prop, receiver) {
          if (prop === method) {
            return () => Promise.reject(new Error("simulated crash"));
          }
          return Reflect.get(target, prop, receiver) as unknown;
        },
      }) as unknown as AuthContext["adapter"];
    }

    /**
     * Writes a valid chain straight to the table, each row `ageDays` old.
     * Back-dating rows written through the API instead (the `ageRows` helper
     * above) rewrites `created_at`, which is part of the hashed payload — fine
     * for the tests where those rows are compacted away before anything
     * verifies them, but not here, where the whole point is that they survive
     * a crash and still verify.
     */
    async function seedChain(t: TestAuth, orgId: string, ageDays: number[]): Promise<void> {
      await t.client.execute({ sql: `DELETE FROM audit_event WHERE org_id = ?`, args: [orgId] });
      let prevHash = "GENESIS";
      for (const [index, days] of ageDays.entries()) {
        const row: AuditRowForHash = {
          orgId,
          seq: index + 1,
          actorType: "user",
          actorId: "user_1",
          action: "member.invited",
          targetType: "member",
          targetId: `inv_${index + 1}`,
          ip: null,
          userAgent: null,
          metadata: {},
          createdAt: Date.now() - days * DAY_MS,
        };
        const hash = await hashRow(prevHash, row);
        await t.client.execute({
          sql: `INSERT INTO audit_event (id, org_id, seq, actor_type, actor_id, action, target_type, target_id, ip, user_agent, metadata, created_at, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          args: [
            `evt_${index + 1}`,
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
    }

    /** Two rows past the 30-day window, one inside it — and the cutoff that window implies. */
    async function seedAgedChain(t: TestAuth, orgId: string): Promise<Date> {
      await seedChain(t, orgId, [40, 40, 0]);
      return new Date(Date.now() - 30 * DAY_MS);
    }

    async function actions(t: TestAuth, orgId: string): Promise<string[]> {
      const rows = await auditRows(t, orgId);
      return rows.map((r) => String(r.action));
    }

    it("crashing before the delete lands: the original chain is untouched and still verifies", async () => {
      const t = await makeAuth({ audit: { retentionDays: 30 } });
      const { cookie } = await signUpOwner(t);
      const { orgId } = await createOrg(t, cookie);
      const cutoff = await seedAgedChain(t, orgId);

      await expect(
        compactChain(
          { context: { adapter: await adapterThatFailsAt(t, "deleteMany") } },
          orgId,
          cutoff,
        ),
      ).rejects.toThrow("simulated crash");

      // The pending anchor is there, in front of a prefix that never went away.
      expect(await actions(t, orgId)).toEqual([
        "audit.retention_compacting",
        "member.invited",
        "member.invited",
        "member.invited",
      ]);
      expect(await verify(t, cookie, orgId)).toEqual({ ok: true });

      // …and the next compaction sweeps the stale anchor with the prefix.
      const retry = await t.api.post("/enterprise/audit/compact", { orgId }, { cookie });
      expect(retry.status).toBe(200);
      expect(await actions(t, orgId)).toEqual(["audit.retention_compacted", "member.invited"]);
      expect(await verify(t, cookie, orgId)).toEqual({ ok: true });
    });

    it("crashing after the delete, before the anchor is marked complete: the pending anchor still anchors the chain", async () => {
      const t = await makeAuth({ audit: { retentionDays: 30 } });
      const { cookie } = await signUpOwner(t);
      const { orgId } = await createOrg(t, cookie);
      const cutoff = await seedAgedChain(t, orgId);

      await expect(
        compactChain(
          { context: { adapter: await adapterThatFailsAt(t, "update") } },
          orgId,
          cutoff,
        ),
      ).rejects.toThrow("simulated crash");

      // This is the state the old delete-then-create order could not survive:
      // the expired prefix is gone. The anchor written *first* is what keeps
      // the chain verifiable.
      expect(await actions(t, orgId)).toEqual(["audit.retention_compacting", "member.invited"]);
      expect(await verify(t, cookie, orgId)).toEqual({ ok: true });
    });

    // Same bug as the completed-anchor test above, reached through the I-4
    // crash window instead of a clean compaction: a pending anchor whose
    // prefix is already gone is, per `verifyChainPage`, exactly like a
    // completed one — so it must anchor the next write's `prevHash` off its
    // `metadata.lastHash` too, not its own `hash`.
    it("the first write after a crash leaves a pending anchor still chains correctly, and a later completed compaction still verifies", async () => {
      const t = await makeAuth({ audit: { retentionDays: 30 } });
      const { cookie } = await signUpOwner(t);
      const { orgId } = await createOrg(t, cookie);

      // Every row expired this time — the crash-created pending anchor ends
      // up as the org's entire surviving chain.
      await seedChain(t, orgId, [40, 40]);
      const cutoff = new Date(Date.now() - 30 * DAY_MS);

      await expect(
        compactChain(
          { context: { adapter: await adapterThatFailsAt(t, "update") } },
          orgId,
          cutoff,
        ),
      ).rejects.toThrow("simulated crash");

      expect(await actions(t, orgId)).toEqual(["audit.retention_compacting"]);
      expect(await verify(t, cookie, orgId)).toEqual({ ok: true });

      await inviteMember(t, cookie, orgId, "one@acme.test");
      expect(await verify(t, cookie, orgId)).toEqual({ ok: true });

      // Age the new row out too (whatever `seq` the write path gave it —
      // deliberately not assumed here) and run a real (non-crashing)
      // compaction: it sweeps the stale pending anchor along with it
      // (existing I-4 behaviour), and the chain must still verify on the
      // far side.
      const newRowSeq = Number((await auditRows(t, orgId)).at(-1)!.seq);
      await ageRows(t, orgId, 40, newRowSeq);
      const retry = await t.api.post("/enterprise/audit/compact", { orgId }, { cookie });
      expect(retry.status).toBe(200);
      expect(await actions(t, orgId)).toEqual(["audit.retention_compacted"]);
      expect(await verify(t, cookie, orgId)).toEqual({ ok: true });
    });
  });

  // The write path used to disagree with `verifyChainPage`'s anchor
  // semantics: when the org's *entire* chain was swept by compaction, the
  // anchor is the only row left, so `insertNextRow`'s "last row" query
  // selects it — and it used to chain the next write off the anchor's own
  // `hash` instead of `metadata.lastHash` (the hash of the last row that was
  // compacted away), which is what `verifyChainPage` re-anchors on. That
  // made the org's chain report `ok:false` forever, starting from the very
  // first write after the compaction.
  it("the first write after compaction removes an org's entire chain still chains correctly, from a completed anchor", async () => {
    const t = await makeAuth({ audit: { retentionDays: 30 } });
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);

    await inviteMember(t, cookie, orgId, "one@acme.test");
    await inviteMember(t, cookie, orgId, "two@acme.test");
    // Every row the org has is now older than the retention window — the
    // whole chain, not just a prefix, is due for compaction.
    await ageRows(t, orgId, 40, 2);

    const compactRes = await t.api.post("/enterprise/audit/compact", { orgId }, { cookie });
    expect(compactRes.status).toBe(200);

    const afterCompaction = await auditRows(t, orgId);
    expect(afterCompaction.length).toBe(1);
    expect(afterCompaction[0]!.action).toBe("audit.retention_compacted");

    await inviteMember(t, cookie, orgId, "three@acme.test");
    expect(await verify(t, cookie, orgId)).toEqual({ ok: true });

    // A second write on top of the first must still check out too.
    await inviteMember(t, cookie, orgId, "four@acme.test");
    expect(await verify(t, cookie, orgId)).toEqual({ ok: true });
  });

  it("POST /enterprise/audit/compact is owner/admin-only and feature-gated", async () => {
    const t = await makeAuth({ resolveEntitlements: async () => [] });
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);

    const gated = await t.api.post("/enterprise/audit/compact", { orgId }, { cookie });
    expect(gated.status).toBe(403);
    expect(((await gated.json()) as { code: string }).code).toBe("FEATURE_NOT_ENTITLED");

    const t2 = await makeAuth();
    const owner = await signUpOwner(t2, "owner@acme.test");
    const org2 = await createOrg(t2, owner.cookie, "acme");
    const outsider = await signUpOwner(t2, "outsider@other.test");
    const res = await t2.api.post(
      "/enterprise/audit/compact",
      { orgId: org2.orgId },
      { cookie: outsider.cookie },
    );
    expect(res.status).toBe(403);
    expect(((await res.json()) as { code: string }).code).toBe("NOT_ORG_MEMBER");
  });
});
