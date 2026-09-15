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
import { makeAuth, signUpOwner, createOrg, type TestAuth } from "../helpers/auth";
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
