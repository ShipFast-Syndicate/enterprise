// M-02 — CSV export formula injection.
//
// Audit repro: an attacker sets `User-Agent: =cmd|'/C calc'!A0`, the victim
// admin opens the exported CSV in Excel/Sheets, and the payload — which
// appeared verbatim in the `user_agent` column — is evaluated as a formula.
// Every cell that starts with `= + - @ TAB CR` is prefixed with `'` now.

import { describe, expect, it } from "vitest";
import { makeAuth, signUpOwner, createOrg } from "../helpers/auth";

const PAYLOAD = "=cmd|'/C calc'!A0";

describe("M-02 — exported CSV cells can't be formulas", () => {
  it("neutralises a formula payload that reached the log through User-Agent", async () => {
    const t = await makeAuth();
    const { cookie, userId } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);

    // The member themselves is the actor, so this is a *legitimately*
    // audited row (C-01) that still carries attacker-controlled text.
    const signOut = await t.api.post(
      `/sign-out?orgId=${orgId}`,
      {},
      { cookie, "user-agent": PAYLOAD },
    );
    expect(signOut.status).toBe(200);
    expect(userId).toBeTruthy();

    const fresh = await t.api.post("/sign-in/email", {
      email: "owner@acme.test",
      password: "password1234",
    });
    const cookie2 = fresh.headers
      .getSetCookie()
      .map((c) => c.split(";")[0])
      .join("; ");

    const res = await t.api.get(`/enterprise/audit/export?orgId=${orgId}`, { cookie: cookie2 });
    expect(res.status).toBe(200);
    const csv = await res.text();

    expect(csv).toContain(`,'${PAYLOAD},`); // the cell is prefixed with a single quote
    expect(csv).not.toMatch(/(^|,)=cmd/m); // …so no cell *starts* with the formula

    // A payload that also needs RFC 4180 quoting gets both treatments.
    const quoted = `=HYPERLINK("http://evil.test","click"),x`;
    const { toCsvRowForTest } = await import("../../src/server/audit/plugin");
    expect(toCsvRowForTest(quoted)).toBe(`"'=HYPERLINK(""http://evil.test"",""click""),x"`);
  });

  it("does not corrupt ordinary cells", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);
    await t.api.post(
      "/organization/invite-member",
      { email: "someone@acme.test", role: "member", organizationId: orgId },
      { cookie },
    );

    const res = await t.api.get(`/enterprise/audit/export?orgId=${orgId}`, { cookie });
    const csv = await res.text();
    expect(csv.split("\r\n")[0]).toBe(
      "id,seq,created_at,actor_type,actor_id,action,target_type,target_id,ip,user_agent,metadata,prev_hash,hash",
    );
    expect(csv).toContain("member.invited");
    expect(csv).not.toContain("'member.invited");
  });

  it("sanitises the orgId interpolated into content-disposition (L-05)", async () => {
    const t = await makeAuth();
    const { cookie, userId } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);
    // A hostile org id can only exist if the product generates ids itself,
    // but the header must not be forgeable regardless.
    await t.client.execute({
      sql: `INSERT INTO member (id, organizationId, userId, role, createdAt) VALUES (?, ?, ?, 'owner', ?)`,
      args: ["member_evil", 'evil"\r\nX-Injected: 1', userId, Date.now()],
    });

    const res = await t.api.get(
      `/enterprise/audit/export?orgId=${encodeURIComponent('evil"\r\nX-Injected: 1')}`,
      { cookie },
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("x-injected")).toBeNull();
    const disposition = res.headers.get("content-disposition") ?? "";
    expect(disposition).toBe(
      `attachment; filename="audit-${'evil"\r\nX-Injected: 1'.replace(/[^A-Za-z0-9_-]/g, "_")}.csv"`,
    );
    expect(disposition).not.toMatch(/[\r\n]/);
    expect(disposition.match(/"/g)?.length).toBe(2); // only the two that quote the filename
    expect(orgId).toBeTruthy();
  });
});
