// C-01 — cross-tenant audit-log injection (High).
//
// Audit repro (verbatim in shape): a user who is a member of nothing signs
// up, then `POST /sign-out?orgId=<victim org>` — and a row landed in the
// victim's chain with the attacker's own `user_agent`, while
// `/enterprise/audit/verify` still reported `ok:true`, i.e. the forgery was
// cryptographically indistinguishable from a genuine entry.

import { describe, expect, it } from "vitest";
import { makeAuth, signUpOwner, createOrg } from "../helpers/auth";
import { auditRows, insertMemberRow } from "./helpers";

describe("C-01 — audit orgId is never taken from the caller", () => {
  it("a non-member's ?orgId=<victim> writes nothing to the victim's chain", async () => {
    const t = await makeAuth();
    const victim = await signUpOwner(t, "victim@victim.test");
    const { orgId } = await createOrg(t, victim.cookie, "victim");
    const before = await auditRows(t, orgId);

    const attacker = await signUpOwner(t, "attacker@evil.test"); // member of nothing
    const res = await t.api.post(
      `/sign-out?orgId=${orgId}`,
      {},
      { cookie: attacker.cookie, "user-agent": "=cmd|'/C calc'!A0" },
    );
    expect(res.status).toBe(200); // the request itself still succeeds — it just isn't audited

    const after = await auditRows(t, orgId);
    expect(after.length).toBe(before.length);
    expect(after.map((r) => r.user_agent)).not.toContain("=cmd|'/C calc'!A0");
  });

  it("a non-member's ?orgId=<victim> on a sign-in path writes nothing either", async () => {
    const t = await makeAuth();
    const victim = await signUpOwner(t, "victim2@victim.test");
    const { orgId } = await createOrg(t, victim.cookie, "victim2");
    await signUpOwner(t, "attacker2@evil.test");
    const before = await auditRows(t, orgId);

    const res = await t.api.post(`/sign-in/email?orgId=${orgId}`, {
      email: "attacker2@evil.test",
      password: "password1234",
    });
    expect(res.status).toBe(200);

    expect((await auditRows(t, orgId)).length).toBe(before.length);
  });

  it("a genuine member's own org is still audited (the fix is not a blanket block)", async () => {
    const t = await makeAuth();
    const owner = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, owner.cookie, "acme");
    const member = await signUpOwner(t, "member@acme.test");
    await insertMemberRow(t, orgId, member.userId, "member");
    const before = await auditRows(t, orgId);

    const res = await t.api.post(`/sign-out?orgId=${orgId}`, {}, { cookie: member.cookie });
    expect(res.status).toBe(200);

    const after = await auditRows(t, orgId);
    expect(after.length).toBe(before.length + 1);
    expect(after[after.length - 1]!.action).toBe("auth.sign_out");
  });
});
