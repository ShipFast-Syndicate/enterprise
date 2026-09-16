// C-03 — SCIM group changes mass-demoted org owners/admins (High).
//
// Audit repro: with `groupRoleMap = {Engineers: "admin"}` configured, adding
// a *second org owner* to any SCIM group rewrote `member.role` to
// `effectiveRole(...)` — `"member"` whenever no group maps them — audited as
// `member.role_changed {"from":"owner","to":"member"}`. The sole-owner guard
// only ever protected the *last* owner, so with two owners either could be
// stripped by a semi-trusted SCIM client. Multi-role values were flattened
// the same way.

import { describe, expect, it } from "vitest";
import { makeAuth, signUpOwner, createOrg, type TestAuth } from "../helpers/auth";
import { insertMemberRow, mintScimToken, setPolicy } from "./helpers";

async function roleOf(t: TestAuth, orgId: string, userId: string): Promise<string> {
  const res = await t.client.execute({
    sql: `SELECT role FROM member WHERE organizationId = ? AND userId = ?`,
    args: [orgId, userId],
  });
  return String(res.rows[0]!.role);
}

describe("C-03 — SCIM never demotes an owner or a manually assigned role", () => {
  it("two owners: a SCIM group add/remove leaves both owners", async () => {
    const t = await makeAuth();
    const first = await signUpOwner(t, "owner1@acme.test");
    const { orgId } = await createOrg(t, first.cookie);
    const second = await signUpOwner(t, "owner2@acme.test");
    await insertMemberRow(t, orgId, second.userId, "owner");

    await setPolicy(t, first.cookie, { orgId, groupRoleMap: { Engineers: "admin" } });
    const bearer = await mintScimToken(t, first.cookie, orgId);

    const created = await t.api.post(
      "/scim/v2/Groups",
      { displayName: "Engineers", members: [{ value: second.userId }] },
      bearer,
    );
    expect(created.status).toBe(201);
    expect(await roleOf(t, orgId, second.userId)).toBe("owner");
    expect(await roleOf(t, orgId, first.userId)).toBe("owner");

    const group = (await created.json()) as { id: string };
    const removed = await t.api.request(
      "PATCH",
      `/scim/v2/Groups/${group.id}`,
      {
        schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        Operations: [{ op: "remove", path: `members[value eq "${second.userId}"]` }],
      },
      bearer,
    );
    expect(removed.status).toBe(200);
    expect(await roleOf(t, orgId, second.userId)).toBe("owner");
    expect(await roleOf(t, orgId, first.userId)).toBe("owner");

    const skipped = await t.client.execute({
      sql: `SELECT metadata FROM audit_event WHERE org_id = ? AND action = 'scim.role_change_skipped' AND target_id = ?`,
      args: [orgId, second.userId],
    });
    expect(skipped.rows.length).toBeGreaterThan(0);
    expect(String(skipped.rows[0]!.metadata)).toContain("owner_protected");
  });

  it("an admin the map never granted is not demoted when the map has no admin target", async () => {
    const t = await makeAuth();
    const owner = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, owner.cookie);
    const admin = await signUpOwner(t, "admin@acme.test");
    await insertMemberRow(t, orgId, admin.userId, "admin");

    await setPolicy(t, owner.cookie, { orgId, groupRoleMap: { Everyone: "member" } });
    const bearer = await mintScimToken(t, owner.cookie, orgId);

    const created = await t.api.post(
      "/scim/v2/Groups",
      { displayName: "Everyone", members: [{ value: admin.userId }] },
      bearer,
    );
    expect(created.status).toBe(201);
    expect(await roleOf(t, orgId, admin.userId)).toBe("admin");
  });

  it("a multi-role member row is never flattened", async () => {
    const t = await makeAuth();
    const owner = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, owner.cookie);
    const multi = await signUpOwner(t, "multi@acme.test");
    await insertMemberRow(t, orgId, multi.userId, "admin,billing");

    await setPolicy(t, owner.cookie, { orgId, groupRoleMap: { Everyone: "member" } });
    const bearer = await mintScimToken(t, owner.cookie, orgId);

    const created = await t.api.post(
      "/scim/v2/Groups",
      { displayName: "Everyone", members: [{ value: multi.userId }] },
      bearer,
    );
    expect(created.status).toBe(201);
    expect(await roleOf(t, orgId, multi.userId)).toBe("admin,billing");
  });

  it("a SCIM-granted role is still raised and still falls back when the user leaves the group", async () => {
    const t = await makeAuth();
    const owner = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, owner.cookie);
    const user = await signUpOwner(t, "plain@acme.test");
    await insertMemberRow(t, orgId, user.userId, "member");

    await setPolicy(t, owner.cookie, { orgId, groupRoleMap: { Admins: "admin" } });
    const bearer = await mintScimToken(t, owner.cookie, orgId);

    const created = await t.api.post(
      "/scim/v2/Groups",
      { displayName: "Admins", members: [{ value: user.userId }] },
      bearer,
    );
    expect(created.status).toBe(201);
    expect(await roleOf(t, orgId, user.userId)).toBe("admin");

    const group = (await created.json()) as { id: string };
    const removed = await t.api.request(
      "PATCH",
      `/scim/v2/Groups/${group.id}`,
      {
        schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        Operations: [{ op: "remove", path: `members[value eq "${user.userId}"]` }],
      },
      bearer,
    );
    expect(removed.status).toBe(200);
    expect(await roleOf(t, orgId, user.userId)).toBe("member");
  });
});
