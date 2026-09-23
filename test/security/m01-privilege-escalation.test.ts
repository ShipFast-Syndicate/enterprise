// M-01 — org **admin** could escalate to **owner** via `groupRoleMap` plus a
// self-minted SCIM token.
//
// Audit repro, end to end: admin `POST /enterprise/policy/set
// {groupRoleMap:{Bosses:"owner"}}` → `POST /scim/generate-token` → `POST
// /scim/v2/Groups {displayName:"Bosses",members:[self]}` → the admin's
// `member.role` was `owner`. Three things now block it: `owner` is refused
// as a mapping target, only an owner may write `groupRoleMap`, and only an
// owner may mint a SCIM token.

import { describe, expect, it } from "vitest";
import { makeAuth, signUpOwner, createOrg, type TestAuth } from "../helpers/auth";
import { insertMemberRow, mintScimToken, createScimUser, coreUserId, setPolicy } from "./helpers";

async function code(res: Response): Promise<string> {
  return ((await res.json()) as { code: string }).code;
}

async function adminOf(t: TestAuth, orgId: string, email = "admin@acme.test") {
  const admin = await signUpOwner(t, email);
  await insertMemberRow(t, orgId, admin.userId, "admin");
  return admin;
}

describe("M-01 — the admin→owner escalation is closed at every step", () => {
  it('groupRoleMap may not target "owner" at all (400)', async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);

    const res = await setPolicy(t, cookie, { orgId, groupRoleMap: { Bosses: "owner" } });
    expect(res.status).toBe(400);
    expect(await code(res)).toBe("GROUP_ROLE_MAP_OWNER_FORBIDDEN");

    const ok = await setPolicy(t, cookie, { orgId, groupRoleMap: { Bosses: "admin" } });
    expect(ok.status).toBe(200);
  });

  it("an admin may not write groupRoleMap (owner only)", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);
    const admin = await adminOf(t, orgId);

    const res = await setPolicy(t, admin.cookie, { orgId, groupRoleMap: { Engineers: "admin" } });
    expect(res.status).toBe(403);
    expect(await code(res)).toBe("NOT_ORG_OWNER");
  });

  it("an admin may not write breakGlassUserId (owner only)", async () => {
    const t = await makeAuth();
    const owner = await signUpOwner(t);
    const { orgId } = await createOrg(t, owner.cookie);
    const admin = await adminOf(t, orgId);

    const res = await setPolicy(t, admin.cookie, { orgId, breakGlassUserId: admin.userId });
    expect(res.status).toBe(403);
    expect(await code(res)).toBe("NOT_ORG_OWNER");
  });

  it("an admin may not mint a SCIM token, on either the wrapper or the upstream path", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);
    const admin = await adminOf(t, orgId);

    const upstream = await t.api.post(
      "/scim/generate-token",
      { providerId: "hris", organizationId: orgId },
      { cookie: admin.cookie },
    );
    expect(upstream.status).toBe(404);

    const wrapper = await t.api.post(
      "/enterprise/scim/tokens/create",
      { orgId, providerId: "hris" },
      { cookie: admin.cookie },
    );
    expect(wrapper.status).toBe(403);
    expect(await code(wrapper)).toBe("NOT_ORG_OWNER");
  });

  // Round 2: the *static* `EnterpriseOptions.scim.groupRoleMap` fallback is
  // a second source of group→role mappings (it only became reachable when
  // the dead `?? opts.scim?.groupRoleMap` chain was fixed), and the raise
  // branch of the role recompute would apply an `"owner"` target from it.
  // The type refuses it; `resolveGroupRoleMap` drops it at runtime too, so
  // neither untyped JavaScript nor a stale policy row can grant ownership.
  it("a static scim.groupRoleMap targeting owner never yields an owner", async () => {
    const t = await makeAuth({
      // Deliberately past the (now narrowed) type — the runtime guard is
      // what this asserts.
      scim: { groupRoleMap: { Bosses: "owner" } as unknown as Record<string, "admin"> },
    });
    const owner = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, owner.cookie);
    const bearer = await mintScimToken(t, owner.cookie, orgId);
    const scimId = await createScimUser(t, bearer, "climber@acme.test");
    const victimOfEscalation = { userId: await coreUserId(t, scimId) };

    const created = await t.api.post(
      "/scim/v2/Groups",
      {
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        displayName: "Bosses",
        members: [{ value: scimId }],
      },
      bearer,
    );
    expect(created.status).toBe(201);

    const role = await t.client.execute({
      sql: `SELECT role FROM member WHERE organizationId = ? AND userId = ?`,
      args: [orgId, victimOfEscalation.userId],
    });
    expect(role.rows[0]!.role).toBe("member");
  });

  it("a stale policy row mapping a group to owner is ignored at runtime", async () => {
    const t = await makeAuth();
    const owner = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, owner.cookie);
    const bearer = await mintScimToken(t, owner.cookie, orgId);
    const scimId = await createScimUser(t, bearer, "climber@acme.test");
    const climber = { userId: await coreUserId(t, scimId) };

    // Written directly, the way a row predating M-01 (or a hand-edited
    // database) would look.
    await setPolicy(t, owner.cookie, { orgId, groupRoleMap: { Bosses: "admin" } });
    await t.client.execute({
      sql: `UPDATE org_policy SET group_role_map = ? WHERE org_id = ?`,
      args: ['{"Bosses":"owner"}', orgId],
    });

    const created = await t.api.post(
      "/scim/v2/Groups",
      {
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        displayName: "Bosses",
        members: [{ value: scimId }],
      },
      bearer,
    );
    expect(created.status).toBe(201);

    const role = await t.client.execute({
      sql: `SELECT role FROM member WHERE organizationId = ? AND userId = ?`,
      args: [orgId, climber.userId],
    });
    expect(role.rows[0]!.role).toBe("member");
  });

  // Final review I-1 — the rule M-01 introduced, narrowed to where the risk
  // actually is. Choosing *who* is exempt from enforcement stays owner-only
  // (the two cases above still hold); switching enforcement on against an
  // exemption an owner already chose is an admin's job, because the spec,
  // the README and `docs/sso.md` all sell SSO setup as an owner-or-admin
  // flow and the wizard's last step was unreachable for admins.
  describe("an admin may enable SSO enforcement against an owner's break-glass user", () => {
    async function orgReadyToEnforce(t: TestAuth) {
      const owner = await signUpOwner(t, "owner@acme.test");
      const { orgId } = await createOrg(t, owner.cookie);
      await t.client.execute({
        sql: `INSERT INTO "ssoProvider" (id, issuer, domain, domainVerified, organizationId, providerId, userId) VALUES (?, ?, ?, 1, ?, ?, ?)`,
        args: ["ssop_okta", "https://idp.test", "acme.test", orgId, "okta", owner.userId],
      });
      const now = Date.now();
      await t.client.execute({
        sql: `INSERT INTO verification (id, identifier, value, expiresAt, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?, ?)`,
        args: [
          "verif_test_ok_okta",
          "ab-sso-test-ok:okta",
          new Date().toISOString(),
          now + 365 * 24 * 60 * 60 * 1000,
          now,
          now,
        ],
      });
      // Only the owner can put the break-glass user in place.
      const set = await setPolicy(t, owner.cookie, { orgId, breakGlassUserId: owner.userId });
      expect(set.status).toBe(200);
      return { owner, orgId };
    }

    it("with breakGlassUserId omitted entirely", async () => {
      const t = await makeAuth();
      const { owner, orgId } = await orgReadyToEnforce(t);
      const admin = await adminOf(t, orgId);

      const res = await setPolicy(t, admin.cookie, { orgId, ssoEnforced: true });
      expect(res.status).toBe(200);
      expect(await res.json()).toMatchObject({
        ssoEnforced: true,
        breakGlassUserId: owner.userId,
      });
    });

    it("with breakGlassUserId repeated unchanged", async () => {
      const t = await makeAuth();
      const { owner, orgId } = await orgReadyToEnforce(t);
      const admin = await adminOf(t, orgId);

      const res = await setPolicy(t, admin.cookie, {
        orgId,
        ssoEnforced: true,
        breakGlassUserId: owner.userId,
      });
      expect(res.status).toBe(200);
    });

    it("but still not while pointing breakGlassUserId at someone else", async () => {
      const t = await makeAuth();
      const { orgId } = await orgReadyToEnforce(t);
      const admin = await adminOf(t, orgId);

      const res = await setPolicy(t, admin.cookie, {
        orgId,
        ssoEnforced: true,
        breakGlassUserId: admin.userId,
      });
      expect(res.status).toBe(403);
      expect(await code(res)).toBe("NOT_ORG_OWNER");
    });

    it("but still not while clearing an owner's break-glass user", async () => {
      const t = await makeAuth();
      const { orgId } = await orgReadyToEnforce(t);
      const admin = await adminOf(t, orgId);

      const res = await setPolicy(t, admin.cookie, { orgId, breakGlassUserId: null });
      expect(res.status).toBe(403);
      expect(await code(res)).toBe("NOT_ORG_OWNER");
    });
  });

  it("an admin may still list and revoke SCIM tokens", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);
    const admin = await adminOf(t, orgId);
    const minted = await t.api.post(
      "/enterprise/scim/tokens/create",
      { orgId, providerId: "hris" },
      { cookie },
    );
    expect(minted.status).toBe(200);

    const list = await t.api.get(`/enterprise/scim/tokens?orgId=${orgId}`, {
      cookie: admin.cookie,
    });
    expect(list.status).toBe(200);

    const revoke = await t.api.post(
      "/enterprise/scim/tokens/revoke",
      { orgId, providerId: "hris" },
      { cookie: admin.cookie },
    );
    expect(revoke.status).toBe(200);
  });
});
