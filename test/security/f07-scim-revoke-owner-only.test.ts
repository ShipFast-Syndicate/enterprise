// F-07 (security audit 3, 2026-09-25) — org *admin* could mass-deprovision.
//
// v0.1's `/enterprise/scim/tokens/revoke` deleted a token row. The 1.7
// migration turned it into `decommissionSCIMManagedConnection`, which replays
// every user the connection provisioned as inactive — and `reconcileUser`
// (`src/server/scim.ts`) answered every such replay with a **global** ban,
// session wipe (upstream) and API-key wipe — while the endpoint kept its
// owner-or-admin check. An admin could therefore lock a SCIM-provisioned user
// who had been manually promoted to *owner* out of the whole platform,
// defeating upstream's "a non-owner cannot touch an owner" invariant.
//
// Fix: revoke is owner-only (`OWNER_ONLY_PATHS` + `authorize(..., true)`),
// and the identity hook never *bans* a user who holds an `owner` membership
// anywhere — SCIM can never *produce* one (M-01). Their API keys are still
// revoked (PR-4, gap 1 / PR-1 residual): a key is a live credential of an
// identity the IdP no longer vouches for, and since self-serve org creation
// stays on (R13) "owner somewhere" can be an org the user created themselves.
// An owner who is not banned signs in again and mints a new key, so nothing
// is irreversible for them; the skipped ban is audited
// (`scim.user_deactivation_skipped`) — see `test/security/gap1-api-keys.test.ts`.

import { describe, expect, it } from "vitest";
import { makeAuth, signUpOwner, createOrg, type TestAuth } from "../helpers/auth";
import {
  insertMemberRow,
  insertSessionCookie,
  mintScimToken,
  createScimUser,
  coreUserId,
} from "./helpers";

async function userState(t: TestAuth, userId: string) {
  const user = await t.client.execute({
    sql: "SELECT banned, banReason FROM user WHERE id = ?",
    args: [userId],
  });
  const keys = await t.client.execute({
    sql: "SELECT id FROM apikey WHERE referenceId = ?",
    args: [userId],
  });
  const members = await t.client.execute({
    sql: "SELECT organizationId, role FROM member WHERE userId = ? ORDER BY organizationId",
    args: [userId],
  });
  return {
    banned: Boolean(user.rows[0]?.banned),
    banReason: user.rows[0]?.banReason ?? null,
    apiKeys: keys.rows.length,
    memberships: members.rows.map((r) => ({
      orgId: String(r.organizationId),
      role: String(r.role),
    })),
  };
}

async function createApiKey(t: TestAuth, userId: string, orgId: string) {
  const cookie = await insertSessionCookie(t, userId);
  const res = await t.api.post("/api-key/create", { name: "k", organizationId: orgId }, { cookie });
  expect(res.status).toBe(200);
}

async function revokeUntilDone(t: TestAuth, cookie: string, orgId: string, providerId: string) {
  let res: Response | undefined;
  for (let i = 0; i < 5; i++) {
    res = await t.api.post("/enterprise/scim/tokens/revoke", { orgId, providerId }, { cookie });
    if (res.status !== 202) break;
  }
  return res!;
}

/** Owner org with a SCIM connection, one SCIM user promoted to owner (X) and one plain SCIM member (Y). */
async function scimOrgWithPromotedOwner(t: TestAuth) {
  const owner = await signUpOwner(t);
  const { orgId } = await createOrg(t, owner.cookie);
  const bearer = await mintScimToken(t, owner.cookie, orgId, "hris");
  const xScim = await createScimUser(t, bearer, "x@acme.test");
  const xId = await coreUserId(t, xScim);
  const yScim = await createScimUser(t, bearer, "y@acme.test");
  const yId = await coreUserId(t, yScim);
  await t.client.execute({
    sql: "UPDATE member SET role = 'owner' WHERE userId = ? AND organizationId = ?",
    args: [xId, orgId],
  });
  await createApiKey(t, xId, orgId);
  return { owner, orgId, bearer, xId, xScim, yId, yScim };
}

describe("F-07 — SCIM decommission is owner-only and never bans an owner", () => {
  it("an org admin cannot revoke (403 NOT_ORG_OWNER); the connection stays active and nobody is banned", async () => {
    const t = await makeAuth();
    const { orgId, bearer, xId, yId } = await scimOrgWithPromotedOwner(t);
    const admin = await signUpOwner(t, "admin@acme.test");
    await insertMemberRow(t, orgId, admin.userId, "admin");

    const res = await t.api.post(
      "/enterprise/scim/tokens/revoke",
      { orgId, providerId: "hris" },
      { cookie: admin.cookie },
    );
    expect(res.status).toBe(403);
    expect(((await res.json()) as { code: string }).code).toBe("NOT_ORG_OWNER");

    expect((await t.api.get("/scim/v2/Users", bearer)).status).toBe(200); // bearer still works
    expect((await userState(t, xId)).banned).toBe(false);
    expect((await userState(t, yId)).banned).toBe(false);
    const audit = await t.client.execute(
      "SELECT * FROM audit_event WHERE action = 'scim.token_revoked'",
    );
    expect(audit.rows.length).toBe(0);
    // Listing stays owner/admin (M-08 unchanged).
    const list = await t.api.get(`/enterprise/scim/tokens?orgId=${orgId}`, {
      cookie: admin.cookie,
    });
    expect(list.status).toBe(200);
  });

  it("owner revoke: a manually promoted owner is not banned (keys revoked, audited); a plain SCIM member is deprovisioned", async () => {
    const t = await makeAuth();
    const { owner, orgId, bearer, xId, yId } = await scimOrgWithPromotedOwner(t);

    const res = await revokeUntilDone(t, owner.cookie, orgId, "hris");
    expect(res.status).toBe(200);
    expect(((await res.json()) as { ok: boolean }).ok).toBe(true);
    expect((await t.api.get("/scim/v2/Users", bearer)).status).toBe(401);

    const x = await userState(t, xId);
    expect(x.banned).toBe(false);
    // Keys go with the identity the feed retired (PR-4); the owner is not
    // banned and can mint a new one. Audited into the org's chain.
    expect(x.apiKeys).toBe(0);
    expect(x.memberships).toEqual([{ orgId, role: "owner" }]);
    const audit = await t.client.execute({
      sql: "SELECT action, actor_type, target_id, metadata FROM audit_event WHERE org_id = ? AND action IN ('api_key.revoked', 'scim.user_deactivation_skipped') AND target_id IN (?, ?) ORDER BY seq",
      args: [orgId, xId, "any"],
    });
    const skipped = audit.rows.filter((r) => r.action === "scim.user_deactivation_skipped");
    expect(skipped).toHaveLength(1);
    expect(skipped[0]!.actor_type).toBe("scim");
    expect(JSON.parse(String(skipped[0]!.metadata))).toEqual({ reason: "owner_protected" });
    const revoked = await t.client.execute({
      sql: "SELECT metadata FROM audit_event WHERE org_id = ? AND action = 'api_key.revoked'",
      args: [orgId],
    });
    expect(revoked.rows).toHaveLength(1);
    expect(JSON.parse(String(revoked.rows[0]!.metadata))).toEqual({
      reason: "scim.deactivate",
      userId: xId,
    });

    const y = await userState(t, yId);
    expect(y.banned).toBe(true);
    expect(y.banReason).toBe("Enterprise SCIM deactivation");
    expect(y.memberships).toEqual([]); // SCIM-owned membership removed
    expect((await t.client.execute("SELECT * FROM enterprise_scim_member")).rows).toHaveLength(0);
  });

  it("an IdP deactivation (PATCH active:false) of a promoted owner does not ban them either", async () => {
    const t = await makeAuth();
    const { bearer, xId, xScim, orgId } = await scimOrgWithPromotedOwner(t);

    const patch = await t.api.patch(
      `/scim/v2/Users/${xScim}`,
      {
        schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        Operations: [{ op: "replace", path: "active", value: false }],
      },
      bearer,
    );
    expect(patch.status).toBe(200);

    const x = await userState(t, xId);
    expect(x.banned).toBe(false);
    expect(x.apiKeys).toBe(0); // revoked with the identity (PR-4), not banned
    expect(x.memberships).toEqual([{ orgId, role: "owner" }]);
    // Upstream still revokes the sessions (`deleteUserSessions`) — the owner
    // is logged out, not locked out.
    const sessions = await t.client.execute({
      sql: "SELECT id FROM session WHERE userId = ?",
      args: [xId],
    });
    expect(sessions.rows.length).toBe(0);
  });

  it("a user who owns an unrelated organization is not banned platform-wide by this org's SCIM feed", async () => {
    const t = await makeAuth();
    const owner = await signUpOwner(t);
    const { orgId } = await createOrg(t, owner.cookie);
    const bearer = await mintScimToken(t, owner.cookie, orgId, "hris");
    const zScim = await createScimUser(t, bearer, "z@acme.test");
    const zId = await coreUserId(t, zScim);
    // Z owns an unrelated org B (manual grant — SCIM cannot produce it).
    const other = await signUpOwner(t, "other@beta.test");
    const { orgId: orgB } = await createOrg(t, other.cookie, "beta");
    await insertMemberRow(t, orgB, zId, "owner");

    expect((await t.api.delete(`/scim/v2/Users/${zScim}`, bearer)).status).toBe(204);

    const z = await userState(t, zId);
    expect(z.banned).toBe(false);
    expect(z.memberships).toEqual([{ orgId: orgB, role: "owner" }]); // acme membership gone, beta kept
  });
});
