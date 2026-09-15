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
import { insertMemberRow, setPolicy } from "./helpers";

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
    expect(upstream.status).toBe(403);
    expect(await code(upstream)).toBe("NOT_ORG_OWNER");

    const wrapper = await t.api.post(
      "/enterprise/scim/tokens/create",
      { orgId, providerId: "hris" },
      { cookie: admin.cookie },
    );
    expect(wrapper.status).toBe(403);
    expect(await code(wrapper)).toBe("NOT_ORG_OWNER");
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
