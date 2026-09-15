import { describe, expect, it } from "vitest";
import { makeAuth, signUpOwner, createOrg, type TestAuth } from "../helpers/auth";

type Json = Record<string, unknown>;

async function mintScimToken(
  t: TestAuth,
  cookie: string,
  orgId: string,
  providerId = "okta",
): Promise<{ authorization: string }> {
  const res = await t.api.post(
    "/scim/generate-token",
    { providerId, organizationId: orgId },
    { cookie },
  );
  if (!res.ok) throw new Error(`generate-token failed: ${res.status} ${await res.text()}`);
  const { scimToken } = (await res.json()) as { scimToken: string };
  return { authorization: `Bearer ${scimToken}` };
}

async function createScimUser(
  t: TestAuth,
  bearer: { authorization: string },
  email: string,
): Promise<string> {
  const res = await t.api.post(
    "/scim/v2/Users",
    { userName: email, emails: [{ value: email, primary: true }] },
    bearer,
  );
  if (!res.ok) throw new Error(`SCIM create user failed: ${res.status} ${await res.text()}`);
  const body = (await res.json()) as { id: string };
  return body.id;
}

/**
 * Strips the `:organizationId` suffix out of an otherwise-valid, minted SCIM
 * bearer token — used to exercise controller ruling (a) ("tokens without
 * organizationId ... are rejected 401") without needing a personal-provider
 * `scimProvider` row: `../gate.ts`'s `ORG_ID_REQUIRED_IN_BODY` already makes
 * `POST /scim/generate-token` refuse to mint a personal token through this
 * preset at all (`test/server/gate.test.ts`), so a forged/stripped token is
 * the only way to reach this code path in a test. Node's `Buffer` is fine
 * here (test-only); `../../src/server/scim-groups/auth.ts` itself avoids it
 * for workerd portability.
 */
function stripOrganizationId(bearerToken: string): string {
  const encoded = bearerToken.replace(/^Bearer\s+/i, "");
  const decoded = Buffer.from(encoded.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString(
    "utf8",
  );
  const [baseToken, providerId] = decoded.split(":");
  return Buffer.from(`${baseToken}:${providerId}`, "utf8")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

// `org_policy.group_role_map` (`../../src/server/policy/store.ts`'s
// `defaultPolicy`) defaults to `{}`, never `undefined`/`null` — so
// `../../src/server/scim-groups/plugin.ts`'s `policy.groupRoleMap ??
// opts.scim?.groupRoleMap ?? {}` (ruling (d), verbatim from the brief) can
// never actually fall through to `opts.scim.groupRoleMap` for an org with no
// policy row set (the realistic default state); that operand exists purely
// as defense against a future relaxation of `OrgPolicy`'s shape. The
// supported, real way to configure a group -> role map for an org is
// `POST /enterprise/policy/set` (an owner/admin action), so that's what
// these tests exercise instead of `EnterpriseOptions.scim.groupRoleMap`.
async function setGroupRoleMap(
  t: TestAuth,
  cookie: string,
  orgId: string,
  groupRoleMap: Record<string, "owner" | "admin" | "member">,
): Promise<void> {
  const res = await t.api.post("/enterprise/policy/set", { orgId, groupRoleMap }, { cookie });
  if (!res.ok) throw new Error(`policy/set failed: ${res.status} ${await res.text()}`);
}

async function setup() {
  const t = await makeAuth();
  const { cookie, userId: ownerUserId } = await signUpOwner(t);
  const { orgId } = await createOrg(t, cookie);
  await setGroupRoleMap(t, cookie, orgId, { Admins: "admin" });
  const bearer = await mintScimToken(t, cookie, orgId);
  return { t, cookie, orgId, bearer, ownerUserId };
}

describe("scimGroups plugin", () => {
  it("no bearer -> 401 SCIM error, application/scim+json", async () => {
    const { t } = await setup();
    const res = await t.api.get("/scim/v2/Groups");
    expect(res.status).toBe(401);
    expect(res.headers.get("content-type")).toBe("application/scim+json");
    const body = (await res.json()) as Json;
    expect(body.schemas).toEqual(["urn:ietf:params:scim:api:messages:2.0:Error"]);
  });

  it("a token minted by upstream POST /scim/generate-token authenticates our endpoints", async () => {
    const { t, bearer } = await setup();
    const res = await t.api.get("/scim/v2/Groups", bearer);
    expect(res.status).toBe(200);
  });

  it("a token without an organizationId is rejected 401 (ruling (a), personal providers are org-only)", async () => {
    const { t, bearer } = await setup();
    const stripped = stripOrganizationId(bearer.authorization);
    const res = await t.api.get("/scim/v2/Groups", { authorization: `Bearer ${stripped}` });
    expect(res.status).toBe(401);
  });

  it("create group -> 201 + Location, team + scim_group rows exist, filter list finds it, resource shape conforms", async () => {
    const { t, orgId, bearer } = await setup();

    const createRes = await t.api.post("/scim/v2/Groups", { displayName: "Engineering" }, bearer);
    expect(createRes.status).toBe(201);
    expect(createRes.headers.get("content-type")).toBe("application/scim+json");
    const group = (await createRes.json()) as Json & { id: string; meta: { location: string } };

    expect(group.schemas).toEqual(["urn:ietf:params:scim:schemas:core:2.0:Group"]);
    expect(group.displayName).toBe("Engineering");
    expect(group.members).toEqual([]);
    expect(group.meta).toMatchObject({ resourceType: "Group" });
    expect(group.meta.location).toBe(`http://localhost:3000/api/auth/scim/v2/Groups/${group.id}`);
    expect(createRes.headers.get("location")).toBe(group.meta.location);

    const teamRows = await t.client.execute({
      sql: `SELECT * FROM team WHERE id = ?`,
      args: [group.id],
    });
    expect(teamRows.rows.length).toBe(1);
    expect(teamRows.rows[0]!.organizationId).toBe(orgId);
    expect(teamRows.rows[0]!.name).toBe("Engineering");

    const scimGroupRows = await t.client.execute({
      sql: `SELECT * FROM scim_group WHERE team_id = ?`,
      args: [group.id],
    });
    expect(scimGroupRows.rows.length).toBe(1);
    expect(scimGroupRows.rows[0]!.org_id).toBe(orgId);

    const createdAudit = await t.client.execute({
      sql: `SELECT * FROM audit_event WHERE org_id = ? AND action = 'scim.group_created'`,
      args: [orgId],
    });
    expect(createdAudit.rows.length).toBe(1);
    expect(createdAudit.rows[0]!.actor_type).toBe("scim");
    expect(createdAudit.rows[0]!.actor_id).toBe("okta");

    const listRes = await t.api.get(
      `/scim/v2/Groups?filter=${encodeURIComponent('displayName eq "Engineering"')}`,
      bearer,
    );
    expect(listRes.status).toBe(200);
    const list = (await listRes.json()) as Json & { totalResults: number; Resources: Json[] };
    expect(list.schemas).toEqual(["urn:ietf:params:scim:api:messages:2.0:ListResponse"]);
    expect(list.totalResults).toBe(1);
    expect(list.startIndex).toBe(1);
    expect((list.Resources[0] as { id: string }).id).toBe(group.id);
  });

  it("GET /scim/v2/Groups/:groupId returns the single resource (not the list)", async () => {
    const { t, bearer } = await setup();
    const createRes = await t.api.post("/scim/v2/Groups", { displayName: "Solo" }, bearer);
    const group = (await createRes.json()) as { id: string };

    const getRes = await t.api.get(`/scim/v2/Groups/${group.id}`, bearer);
    expect(getRes.status).toBe(200);
    const body = (await getRes.json()) as Json;
    expect(body.id).toBe(group.id);
    expect(body.schemas).toEqual(["urn:ietf:params:scim:schemas:core:2.0:Group"]);
  });

  it("GET list with an unsupported filter operator returns 400 invalidFilter", async () => {
    const { t, bearer } = await setup();
    const res = await t.api.get(
      `/scim/v2/Groups?filter=${encodeURIComponent('displayName co "Eng"')}`,
      bearer,
    );
    expect(res.status).toBe(400);
    const body = (await res.json()) as Json;
    expect(body.scimType).toBe("invalidFilter");
  });

  it("creating a second group with the same displayName in the org returns 409 uniqueness", async () => {
    const { t, bearer } = await setup();
    await t.api.post("/scim/v2/Groups", { displayName: "Engineering" }, bearer);
    const res = await t.api.post("/scim/v2/Groups", { displayName: "Engineering" }, bearer);
    expect(res.status).toBe(409);
    const body = (await res.json()) as Json;
    expect(body.scimType).toBe("uniqueness");
  });

  it("creating a group with a member id that is not an org member returns 400 invalidValue", async () => {
    const { t, bearer } = await setup();
    const res = await t.api.post(
      "/scim/v2/Groups",
      { displayName: "X", members: [{ value: "not-a-real-user" }] },
      bearer,
    );
    expect(res.status).toBe(400);
    const body = (await res.json()) as Json;
    expect(body.scimType).toBe("invalidValue");
  });

  it("PATCH adds two SCIM-provisioned users as teamMember rows and audits each add", async () => {
    const { t, orgId, bearer } = await setup();
    const userA = await createScimUser(t, bearer, "a@acme.test");
    const userB = await createScimUser(t, bearer, "b@acme.test");
    const createRes = await t.api.post("/scim/v2/Groups", { displayName: "Team" }, bearer);
    const group = (await createRes.json()) as { id: string };

    const patchRes = await t.api.request(
      "PATCH",
      `/scim/v2/Groups/${group.id}`,
      {
        schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        Operations: [{ op: "add", path: "members", value: [{ value: userA }, { value: userB }] }],
      },
      bearer,
    );
    expect(patchRes.status).toBe(200);
    const updated = (await patchRes.json()) as { members: { value: string }[] };
    expect(updated.members.map((m) => m.value).sort()).toEqual([userA, userB].sort());

    const rows = await t.client.execute({
      sql: `SELECT * FROM teamMember WHERE teamId = ?`,
      args: [group.id],
    });
    expect(rows.rows.length).toBe(2);

    const addedAudit = await t.client.execute({
      sql: `SELECT * FROM audit_event WHERE org_id = ? AND action = 'scim.group_member_added'`,
      args: [orgId],
    });
    expect(addedAudit.rows.length).toBe(2);
  });

  it("PATCH with an unsupported path returns 400 invalidPath", async () => {
    const { t, bearer } = await setup();
    const createRes = await t.api.post("/scim/v2/Groups", { displayName: "X" }, bearer);
    const group = (await createRes.json()) as { id: string };

    const res = await t.api.request(
      "PATCH",
      `/scim/v2/Groups/${group.id}`,
      {
        schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        Operations: [{ op: "replace", path: "externalId", value: "y" }],
      },
      bearer,
    );
    expect(res.status).toBe(400);
    const body = (await res.json()) as Json;
    expect(body.scimType).toBe("invalidPath");
  });

  it("PUT replaces displayName and the full members set", async () => {
    const { t, bearer } = await setup();
    const userId = await createScimUser(t, bearer, "putme@acme.test");
    const createRes = await t.api.post("/scim/v2/Groups", { displayName: "Old Name" }, bearer);
    const group = (await createRes.json()) as { id: string };

    const putRes = await t.api.put(
      `/scim/v2/Groups/${group.id}`,
      { displayName: "New Name", members: [{ value: userId }] },
      bearer,
    );
    expect(putRes.status).toBe(200);
    const updated = (await putRes.json()) as { displayName: string; members: { value: string }[] };
    expect(updated.displayName).toBe("New Name");
    expect(updated.members.map((m) => m.value)).toEqual([userId]);

    const teamRows = await t.client.execute({
      sql: `SELECT name FROM team WHERE id = ?`,
      args: [group.id],
    });
    expect(teamRows.rows[0]!.name).toBe("New Name");
  });

  it('group named "Admins" with groupRoleMap {"Admins":"admin"} promotes an added member; removal demotes back to member', async () => {
    const { t, orgId, bearer } = await setup();
    const userId = await createScimUser(t, bearer, "promo@acme.test");
    const createRes = await t.api.post("/scim/v2/Groups", { displayName: "Admins" }, bearer);
    const group = (await createRes.json()) as { id: string };

    const addRes = await t.api.request(
      "PATCH",
      `/scim/v2/Groups/${group.id}`,
      {
        schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        Operations: [{ op: "add", path: `members[value eq "${userId}"]` }],
      },
      bearer,
    );
    expect(addRes.status).toBe(200);

    const afterAdd = await t.client.execute({
      sql: `SELECT role FROM member WHERE organizationId = ? AND userId = ?`,
      args: [orgId, userId],
    });
    expect(afterAdd.rows[0]!.role).toBe("admin");

    const roleChangedAudit = await t.client.execute({
      sql: `SELECT * FROM audit_event WHERE org_id = ? AND action = 'member.role_changed' AND target_id = ?`,
      args: [orgId, userId],
    });
    expect(roleChangedAudit.rows.length).toBe(1);

    const removeRes = await t.api.request(
      "PATCH",
      `/scim/v2/Groups/${group.id}`,
      {
        schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        Operations: [{ op: "remove", path: `members[value eq "${userId}"]` }],
      },
      bearer,
    );
    expect(removeRes.status).toBe(200);

    const afterRemove = await t.client.execute({
      sql: `SELECT role FROM member WHERE organizationId = ? AND userId = ?`,
      args: [orgId, userId],
    });
    expect(afterRemove.rows[0]!.role).toBe("member");
  });

  it("never demotes the org's only owner; writes scim.role_change_skipped instead", async () => {
    const { t, orgId, bearer, ownerUserId } = await setup();
    // "Members" isn't in groupRoleMap, so effectiveRole for it is "member" —
    // adding the sole owner would otherwise demote them.
    const createRes = await t.api.post(
      "/scim/v2/Groups",
      { displayName: "Members", members: [{ value: ownerUserId }] },
      bearer,
    );
    expect(createRes.status).toBe(201);

    const memberRow = await t.client.execute({
      sql: `SELECT role FROM member WHERE organizationId = ? AND userId = ?`,
      args: [orgId, ownerUserId],
    });
    expect(memberRow.rows[0]!.role).toBe("owner");

    const skipped = await t.client.execute({
      sql: `SELECT * FROM audit_event WHERE org_id = ? AND action = 'scim.role_change_skipped' AND target_id = ?`,
      args: [orgId, ownerUserId],
    });
    expect(skipped.rows.length).toBe(1);
    expect(skipped.rows[0]!.actor_type).toBe("scim");
  });

  it("DELETE -> 204, removes team/scim_group/teamMember rows, and recomputes affected members' roles", async () => {
    const { t, orgId, bearer } = await setup();
    const userId = await createScimUser(t, bearer, "del@acme.test");
    const createRes = await t.api.post(
      "/scim/v2/Groups",
      { displayName: "Admins", members: [{ value: userId }] },
      bearer,
    );
    const group = (await createRes.json()) as { id: string };

    const afterCreate = await t.client.execute({
      sql: `SELECT role FROM member WHERE organizationId = ? AND userId = ?`,
      args: [orgId, userId],
    });
    expect(afterCreate.rows[0]!.role).toBe("admin");

    const deleteRes = await t.api.delete(`/scim/v2/Groups/${group.id}`, bearer);
    expect(deleteRes.status).toBe(204);

    const teamRows = await t.client.execute({
      sql: `SELECT * FROM team WHERE id = ?`,
      args: [group.id],
    });
    expect(teamRows.rows.length).toBe(0);
    const scimGroupRows = await t.client.execute({
      sql: `SELECT * FROM scim_group WHERE team_id = ?`,
      args: [group.id],
    });
    expect(scimGroupRows.rows.length).toBe(0);
    const teamMemberRows = await t.client.execute({
      sql: `SELECT * FROM teamMember WHERE teamId = ?`,
      args: [group.id],
    });
    expect(teamMemberRows.rows.length).toBe(0);

    const afterDelete = await t.client.execute({
      sql: `SELECT role FROM member WHERE organizationId = ? AND userId = ?`,
      args: [orgId, userId],
    });
    expect(afterDelete.rows[0]!.role).toBe("member");

    const deletedAudit = await t.client.execute({
      sql: `SELECT * FROM audit_event WHERE org_id = ? AND action = 'scim.group_deleted'`,
      args: [orgId],
    });
    expect(deletedAudit.rows.length).toBe(1);
  });

  it("a user in two mapped groups keeps the higher role when removed from just one", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);
    await setGroupRoleMap(t, cookie, orgId, { Admins: "admin", Owners: "owner" });
    const bearer = await mintScimToken(t, cookie, orgId);
    const userId = await createScimUser(t, bearer, "twogroups@acme.test");

    const admins = (await (
      await t.api.post("/scim/v2/Groups", { displayName: "Admins" }, bearer)
    ).json()) as { id: string };
    const owners = (await (
      await t.api.post("/scim/v2/Groups", { displayName: "Owners" }, bearer)
    ).json()) as { id: string };

    const patchAdd = (groupId: string) =>
      t.api.request(
        "PATCH",
        `/scim/v2/Groups/${groupId}`,
        {
          schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
          Operations: [{ op: "add", path: `members[value eq "${userId}"]` }],
        },
        bearer,
      );
    const patchRemove = (groupId: string) =>
      t.api.request(
        "PATCH",
        `/scim/v2/Groups/${groupId}`,
        {
          schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
          Operations: [{ op: "remove", path: `members[value eq "${userId}"]` }],
        },
        bearer,
      );
    const roleOf = async () => {
      const res = await t.client.execute({
        sql: `SELECT role FROM member WHERE organizationId = ? AND userId = ?`,
        args: [orgId, userId],
      });
      return res.rows[0]!.role;
    };

    expect((await patchAdd(admins.id)).status).toBe(200);
    expect(await roleOf()).toBe("admin");
    expect((await patchAdd(owners.id)).status).toBe(200);
    expect(await roleOf()).toBe("owner"); // highest of {admin, owner} wins, still in both groups

    // Removing from "Owners" while still in "Admins" -> falls back to
    // "admin", not all the way to "member". (This user isn't the org's sole
    // owner at this point — the human org creator also holds "owner" — so
    // the sole-owner guard doesn't block this demotion.)
    const removeOwnersRes = await patchRemove(owners.id);
    expect(removeOwnersRes.status).toBe(200);
    expect(await roleOf()).toBe("admin");

    const removeAdminsRes = await patchRemove(admins.id);
    expect(removeAdminsRes.status).toBe(200);
    expect(await roleOf()).toBe("member");
  });

  it("PATCH replace on members with [] clears the members (Entra's clear pattern)", async () => {
    const { t, orgId, bearer } = await setup();
    const userId = await createScimUser(t, bearer, "clearme@acme.test");
    const createRes = await t.api.post(
      "/scim/v2/Groups",
      { displayName: "ClearMe", members: [{ value: userId }] },
      bearer,
    );
    const group = (await createRes.json()) as { id: string };

    const patchRes = await t.api.request(
      "PATCH",
      `/scim/v2/Groups/${group.id}`,
      {
        schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        Operations: [{ op: "replace", path: "members", value: [] }],
      },
      bearer,
    );
    expect(patchRes.status).toBe(200);
    const updated = (await patchRes.json()) as { members: unknown[] };
    expect(updated.members).toEqual([]);

    const rows = await t.client.execute({
      sql: `SELECT * FROM teamMember WHERE teamId = ?`,
      args: [group.id],
    });
    expect(rows.rows.length).toBe(0);

    const removedAudit = await t.client.execute({
      sql: `SELECT * FROM audit_event WHERE org_id = ? AND action = 'scim.group_member_removed' AND target_id = ?`,
      args: [orgId, userId],
    });
    expect(removedAudit.rows.length).toBe(1);
  });

  it("duplicate externalId within an org returns a clean 409 uniqueness on POST", async () => {
    const { t, bearer } = await setup();
    const first = await t.api.post(
      "/scim/v2/Groups",
      { displayName: "A", externalId: "ext-dup" },
      bearer,
    );
    expect(first.status).toBe(201);
    const res = await t.api.post(
      "/scim/v2/Groups",
      { displayName: "B", externalId: "ext-dup" },
      bearer,
    );
    expect(res.status).toBe(409);
    const body = (await res.json()) as Json;
    expect(body.scimType).toBe("uniqueness");
  });

  it("PUT changing externalId to one already used by another group in the org returns 409 uniqueness", async () => {
    const { t, bearer } = await setup();
    await t.api.post("/scim/v2/Groups", { displayName: "A", externalId: "ext-1" }, bearer);
    const createRes = await t.api.post(
      "/scim/v2/Groups",
      { displayName: "B", externalId: "ext-2" },
      bearer,
    );
    const groupB = (await createRes.json()) as { id: string };

    const conflictRes = await t.api.put(
      `/scim/v2/Groups/${groupB.id}`,
      { displayName: "B", externalId: "ext-1" },
      bearer,
    );
    expect(conflictRes.status).toBe(409);
    const body = (await conflictRes.json()) as Json;
    expect(body.scimType).toBe("uniqueness");

    // PUTting a group's own unchanged externalId back onto itself must not
    // false-positive as a conflict (the uniqueness check excludes the
    // group's own team id).
    const selfRes = await t.api.put(
      `/scim/v2/Groups/${groupB.id}`,
      { displayName: "B", externalId: "ext-2" },
      bearer,
    );
    expect(selfRes.status).toBe(200);
  });

  it("startIndex is 1-based and count paginates the (unfiltered) list in stable, deterministic order", async () => {
    const { t, bearer } = await setup();
    await t.api.post("/scim/v2/Groups", { displayName: "Alpha" }, bearer);
    await t.api.post("/scim/v2/Groups", { displayName: "Beta" }, bearer);
    await t.api.post("/scim/v2/Groups", { displayName: "Gamma" }, bearer);

    // Two independent list calls, one page each, must together reproduce
    // the full, non-overlapping, creation-order sequence — proving the
    // underlying `findMany` is deterministically ordered (`sortBy:
    // createdAt asc`) rather than however the adapter/index happens to
    // return rows, which `startIndex`/`count` slicing depends on.
    const page1 = (await (
      await t.api.get("/scim/v2/Groups?startIndex=1&count=1", bearer)
    ).json()) as { Resources: { displayName: string }[] };
    const page2 = (await (
      await t.api.get("/scim/v2/Groups?startIndex=2&count=1", bearer)
    ).json()) as {
      totalResults: number;
      startIndex: number;
      itemsPerPage: number;
      Resources: { displayName: string }[];
    };
    const page3 = (await (
      await t.api.get("/scim/v2/Groups?startIndex=3&count=1", bearer)
    ).json()) as { Resources: { displayName: string }[] };

    expect(page2.totalResults).toBe(3);
    expect(page2.startIndex).toBe(2);
    expect(page2.itemsPerPage).toBe(1);
    expect(page2.Resources.length).toBe(1);
    expect([
      page1.Resources[0]!.displayName,
      page2.Resources[0]!.displayName,
      page3.Resources[0]!.displayName,
    ]).toEqual(["Alpha", "Beta", "Gamma"]);
  });

  it("cross-org: a token for org B gets 404 on org A's group", async () => {
    const { t, bearer: bearerA } = await setup();
    const createRes = await t.api.post("/scim/v2/Groups", { displayName: "OnlyInA" }, bearerA);
    const groupA = (await createRes.json()) as { id: string };

    const { cookie: cookieB } = await signUpOwner(t, "ownerb@acme.test");
    const { orgId: orgBId } = await createOrg(t, cookieB, "acme-b");
    const bearerB = await mintScimToken(t, cookieB, orgBId, "okta-b");

    const res = await t.api.get(`/scim/v2/Groups/${groupA.id}`, bearerB);
    expect(res.status).toBe(404);
  });
});
