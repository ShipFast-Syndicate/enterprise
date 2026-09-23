import { describe, expect, it } from "vitest";
import { makeAuth, signUpOwner, createOrg } from "../helpers/auth";
import { mintScimToken, createScimUser, coreUserId } from "../security/helpers";
const GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group";
const PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
async function setup() {
  const t = await makeAuth({ scim: { groupRoleMap: { Admins: "admin", Everyone: "member" } } });
  const owner = await signUpOwner(t);
  const { orgId } = await createOrg(t, owner.cookie);
  const bearer = await mintScimToken(t, owner.cookie, orgId);
  const scimId = await createScimUser(t, bearer, "employee@acme.test");
  const userId = await coreUserId(t, scimId);
  const role = async () =>
    (
      await t.client.execute({
        sql: "SELECT role FROM member WHERE userId = ? AND organizationId = ?",
        args: [userId, orgId],
      })
    ).rows[0]?.role;
  const group = (displayName: string, members = [scimId], externalId?: string) =>
    t.api.post(
      "/scim/v2/Groups",
      { schemas: [GROUP], displayName, externalId, members: members.map((value) => ({ value })) },
      bearer,
    );
  return { t, owner, orgId, bearer, scimId, userId, role, group };
}

describe("native SCIM 1.7 Groups and organization projection", () => {
  it("requires a bearer and returns SCIM errors", async () => {
    const t = await makeAuth();
    const res = await t.api.get("/scim/v2/Groups");
    expect(res.status).toBe(401);
    expect((await res.json()).schemas).toEqual(["urn:ietf:params:scim:api:messages:2.0:Error"]);
  });
  it("creates a source-owned group, projects role, and audits it in its organization", async () => {
    const { t, bearer, group, role, orgId, scimId, userId } = await setup();
    expect(scimId).not.toBe(userId);
    expect(await role()).toBe("member");
    const res = await group("Admins");
    expect(res.status, await res.clone().text()).toBe(201);
    const body = await res.json();
    expect(body.members[0].value).toBe(scimId);
    expect(await role()).toBe("admin");
    const get = await t.api.get(`/scim/v2/Groups/${body.id}`, bearer);
    expect(get.status).toBe(200);
    const audit = await t.client.execute({
      sql: "SELECT actor_type,target_id FROM audit_event WHERE org_id=? AND action='scim.group_created'",
      args: [orgId],
    });
    expect(audit.rows).toHaveLength(1);
    expect(audit.rows[0]).toMatchObject({ actor_type: "scim", target_id: body.id });
  });
  it("PATCH removal and DELETE recompute only the projected role", async () => {
    const { t, bearer, group, role, scimId } = await setup();
    const admin = await (await group("Admins")).json();
    await group("Everyone");
    expect(await role()).toBe("admin");
    const removed = await t.api.patch(
      `/scim/v2/Groups/${admin.id}`,
      { schemas: [PATCH], Operations: [{ op: "remove", path: `members[value eq "${scimId}"]` }] },
      bearer,
    );
    expect(removed.status).toBe(200);
    expect(await role()).toBe("member");
    const added = await t.api.patch(
      `/scim/v2/Groups/${admin.id}`,
      {
        schemas: [PATCH],
        Operations: [{ op: "add", path: "members", value: [{ value: scimId }] }],
      },
      bearer,
    );
    expect(added.status).toBe(200);
    expect(await role()).toBe("admin");
    expect((await t.api.delete(`/scim/v2/Groups/${admin.id}`, bearer)).status).toBe(204);
    expect(await role()).toBe("member");
  });
  it("PUT replacement changes members and grants", async () => {
    const { t, bearer, group, role } = await setup();
    const old = await (await group("Admins")).json();
    const res = await t.api.put(
      `/scim/v2/Groups/${old.id}`,
      { schemas: [GROUP], displayName: "Everyone", members: [] },
      bearer,
    );
    expect(res.status).toBe(200);
    expect(await role()).toBe("member");
    expect((await res.json()).members).toEqual([]);
  });
  it("supports filtering and pagination without returning unrelated groups", async () => {
    const { t, bearer, group } = await setup();
    for (const name of ["Alpha", "Beta", "Gamma"]) expect((await group(name, [])).status).toBe(201);
    const filtered = await t.api.get(
      "/scim/v2/Groups?filter=" + encodeURIComponent('displayName eq "Beta"'),
      bearer,
    );
    const data = await filtered.json();
    expect(data.totalResults).toBe(1);
    expect(data.Resources[0].displayName).toBe("Beta");
    const first = await (await t.api.get("/scim/v2/Groups?count=1&startIndex=1", bearer)).json();
    const second = await (await t.api.get("/scim/v2/Groups?count=1&startIndex=2", bearer)).json();
    expect(first.totalResults).toBe(3);
    expect(first.Resources).toHaveLength(1);
    expect(second.Resources[0].id).not.toBe(first.Resources[0].id);
  });
  it("rejects a duplicate externalId without changing existing grants", async () => {
    const { group, role } = await setup();
    expect((await group("Admins", undefined, "external-1")).status).toBe(201);
    expect((await group("Other", [], "external-1")).status).toBe(409);
    expect(await role()).toBe("admin");
  });
  it("rejects core User IDs and rolls back the entire group write", async () => {
    const { t, bearer, group, userId, role } = await setup();
    const res = await group("Admins", [userId]);
    expect(res.status).toBe(400);
    expect(await role()).toBe("member");
    expect((await (await t.api.get("/scim/v2/Groups", bearer)).json()).totalResults).toBe(0);
  });
  it("keeps users and groups private to their connection, including identical provider labels", async () => {
    const { t, owner, group, bearer, scimId } = await setup();
    const orgB = await createOrg(t, owner.cookie, "other");
    const tokenB = await mintScimToken(t, owner.cookie, orgB.orgId);
    const created = await (await group("Admins")).json();
    expect((await t.api.get(`/scim/v2/Groups/${created.id}`, tokenB)).status).toBe(404);
    expect((await t.api.get(`/scim/v2/Users/${scimId}`, tokenB)).status).toBe(404);
    const foreign = await t.api.post(
      "/scim/v2/Groups",
      { schemas: [GROUP], displayName: "Admins", members: [{ value: scimId }] },
      tokenB,
    );
    expect(foreign.status).toBe(400);
    expect((await t.api.get(`/scim/v2/Groups/${created.id}`, bearer)).status).toBe(200);
  });
});
