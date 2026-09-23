import { describe, expect, it } from "vitest";
import { makeAuth, signUpOwner, createOrg } from "../helpers/auth";
import { mintScimToken, createScimUser, coreUserId } from "./helpers";
const GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group";
describe("C-03: manual roles are never owned by the SCIM projector", () => {
  it.each(["owner", "admin", "admin,billing"])(
    "preserves a manually assigned %s through group add, delete and deactivation",
    async (role) => {
      const t = await makeAuth({ scim: { groupRoleMap: { Everyone: "member" } } });
      const owner = await signUpOwner(t);
      const { orgId } = await createOrg(t, owner.cookie);
      const bearer = await mintScimToken(t, owner.cookie, orgId);
      const scimId = await createScimUser(t, bearer, "employee@acme.test");
      const userId = await coreUserId(t, scimId);
      await t.client.execute({
        sql: "UPDATE member SET role=? WHERE userId=?",
        args: [role, userId],
      });
      const created = await t.api.post(
        "/scim/v2/Groups",
        { schemas: [GROUP], displayName: "Everyone", members: [{ value: scimId }] },
        bearer,
      );
      expect(created.status).toBe(201);
      expect(
        (await t.api.delete("/scim/v2/Groups/" + (await created.json()).id, bearer)).status,
      ).toBe(204);
      expect((await t.api.delete("/scim/v2/Users/" + scimId, bearer)).status).toBe(204);
      const rows = await t.client.execute({
        sql: "SELECT role FROM member WHERE userId=? AND organizationId=?",
        args: [userId, orgId],
      });
      expect(rows.rows[0]?.role).toBe(role);
      const owners = await t.client.execute({
        sql: "SELECT role FROM member WHERE userId=?",
        args: [owner.userId],
      });
      expect(owners.rows[0]?.role).toBe("owner");
    },
  );
  it("never automatically links a matching local email or creates an authentication account", async () => {
    const t = await makeAuth();
    const owner = await signUpOwner(t);
    const { orgId } = await createOrg(t, owner.cookie);
    const bearer = await mintScimToken(t, owner.cookie, orgId);
    const collision = await t.api.post(
      "/scim/v2/Users",
      {
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
        userName: "owner@acme.test",
        emails: [{ value: "owner@acme.test", primary: true }],
      },
      bearer,
    );
    expect(collision.status).toBe(409);
    expect((await t.client.execute("SELECT * FROM scimUser")).rows).toHaveLength(0);
    const scimId = await createScimUser(t, bearer, "new@acme.test");
    const userId = await coreUserId(t, scimId);
    expect(
      (await t.client.execute({ sql: "SELECT * FROM account WHERE userId=?", args: [userId] }))
        .rows,
    ).toHaveLength(0);
  });
});
