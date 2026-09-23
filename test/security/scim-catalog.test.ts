import { describe, expect, it } from "vitest";
import { makeAuth, signUpOwner, createOrg } from "../helpers/auth";
import { createScimUser } from "./helpers";
async function setup() {
  const t = await makeAuth();
  const owner = await signUpOwner(t);
  const { orgId } = await createOrg(t, owner.cookie);
  const res = await t.api.post(
    "/enterprise/scim/tokens/create",
    { orgId, providerId: "okta" },
    { cookie: owner.cookie },
  );
  expect(res.status).toBe(200);
  expect(res.headers.get("cache-control")).toBe("no-store");
  const token = (await res.json()).scimToken as string;
  return { t, owner, orgId, token, bearer: { authorization: `Bearer ${token}` } };
}
describe("managed SCIM credential security", () => {
  it("stores a keyed digest and never returns secrets when listing", async () => {
    const { t, owner, orgId, token } = await setup();
    const stored = JSON.stringify(
      (await t.client.execute("SELECT * FROM scimManagedCredential")).rows,
    );
    expect(stored).not.toContain(token);
    const row = (
      await t.client.execute("SELECT tokenDigest, hashVersion FROM scimManagedCredential")
    ).rows[0]!;
    expect(row.hashVersion).toBe("v1");
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode("catalog-test-key-".repeat(3)),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const digest = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(token));
    expect(row.tokenDigest).toBe(Buffer.from(digest).toString("base64url"));
    const listing = await t.api.get(`/enterprise/scim/tokens?orgId=${orgId}`, {
      cookie: owner.cookie,
    });
    expect(await listing.text()).not.toContain(token);
  });
  it("rotates atomically, immediately rejects the old bearer and keeps existing SCIM IDs", async () => {
    const { t, owner, orgId, bearer } = await setup();
    const id = await createScimUser(t, bearer, "worker@acme.test");
    const res = await t.api.post(
      "/enterprise/scim/tokens/rotate",
      { orgId, providerId: "okta" },
      { cookie: owner.cookie },
    );
    expect(res.status, await res.clone().text()).toBe(200);
    const next = { authorization: `Bearer ${(await res.json()).scimToken}` };
    expect((await t.api.get(`/scim/v2/Users/${id}`, bearer)).status).toBe(401);
    expect((await t.api.get(`/scim/v2/Users/${id}`, next)).status).toBe(200);
  });
  it("forbids another organization owner from listing, rotating or revoking the connection", async () => {
    const { t, orgId, bearer } = await setup();
    const outsider = await signUpOwner(t, "other@acme.test");
    await createOrg(t, outsider.cookie, "other");
    for (const action of ["create", "rotate", "revoke"])
      expect(
        (
          await t.api.post(
            `/enterprise/scim/tokens/${action}`,
            { orgId, providerId: "okta" },
            { cookie: outsider.cookie },
          )
        ).status,
      ).toBe(403);
    expect(
      (await t.api.get(`/enterprise/scim/tokens?orgId=${orgId}`, { cookie: outsider.cookie }))
        .status,
    ).toBe(403);
    expect((await t.api.get("/scim/v2/Users", bearer)).status).toBe(200);
  });
  it("rolls back credential creation when the audit cannot be persisted", async () => {
    const t = await makeAuth();
    const owner = await signUpOwner(t);
    const { orgId } = await createOrg(t, owner.cookie);
    await t.client.execute("DROP TABLE audit_event");
    const res = await t.api.post(
      "/enterprise/scim/tokens/create",
      { orgId, providerId: "okta" },
      { cookie: owner.cookie },
    );
    expect(res.status).toBe(500);
    expect((await t.client.execute("SELECT * FROM scimManagedCredential")).rows).toHaveLength(0);
    expect((await t.client.execute("SELECT * FROM scimManagedConnection")).rows).toHaveLength(0);
  });
  it("rejects duplicate active labels but allows a new connection after decommission", async () => {
    const { t, owner, orgId, bearer } = await setup();
    const body = { orgId, providerId: "okta" },
      headers = { cookie: owner.cookie };
    expect((await t.api.post("/enterprise/scim/tokens/create", body, headers)).status).toBe(409);
    await createScimUser(t, bearer, "worker@acme.test");
    let result: { ok: boolean } = { ok: false };
    for (let i = 0; i < 5 && !result.ok; i++)
      result = await (await t.api.post("/enterprise/scim/tokens/revoke", body, headers)).json();
    expect(result.ok).toBe(true);
    expect((await t.api.get("/scim/v2/Users", bearer)).status).toBe(401);
    expect((await t.client.execute("SELECT * FROM enterprise_scim_member")).rows).toHaveLength(0);
    expect((await t.api.post("/enterprise/scim/tokens/create", body, headers)).status).toBe(200);
  });
});
