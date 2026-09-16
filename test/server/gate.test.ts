import { describe, expect, it } from "vitest";
import { makeAuth, signUpOwner, createOrg } from "../helpers/auth";

const oidcConfig = {
  clientId: "a",
  clientSecret: "b",
  skipDiscovery: true,
  authorizationEndpoint: "https://idp.test/a",
  tokenEndpoint: "https://idp.test/t",
};

describe("enterpriseGate", () => {
  it("POST /sso/register returns 403 without the sso feature", async () => {
    const t = await makeAuth({ resolveEntitlements: async () => [] });
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);

    const res = await t.api.post(
      "/sso/register",
      {
        providerId: "p",
        issuer: "https://idp.test",
        domain: "acme.test",
        organizationId: orgId,
        oidcConfig,
      },
      { cookie },
    );

    expect(res.status).toBe(403);
    expect((await res.json()).code).toBe("FEATURE_NOT_ENTITLED");
  });

  it("the same call succeeds with the feature", async () => {
    const t = await makeAuth({ resolveEntitlements: async () => ["sso"] });
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);

    const res = await t.api.post(
      "/sso/register",
      {
        providerId: "p",
        issuer: "https://idp.test",
        domain: "acme.test",
        organizationId: orgId,
        oidcConfig,
      },
      { cookie },
    );

    expect(res.status).toBe(200);
  });

  it("does not gate an anonymous call — the endpoint answers its own 401", async () => {
    const t = await makeAuth({ resolveEntitlements: async () => [] });

    const res = await t.api.post("/sso/register", {
      providerId: "p",
      issuer: "https://idp.test",
      domain: "acme.test",
      organizationId: "org_1",
      oidcConfig,
    });

    expect(res.status).toBe(401);
  });

  it("orgId is read from body.organizationId, then from the active org of the session", async () => {
    const seenOrgIds: string[] = [];
    const t = await makeAuth({
      resolveEntitlements: async (orgId) => {
        seenOrgIds.push(orgId);
        return ["teams"];
      },
    });
    const { cookie } = await signUpOwner(t);
    const { orgId: orgId1 } = await createOrg(t, cookie, "acme");
    // Creating a second org makes it the new active org (per better-auth's
    // /organization/create, which sets the newly created org active unless
    // told to keep the current one).
    const { orgId: orgId2 } = await createOrg(t, cookie, "beta");

    const fallback = await t.api.post(
      "/organization/create-team",
      { name: "team-fallback" },
      { cookie },
    );
    expect(fallback.status).toBe(200);
    expect(seenOrgIds.at(-1)).toBe(orgId2);

    const explicit = await t.api.post(
      "/organization/create-team",
      { name: "team-explicit", organizationId: orgId1 },
      { cookie },
    );
    expect(explicit.status).toBe(200);
    expect(seenOrgIds.at(-1)).toBe(orgId1);
  });

  it("returns 400 ORG_REQUIRED when no org can be resolved", async () => {
    const t = await makeAuth({ resolveEntitlements: async () => ["teams"] });
    const { cookie } = await signUpOwner(t);
    // No org created — no active org, and none in the body.

    const res = await t.api.post("/organization/create-team", { name: "team-x" }, { cookie });

    expect(res.status).toBe(400);
    expect((await res.json()).code).toBe("ORG_REQUIRED");
  });

  // GHSA-j8v8-g9cx-5qf4: @better-auth/scim below 1.7 lets a SCIM provider be
  // created without an organizationId ("personal" provider), which can then
  // be taken over. This design only allows org-scoped providers, so
  // `/scim/generate-token` and `/scim/delete-provider-connection` must
  // require `organizationId` explicitly in the body — never falling back to
  // the session's active org, unlike every other gated path.
  describe("SCIM provider paths never fall back to the session's active org", () => {
    it("POST /scim/generate-token without organizationId returns 400 ORG_REQUIRED, even with an active org, and creates no scimProvider row", async () => {
      const t = await makeAuth({ resolveEntitlements: async () => ["scim"] });
      const { cookie } = await signUpOwner(t);
      await createOrg(t, cookie); // sets an active org on the session

      const res = await t.api.post("/scim/generate-token", { providerId: "p1" }, { cookie });

      expect(res.status).toBe(400);
      expect((await res.json()).code).toBe("ORG_REQUIRED");

      const rows = await t.client.execute(`SELECT * FROM "scimProvider"`);
      expect(rows.rows.length).toBe(0);
    });

    it("POST /scim/generate-token with organizationId passes the gate (201 from upstream)", async () => {
      const t = await makeAuth({ resolveEntitlements: async () => ["scim"] });
      const { cookie } = await signUpOwner(t);
      const { orgId } = await createOrg(t, cookie);

      const res = await t.api.post(
        "/scim/generate-token",
        { providerId: "p1", organizationId: orgId },
        { cookie },
      );

      expect(res.status).toBe(201);
      const rows = await t.client.execute(`SELECT * FROM "scimProvider"`);
      expect(rows.rows.length).toBe(1);
    });
  });
});
