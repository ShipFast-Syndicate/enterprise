import { afterEach, describe, expect, it, vi } from "vitest";
import { makeAuth, signUpOwner, createOrg } from "../helpers/auth";
import { resetOptionWarningsForTests } from "../../src/server/options";

const oidcConfig = {
  clientId: "a",
  clientSecret: "b",
  skipDiscovery: true,
  authorizationEndpoint: "https://idp.test/a",
  tokenEndpoint: "https://idp.test/t",
};

describe("enterpriseGate", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    resetOptionWarningsForTests();
  });

  it('warns once per process, through the auth logger, when sso.domainBinding is "off" and sso.allowedIssuers is not configured — and not when the allow-list is set', async () => {
    // better-auth's default logger prints `warn` lines with `console.warn`.
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const unlisted = (calls: unknown[][]) =>
      calls.filter((call) => String(call[0]).includes('"sso.allowedIssuers" is not configured'));

    await makeAuth({ sso: { domainBinding: "off" } });
    await makeAuth({ sso: { domainBinding: "off" } });
    expect(unlisted(warn.mock.calls)).toHaveLength(1);
    expect(String(unlisted(warn.mock.calls)[0]?.[0])).toContain("samlCertificateFingerprints");

    resetOptionWarningsForTests();
    warn.mockClear();
    await makeAuth({ sso: { domainBinding: "off", allowedIssuers: ["https://idp.test"] } });
    await makeAuth();
    await makeAuth({ sso: { domainBinding: "verified-domain" } });
    expect(unlisted(warn.mock.calls)).toHaveLength(0);
  });

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

  it("/sso/register returns 400 ORG_REQUIRED without body.organizationId even when the session has an active org (gap 5)", async () => {
    const t = await makeAuth({ resolveEntitlements: async () => ["sso"] });
    const { cookie } = await signUpOwner(t);
    await createOrg(t, cookie); // becomes the session's active org — the fallback chain must not use it here

    const res = await t.api.post(
      "/sso/register",
      { providerId: "p", issuer: "https://idp.test", domain: "acme.test", oidcConfig },
      { cookie },
    );

    expect(res.status).toBe(400);
    expect((await res.json()).code).toBe("ORG_REQUIRED");
  });

  it("returns 400 ORG_REQUIRED when no org can be resolved", async () => {
    const t = await makeAuth({ resolveEntitlements: async () => ["teams"] });
    const { cookie } = await signUpOwner(t);
    // No org created — no active org, and none in the body.

    const res = await t.api.post("/organization/create-team", { name: "team-x" }, { cookie });

    expect(res.status).toBe(400);
    expect((await res.json()).code).toBe("ORG_REQUIRED");
  });

  it("legacy SCIM management endpoints are no longer exposed", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);
    for (const path of ["/scim/generate-token", "/scim/delete-provider-connection"]) {
      const res = await t.api.post(path, { providerId: "p1", organizationId: orgId }, { cookie });
      expect(res.status).toBe(404);
    }
    expect((await t.client.execute("SELECT * FROM scimManagedConnection")).rows).toHaveLength(0);
  });
});
