import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from "vitest";
import dns from "node:dns/promises";
import { syncBuiltinESMExports } from "node:module";
import { createOrg, makeAuth, signUpOwner, type TestAuth } from "../helpers/auth";

let resolveTxt: MockInstance<typeof dns.resolveTxt>;

const paths = ["/sso/request-domain-verification", "/sso/verify-domain"];

async function register(t: TestAuth, cookie: string, orgId: string) {
  const response = await t.api.post(
    "/sso/register",
    {
      providerId: "domain-proof",
      issuer: "https://idp.test",
      domain: "acme.test",
      organizationId: orgId,
      oidcConfig: {
        clientId: "client",
        clientSecret: "secret",
        skipDiscovery: true,
        authorizationEndpoint: "https://idp.test/authorize",
        tokenEndpoint: "https://idp.test/token",
      },
    },
    { cookie },
  );
  expect(response.status).toBe(200);
  return (await response.json()) as { domainVerificationToken: string };
}

describe("provider-bound domain verification entitlement", () => {
  beforeEach(() => {
    // Upstream imports node:dns dynamically outside Vitest's module graph.
    resolveTxt = vi.spyOn(dns, "resolveTxt");
    syncBuiltinESMExports();
  });
  afterEach(() => {
    resolveTxt.mockRestore();
    syncBuiltinESMExports();
  });

  it("verifies the wizard provider without an active organization", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);
    const registered = await register(t, cookie, orgId);
    await t.client.execute("UPDATE session SET activeOrganizationId = NULL");
    resolveTxt.mockResolvedValue([[registered.domainVerificationToken]]);

    const request = await t.api.post(paths[0]!, { providerId: "domain-proof" }, { cookie });
    expect(request.status).toBe(201);
    const verified = await t.api.post(paths[1]!, { providerId: "domain-proof" }, { cookie });
    expect(verified.status).toBe(204);
    expect(resolveTxt).toHaveBeenCalledWith("_better-auth-token-domain-proof.acme.test");
    const rows = await t.client.execute("SELECT domainVerified FROM ssoProvider");
    expect(rows.rows[0]?.domainVerified).toBe(1);
  });

  it.each(paths)(
    "%s checks the provider's entitlement even with another active/caller org",
    async (path) => {
      const seen: string[] = [];
      const denied = new Set<string>();
      const t = await makeAuth({
        resolveEntitlements: async (orgId) => {
          seen.push(orgId);
          return denied.has(orgId) ? [] : ["sso"];
        },
      });
      const { cookie } = await signUpOwner(t);
      const { orgId } = await createOrg(t, cookie);
      await register(t, cookie, orgId);
      const { orgId: otherOrg } = await createOrg(t, cookie, "other");
      denied.add(orgId);
      seen.length = 0;

      const response = await t.api.post(
        path,
        {
          providerId: "domain-proof",
          organizationId: otherOrg,
          orgId: otherOrg,
        },
        { cookie },
      );
      expect(response.status).toBe(403);
      expect((await response.json()).code).toBe("FEATURE_NOT_ENTITLED");
      expect(seen).toEqual([orgId]);
      expect(resolveTxt).not.toHaveBeenCalled();
    },
  );

  it.each(paths)("%s rejects a nonmember before resolving the provider's plan", async (path) => {
    const resolver = vi.fn(async () => ["sso"] as const);
    const t = await makeAuth({ resolveEntitlements: resolver });
    const owner = await signUpOwner(t);
    const { orgId } = await createOrg(t, owner.cookie);
    await register(t, owner.cookie, orgId);
    const outsider = await signUpOwner(t, "outsider@other.test");
    const { orgId: otherOrg } = await createOrg(t, outsider.cookie, "other");
    resolver.mockClear();

    const response = await t.api.post(
      path,
      { providerId: "domain-proof", orgId: otherOrg },
      { cookie: outsider.cookie },
    );
    expect(response.status).toBe(403);
    expect((await response.json()).code).toBe("NOT_ORG_MEMBER");
    expect(resolver).not.toHaveBeenCalled();
    expect(resolveTxt).not.toHaveBeenCalled();
  });

  it.each(paths)(
    "%s rejects an unbound provider instead of using the session org",
    async (path) => {
      const resolver = vi.fn(async () => ["sso"] as const);
      const t = await makeAuth({ resolveEntitlements: resolver });
      const { cookie } = await signUpOwner(t);
      const { orgId } = await createOrg(t, cookie);
      await register(t, cookie, orgId);
      await t.client.execute("UPDATE ssoProvider SET organizationId = NULL");
      resolver.mockClear();

      const response = await t.api.post(path, { providerId: "domain-proof" }, { cookie });
      expect(response.status).toBe(403);
      expect((await response.json()).code).toBe("NOT_ORG_MEMBER");
      expect(resolver).not.toHaveBeenCalled();
    },
  );
});
