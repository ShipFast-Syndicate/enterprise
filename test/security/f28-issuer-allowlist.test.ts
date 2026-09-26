// GHSA-8p84-pc7q-69jr — F-28: `trustedOrigins` is not an issuer allow-list.
// The docs said an operator controlled which IdPs an org admin may point a
// provider at through better-auth's `trustedOrigins`; that option is the
// SSRF boundary for discovery/endpoint origins (and the redirect
// allow-list) — the `issuer` itself was stored whatever it was. The honest
// control is `sso.allowedIssuers` (`src/server/sso-domain.ts`, checked on
// `/sso/register` and `/sso/update-provider`): strings, `RegExp`s, or a
// predicate that also sees the target org. Absent = any issuer (upstream
// behaviour, the "honest default" control below).
import { describe, expect, it, vi } from "vitest";
import { issuerAllowed } from "../../src/server/sso-domain";
import { createOrg, makeAuth, signUpOwner, type TestAuth } from "../helpers/auth";

const oidcConfig = {
  clientId: "c",
  clientSecret: "s",
  skipDiscovery: true,
  authorizationEndpoint: "https://idp.example.com/authorize",
  tokenEndpoint: "https://idp.example.com/token",
  jwksEndpoint: "https://idp.example.com/jwks",
};

async function owner(t: TestAuth) {
  const o = await signUpOwner(t, "owner@acme.test");
  const { orgId } = await createOrg(t, o.cookie, "acme");
  return { ...o, orgId };
}

async function register(
  t: TestAuth,
  cookie: string,
  orgId: string,
  providerId: string,
  issuer: string,
): Promise<Response> {
  return t.api.post(
    "/sso/register",
    { providerId, issuer, domain: `${providerId}.test`, organizationId: orgId, oidcConfig },
    { cookie },
  );
}

async function rowCount(t: TestAuth, providerId: string): Promise<number> {
  const rows = await t.client.execute({
    sql: `SELECT id FROM "ssoProvider" WHERE providerId = ?`,
    args: [providerId],
  });
  return rows.rows.length;
}

async function expectRefused(t: TestAuth, res: Response, providerId: string): Promise<void> {
  expect(res.status).toBe(403);
  expect(((await res.json()) as { code?: string }).code).toBe("SSO_ISSUER_NOT_ALLOWED");
  expect(await rowCount(t, providerId)).toBe(0);
}

describe("F-28 — sso.allowedIssuers is the issuer allow-list", () => {
  it("honest default: with no allow-list any issuer registers (upstream behaviour)", async () => {
    const t = await makeAuth();
    const o = await owner(t);
    expect(
      (await register(t, o.cookie, o.orgId, "any", "https://anything.example.net")).status,
    ).toBe(200);
  });

  it("string entries: exact match only", async () => {
    const t = await makeAuth({ sso: { allowedIssuers: ["https://idp.example.com"] } });
    const o = await owner(t);
    expect((await register(t, o.cookie, o.orgId, "ok", "https://idp.example.com")).status).toBe(
      200,
    );
    await expectRefused(
      t,
      await register(t, o.cookie, o.orgId, "evil", "https://idp.evil.test"),
      "evil",
    );
    await expectRefused(
      t,
      await register(t, o.cookie, o.orgId, "prefix", "https://idp.example.com.evil.test"),
      "prefix",
    );
  });

  it("RegExp entries", async () => {
    const t = await makeAuth({ sso: { allowedIssuers: [/^https:\/\/[a-z-]+\.okta\.example$/] } });
    const o = await owner(t);
    expect((await register(t, o.cookie, o.orgId, "ok", "https://acme.okta.example")).status).toBe(
      200,
    );
    await expectRefused(
      t,
      await register(t, o.cookie, o.orgId, "evil", "https://acme.okta.example.evil.test"),
      "evil",
    );
  });

  it("predicate: receives the issuer and the target org; a false verdict or a throw refuses", async () => {
    const allowedIssuers = vi.fn(async (issuer: string, ctx: { organizationId: string | null }) => {
      if (issuer === "https://boom.example") throw new Error("boom");
      return issuer === `https://${ctx.organizationId}.idp.example`;
    });
    const t = await makeAuth({ sso: { allowedIssuers } });
    const o = await owner(t);
    expect(
      (await register(t, o.cookie, o.orgId, "ok", `https://${o.orgId}.idp.example`)).status,
    ).toBe(200);
    expect(allowedIssuers).toHaveBeenLastCalledWith(`https://${o.orgId}.idp.example`, {
      organizationId: o.orgId,
    });
    await expectRefused(
      t,
      await register(t, o.cookie, o.orgId, "other", "https://other-org.idp.example"),
      "other",
    );
    await expectRefused(
      t,
      await register(t, o.cookie, o.orgId, "boom", "https://boom.example"),
      "boom",
    );
  });

  it("/sso/update-provider: changing the issuer to one outside the list is refused; other updates still go through", async () => {
    const t = await makeAuth({
      sso: { allowedIssuers: ["https://idp.example.com", "https://idp2.example.com"] },
    });
    const o = await owner(t);
    expect((await register(t, o.cookie, o.orgId, "acme", "https://idp.example.com")).status).toBe(
      200,
    );

    const refused = await t.api.post(
      "/sso/update-provider",
      { providerId: "acme", issuer: "https://idp.evil.test" },
      { cookie: o.cookie },
    );
    expect(refused.status).toBe(403);
    expect(((await refused.json()) as { code?: string }).code).toBe("SSO_ISSUER_NOT_ALLOWED");

    const ok = await t.api.post(
      "/sso/update-provider",
      { providerId: "acme", issuer: "https://idp2.example.com" },
      { cookie: o.cookie },
    );
    expect(ok.status).toBe(200);
    const row = await t.client.execute({
      sql: `SELECT issuer FROM "ssoProvider" WHERE providerId = 'acme'`,
    });
    expect(row.rows[0]!.issuer).toBe("https://idp2.example.com");
  });

  it("issuerAllowed: the three forms, unit-level", async () => {
    expect(await issuerAllowed(undefined, "https://x", null)).toBe(true);
    expect(await issuerAllowed({ sso: { allowedIssuers: [] } } as never, "https://x", null)).toBe(
      false,
    );
    expect(
      await issuerAllowed({ sso: { allowedIssuers: ["https://x"] } } as never, "https://x", null),
    ).toBe(true);
    expect(
      await issuerAllowed(
        { sso: { allowedIssuers: [/^https:\/\/x$/] } } as never,
        "https://x",
        "o",
      ),
    ).toBe(true);
    expect(
      await issuerAllowed(
        { sso: { allowedIssuers: () => "yes" as never } } as never,
        "https://x",
        "o",
      ),
    ).toBe(false);
  });
});
