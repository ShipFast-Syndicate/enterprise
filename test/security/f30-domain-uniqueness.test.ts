// GHSA-8p84-pc7q-69jr — F-30: SSO domain ownership and uniqueness
// (`src/server/sso-domain.ts`, installed by the gate). Upstream never
// checked that a provider's domain was free: any tenant could register a
// second (unverified) provider for a domain another org had verified, and
// because upstream's e-mail `/sign-in/sso` resolves the provider with an
// exact `findOne({domain})` over unverified rows too, the squat row won and
// the legitimate org's e-mail sign-in answered "domain has not been
// verified". Now: 409 `SSO_DOMAIN_TAKEN` on register/update/verify when
// another org already verified an overlapping domain, `/sso/register`
// stores the normalised list (R15), and the e-mail sign-in is pinned to the
// verified provider (R7).
import { describe, expect, it, vi } from "vitest";
import { createOrg, makeAuth, signUpOwner, type TestAuth } from "../helpers/auth";
import { verifyProviderDomain } from "../helpers/sso";

const oidcConfig = {
  clientId: "c",
  clientSecret: "s",
  skipDiscovery: true,
  authorizationEndpoint: "https://idp.example.com/authorize",
  tokenEndpoint: "https://idp.example.com/token",
  jwksEndpoint: "https://idp.example.com/jwks",
};

async function register(
  t: TestAuth,
  cookie: string,
  body: { providerId: string; domain: string; organizationId: string; issuer?: string },
): Promise<Response> {
  return t.api.post(
    "/sso/register",
    { issuer: "https://idp.example.com", oidcConfig, ...body },
    { cookie },
  );
}

async function code(res: Response): Promise<string | undefined> {
  return ((await res.clone().json()) as { code?: string }).code;
}

async function storedDomain(t: TestAuth, providerId: string): Promise<string | null> {
  const rows = await t.client.execute({
    sql: `SELECT domain FROM "ssoProvider" WHERE providerId = ?`,
    args: [providerId],
  });
  return rows.rows.length ? String(rows.rows[0]!.domain) : null;
}

/** Victim org `acme` with a *verified* `acme.test` provider, and attacker org `evil`. */
async function acmeAndEvil(t: TestAuth, acmeDomain = "acme.test") {
  const acmeOwner = await signUpOwner(t, "owner@acme.test");
  const { orgId: acmeOrg } = await createOrg(t, acmeOwner.cookie, "acme");
  const acme = await register(t, acmeOwner.cookie, {
    providerId: "acme-oidc",
    domain: acmeDomain,
    organizationId: acmeOrg,
  });
  expect(acme.status).toBe(200);
  await verifyProviderDomain(t, "acme-oidc");
  const evilOwner = await signUpOwner(t, "owner@evil.test");
  const { orgId: evilOrg } = await createOrg(t, evilOwner.cookie, "evil");
  return { acmeOwner, acmeOrg, evilOwner, evilOrg };
}

describe("F-30 — a verified domain belongs to one organization", () => {
  it("/sso/register: 409 SSO_DOMAIN_TAKEN for the exact domain, any case, a subdomain, or a comma list containing it; a disjoint domain is fine", async () => {
    const t = await makeAuth();
    const { evilOwner, evilOrg } = await acmeAndEvil(t);
    for (const [providerId, domain] of [
      ["squat-exact", "acme.test"],
      ["squat-case", "ACME.test"],
      ["squat-sub", "eu.acme.test"],
      ["squat-list", "foo.test, Acme.test"],
    ] as const) {
      const res = await register(t, evilOwner.cookie, {
        providerId,
        domain,
        organizationId: evilOrg,
      });
      expect(res.status, providerId).toBe(409);
      expect(await code(res)).toBe("SSO_DOMAIN_TAKEN");
      expect(await storedDomain(t, providerId)).toBeNull();
    }
    const ok = await register(t, evilOwner.cookie, {
      providerId: "evil-own",
      domain: "acmex.test",
      organizationId: evilOrg,
    });
    expect(ok.status).toBe(200);
  });

  it("/sso/register: a parent domain is taken when another org verified one of its subdomains (a parent provider would match that org's mail)", async () => {
    const t = await makeAuth();
    const { evilOwner, evilOrg } = await acmeAndEvil(t, "eu.acme.test");
    const res = await register(t, evilOwner.cookie, {
      providerId: "squat-parent",
      domain: "acme.test",
      organizationId: evilOrg,
    });
    expect(res.status).toBe(409);
    expect(await code(res)).toBe("SSO_DOMAIN_TAKEN");
  });

  it("/sso/register: the same org may register a second provider for its own domain", async () => {
    const t = await makeAuth();
    const { acmeOwner, acmeOrg } = await acmeAndEvil(t);
    const second = await register(t, acmeOwner.cookie, {
      providerId: "acme-oidc-2",
      domain: "eu.acme.test",
      organizationId: acmeOrg,
    });
    expect(second.status).toBe(200);
  });

  it("/sso/register stores the normalised list (trimmed, lower-cased, de-duplicated, trailing dot dropped) and refuses one that could never match", async () => {
    const t = await makeAuth();
    const owner = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, owner.cookie, "acme");
    const res = await register(t, owner.cookie, {
      providerId: "acme-list",
      domain: " Acme.test , two.test., ACME.TEST ",
      organizationId: orgId,
    });
    expect(res.status).toBe(200);
    expect(await storedDomain(t, "acme-list")).toBe("acme.test,two.test");

    const invalid = await register(t, owner.cookie, {
      providerId: "acme-bad",
      domain: "https://acme.test",
      organizationId: orgId,
    });
    expect(invalid.status).toBe(400);
    expect(await code(invalid)).toBe("SSO_DOMAIN_INVALID");
    expect(await storedDomain(t, "acme-bad")).toBeNull();
  });

  it("/sso/update-provider: moving a provider onto another org's verified domain is 409; a free domain is stored normalised; an unchanged domain is passed through", async () => {
    const t = await makeAuth();
    const { evilOwner, evilOrg } = await acmeAndEvil(t);
    expect(
      (
        await register(t, evilOwner.cookie, {
          providerId: "evil-oidc",
          domain: "evil.test",
          organizationId: evilOrg,
        })
      ).status,
    ).toBe(200);
    await verifyProviderDomain(t, "evil-oidc");

    const taken = await t.api.post(
      "/sso/update-provider",
      { providerId: "evil-oidc", domain: "eu.acme.test" },
      { cookie: evilOwner.cookie },
    );
    expect(taken.status).toBe(409);
    expect(await code(taken)).toBe("SSO_DOMAIN_TAKEN");
    expect(await storedDomain(t, "evil-oidc")).toBe("evil.test");

    const moved = await t.api.post(
      "/sso/update-provider",
      { providerId: "evil-oidc", domain: " Evil2.test " },
      { cookie: evilOwner.cookie },
    );
    expect(moved.status).toBe(200);
    expect(await storedDomain(t, "evil-oidc")).toBe("evil2.test");
    await verifyProviderDomain(t, "evil-oidc");

    // Repeating the stored value verbatim is not a domain change: upstream
    // keeps `domainVerified` and the guard leaves the body alone.
    const same = await t.api.post(
      "/sso/update-provider",
      { providerId: "evil-oidc", domain: "evil2.test" },
      { cookie: evilOwner.cookie },
    );
    expect(same.status).toBe(200);
    const row = await t.client.execute({
      sql: `SELECT domainVerified FROM "ssoProvider" WHERE providerId = 'evil-oidc'`,
    });
    expect(row.rows[0]!.domainVerified).toBe(1);
  });

  it("/sso/verify-domain: a provider registered before the other org verified the same domain cannot be verified afterwards (409 before any DNS lookup)", async () => {
    const t = await makeAuth();
    const acmeOwner = await signUpOwner(t, "owner@acme.test");
    const { orgId: acmeOrg } = await createOrg(t, acmeOwner.cookie, "acme");
    const evilOwner = await signUpOwner(t, "owner@evil.test");
    const { orgId: evilOrg } = await createOrg(t, evilOwner.cookie, "evil");
    // Both register while nobody has verified yet — both allowed.
    expect(
      (
        await register(t, evilOwner.cookie, {
          providerId: "squat",
          domain: "acme.test",
          organizationId: evilOrg,
        })
      ).status,
    ).toBe(200);
    expect(
      (
        await register(t, acmeOwner.cookie, {
          providerId: "acme-oidc",
          domain: "acme.test",
          organizationId: acmeOrg,
        })
      ).status,
    ).toBe(200);
    await verifyProviderDomain(t, "acme-oidc");

    const res = await t.api.post(
      "/sso/verify-domain",
      { providerId: "squat" },
      { cookie: evilOwner.cookie },
    );
    expect(res.status).toBe(409);
    expect(await code(res)).toBe("SSO_DOMAIN_TAKEN");
    const row = await t.client.execute({
      sql: `SELECT domainVerified FROM "ssoProvider" WHERE providerId = 'squat'`,
    });
    expect(row.rows[0]!.domainVerified).toBe(0);
  });

  it("e-mail /sign-in/sso is pinned to the verified provider past an earlier, unverified squat row (by email and by domain); home-realm agrees", async () => {
    const t = await makeAuth();
    const evilOwner = await signUpOwner(t, "owner@evil.test");
    const { orgId: evilOrg } = await createOrg(t, evilOwner.cookie, "evil");
    expect(
      (
        await register(t, evilOwner.cookie, {
          providerId: "squat",
          domain: "acme.test",
          organizationId: evilOrg,
        })
      ).status,
    ).toBe(200);
    const acmeOwner = await signUpOwner(t, "owner@acme.test");
    const { orgId: acmeOrg } = await createOrg(t, acmeOwner.cookie, "acme");
    expect(
      (
        await register(t, acmeOwner.cookie, {
          providerId: "acme-oidc",
          domain: "acme.test",
          organizationId: acmeOrg,
        })
      ).status,
    ).toBe(200);
    await verifyProviderDomain(t, "acme-oidc");

    const byEmail = await t.api.post(
      "/sign-in/sso",
      { email: "someone@acme.test", callbackURL: "/" },
      {},
    );
    expect(byEmail.status).toBe(200);
    expect(((await byEmail.json()) as { url: string }).url).toContain("idp.example.com/authorize");
    const byDomain = await t.api.post(
      "/sign-in/sso",
      { domain: "acme.test", callbackURL: "/" },
      {},
    );
    expect(byDomain.status).toBe(200);
    const sub = await t.api.post(
      "/sign-in/sso",
      { email: "someone@eu.acme.test", callbackURL: "/" },
      {},
    );
    expect(sub.status).toBe(200);

    const realm = await t.api.post("/enterprise/home-realm", { email: "someone@acme.test" }, {});
    expect(await realm.json()).toEqual({ method: "sso", providerId: "acme-oidc" });
  });

  it("two orgs holding verified legacy rows for one domain are not pinned: upstream's own lookup runs and the ambiguity is logged", async () => {
    const t = await makeAuth();
    // Legacy data, written before uniqueness was enforced: an unverified
    // squat row first (it wins upstream's exact `findOne`), then two
    // verified rows in two different orgs.
    for (const [id, providerId, orgId, verified] of [
      ["p_squat", "squat", "org_evil", 0],
      ["p_x", "x-idp", "org_x", 1],
      ["p_y", "y-idp", "org_y", 1],
    ] as const) {
      await t.client.execute({
        sql: `INSERT INTO "ssoProvider" (id, issuer, domain, domainVerified, organizationId, providerId, userId, oidcConfig) VALUES (?, ?, 'acme.test', ?, ?, ?, 'u', ?)`,
        args: [
          id,
          "https://idp.example.com",
          verified,
          orgId,
          providerId,
          JSON.stringify({ ...oidcConfig, issuer: "https://idp.example.com" }),
        ],
      });
    }
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      const res = await t.api.post(
        "/sign-in/sso",
        { email: "someone@acme.test", callbackURL: "/" },
        {},
      );
      expect(res.status).toBe(401); // upstream: the squat row, "domain has not been verified"
      expect(
        warn.mock.calls.some((call) =>
          String(call[0]).includes("2 organizations hold a verified SSO provider"),
        ),
      ).toBe(true);
    } finally {
      warn.mockRestore();
    }
  });
});
