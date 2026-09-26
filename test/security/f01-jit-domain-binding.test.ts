// GHSA-8p84-pc7q-69jr — F-01: cross-tenant account squatting through a
// foreign IdP's JIT sign-up, and the session-level binding that makes a
// legacy squat inert (fix plan R3/R4).
//
// Every assertion states the FIXED behaviour. Against the parent commit
// (policy core), a tenant's domain-verified IdP could mint an account for
// any e-mail address on the deployment (`evil-oidc` asserting
// `ceo@acme.test` → user row + session), the squatted account satisfied
// acme's `ssoEnforced`, and a legacy squat row kept signing in for ever.
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import type { BetterAuthPlugin } from "better-auth";
import { resetOptionWarningsForTests } from "../../src/server/options";
import {
  buildDomainBindingUserCreateBeforeHook,
  composeUserCreateBeforeHooks,
  resolveSsoCallbackProviderId,
} from "../../src/server/policy/sso-jit";
import { createOrg, extractCookie, makeAuth, signUpOwner, type TestAuth } from "../helpers/auth";
import { startOidcIssuer, type OidcIssuer } from "../helpers/oidc-issuer";
import { mintSamlResponse } from "../helpers/saml-idp";
import { registerOidcProvider, registerSamlProvider } from "../helpers/sso";
import { setPolicy } from "./helpers";
import {
  driveSsoSignIn,
  driveSsoSignInViaSharedCallback,
  insertLegacySquat,
  insertTestLoginPassed,
  sessionCookieOf,
  sessionCountFor,
  sessionOf,
  twoTenants,
  userRowsFor,
} from "./ghsa-sso-helpers";

function locationOf(res: Response): string {
  expect(res.status).toBe(302);
  return res.headers.get("location") ?? "";
}

async function memberRole(t: TestAuth, orgId: string, userId: string): Promise<string | null> {
  const rows = await t.client.execute({
    sql: `SELECT role FROM member WHERE organizationId = ? AND userId = ?`,
    args: [orgId, userId],
  });
  return rows.rows.length ? String(rows.rows[0]!.role) : null;
}

describe("F-01 — JIT sign-up is bound to the signing provider's verified domain", () => {
  let issuer: OidcIssuer;
  beforeAll(async () => {
    issuer = await startOidcIssuer();
  });
  afterAll(async () => {
    await issuer.close();
  });

  it("OIDC: evil-oidc (evil.test) asserting ceo@acme.test is refused — no user row, no session, error=SSO_DOMAIN_NOT_ALLOWED; the real CEO then signs in through acme-oidc, verified, as a member", async () => {
    const provisionUser = vi.fn(async () => {});
    const t = await makeAuth({ trustedOrigins: [issuer.issuerUrl], provisionUser });
    const { acmeOrg, evilOrg } = await twoTenants(t, issuer);

    issuer.setUser({ sub: "attacker-1", email: "ceo@acme.test" });
    const squat = await driveSsoSignIn(t, issuer, "evil-oidc");
    expect(locationOf(squat)).toContain("error=SSO_DOMAIN_NOT_ALLOWED");
    expect(extractCookie(squat)).not.toContain("session_token");
    expect(await userRowsFor(t, "ceo@acme.test")).toBe(0);
    expect(provisionUser).not.toHaveBeenCalled();

    // The refusal is a policy refusal (`SSO_DOMAIN_NOT_ALLOWED`), audited as
    // `auth.sign_in_refused` (PR-6, R6) — in the *attacker's* org (the
    // signing provider's) **and** in the victim org that owns the domain of
    // the address the IdP asserted, which before saw nothing of the squat.
    // No `auth.sso_sign_in_failed` row is written for it on top.
    const refusedRows = await t.client.execute({
      sql: `SELECT org_id, target_id, metadata FROM audit_event WHERE action = 'auth.sign_in_refused' ORDER BY org_id`,
    });
    expect(refusedRows.rows.map((r) => r.org_id)).toEqual([evilOrg, acmeOrg].sort());
    for (const row of refusedRows.rows) {
      expect(row.target_id).toBeNull(); // no user was created
      expect(JSON.parse(String(row.metadata))).toMatchObject({
        code: "SSO_DOMAIN_NOT_ALLOWED",
        providerId: "evil-oidc",
        email: "ceo@acme.test",
      });
    }
    const failed = await t.client.execute({
      sql: `SELECT org_id FROM audit_event WHERE action = 'auth.sso_sign_in_failed'`,
    });
    expect(failed.rows).toEqual([]);

    issuer.setUser({ sub: "ceo-real", email: "ceo@acme.test" });
    const real = await driveSsoSignIn(t, issuer, "acme-oidc");
    expect(locationOf(real)).not.toContain("error=");
    const session = await sessionOf(t, sessionCookieOf(real));
    expect(session.user.email).toBe("ceo@acme.test");
    expect(session.user.emailVerified).toBe(true);
    expect(await memberRole(t, acmeOrg, session.user.id)).toBe("member");
    expect(provisionUser).toHaveBeenCalledTimes(1);
  });

  it("SAML: a signed assertion for ceo@acme.test from evil's IdP is refused the same way; acme's own SAML IdP still provisions a verified member", async () => {
    const t = await makeAuth();
    const evilOwner = await signUpOwner(t, "owner@evil.test");
    const { orgId: evilOrg } = await createOrg(t, evilOwner.cookie, "evil");
    const evil = await registerSamlProvider(
      t,
      evilOwner.cookie,
      evilOrg,
      "evil-saml",
      undefined,
      "evil.test",
    );
    const acmeOwner = await signUpOwner(t, "owner@acme.test");
    const { orgId: acmeOrg } = await createOrg(t, acmeOwner.cookie, "acme");
    const acme = await registerSamlProvider(
      t,
      acmeOwner.cookie,
      acmeOrg,
      "acme-saml",
      undefined,
      "acme.test",
    );

    const squat = await t.api.postForm(`/sso/saml2/sp/acs/evil-saml`, {
      SAMLResponse: await mintSamlResponse({ ...evil, email: "ceo@acme.test" }),
      RelayState: "",
    });
    expect(locationOf(squat)).toContain("error=SSO_DOMAIN_NOT_ALLOWED");
    expect(extractCookie(squat)).not.toContain("session_token");
    expect(await userRowsFor(t, "ceo@acme.test")).toBe(0);

    const real = await t.api.postForm(`/sso/saml2/sp/acs/acme-saml`, {
      SAMLResponse: await mintSamlResponse({ ...acme, email: "ceo@acme.test" }),
      RelayState: "",
    });
    expect(locationOf(real)).not.toContain("error=");
    const session = await sessionOf(t, sessionCookieOf(real));
    expect(session.user.emailVerified).toBe(true);
    expect(await memberRole(t, acmeOrg, session.user.id)).toBe("member");
  });

  it("matches like upstream: a comma-list, mixed-case provider admits its second domain and subdomains, and refuses a look-alike", async () => {
    const t = await makeAuth({ trustedOrigins: [issuer.issuerUrl] });
    const owner = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, owner.cookie, "acme");
    await registerOidcProvider(
      t,
      owner.cookie,
      orgId,
      issuer,
      "acme-oidc",
      "Acme.test, acme-two.test",
    );

    for (const [sub, email] of [
      ["u1", "a@eu.acme.test"],
      ["u2", "b@acme-two.test"],
    ] as const) {
      issuer.setUser({ sub, email });
      const res = await driveSsoSignIn(t, issuer, "acme-oidc");
      expect(locationOf(res)).not.toContain("error=");
      expect(await sessionOf(t, sessionCookieOf(res))).toMatchObject({
        user: { email, emailVerified: true },
      });
    }
    issuer.setUser({ sub: "u3", email: "c@evilacme.test" });
    const lookAlike = await driveSsoSignIn(t, issuer, "acme-oidc");
    expect(locationOf(lookAlike)).toContain("error=SSO_DOMAIN_NOT_ALLOWED");
    expect(await userRowsFor(t, "c@evilacme.test")).toBe(0);
  });

  it("the shared /sso/callback (provider from the OAuth state, none in the URL) is bound the same way", async () => {
    const t = await makeAuth({ trustedOrigins: [issuer.issuerUrl] });
    const { acmeOrg } = await twoTenants(t, issuer);

    issuer.setUser({ sub: "attacker-2", email: "cfo@acme.test" });
    const squat = await driveSsoSignInViaSharedCallback(t, issuer, "evil-oidc");
    expect(locationOf(squat)).toContain("error=SSO_DOMAIN_NOT_ALLOWED");
    expect(await userRowsFor(t, "cfo@acme.test")).toBe(0);

    issuer.setUser({ sub: "cfo-real", email: "cfo@acme.test" });
    const real = await driveSsoSignInViaSharedCallback(t, issuer, "acme-oidc");
    expect(locationOf(real)).not.toContain("error=");
    const session = await sessionOf(t, sessionCookieOf(real));
    expect(session.user.emailVerified).toBe(true);
    expect(await memberRole(t, acmeOrg, session.user.id)).toBe("member");
  });

  it("R4: a legacy account row linked to evil-oidc is refused at session time even though acme enforces nothing", async () => {
    const t = await makeAuth({ trustedOrigins: [issuer.issuerUrl] });
    const { evilOrg } = await twoTenants(t, issuer);
    const userId = await insertLegacySquat(t, {
      email: "ceo@acme.test",
      providerId: "evil-oidc",
      accountId: "attacker-1",
      memberOfOrgId: evilOrg,
    });

    issuer.setUser({ sub: "attacker-1", email: "ceo@acme.test" });
    const res = await driveSsoSignIn(t, issuer, "evil-oidc");
    expect(locationOf(res)).toContain("error=SSO_DOMAIN_NOT_ALLOWED");
    expect(extractCookie(res)).not.toContain("session_token");
    expect(await sessionCountFor(t, userId)).toBe(0);
  });

  it("R3 (binding off): a legacy squat cannot satisfy acme's ssoEnforced through evil's IdP — SSO_REQUIRED, and acme's own IdP still can", async () => {
    resetOptionWarningsForTests();
    const t = await makeAuth({ trustedOrigins: [issuer.issuerUrl], sso: { domainBinding: "off" } });
    const { acmeOwner, acmeOrg, evilOrg } = await twoTenants(t, issuer);
    await insertTestLoginPassed(t, "acme-oidc");
    const pol = await setPolicy(t, acmeOwner.cookie, {
      orgId: acmeOrg,
      ssoEnforced: true,
      breakGlassUserId: acmeOwner.userId,
    });
    expect(pol.status).toBe(200);
    const userId = await insertLegacySquat(t, {
      email: "ceo@acme.test",
      providerId: "evil-oidc",
      accountId: "attacker-1",
      memberOfOrgId: evilOrg,
    });

    issuer.setUser({ sub: "attacker-1", email: "ceo@acme.test" });
    const squat = await driveSsoSignIn(t, issuer, "evil-oidc");
    expect(locationOf(squat)).toContain("error=SSO_REQUIRED");
    expect(await sessionCountFor(t, userId)).toBe(0);

    // Control: acme's own IdP satisfies acme's rule for an acme address.
    // (The squatted `ceo@acme.test` row itself stays un-linkable to
    // `acme-oidc` — upstream's "account not linked" — until the operator
    // removes the foreign `account` row; see the detection SQL in
    // `docs/security.md`.)
    issuer.setUser({ sub: "emp-real", email: "emp@acme.test" });
    const real = await driveSsoSignIn(t, issuer, "acme-oidc");
    expect(locationOf(real)).not.toContain("error=");
    sessionCookieOf(real);
  });

  it("R3 (binding off): the attacker flipping *their own* org to ssoEnforced does not let evil's IdP sign in an acme-domain user", async () => {
    resetOptionWarningsForTests();
    const t = await makeAuth({ trustedOrigins: [issuer.issuerUrl], sso: { domainBinding: "off" } });
    const { evilOwner, evilOrg } = await twoTenants(t, issuer);
    await insertTestLoginPassed(t, "evil-oidc");
    const pol = await setPolicy(t, evilOwner.cookie, {
      orgId: evilOrg,
      ssoEnforced: true,
      breakGlassUserId: evilOwner.userId,
    });
    expect(pol.status).toBe(200);
    const userId = await insertLegacySquat(t, {
      email: "ceo@acme.test",
      providerId: "evil-oidc",
      accountId: "attacker-1",
      memberOfOrgId: evilOrg,
    });

    issuer.setUser({ sub: "attacker-1", email: "ceo@acme.test" });
    const res = await driveSsoSignIn(t, issuer, "evil-oidc");
    expect(locationOf(res)).toContain("error=SSO_REQUIRED");
    expect(await sessionCountFor(t, userId)).toBe(0);

    // Control: evil's IdP still signs in evil's own people under evil's rule.
    issuer.setUser({ sub: "evil-emp", email: "emp@evil.test" });
    const own = await driveSsoSignIn(t, issuer, "evil-oidc");
    expect(locationOf(own)).not.toContain("error=");
    sessionCookieOf(own);
  });

  it("sso.domainBinding:'off' restores upstream behaviour (the squat succeeds, unverified) and warns naming the advisory", async () => {
    resetOptionWarningsForTests();
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      const t = await makeAuth({
        trustedOrigins: [issuer.issuerUrl],
        sso: { domainBinding: "off" },
      });
      expect(warn.mock.calls.some((call) => String(call[0]).includes("GHSA-8p84-pc7q-69jr"))).toBe(
        true,
      );
      await twoTenants(t, issuer);
      issuer.setUser({ sub: "attacker-1", email: "ceo@acme.test" });
      const squat = await driveSsoSignIn(t, issuer, "evil-oidc");
      expect(locationOf(squat)).not.toContain("error=");
      const session = await sessionOf(t, sessionCookieOf(squat));
      expect(session.user.email).toBe("ceo@acme.test");
      expect(session.user.emailVerified).toBe(false);
    } finally {
      warn.mockRestore();
    }
  });

  it("sso.trustVerifiedDomainEmail:false leaves a domain-bound JIT user unverified (binding still applied)", async () => {
    const t = await makeAuth({
      trustedOrigins: [issuer.issuerUrl],
      sso: { trustVerifiedDomainEmail: false },
    });
    await twoTenants(t, issuer);
    issuer.setUser({ sub: "emp-1", email: "emp@acme.test" });
    const res = await driveSsoSignIn(t, issuer, "acme-oidc");
    expect(locationOf(res)).not.toContain("error=");
    expect((await sessionOf(t, sessionCookieOf(res))).user.emailVerified).toBe(false);

    issuer.setUser({ sub: "attacker-1", email: "ceo@acme.test" });
    expect(locationOf(await driveSsoSignIn(t, issuer, "evil-oidc"))).toContain(
      "error=SSO_DOMAIN_NOT_ALLOWED",
    );
  });

  it("canary: ctx.params.providerId is present at user.create.before for both callback route families", async () => {
    const seen: Array<{ path?: string; providerId?: string }> = [];
    const probe = {
      id: "ghsa-probe",
      init() {
        return {
          options: {
            databaseHooks: {
              user: {
                create: {
                  before: async (
                    _user: unknown,
                    ctx: { path?: string; params?: Record<string, string | undefined> } | null,
                  ) => {
                    seen.push({ path: ctx?.path, providerId: ctx?.params?.providerId });
                  },
                },
              },
            },
          },
        };
      },
    } satisfies BetterAuthPlugin;
    const t = await makeAuth({ trustedOrigins: [issuer.issuerUrl], plugins: [probe] });
    const owner = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, owner.cookie, "acme");
    await registerOidcProvider(t, owner.cookie, orgId, issuer, "acme-oidc", "acme.test");
    const saml = await registerSamlProvider(
      t,
      owner.cookie,
      orgId,
      "acme-saml",
      undefined,
      "acme.test",
    );
    seen.length = 0;

    issuer.setUser({ sub: "emp-oidc", email: "oidc@acme.test" });
    sessionCookieOf(await driveSsoSignIn(t, issuer, "acme-oidc"));
    sessionCookieOf(
      await t.api.postForm(`/sso/saml2/sp/acs/acme-saml`, {
        SAMLResponse: await mintSamlResponse({ ...saml, email: "saml@acme.test" }),
        RelayState: "",
      }),
    );
    expect(seen.map((s) => s.providerId)).toEqual(["acme-oidc", "acme-saml"]);
    expect(seen.every((s) => s.path?.startsWith("/sso/"))).toBe(true);
  });
});

describe("F-01 — the binding fails closed when the provider cannot be named", () => {
  const notFoundCtx = (path: string, params: Record<string, string> = {}) =>
    ({
      path,
      params,
      context: {
        adapter: { findOne: async () => null },
        logger: { error: () => {} },
      },
    }) as never;

  it("resolveSsoCallbackProviderId: params first, then the concrete path segment, never a pattern placeholder", async () => {
    expect(
      await resolveSsoCallbackProviderId({
        path: "/sso/callback/:providerId",
        params: { providerId: "okta" },
      }),
    ).toBe("okta");
    expect(await resolveSsoCallbackProviderId({ path: "/sso/callback/okta" })).toBe("okta");
    expect(await resolveSsoCallbackProviderId({ path: "/sso/saml2/sp/acs/okta" })).toBe("okta");
    expect(await resolveSsoCallbackProviderId({ path: "/sso/callback/:providerId" })).toBeNull();
    expect(await resolveSsoCallbackProviderId({ path: "/sso/callback" })).toBeNull();
    expect(await resolveSsoCallbackProviderId({ path: "/sign-in/email" })).toBeNull();
  });

  it("SSO_PROVIDER_UNRESOLVED when no source names a provider, or the named one has no row", async () => {
    const hook = buildDomainBindingUserCreateBeforeHook();
    await expect(
      hook({ email: "x@acme.test" }, notFoundCtx("/sso/callback/:providerId")),
    ).rejects.toMatchObject({
      body: { code: "SSO_PROVIDER_UNRESOLVED" },
    });
    await expect(
      hook({ email: "x@acme.test" }, notFoundCtx("/sso/callback/ghost", { providerId: "ghost" })),
    ).rejects.toMatchObject({
      body: { code: "SSO_PROVIDER_UNRESOLVED" },
    });
  });

  it("never touches a user created from a non-SSO path, and composes with a following hook", async () => {
    const calls: string[] = [];
    const composed = composeUserCreateBeforeHooks(
      buildDomainBindingUserCreateBeforeHook(),
      async (user) => {
        calls.push(String(user.email));
        return { data: { ...user, name: "renamed" } };
      },
    );
    const result = await composed({ email: "x@acme.test" }, notFoundCtx("/sign-up/email"));
    expect(calls).toEqual(["x@acme.test"]);
    expect(result).toEqual({ data: { email: "x@acme.test", name: "renamed" } });
    expect(await composed({ email: "y@acme.test" }, null)).toEqual({
      data: { email: "y@acme.test", name: "renamed" },
    });
  });
});
