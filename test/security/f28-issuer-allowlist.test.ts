// GHSA-8p84-pc7q-69jr — F-28: `trustedOrigins` is not an issuer allow-list.
// The docs said an operator controlled which IdPs an org admin may point a
// provider at through better-auth's `trustedOrigins`; that option is the
// SSRF boundary for discovery/endpoint origins (and the redirect
// allow-list) — the `issuer` itself was stored whatever it was. The honest
// control is `sso.allowedIssuers` (`src/server/sso-domain.ts`, checked on
// `/sso/register` and `/sso/update-provider`): strings, `RegExp`s, or a
// predicate that also sees the target org. Absent = any issuer (upstream
// behaviour, the "honest default" control below).
//
// The allow-list binds the **IdP**, not just the `issuer` string: upstream
// verifies an id_token's `iss` against the stored issuer but fetches the
// signing keys from the tenant-supplied `jwksEndpoint` (and trusts a SAML
// assertion against the tenant-supplied cert/entryPoint), so a tenant who
// may write `issuer: <allowed>` and point every endpoint at an IdP of their
// own would satisfy a string-only list while signing in through their own
// keys. The "rogue IdP" cases below run exactly that: an in-process issuer
// whose id_tokens *claim* the allowed `iss` (`issClaim`) — live without a
// list (the control that proves the attack is real), refused with one.
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { X509Certificate } from "node:crypto";
import {
  collectIdpEndpoints,
  collectSamlTrustRoot,
  issuerAllowed,
  normalizeFingerprint,
} from "../../src/server/sso-domain";
import { createOrg, extractCookie, makeAuth, signUpOwner, type TestAuth } from "../helpers/auth";
import { startOidcIssuer, type OidcIssuer } from "../helpers/oidc-issuer";
import { mintSamlResponse, TEST_IDP_ENTITY_ID } from "../helpers/saml-idp";
import { IDP_CERT, SP_CERT } from "../helpers/fixtures/saml-keys";
import { verifyProviderDomain } from "../helpers/sso";
import { driveSsoSignIn, sessionOf } from "./ghsa-sso-helpers";

const IDP = "https://idp.example.com";

/** Endpoints on `origin` (default: the allowed IdP's own origin). */
function oidcConfigOn(origin = IDP) {
  return {
    clientId: "c",
    clientSecret: "s",
    skipDiscovery: true,
    authorizationEndpoint: `${origin}/authorize`,
    tokenEndpoint: `${origin}/token`,
    jwksEndpoint: `${origin}/jwks`,
  };
}

function rogueOidcConfig(rogue: OidcIssuer) {
  return {
    clientId: rogue.clientId,
    clientSecret: rogue.clientSecret,
    skipDiscovery: true,
    authorizationEndpoint: rogue.authorizationEndpoint,
    tokenEndpoint: rogue.tokenEndpoint,
    jwksEndpoint: rogue.jwksEndpoint,
  };
}

async function owner(t: TestAuth, email = "owner@acme.test", slug = "acme") {
  const o = await signUpOwner(t, email);
  const { orgId } = await createOrg(t, o.cookie, slug);
  return { ...o, orgId };
}

async function register(
  t: TestAuth,
  cookie: string,
  orgId: string,
  providerId: string,
  issuer: string,
  oidcConfig: Record<string, unknown> = oidcConfigOn(),
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

async function storedOidcConfig(t: TestAuth, providerId: string): Promise<Record<string, unknown>> {
  const rows = await t.client.execute({
    sql: `SELECT oidcConfig FROM "ssoProvider" WHERE providerId = ?`,
    args: [providerId],
  });
  return JSON.parse(String(rows.rows[0]!.oidcConfig)) as Record<string, unknown>;
}

async function expectRefused(t: TestAuth, res: Response, providerId: string): Promise<void> {
  expect(res.status).toBe(403);
  expect(((await res.json()) as { code?: string }).code).toBe("SSO_ISSUER_NOT_ALLOWED");
  expect(await rowCount(t, providerId)).toBe(0);
}

async function expectUpdateRefused(res: Response): Promise<void> {
  expect(res.status).toBe(403);
  expect(((await res.json()) as { code?: string }).code).toBe("SSO_ISSUER_NOT_ALLOWED");
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
    const t = await makeAuth({ sso: { allowedIssuers: [IDP] } });
    const o = await owner(t);
    expect((await register(t, o.cookie, o.orgId, "ok", IDP)).status).toBe(200);
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
    expect(
      (
        await register(
          t,
          o.cookie,
          o.orgId,
          "ok",
          "https://acme.okta.example",
          oidcConfigOn("https://acme.okta.example"),
        )
      ).status,
    ).toBe(200);
    await expectRefused(
      t,
      await register(
        t,
        o.cookie,
        o.orgId,
        "evil",
        "https://acme.okta.example.evil.test",
        oidcConfigOn("https://acme.okta.example.evil.test"),
      ),
      "evil",
    );
  });

  it("predicate: receives the issuer, the target org and the IdP endpoints; a false verdict or a throw refuses", async () => {
    const allowedIssuers = vi.fn(
      async (issuer: string, ctx: { organizationId: string | null; endpoints: string[] }) => {
        if (issuer === "https://boom.example") throw new Error("boom");
        return (
          issuer === `https://${ctx.organizationId}.idp.example` &&
          ctx.endpoints.every((endpoint) => endpoint.startsWith(`${issuer}/`))
        );
      },
    );
    const t = await makeAuth({ sso: { allowedIssuers } });
    const o = await owner(t);
    const mine = `https://${o.orgId}.idp.example`;
    expect((await register(t, o.cookie, o.orgId, "ok", mine, oidcConfigOn(mine))).status).toBe(200);
    expect(allowedIssuers).toHaveBeenLastCalledWith(mine, {
      organizationId: o.orgId,
      endpoints: [`${mine}/authorize`, `${mine}/token`, `${mine}/jwks`],
      samlCertFingerprints: [], // OIDC: nothing to pin
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
    // The predicate sees the endpoints: an allowed issuer string with
    // endpoints elsewhere is its call — and this one says no.
    await expectRefused(
      t,
      await register(t, o.cookie, o.orgId, "elsewhere", mine, oidcConfigOn("https://rogue.test")),
      "elsewhere",
    );
  });

  it("/sso/update-provider: changing the issuer to one outside the list is refused; other updates still go through", async () => {
    const t = await makeAuth({
      sso: { allowedIssuers: [IDP, "https://idp2.example.com"] },
    });
    const o = await owner(t);
    expect((await register(t, o.cookie, o.orgId, "acme", IDP)).status).toBe(200);

    const refused = await t.api.post(
      "/sso/update-provider",
      { providerId: "acme", issuer: "https://idp.evil.test" },
      { cookie: o.cookie },
    );
    expect(refused.status).toBe(403);
    expect(((await refused.json()) as { code?: string }).code).toBe("SSO_ISSUER_NOT_ALLOWED");

    // The stored endpoints stay on `idp.example.com`, itself on the list —
    // so moving the issuer to the second allowed entry is fine.
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

  it("/sso/update-provider: a new issuer is judged against the *stored* endpoints — an allowed issuer whose stored endpoints are no longer covered is refused", async () => {
    const t = await makeAuth({
      sso: { allowedIssuers: [IDP, "https://idp2.example.com", /^https:\/\/only-me\.example$/] },
    });
    const o = await owner(t);
    expect(
      (await register(t, o.cookie, o.orgId, "acme", IDP, oidcConfigOn("https://idp2.example.com")))
        .status,
    ).toBe(200);
    // `only-me` is an allowed issuer, but the stored endpoints sit on
    // `idp2.example.com` — a listed origin, so still fine …
    expect(
      (
        await t.api.post(
          "/sso/update-provider",
          { providerId: "acme", issuer: "https://only-me.example" },
          { cookie: o.cookie },
        )
      ).status,
    ).toBe(200);
    // … whereas endpoints on an unlisted origin are refused even though the
    // issuer stays allowed.
    await expectUpdateRefused(
      await t.api.post(
        "/sso/update-provider",
        { providerId: "acme", oidcConfig: { jwksEndpoint: "https://rogue.test/jwks" } },
        { cookie: o.cookie },
      ),
    );
    expect((await storedOidcConfig(t, "acme")).jwksEndpoint).toBe("https://idp2.example.com/jwks");
  });

  it("/sso/update-provider: an issuer-only change is refused when the *stored* endpoints were covered only by the old issuer's origin (proves the stored config is read)", async () => {
    const t = await makeAuth({
      sso: {
        allowedIssuers: [/^https:\/\/idp\.example\.com\/tenant-[ab]$/, "https://idp2.example.com"],
      },
    });
    const o = await owner(t);
    // Allowed by the RegExp; the endpoints sit on the issuer's origin, which
    // is *not* itself an entry (the RegExp demands the `/tenant-x` path).
    expect(
      (
        await register(
          t,
          o.cookie,
          o.orgId,
          "acme",
          "https://idp.example.com/tenant-a",
          oidcConfigOn("https://idp.example.com"),
        )
      ).status,
    ).toBe(200);
    // Moving the issuer to `idp2` leaves the stored endpoints on an origin
    // nothing covers any more → refused, row untouched. (Were the stored
    // config not read, the endpoint set would be empty and this would pass.)
    await expectUpdateRefused(
      await t.api.post(
        "/sso/update-provider",
        { providerId: "acme", issuer: "https://idp2.example.com" },
        { cookie: o.cookie },
      ),
    );
    const row = await t.client.execute({
      sql: `SELECT issuer FROM "ssoProvider" WHERE providerId = 'acme'`,
    });
    expect(row.rows[0]!.issuer).toBe("https://idp.example.com/tenant-a");
    // Moving both together onto `idp2` is fine — every stored endpoint
    // included: upstream's merge keeps a stored `discoveryEndpoint` the body
    // does not replace, so one left on the old origin is (rightly) refused.
    await expectUpdateRefused(
      await t.api.post(
        "/sso/update-provider",
        {
          providerId: "acme",
          issuer: "https://idp2.example.com",
          oidcConfig: oidcConfigOn("https://idp2.example.com"),
        },
        { cookie: o.cookie },
      ),
    );
    expect(
      (
        await t.api.post(
          "/sso/update-provider",
          {
            providerId: "acme",
            issuer: "https://idp2.example.com",
            oidcConfig: {
              ...oidcConfigOn("https://idp2.example.com"),
              discoveryEndpoint: "https://idp2.example.com/.well-known/openid-configuration",
            },
          },
          { cookie: o.cookie },
        )
      ).status,
    ).toBe(200);
    const moved = await storedOidcConfig(t, "acme");
    expect(moved.discoveryEndpoint).toBe(
      "https://idp2.example.com/.well-known/openid-configuration",
    );
    expect(moved.jwksEndpoint).toBe("https://idp2.example.com/jwks");
  });

  describe("the allow-list binds the IdP, not the issuer string (a rogue IdP claiming an allowed `iss`)", () => {
    const ALLOWED = "https://idp.allowed.example";
    let rogue: OidcIssuer;
    beforeAll(async () => {
      rogue = await startOidcIssuer({ issClaim: ALLOWED });
    });
    afterAll(async () => {
      await rogue.close();
    });

    it("control — without an allow-list the rogue IdP registers under the allowed issuer string and mints a session (the attack is real)", async () => {
      const t = await makeAuth({ trustedOrigins: [rogue.issuerUrl] });
      const o = await owner(t, "owner@evil.test", "evil");
      const reg = await register(t, o.cookie, o.orgId, "evil", ALLOWED, rogueOidcConfig(rogue));
      expect(reg.status).toBe(200);
      await verifyProviderDomain(t, "evil");
      rogue.setUser({ sub: "r-1", email: "mallory@evil.test" });
      const res = await driveSsoSignIn(t, rogue, "evil");
      const cookie = extractCookie(res);
      expect(cookie).toContain("session_token");
      expect((await sessionOf(t, cookie)).user.email).toBe("mallory@evil.test");
    });

    it("C1 /sso/register: issuer string allowed, every OIDC endpoint on a rogue origin → 403, nothing stored, no provider to sign in through", async () => {
      const t = await makeAuth({
        trustedOrigins: [rogue.issuerUrl],
        sso: { allowedIssuers: [ALLOWED] },
      });
      const o = await owner(t, "owner@evil.test", "evil");
      await expectRefused(
        t,
        await register(t, o.cookie, o.orgId, "evil", ALLOWED, rogueOidcConfig(rogue)),
        "evil",
      );
      // One rogue endpoint among allowed ones is enough — each of the five.
      for (const field of [
        "discoveryEndpoint",
        "authorizationEndpoint",
        "tokenEndpoint",
        "jwksEndpoint",
        "userInfoEndpoint",
      ]) {
        await expectRefused(
          t,
          await register(t, o.cookie, o.orgId, `evil-${field}`, ALLOWED, {
            ...oidcConfigOn(ALLOWED),
            [field]: `${rogue.issuerUrl}/${field}`,
          }),
          `evil-${field}`,
        );
      }
      const signIn = await t.api.post("/sign-in/sso", { providerId: "evil", callbackURL: "/" }, {});
      expect(signIn.status).toBe(404);
      expect(extractCookie(signIn)).not.toContain("session_token");
      // The same endpoints on the allowed origin register (the list works).
      expect(
        (await register(t, o.cookie, o.orgId, "legit", ALLOWED, oidcConfigOn(ALLOWED))).status,
      ).toBe(200);
    });

    it("C1b the operator can list the extra origins an IdP serves from (a listed origin, or a RegExp over it)", async () => {
      const t = await makeAuth({
        trustedOrigins: [rogue.issuerUrl],
        sso: { allowedIssuers: [ALLOWED, rogue.issuerUrl] },
      });
      const o = await owner(t, "owner@evil.test", "evil");
      expect(
        (await register(t, o.cookie, o.orgId, "listed", ALLOWED, rogueOidcConfig(rogue))).status,
      ).toBe(200);
    });

    it("C2 /sso/update-provider with only `oidcConfig` (issuer untouched) cannot swap the endpoints to a rogue origin; a non-endpoint update still goes through", async () => {
      const t = await makeAuth({
        trustedOrigins: [rogue.issuerUrl],
        sso: { allowedIssuers: [ALLOWED] },
      });
      const o = await owner(t, "owner@evil.test", "evil");
      expect(
        (await register(t, o.cookie, o.orgId, "p", ALLOWED, oidcConfigOn(ALLOWED))).status,
      ).toBe(200);

      await expectUpdateRefused(
        await t.api.post(
          "/sso/update-provider",
          { providerId: "p", oidcConfig: rogueOidcConfig(rogue) },
          { cookie: o.cookie },
        ),
      );
      await expectUpdateRefused(
        await t.api.post(
          "/sso/update-provider",
          { providerId: "p", oidcConfig: { jwksEndpoint: rogue.jwksEndpoint } },
          { cookie: o.cookie },
        ),
      );
      await expectUpdateRefused(
        await t.api.post(
          "/sso/update-provider",
          { providerId: "p", oidcConfig: { discoveryEndpoint: rogue.discoveryEndpoint } },
          { cookie: o.cookie },
        ),
      );
      const stored = await storedOidcConfig(t, "p");
      expect(stored.jwksEndpoint).toBe(`${ALLOWED}/jwks`);
      expect(stored.authorizationEndpoint).toBe(`${ALLOWED}/authorize`);
      expect(stored.discoveryEndpoint ?? `${ALLOWED}/.well-known/openid-configuration`).toContain(
        ALLOWED,
      );

      const ok = await t.api.post(
        "/sso/update-provider",
        { providerId: "p", oidcConfig: { clientId: "rotated" } },
        { cookie: o.cookie },
      );
      expect(ok.status).toBe(200);
      expect((await storedOidcConfig(t, "p")).clientId).toBe("rotated");
    });

    it("C3 SAML: issuer/entityID string allowed, a tenant-supplied cert and an entryPoint (or entityID) on a rogue origin → 403; the allowed IdP's own entryPoint registers and signs in", async () => {
      // Round 3: a SAML provider under an array allow-list also needs its
      // signing certificate pinned (`test/security/f28-saml-trust-root.test.ts`).
      const t = await makeAuth({
        sso: {
          allowedIssuers: [TEST_IDP_ENTITY_ID],
          samlCertificateFingerprints: {
            [TEST_IDP_ENTITY_ID]: [new X509Certificate(IDP_CERT).fingerprint256],
          },
        },
      });
      const o = await owner(t, "owner@evil.test", "evil");
      const base = "http://localhost:3000/api/auth";
      const saml = (providerId: string, overrides: Record<string, unknown>) => ({
        providerId,
        issuer: TEST_IDP_ENTITY_ID,
        domain: `${providerId}.test`,
        organizationId: o.orgId,
        samlConfig: {
          entryPoint: `${TEST_IDP_ENTITY_ID}/sso`,
          cert: IDP_CERT,
          idpMetadata: { entityID: TEST_IDP_ENTITY_ID },
          callbackUrl: `${base}/sso/saml2/sp/acs/${providerId}`,
          spMetadata: { entityID: `${base}/sso/saml2/sp/${providerId}` },
          ...overrides,
        },
      });

      await expectRefused(
        t,
        await t.api.post(
          "/sso/register",
          saml("rogue-entry", { entryPoint: "https://rogue.example/sso" }),
          { cookie: o.cookie },
        ),
        "rogue-entry",
      );
      await expectRefused(
        t,
        await t.api.post(
          "/sso/register",
          saml("rogue-entity", { idpMetadata: { entityID: "https://rogue.example/idp" } }),
          { cookie: o.cookie },
        ),
        "rogue-entity",
      );
      await expectRefused(
        t,
        await t.api.post(
          "/sso/register",
          saml("rogue-sso-service", {
            idpMetadata: {
              entityID: TEST_IDP_ENTITY_ID,
              singleSignOnService: [
                {
                  Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                  Location: "https://rogue.example/sso",
                },
              ],
            },
          }),
          { cookie: o.cookie },
        ),
        "rogue-sso-service",
      );
      for (const providerId of ["rogue-entry", "rogue-entity", "rogue-sso-service"]) {
        const acs = await t.api.postForm(`/sso/saml2/sp/acs/${providerId}`, {
          SAMLResponse: await mintSamlResponse({
            spEntityID: `${base}/sso/saml2/sp/${providerId}`,
            acsUrl: `${base}/sso/saml2/sp/acs/${providerId}`,
            email: "mallory@evil.test",
          }),
          RelayState: "",
        });
        expect(extractCookie(acs)).not.toContain("session_token");
      }

      // Control: the allowed IdP's own entryPoint registers and its
      // assertions sign in.
      const ok = await t.api.post("/sso/register", saml("legit", {}), { cookie: o.cookie });
      expect(ok.status).toBe(200);
      await verifyProviderDomain(t, "legit");
      const acs = await t.api.postForm(`/sso/saml2/sp/acs/legit`, {
        SAMLResponse: await mintSamlResponse({
          spEntityID: `${base}/sso/saml2/sp/legit`,
          acsUrl: `${base}/sso/saml2/sp/acs/legit`,
          email: "mallory@legit.test",
        }),
        RelayState: "",
      });
      expect(extractCookie(acs)).toContain("session_token");

      // And the same swap through update-provider (samlConfig alone).
      await expectUpdateRefused(
        await t.api.post(
          "/sso/update-provider",
          { providerId: "legit", samlConfig: { entryPoint: "https://rogue.example/sso" } },
          { cookie: o.cookie },
        ),
      );
      const row = await t.client.execute({
        sql: `SELECT samlConfig FROM "ssoProvider" WHERE providerId = 'legit'`,
      });
      expect(
        (JSON.parse(String(row.rows[0]!.samlConfig)) as { entryPoint: string }).entryPoint,
      ).toBe(`${TEST_IDP_ENTITY_ID}/sso`);
    });
  });

  it("collectIdpEndpoints: the IdP-defining values of an OIDC and a SAML configuration, metadata XML included; a metadata document without an entityID fails closed", () => {
    expect(collectIdpEndpoints(undefined, undefined)).toEqual([]);
    expect(collectIdpEndpoints({ clientId: "c", jwksEndpoint: 42 }, null)).toEqual([]);
    expect(collectIdpEndpoints(oidcConfigOn("https://a.test"), undefined)).toEqual([
      "https://a.test/authorize",
      "https://a.test/token",
      "https://a.test/jwks",
    ]);
    expect(
      collectIdpEndpoints(
        { discoveryEndpoint: "https://d.test/.well-known", userInfoEndpoint: "https://u.test/me" },
        undefined,
      ),
    ).toEqual(["https://d.test/.well-known", "https://u.test/me"]);
    expect(
      collectIdpEndpoints(undefined, {
        entryPoint: "https://idp.test/sso",
        idpMetadata: {
          entityID: "urn:idp:test",
          singleSignOnService: [{ Location: "https://idp.test/sso2" }],
          singleLogoutService: [{ Location: "https://idp.test/slo" }, "junk"],
        },
      }),
    ).toEqual([
      "https://idp.test/sso",
      "urn:idp:test",
      "https://idp.test/sso2",
      "https://idp.test/slo",
    ]);
    const xml = `<?xml version="1.0"?><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" ID="_x" entityID='https://meta.test/idp'><md:IDPSSODescriptor><md:SingleLogoutService Binding="b" Location="https://meta.test/slo"/><md:SingleSignOnService Binding="b"
      Location="https://meta.test/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>`;
    expect(collectIdpEndpoints(undefined, { idpMetadata: { metadata: xml } })).toEqual([
      "https://meta.test/idp",
      "https://meta.test/slo",
      "https://meta.test/sso",
    ]);
    expect(
      collectIdpEndpoints(undefined, { idpMetadata: { metadata: "<EntityDescriptor ID='x'/>" } }),
    ).toBeNull();
  });

  it("issuerAllowed: the three forms, unit-level — endpoints must be the issuer, on its origin, or listed (by value or origin)", async () => {
    const ctx = (endpoints: string[] | null, organizationId: string | null = null) => ({
      organizationId,
      endpoints,
    });
    const list = (allowedIssuers: Array<string | RegExp>) => ({ sso: { allowedIssuers } }) as never;
    expect(await issuerAllowed(undefined, "https://x", ctx(["https://anything/"]))).toBe(true);
    expect(await issuerAllowed(list([]), "https://x", ctx([]))).toBe(false);
    expect(await issuerAllowed(list(["https://x"]), "https://x", ctx([]))).toBe(true);
    expect(await issuerAllowed(list([/^https:\/\/x$/]), "https://x", ctx([], "o"))).toBe(true);
    // endpoints: the issuer itself / its origin / a listed value / a listed origin / a RegExp over the origin
    expect(await issuerAllowed(list(["https://x"]), "https://x", ctx(["https://x"]))).toBe(true);
    expect(await issuerAllowed(list(["https://x"]), "https://x", ctx(["https://x/a/b"]))).toBe(
      true,
    );
    expect(
      await issuerAllowed(
        list(["https://x/tenant/v2.0"]),
        "https://x/tenant/v2.0",
        ctx(["https://x/tenant/oauth2/authorize"]),
      ),
    ).toBe(true);
    expect(
      await issuerAllowed(
        list(["https://x", "https://y/jwks"]),
        "https://x",
        ctx(["https://y/jwks"]),
      ),
    ).toBe(true);
    expect(
      await issuerAllowed(list(["https://x", "https://y"]), "https://x", ctx(["https://y/jwks"])),
    ).toBe(true);
    expect(
      await issuerAllowed(
        list([/^https:\/\/[a-z]+\.okta\.test$/]),
        "https://acme.okta.test",
        ctx(["https://acme.okta.test/oauth2/v1/keys", "https://ok.okta.test/keys"]),
      ),
    ).toBe(true);
    // refused: one endpoint off-list; a URN entityID that is neither the issuer nor listed; unreadable endpoints
    expect(
      await issuerAllowed(list(["https://x"]), "https://x", ctx(["https://x/a", "https://y/jwks"])),
    ).toBe(false);
    expect(await issuerAllowed(list(["https://x"]), "https://x", ctx(["urn:other"]))).toBe(false);
    expect(await issuerAllowed(list(["urn:idp"]), "urn:idp", ctx(["urn:idp"]))).toBe(true);
    expect(await issuerAllowed(list(["https://x"]), "https://x", ctx(null))).toBe(false);
    // predicate: sees the endpoints, decides alone; a non-boolean verdict or unreadable endpoints refuse
    const seen: unknown[] = [];
    const predicate = (verdict: unknown) =>
      ({
        sso: {
          allowedIssuers: (issuer: string, c: unknown) => {
            seen.push([issuer, c]);
            return verdict;
          },
        },
      }) as never;
    expect(await issuerAllowed(predicate(true), "https://x", ctx(["https://y"], "o"))).toBe(true);
    expect(seen).toEqual([
      ["https://x", { organizationId: "o", endpoints: ["https://y"], samlCertFingerprints: [] }],
    ]);
    expect(await issuerAllowed(predicate("yes"), "https://x", ctx([], "o"))).toBe(false);
    expect(await issuerAllowed(predicate(true), "https://x", ctx(null, "o"))).toBe(false);
  });

  it("normalizeFingerprint / collectSamlTrustRoot: every certificate source upstream honours, every spelling, fail closed on anything unreadable", () => {
    const idp = new X509Certificate(IDP_CERT).fingerprint256; // AB:CD:…
    const idpLower = idp.replace(/:/g, "").toLowerCase();
    const spLower = new X509Certificate(SP_CERT).fingerprint256.replace(/:/g, "").toLowerCase();
    expect(normalizeFingerprint(idp)).toBe(idpLower);
    expect(normalizeFingerprint(idpLower.toUpperCase())).toBe(idpLower);
    expect(normalizeFingerprint(" ab:cd ")).toBeNull();
    expect(normalizeFingerprint("z".repeat(64))).toBeNull();
    expect(normalizeFingerprint(idpLower.slice(0, 40))).toBeNull(); // SHA-1 length

    // Not SAML → no trust root to pin.
    expect(collectSamlTrustRoot(undefined, "https://x")).toBeNull();
    expect(collectSamlTrustRoot("junk", "https://x")).toBeNull();

    const bare = IDP_CERT.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
    const x509 = (cert: string, use?: string) =>
      `<md:KeyDescriptor${use ? ` use='${use}'` : ""}><ds:KeyInfo><ds:X509Data><ds:X509Certificate>${cert
        .replace(/-----[^-]+-----/g, "")
        .replace(/\s+/g, "")}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`;
    const doc = (entityId: string, keys: string) =>
      `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="${entityId}"><md:IDPSSODescriptor>${keys}</md:IDPSSODescriptor></md:EntityDescriptor>`;

    // inline `cert` (PEM or the bare base64 upstream accepts), a rotation list, `idpMetadata.cert` — de-duplicated
    expect(
      collectSamlTrustRoot({ cert: IDP_CERT, idpMetadata: { entityID: "urn:idp" } }, "https://sp"),
    ).toEqual({ entityIds: ["urn:idp"], certFingerprints: [idpLower] });
    expect(
      collectSamlTrustRoot({ cert: bare, idpMetadata: { entityID: "urn:idp" } }, "https://sp"),
    ).toEqual({ entityIds: ["urn:idp"], certFingerprints: [idpLower] });
    // No entity id and no metadata document: upstream's `createIdP` throws
    // for this configuration at the ACS (round 4 derives the trust root
    // through the same call), so there is no trust root to pin — the
    // `issuer` still names the pins slot, the fingerprints fail closed.
    expect(collectSamlTrustRoot({ cert: bare }, "https://sp")).toEqual({
      entityIds: ["https://sp"],
      certFingerprints: null,
    });
    expect(
      collectSamlTrustRoot(
        { cert: [IDP_CERT, SP_CERT], idpMetadata: { entityID: "urn:idp", cert: IDP_CERT } },
        "https://sp",
      ),
    ).toEqual({ entityIds: ["urn:idp"], certFingerprints: [idpLower, spLower] });
    // metadata document: signing / no-`use` KeyDescriptors count, `encryption` does not; its entityID joins the inline one
    expect(
      collectSamlTrustRoot(
        {
          idpMetadata: {
            entityID: "urn:idp",
            metadata: doc(
              "https://meta.test/idp",
              x509(IDP_CERT, "signing") + x509(SP_CERT) + x509(SP_CERT, "encryption"),
            ),
          },
        },
        "https://sp",
      ),
    ).toEqual({
      entityIds: ["urn:idp", "https://meta.test/idp"],
      certFingerprints: [idpLower, spLower],
    });
    expect(
      collectSamlTrustRoot(
        {
          idpMetadata: {
            metadata: doc("urn:m", x509(IDP_CERT, "signing") + x509(SP_CERT, "encryption")),
          },
        },
        "https://sp",
      ),
    ).toEqual({ entityIds: ["urn:m"], certFingerprints: [idpLower] });
    // fail closed: no certificate anywhere, an unparsable one, a non-string, a document without an entityID
    expect(collectSamlTrustRoot({ idpMetadata: { entityID: "urn:idp" } }, "https://sp")).toEqual({
      entityIds: ["urn:idp"],
      certFingerprints: null,
    });
    expect(
      collectSamlTrustRoot({ cert: "not a certificate", idpMetadata: { entityID: "urn:idp" } }, "x")
        ?.certFingerprints,
    ).toBeNull();
    expect(
      collectSamlTrustRoot({ cert: [IDP_CERT, 42], idpMetadata: { entityID: "urn:idp" } }, "x")
        ?.certFingerprints,
    ).toBeNull();
    expect(
      collectSamlTrustRoot(
        {
          idpMetadata: {
            metadata: `<md:EntityDescriptor>${x509(IDP_CERT, "signing")}</md:EntityDescriptor>`,
          },
        },
        "x",
      )?.certFingerprints,
    ).toBeNull();
    expect(
      collectSamlTrustRoot({ idpMetadata: { metadata: doc("urn:m", "") } }, "x")?.certFingerprints,
    ).toBeNull();
  });

  it("issuerAllowed: SAML pins, unit-level — every entity id needs pins, every certificate must be pinned, unreadable trust roots fail before any predicate", async () => {
    const idp = new X509Certificate(IDP_CERT).fingerprint256;
    const idpLower = idp.replace(/:/g, "").toLowerCase();
    const spLower = new X509Certificate(SP_CERT).fingerprint256.replace(/:/g, "").toLowerCase();
    const opts = (samlCertificateFingerprints?: Record<string, string[]>) =>
      ({ sso: { allowedIssuers: ["urn:idp", "urn:other"], samlCertificateFingerprints } }) as never;
    const saml = (entityIds: string[], certFingerprints: string[] | null) => ({
      organizationId: null,
      endpoints: [],
      saml: { entityIds, certFingerprints },
    });

    expect(
      await issuerAllowed(opts({ "urn:idp": [idp] }), "urn:idp", saml(["urn:idp"], [idpLower])),
    ).toBe(true);
    expect(
      await issuerAllowed(
        opts({ "urn:idp": [idpLower.toUpperCase()] }),
        "urn:idp",
        saml(["urn:idp"], [idpLower]),
      ),
    ).toBe(true);
    // rotation: both listed; one missing → refused
    expect(
      await issuerAllowed(
        opts({ "urn:idp": [idp, spLower] }),
        "urn:idp",
        saml(["urn:idp"], [idpLower, spLower]),
      ),
    ).toBe(true);
    expect(
      await issuerAllowed(
        opts({ "urn:idp": [idp] }),
        "urn:idp",
        saml(["urn:idp"], [idpLower, spLower]),
      ),
    ).toBe(false);
    // no pins at all / none for this entity id / one of two entity ids unpinned / an empty pin list
    expect(await issuerAllowed(opts(), "urn:idp", saml(["urn:idp"], [idpLower]))).toBe(false);
    expect(
      await issuerAllowed(opts({ "urn:other": [idp] }), "urn:idp", saml(["urn:idp"], [idpLower])),
    ).toBe(false);
    expect(
      await issuerAllowed(
        opts({ "urn:idp": [idp] }),
        "urn:idp",
        saml(["urn:idp", "urn:other"], [idpLower]),
      ),
    ).toBe(false);
    expect(
      await issuerAllowed(opts({ "urn:idp": [] }), "urn:idp", saml(["urn:idp"], [idpLower])),
    ).toBe(false);
    // prototype members are not pins
    expect(
      await issuerAllowed(opts({ "urn:idp": [idp] }), "urn:idp", saml(["constructor"], [idpLower])),
    ).toBe(false);
    // unreadable trust root fails every form, before a predicate is consulted
    expect(
      await issuerAllowed(opts({ "urn:idp": [idp] }), "urn:idp", saml(["urn:idp"], null)),
    ).toBe(false);
    const predicate = vi.fn(async () => true);
    expect(
      await issuerAllowed(
        { sso: { allowedIssuers: predicate } } as never,
        "urn:idp",
        saml(["urn:idp"], null),
      ),
    ).toBe(false);
    expect(predicate).not.toHaveBeenCalled();
    expect(
      await issuerAllowed(
        { sso: { allowedIssuers: predicate } } as never,
        "urn:idp",
        saml(["urn:idp"], [spLower]),
      ),
    ).toBe(true);
    expect(predicate).toHaveBeenLastCalledWith("urn:idp", {
      organizationId: null,
      endpoints: [],
      samlCertFingerprints: [spLower],
    });
    // OIDC (no trust root) under pins-less options: unchanged
    expect(
      await issuerAllowed(opts(), "urn:idp", { organizationId: null, endpoints: ["urn:idp"] }),
    ).toBe(true);
  });
});
