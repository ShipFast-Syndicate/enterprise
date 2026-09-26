// GHSA-8p84-pc7q-69jr — F-28, round 3: the SAML trust root is the signing
// certificate, so the allow-list pins it.
//
// Round 2 bound `sso.allowedIssuers` to the IdP *endpoints* (OIDC: where
// the keys are fetched from; SAML: `entryPoint`, `entityID`, SSO/SLO
// locations). For SAML that still bound nothing: an assertion is verified
// against the certificate the *tenant* supplied inline (`cert`,
// `idpMetadata.cert`) or inside a metadata document, so a tenant could
// claim an allowed `entityID` + `entryPoint` word for word while supplying
// a keypair of their own — and sign in through it (the round-2 verifier's
// own-keypair attack, ported below as the control). The fix pins the
// certificates: with an array allow-list every certificate a SAML
// configuration carries must be listed under `sso.samlCertificateFingerprints`
// for its entity id (SHA-256 of the DER form), fail closed; the predicate
// form receives the fingerprints and decides alone; and a stored row is
// re-judged at every sign-in (`storedProviderAllowed`), for SAML and OIDC
// alike, so tightening the list after registration is not a no-op.
//
// The mint helper here signs with an arbitrary, *self-consistent* keypair
// (the KeyInfo certificate matches the signing key) — the shared
// `mintSamlResponse` always embeds `IDP_CERT`, which is what masked the gap.
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { randomUUID, X509Certificate } from "node:crypto";
import samlify from "samlify";
import { createOrg, extractCookie, makeAuth, signUpOwner, type TestAuth } from "../helpers/auth";
import { startOidcIssuer, type OidcIssuer } from "../helpers/oidc-issuer";
import { TEST_IDP_ENTITY_ID } from "../helpers/saml-idp";
import { IDP_CERT, IDP_KEY, SP_CERT, SP_KEY } from "../helpers/fixtures/saml-keys";
import { registerOidcProvider, verifyProviderDomain } from "../helpers/sso";
import { driveSsoSignIn, sessionCookieOf, sessionOf, userRowsFor } from "./ghsa-sso-helpers";

const base = "http://localhost:3000/api/auth";

/** `AB:CD:…` — the form `openssl x509 -fingerprint -sha256` prints. */
const fingerprint = (cert: string): string => new X509Certificate(cert).fingerprint256;
/** The normalised form the predicate receives. */
const fingerprintLower = (cert: string): string =>
  fingerprint(cert).replace(/:/g, "").toLowerCase();

const PINS = { [TEST_IDP_ENTITY_ID]: [fingerprint(IDP_CERT)] };
const LIST = { allowedIssuers: [TEST_IDP_ENTITY_ID], samlCertificateFingerprints: PINS };

const acsUrl = (providerId: string) => `${base}/sso/saml2/sp/acs/${providerId}`;
const spEntityID = (providerId: string) => `${base}/sso/saml2/sp/${providerId}`;

/** A signed, IdP-initiated SAMLResponse for `providerId` from an IdP whose signing identity is `signingCert`+`privateKey` (self-consistent: KeyInfo carries the certificate of the key that signed). */
async function mintWith(opts: {
  providerId: string;
  email: string;
  signingCert: string;
  privateKey: string;
  entityID?: string;
}): Promise<string> {
  const entityID = opts.entityID ?? TEST_IDP_ENTITY_ID;
  const idp = samlify.IdentityProvider({
    entityID,
    singleSignOnService: [
      {
        Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
        Location: `${entityID}/sso`,
      },
    ],
    signingCert: opts.signingCert,
    privateKey: opts.privateKey,
  });
  const sp = samlify.ServiceProvider({
    entityID: spEntityID(opts.providerId),
    assertionConsumerService: [
      {
        Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
        Location: acsUrl(opts.providerId),
      },
    ],
    wantMessageSigned: true,
  });
  const { context } = await idp.createLoginResponse(
    sp,
    null as unknown as Parameters<typeof idp.createLoginResponse>[1],
    "post",
    { email: opts.email },
    (template: string) => {
      const now = new Date();
      const later = new Date(now.getTime() + 5 * 60_000);
      const id = `_${randomUUID()}`;
      return {
        id,
        context: samlify.SamlLib.replaceTagsByValue(template, {
          ID: id,
          AssertionID: `_${randomUUID()}`,
          Destination: acsUrl(opts.providerId),
          Audience: spEntityID(opts.providerId),
          EntityID: spEntityID(opts.providerId),
          SubjectRecipient: acsUrl(opts.providerId),
          Issuer: entityID,
          IssueInstant: now.toISOString(),
          AssertionConsumerServiceURL: acsUrl(opts.providerId),
          StatusCode: "urn:oasis:names:tc:SAML:2.0:status:Success",
          ConditionsNotBefore: now.toISOString(),
          ConditionsNotOnOrAfter: later.toISOString(),
          SubjectConfirmationDataNotOnOrAfter: later.toISOString(),
          NameIDFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
          NameID: opts.email,
          InResponseTo: "",
          AuthnStatement: `<saml:AuthnStatement AuthnInstant="${now.toISOString()}" SessionIndex="${id}"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>`,
          AttributeStatement: `<saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>${opts.email}</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>`,
        }),
      };
    },
  );
  return context as string;
}

const IDP_KEYS = { signingCert: IDP_CERT, privateKey: IDP_KEY };
const OWN_KEYS = { signingCert: SP_CERT, privateKey: SP_KEY };

/** An IdP metadata document for `entityID` carrying one `KeyDescriptor` per entry (`use` omitted = both uses, per the spec). */
function metadataXml(
  keys: Array<{ cert: string; use?: "signing" | "encryption" }>,
  entityID = TEST_IDP_ENTITY_ID,
): string {
  const body = (cert: string) => cert.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  const descriptors = keys
    .map(
      ({ cert, use }) =>
        `<md:KeyDescriptor${use ? ` use="${use}"` : ""}><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>${body(cert)}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`,
    )
    .join("");
  return `<?xml version="1.0"?><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="${entityID}"><md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">${descriptors}<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="${entityID}/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>`;
}

async function owner(t: TestAuth, email = "owner@acme.test", slug = "acme") {
  const o = await signUpOwner(t, email);
  const { orgId } = await createOrg(t, o.cookie, slug);
  return { ...o, orgId };
}

/** The verifier's registration body: allowed `issuer`, `entryPoint` and `entityID`, a caller-chosen `samlConfig` overlay. */
function samlBody(providerId: string, orgId: string, overrides: Record<string, unknown> = {}) {
  return {
    providerId,
    issuer: TEST_IDP_ENTITY_ID,
    domain: `${providerId}.test`,
    organizationId: orgId,
    samlConfig: {
      entryPoint: `${TEST_IDP_ENTITY_ID}/sso`,
      cert: IDP_CERT,
      idpMetadata: { entityID: TEST_IDP_ENTITY_ID },
      callbackUrl: acsUrl(providerId),
      spMetadata: { entityID: spEntityID(providerId) },
      ...overrides,
    },
  };
}

async function acs(t: TestAuth, providerId: string, samlResponse: string): Promise<Response> {
  return t.api.postForm(`/sso/saml2/sp/acs/${providerId}`, {
    SAMLResponse: samlResponse,
    RelayState: "",
  });
}

async function rowCount(t: TestAuth, providerId: string): Promise<number> {
  const rows = await t.client.execute({
    sql: `SELECT id FROM "ssoProvider" WHERE providerId = ?`,
    args: [providerId],
  });
  return rows.rows.length;
}

async function storedConfig(
  t: TestAuth,
  providerId: string,
  column: "samlConfig" | "oidcConfig",
): Promise<Record<string, unknown>> {
  const rows = await t.client.execute({
    sql: `SELECT ${column} FROM "ssoProvider" WHERE providerId = ?`,
    args: [providerId],
  });
  return JSON.parse(String(rows.rows[0]![column])) as Record<string, unknown>;
}

/** Rewrites a stored configuration *behind* the guard — a row as a deployment that ran without the allow-list (or the pins) left it. */
async function plantStoredConfig(
  t: TestAuth,
  providerId: string,
  column: "samlConfig" | "oidcConfig",
  mutate: (config: Record<string, unknown>) => void,
): Promise<void> {
  const config = await storedConfig(t, providerId, column);
  mutate(config);
  await t.client.execute({
    sql: `UPDATE "ssoProvider" SET ${column} = ? WHERE providerId = ?`,
    args: [JSON.stringify(config), providerId],
  });
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

function locationOf(res: Response): string {
  expect(res.status).toBe(302);
  return res.headers.get("location") ?? "";
}

async function failedSignIns(t: TestAuth): Promise<Array<{ orgId: string; error: string | null }>> {
  const rows = await t.client.execute({
    sql: `SELECT org_id, metadata FROM audit_event WHERE action = 'auth.sso_sign_in_failed'`,
  });
  return rows.rows.map((r) => ({
    orgId: String(r.org_id),
    error: (JSON.parse(String(r.metadata)) as { error?: string | null }).error ?? null,
  }));
}

describe("F-28 (round 3) — sso.allowedIssuers pins the SAML trust root, fail closed", () => {
  it("control — without an allow-list a tenant's own keypair behind an allowed-looking entityID/entryPoint registers and signs in (the attack is real)", async () => {
    const t = await makeAuth();
    const o = await owner(t, "owner@evil.test", "evil");
    const reg = await t.api.post("/sso/register", samlBody("own-key", o.orgId, { cert: SP_CERT }), {
      cookie: o.cookie,
    });
    expect(reg.status).toBe(200);
    await verifyProviderDomain(t, "own-key");
    const res = await acs(
      t,
      "own-key",
      await mintWith({ providerId: "own-key", email: "mallory@own-key.test", ...OWN_KEYS }),
    );
    const cookie = sessionCookieOf(res);
    expect((await sessionOf(t, cookie)).user.email).toBe("mallory@own-key.test");
  });

  it("ATTACK refused at register: the allowed entityID + entryPoint with the tenant's own certificate — inline, under idpMetadata.cert (which wins upstream), or appended to a pinned list — is 403 SSO_ISSUER_NOT_ALLOWED, nothing is stored, and the ACS has no provider to sign in through", async () => {
    const t = await makeAuth({ sso: LIST });
    const o = await owner(t, "owner@evil.test", "evil");
    const post = (providerId: string, overrides: Record<string, unknown>) =>
      t.api.post("/sso/register", samlBody(providerId, o.orgId, overrides), { cookie: o.cookie });

    await expectRefused(t, await post("rogue-key", { cert: SP_CERT }), "rogue-key");
    await expectRefused(
      t,
      await post("rogue-idp-cert", {
        cert: IDP_CERT,
        idpMetadata: { entityID: TEST_IDP_ENTITY_ID, cert: SP_CERT },
      }),
      "rogue-idp-cert",
    );
    await expectRefused(
      t,
      await post("rogue-appended", { cert: [IDP_CERT, SP_CERT] }),
      "rogue-appended",
    );

    for (const providerId of ["rogue-key", "rogue-idp-cert", "rogue-appended"]) {
      const res = await acs(
        t,
        providerId,
        await mintWith({ providerId, email: `mallory@${providerId}.test`, ...OWN_KEYS }),
      );
      expect(extractCookie(res)).not.toContain("session_token");
    }
    expect(await userRowsFor(t, "mallory@rogue-key.test")).toBe(0);
  });

  it("pinned certificate: the approved IdP registers under either fingerprint spelling and its assertions sign in; a rotation lists both certificates", async () => {
    for (const pins of [
      { [TEST_IDP_ENTITY_ID]: [fingerprint(IDP_CERT)] }, // AB:CD:… (openssl)
      { [TEST_IDP_ENTITY_ID]: [fingerprintLower(IDP_CERT)] }, // abcd…
    ]) {
      const t = await makeAuth({
        sso: { allowedIssuers: [TEST_IDP_ENTITY_ID], samlCertificateFingerprints: pins },
      });
      const o = await owner(t);
      const reg = await t.api.post("/sso/register", samlBody("legit", o.orgId), {
        cookie: o.cookie,
      });
      expect(reg.status).toBe(200);
      await verifyProviderDomain(t, "legit");
      const res = await acs(
        t,
        "legit",
        await mintWith({ providerId: "legit", email: "user@legit.test", ...IDP_KEYS }),
      );
      expect((await sessionOf(t, sessionCookieOf(res))).user.email).toBe("user@legit.test");
    }

    const t = await makeAuth({
      sso: {
        allowedIssuers: [TEST_IDP_ENTITY_ID],
        samlCertificateFingerprints: {
          [TEST_IDP_ENTITY_ID]: [fingerprint(IDP_CERT), fingerprint(SP_CERT)],
        },
      },
    });
    const o = await owner(t);
    const rotation = await t.api.post(
      "/sso/register",
      samlBody("rotating", o.orgId, { cert: [IDP_CERT, SP_CERT] }),
      { cookie: o.cookie },
    );
    expect(rotation.status).toBe(200);
  });

  it("fail closed: an array allow-list with no pins at all, or none for this entityID, refuses every SAML provider — even the approved IdP's own certificate; an OIDC provider on the list is unaffected", async () => {
    // The round-2 verifier's SANITY case (allow-list, approved certificate,
    // no pins) is exactly this: it is now refused until the operator pins.
    const noPins = await makeAuth({ sso: { allowedIssuers: [TEST_IDP_ENTITY_ID] } });
    const a = await owner(noPins);
    await expectRefused(
      noPins,
      await noPins.api.post("/sso/register", samlBody("unpinned", a.orgId), { cookie: a.cookie }),
      "unpinned",
    );

    const otherEntity = await makeAuth({
      sso: {
        allowedIssuers: [TEST_IDP_ENTITY_ID],
        samlCertificateFingerprints: { "https://other-idp.example/idp": [fingerprint(IDP_CERT)] },
      },
    });
    const b = await owner(otherEntity);
    await expectRefused(
      otherEntity,
      await otherEntity.api.post("/sso/register", samlBody("no-pins-here", b.orgId), {
        cookie: b.cookie,
      }),
      "no-pins-here",
    );

    // OIDC: the pins are a SAML concern; the list alone is enough.
    const oidc = await makeAuth({ sso: { allowedIssuers: ["https://idp.example.com"] } });
    const c = await owner(oidc);
    const reg = await oidc.api.post(
      "/sso/register",
      {
        providerId: "oidc",
        issuer: "https://idp.example.com",
        domain: "oidc.test",
        organizationId: c.orgId,
        oidcConfig: {
          clientId: "c",
          clientSecret: "s",
          skipDiscovery: true,
          authorizationEndpoint: "https://idp.example.com/authorize",
          tokenEndpoint: "https://idp.example.com/token",
          jwksEndpoint: "https://idp.example.com/jwks",
        },
      },
      { cookie: c.cookie },
    );
    expect(reg.status).toBe(200);
  });

  it("/sso/update-provider: a certificate swap on a pinned provider is refused and the row is untouched — inline cert, idpMetadata.cert, or a replaced metadata document; a non-certificate update still goes through and the provider keeps signing in", async () => {
    const t = await makeAuth({ sso: LIST });
    const o = await owner(t);
    expect(
      (await t.api.post("/sso/register", samlBody("legit", o.orgId), { cookie: o.cookie })).status,
    ).toBe(200);
    await verifyProviderDomain(t, "legit");
    const update = (samlConfig: Record<string, unknown>) =>
      t.api.post("/sso/update-provider", { providerId: "legit", samlConfig }, { cookie: o.cookie });

    await expectUpdateRefused(await update({ cert: SP_CERT }));
    await expectUpdateRefused(await update({ idpMetadata: { cert: SP_CERT } }));
    await expectUpdateRefused(
      await update({ idpMetadata: { metadata: metadataXml([{ cert: SP_CERT, use: "signing" }]) } }),
    );
    await expectUpdateRefused(await update({ cert: [IDP_CERT, SP_CERT] }));

    const stored = await storedConfig(t, "legit", "samlConfig");
    expect(stored.cert).toBe(IDP_CERT);
    expect((stored.idpMetadata as Record<string, unknown>).cert).toBeUndefined();
    expect((stored.idpMetadata as Record<string, unknown>).metadata).toBeUndefined();

    // Not a trust-root change: a second entry point on the IdP's origin.
    const ok = await update({ entryPoint: `${TEST_IDP_ENTITY_ID}/sso2` });
    expect(ok.status).toBe(200);
    expect((await storedConfig(t, "legit", "samlConfig")).entryPoint).toBe(
      `${TEST_IDP_ENTITY_ID}/sso2`,
    );
    const res = await acs(
      t,
      "legit",
      await mintWith({ providerId: "legit", email: "user@legit.test", ...IDP_KEYS }),
    );
    expect(sessionCookieOf(res)).toContain("session_token");
  });

  it('metadata document: every signing KeyDescriptor is pinned — an extra certificate (use="signing" or no `use`) refuses, an `encryption` KeyDescriptor is not a trust root, and a document carrying only the pinned certificate registers and signs in', async () => {
    const t = await makeAuth({ sso: LIST });
    const o = await owner(t);
    const post = (providerId: string, keys: Parameters<typeof metadataXml>[0]) =>
      t.api.post(
        "/sso/register",
        samlBody(providerId, o.orgId, {
          cert: undefined,
          idpMetadata: { metadata: metadataXml(keys) },
        }),
        { cookie: o.cookie },
      );

    await expectRefused(
      t,
      await post("extra-signing", [
        { cert: IDP_CERT, use: "signing" },
        { cert: SP_CERT, use: "signing" },
      ]),
      "extra-signing",
    );
    await expectRefused(
      t,
      await post("extra-no-use", [{ cert: IDP_CERT, use: "signing" }, { cert: SP_CERT }]),
      "extra-no-use",
    );
    await expectRefused(t, await post("only-own", [{ cert: SP_CERT, use: "signing" }]), "only-own");

    const encryptionOnly = await post("enc-descriptor", [
      { cert: IDP_CERT, use: "signing" },
      { cert: SP_CERT, use: "encryption" },
    ]);
    expect(encryptionOnly.status).toBe(200);

    const pinnedDoc = await post("pinned-doc", [{ cert: IDP_CERT, use: "signing" }]);
    expect(pinnedDoc.status).toBe(200);
    await verifyProviderDomain(t, "pinned-doc");
    const res = await acs(
      t,
      "pinned-doc",
      await mintWith({ providerId: "pinned-doc", email: "user@pinned-doc.test", ...IDP_KEYS }),
    );
    expect((await sessionOf(t, sessionCookieOf(res))).user.email).toBe("user@pinned-doc.test");
  });

  it("predicate form: receives the normalised certificate fingerprints alongside the endpoints and decides alone", async () => {
    const allowedIssuers = vi.fn(
      async (
        _issuer: string,
        ctx: { organizationId: string | null; endpoints: string[]; samlCertFingerprints: string[] },
      ) =>
        ctx.samlCertFingerprints.length > 0 &&
        ctx.samlCertFingerprints.every((f) => f === fingerprintLower(IDP_CERT)),
    );
    const t = await makeAuth({ sso: { allowedIssuers } });
    const o = await owner(t, "owner@evil.test", "evil");

    await expectRefused(
      t,
      await t.api.post("/sso/register", samlBody("own-key", o.orgId, { cert: SP_CERT }), {
        cookie: o.cookie,
      }),
      "own-key",
    );
    expect(allowedIssuers).toHaveBeenLastCalledWith(TEST_IDP_ENTITY_ID, {
      organizationId: o.orgId,
      endpoints: [`${TEST_IDP_ENTITY_ID}/sso`, TEST_IDP_ENTITY_ID],
      samlCertFingerprints: [fingerprintLower(SP_CERT)],
    });
    expect(
      (await t.api.post("/sso/register", samlBody("legit", o.orgId), { cookie: o.cookie })).status,
    ).toBe(200);
    expect(allowedIssuers).toHaveBeenLastCalledWith(TEST_IDP_ENTITY_ID, {
      organizationId: o.orgId,
      endpoints: [`${TEST_IDP_ENTITY_ID}/sso`, TEST_IDP_ENTITY_ID],
      samlCertFingerprints: [fingerprintLower(IDP_CERT)],
    });
  });

  it("sign-in time (SAML): a stored row whose certificate the operator's pins do not cover is refused at the ACS — no session, no user row, audited as auth.sso_sign_in_failed — and honoured again once its certificate is pinned", async () => {
    const t = await makeAuth({ sso: LIST });
    const o = await owner(t);
    expect(
      (await t.api.post("/sso/register", samlBody("legit", o.orgId), { cookie: o.cookie })).status,
    ).toBe(200);
    await verifyProviderDomain(t, "legit");

    // The row as a 1.0.x deployment (no allow-list, no pins) left it: the
    // tenant's own certificate, stored without ever passing the guard.
    await plantStoredConfig(t, "legit", "samlConfig", (config) => {
      config.cert = SP_CERT;
    });
    const refused = await acs(
      t,
      "legit",
      await mintWith({ providerId: "legit", email: "mallory@legit.test", ...OWN_KEYS }),
    );
    expect(locationOf(refused)).toContain("error=SSO_ISSUER_NOT_ALLOWED");
    expect(extractCookie(refused)).not.toContain("session_token");
    expect(await userRowsFor(t, "mallory@legit.test")).toBe(0);
    expect(await failedSignIns(t)).toEqual([{ orgId: o.orgId, error: "SSO_ISSUER_NOT_ALLOWED" }]);

    // Nor does the approved key help while the stored certificate is the
    // unpinned one — the *row* is what the operator no longer trusts.
    const approvedKey = await acs(
      t,
      "legit",
      await mintWith({ providerId: "legit", email: "user@legit.test", ...IDP_KEYS }),
    );
    expect(extractCookie(approvedKey)).not.toContain("session_token");

    await plantStoredConfig(t, "legit", "samlConfig", (config) => {
      config.cert = IDP_CERT;
    });
    const ok = await acs(
      t,
      "legit",
      await mintWith({ providerId: "legit", email: "user@legit.test", ...IDP_KEYS }),
    );
    expect((await sessionOf(t, sessionCookieOf(ok))).user.email).toBe("user@legit.test");
  });

  describe("sign-in time (OIDC): the same re-check of the stored row", () => {
    let legit: OidcIssuer;
    let rogue: OidcIssuer;
    beforeAll(async () => {
      legit = await startOidcIssuer();
      rogue = await startOidcIssuer({ issClaim: legit.issuerUrl });
    });
    afterAll(async () => {
      await legit.close();
      await rogue.close();
    });

    it("a stored OIDC row whose endpoints the allow-list no longer covers is refused at the callback — no session, no user row, audited — and honoured again once they are back on the list", async () => {
      const t = await makeAuth({
        trustedOrigins: [legit.issuerUrl, rogue.issuerUrl],
        sso: { allowedIssuers: [legit.issuerUrl] },
      });
      const o = await owner(t);
      await registerOidcProvider(t, o.cookie, o.orgId, legit, "acme-oidc");

      // A row written before the operator listed the issuer, pointing the
      // key source at an IdP of the tenant's own that claims the allowed `iss`.
      await plantStoredConfig(t, "acme-oidc", "oidcConfig", (config) => {
        config.authorizationEndpoint = rogue.authorizationEndpoint;
        config.tokenEndpoint = rogue.tokenEndpoint;
        config.jwksEndpoint = rogue.jwksEndpoint;
      });
      rogue.setUser({ sub: "r-1", email: "mallory@acme.test" });
      const refused = await driveSsoSignIn(t, rogue, "acme-oidc");
      expect(locationOf(refused)).toContain("error=SSO_ISSUER_NOT_ALLOWED");
      expect(extractCookie(refused)).not.toContain("session_token");
      expect(await userRowsFor(t, "mallory@acme.test")).toBe(0);
      expect(await failedSignIns(t)).toEqual([{ orgId: o.orgId, error: "SSO_ISSUER_NOT_ALLOWED" }]);

      await plantStoredConfig(t, "acme-oidc", "oidcConfig", (config) => {
        config.authorizationEndpoint = legit.authorizationEndpoint;
        config.tokenEndpoint = legit.tokenEndpoint;
        config.jwksEndpoint = legit.jwksEndpoint;
      });
      legit.setUser({ sub: "u-1", email: "user@acme.test" });
      const ok = await driveSsoSignIn(t, legit, "acme-oidc");
      expect((await sessionOf(t, sessionCookieOf(ok))).user.email).toBe("user@acme.test");
    });
  });
});
