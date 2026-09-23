// Test helper: SSO provider registration shared by the Task 8 SAML/OIDC
// end-to-end test files (`test/e2e/oidc.test.ts`, `test/e2e/saml.test.ts`,
// `test/e2e/jit.test.ts`) — each needs the same upstream `/sso/register`
// call (real DNS domain verification is out of scope for these tests, so
// `domainVerified` is flipped directly via raw SQL the same way
// `test/server/enterprise-api.test.ts`'s `verifyProviderDomain` and
// `test/server/policy.test.ts`'s `insertVerifiedProvider` already do).

import { IDP_CERT } from "./fixtures/saml-keys";
import { TEST_IDP_ENTITY_ID } from "./saml-idp";
import type { TestAuth } from "./auth";
import type { OidcIssuer } from "./oidc-issuer";

export async function verifyProviderDomain(t: TestAuth, providerId: string): Promise<void> {
  await t.client.execute({
    sql: `UPDATE "ssoProvider" SET domainVerified = 1 WHERE providerId = ?`,
    args: [providerId],
  });
}

/** Registers an OIDC provider against a `startOidcIssuer()` fixture (org-scoped, `skipDiscovery: true` with explicit endpoints), then marks its domain verified. */
export async function registerOidcProvider(
  t: TestAuth,
  cookie: string,
  orgId: string,
  issuer: OidcIssuer,
  providerId: string,
  domain = "acme.test",
): Promise<void> {
  const res = await t.api.post(
    "/sso/register",
    {
      providerId,
      issuer: issuer.issuerUrl,
      domain,
      organizationId: orgId,
      oidcConfig: {
        clientId: issuer.clientId,
        clientSecret: issuer.clientSecret,
        skipDiscovery: true,
        authorizationEndpoint: issuer.authorizationEndpoint,
        tokenEndpoint: issuer.tokenEndpoint,
        jwksEndpoint: issuer.jwksEndpoint,
      },
    },
    { cookie },
  );
  if (!res.ok) throw new Error(`register failed: ${res.status} ${await res.text()}`);
  await verifyProviderDomain(t, providerId);
}

export interface SamlProviderUrls {
  acsUrl: string;
  spEntityID: string;
}

/** Registers a SAML provider from the test IdP's entryPoint+cert (`test/helpers/saml-idp.ts`), then marks its domain verified. */
export async function registerSamlProvider(
  t: TestAuth,
  cookie: string,
  orgId: string,
  providerId: string,
  baseUrl = "http://localhost:3000/api/auth",
  domain = "acme.test",
): Promise<SamlProviderUrls> {
  const acsUrl = `${baseUrl}/sso/saml2/sp/acs/${providerId}`;
  const spEntityID = `${baseUrl}/sso/saml2/sp/${providerId}`;

  const res = await t.api.post(
    "/sso/register",
    {
      providerId,
      issuer: TEST_IDP_ENTITY_ID,
      domain,
      organizationId: orgId,
      samlConfig: {
        entryPoint: `${TEST_IDP_ENTITY_ID}/sso`,
        cert: IDP_CERT,
        idpMetadata: { entityID: TEST_IDP_ENTITY_ID },
        callbackUrl: acsUrl,
        spMetadata: { entityID: spEntityID },
      },
    },
    { cookie },
  );
  if (!res.ok) throw new Error(`register failed: ${res.status} ${await res.text()}`);
  await verifyProviderDomain(t, providerId);
  return { acsUrl, spEntityID };
}
