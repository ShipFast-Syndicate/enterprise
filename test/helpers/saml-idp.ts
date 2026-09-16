// Test helper: a fake SAML IdP that mints signed SAMLResponses for the
// enterprise-layer SAML end-to-end tests (`test/e2e/saml.test.ts`).
//
// Ports `spike-a-saml/level1`+`level2`'s samlify IdP round trip (see
// `spike-a-saml/REPORT.md`) rather than rewriting it: `idp.createLoginResponse
// (sp, null, "post", userInfo, customTagReplacement)` with a hand-written
// custom-tag-replacement callback that fills in NameID/attributes/Audience/
// Recipient/Destination — the same shape `spike-a-saml/level2/gen-response.mjs`
// used to mint responses against a real `@better-auth/sso` worker's ACS. The
// `null` second argument (no AuthnRequest) is what makes every minted
// response IdP-initiated (no `InResponseTo`); `@better-auth/sso@1.6.33`
// accepts that by default (`options?.saml?.allowIdpInitiated !== false`,
// verified directly against `node_modules/@better-auth/sso/dist/index.mjs`),
// so this helper never needs to drive a prior `/sign-in/sso` AuthnRequest.
//
// The IdP's signing identity (`IDP_KEY`/`IDP_CERT`, `test/helpers/fixtures/
// saml-keys.ts`) is the same static, test-only key pair the spike generated
// — see that file's header for why a static fixture is used instead of
// generating a cert at test start.

import { randomUUID } from "node:crypto";
// A plain default import matches how `spike-a-saml/level2/gen-response.mjs`
// — the exact code this ports — imports samlify under plain Node (not
// workerd, where the spike needed a namespace-vs-default interop guard).
import samlify from "samlify";
import { IDP_CERT, IDP_KEY } from "./fixtures/saml-keys";

// Matches `@better-auth/sso`'s own schema validator wiring (`fast-xml-parser`
// based, no libxml) — a permissive stub is enough here since this helper
// only ever produces well-formed XML from samlify's own templates.
samlify.setSchemaValidator({ validate: async () => "SUCCESS_VALIDATE_XML" });

/** Entity ID of the fake test IdP. Register SAML providers with `issuer: TEST_IDP_ENTITY_ID` so the ACS's IdP-entity fallback (`idpMetadata?.entityID || config.issuer`) resolves to this. */
export const TEST_IDP_ENTITY_ID = "https://test-idp.alphabros.test/idp";

function buildIdp(signingKey: string) {
  return samlify.IdentityProvider({
    entityID: TEST_IDP_ENTITY_ID,
    singleSignOnService: [
      {
        Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
        Location: `${TEST_IDP_ENTITY_ID}/sso`,
      },
    ],
    signingCert: IDP_CERT,
    privateKey: signingKey,
  });
}

function buildSp(entityID: string, acsUrl: string) {
  return samlify.ServiceProvider({
    entityID,
    assertionConsumerService: [
      { Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", Location: acsUrl },
    ],
    wantMessageSigned: true,
  });
}

export interface MintSamlResponseOptions {
  /** The registered provider's `spMetadata.entityID` — must match exactly what the SP (better-auth) expects as its own audience. */
  spEntityID: string;
  /** The registered provider's ACS URL (`samlConfig.callbackUrl`). */
  acsUrl: string;
  email: string;
  /** Signs with this PEM key instead of `IDP_KEY` — pass `SP_KEY` to produce a "wrong signing key" response for the negative test. */
  signWithKey?: string;
}

/** Mints a base64-encoded, IdP-initiated, signed SAMLResponse asserting `email`. */
export async function mintSamlResponse(opts: MintSamlResponseOptions): Promise<string> {
  const sp = buildSp(opts.spEntityID, opts.acsUrl);
  const idp = buildIdp(opts.signWithKey ?? IDP_KEY);

  // samlify's own `RequestInfo` (`node_modules/samlify/types/src/types.d.ts`)
  // isn't declared nullable/optional even though the IdP-initiated flow
  // (no prior AuthnRequest to correlate) accepts a falsy value at runtime —
  // the same `null` `spike-a-saml/level2/gen-response.mjs` passes here,
  // confirmed working end to end in the spike. Cast rather than widen the
  // (unexported) upstream type.
  const { context } = await idp.createLoginResponse(
    sp,
    null as unknown as Parameters<typeof idp.createLoginResponse>[1],
    "post",
    { email: opts.email },
    (template: string) => {
      const now = new Date();
      const later = new Date(now.getTime() + 5 * 60_000);
      const id = `_${randomUUID()}`;
      const attributeStatement = `<saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>${opts.email}</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>`;
      return {
        id,
        context: samlify.SamlLib.replaceTagsByValue(template, {
          ID: id,
          AssertionID: `_${randomUUID()}`,
          Destination: opts.acsUrl,
          Audience: opts.spEntityID,
          EntityID: opts.spEntityID,
          SubjectRecipient: opts.acsUrl,
          Issuer: TEST_IDP_ENTITY_ID,
          IssueInstant: now.toISOString(),
          AssertionConsumerServiceURL: opts.acsUrl,
          StatusCode: "urn:oasis:names:tc:SAML:2.0:status:Success",
          ConditionsNotBefore: now.toISOString(),
          ConditionsNotOnOrAfter: later.toISOString(),
          SubjectConfirmationDataNotOnOrAfter: later.toISOString(),
          NameIDFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
          NameID: opts.email,
          InResponseTo: "",
          AuthnStatement: `<saml:AuthnStatement AuthnInstant="${now.toISOString()}" SessionIndex="${id}"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>`,
          AttributeStatement: attributeStatement,
        }),
      };
    },
  );
  return context as string;
}

/** Flips one string (typically the asserted email) inside an already-signed base64 SAMLResponse, breaking its signature — for the "tampered response is rejected" test case. */
export function tamperSamlResponse(base64Response: string, from: string, to: string): string {
  const xml = Buffer.from(base64Response, "base64").toString("utf8").split(from).join(to);
  return Buffer.from(xml, "utf8").toString("base64");
}
