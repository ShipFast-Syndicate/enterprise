// Unit test for the runtime SAML key generation helper (security audit
// R8/X1 — replaces the previously committed static test key fixture). The
// full SAML round trip (mint a response with these keys, verify it against
// a real `@better-auth/sso` ACS) is already covered end to end by
// `test/e2e/saml.test.ts`; this file only checks the generator's own two
// promises: the certs it produces are well-formed X.509, and samlify
// accepts them as an IdP signing identity.
import { X509Certificate } from "node:crypto";
import { describe, expect, it } from "vitest";
import samlify from "samlify";
import { IDP_CERT, IDP_KEY, SP_CERT, SP_KEY } from "./saml-keys";

describe("runtime-generated SAML test keys", () => {
  it("produces certificates node:crypto can parse, with the expected CN and a >=29-day validity window", () => {
    const idpCert = new X509Certificate(IDP_CERT);
    const spCert = new X509Certificate(SP_CERT);

    expect(idpCert.subject).toBe("CN=spike-idp");
    expect(spCert.subject).toBe("CN=spike-sp");

    const now = Date.now();
    expect(new Date(idpCert.validTo).getTime()).toBeGreaterThan(now + 29 * 24 * 60 * 60 * 1000);
    expect(new Date(idpCert.validFrom).getTime()).toBeLessThanOrEqual(now);
  });

  it("produces distinct IdP and SP key/cert pairs", () => {
    expect(IDP_KEY).not.toBe(SP_KEY);
    expect(IDP_CERT).not.toBe(SP_CERT);
  });

  it("mints PEM material samlify accepts as an IdP signing identity", () => {
    samlify.setSchemaValidator({ validate: async () => "SUCCESS_VALIDATE_XML" });
    expect(() =>
      samlify.IdentityProvider({
        entityID: "https://test-idp.alphabros.test/idp",
        singleSignOnService: [
          {
            Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            Location: "https://test-idp.alphabros.test/idp/sso",
          },
        ],
        signingCert: IDP_CERT,
        privateKey: IDP_KEY,
      }),
    ).not.toThrow();
  });
});
