// GHSA-8p84-pc7q-69jr — F-28, round 4: the pinned SAML trust root is
// computed **through samlify**, not re-derived with a parser of our own.
//
// Round 3 read the certificates out of `idpMetadata.metadata` with a
// `use`-attribute regex and skipped every `use="encryption"` descriptor.
// samlify does not read the document that way: a document with a single
// `KeyDescriptor` is one *shared* certificate for both uses whatever its
// `use` says (`metadata.js`, the `sharedCertificate` collapse), so a lone
// `use="encryption"` descriptor is exactly what `@better-auth/sso` verifies
// assertions against at the ACS — and round 3 never required it to be
// pinned. The fix stops re-implementing samlify: `samlifySigningCertificates`
// builds the IdP with the inputs upstream's `createIdP` uses and asks
// `entityMeta.getX509Certificate("signing")`; `collectSamlTrustRoot` pins the
// union of that and every literal signing-position source. These cases pin
// samlify's own behaviour so an upgrade that changes it is noticed here,
// and prove the pinned set equals samlify's signing set for every shape.
import { describe, expect, it } from "vitest";
import { X509Certificate } from "node:crypto";
import samlify from "samlify";
import { collectSamlTrustRoot, samlifySigningCertificates } from "../../src/server/sso-domain";
import { IDP_CERT, SP_CERT } from "../helpers/fixtures/saml-keys";

const body = (cert: string) => cert.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
/** Normalised SHA-256 fingerprint of a certificate given as PEM or — as samlify hands them back — a bare base64 body. */
const fp = (cert: string): string => {
  const pem = cert.includes("-----BEGIN")
    ? cert
    : `-----BEGIN CERTIFICATE-----\n${body(cert)}\n-----END CERTIFICATE-----`;
  return new X509Certificate(pem).fingerprint256.replace(/:/g, "").toLowerCase();
};
const sorted = (list: readonly string[] | null | undefined): string[] | null =>
  list ? [...list].sort() : null;

const ENTITY = "https://meta.test/idp";

/** One `KeyDescriptor` per entry; `use` omitted = no attribute. */
function metadataXml(keys: Array<{ cert: string; use?: string }>, entityID = ENTITY): string {
  const descriptors = keys
    .map(
      ({ cert, use }) =>
        `<md:KeyDescriptor${use ? ` use="${use}"` : ""}><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>${body(cert)}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`,
    )
    .join("");
  return `<?xml version="1.0"?><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="${entityID}"><md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">${descriptors}<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="${entityID}/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>`;
}

/** What samlify itself holds as the signing certificate(s) for a metadata document — the direct call, no layer of ours in between. */
function samlifySigning(metadata: string): string[] | null {
  const value: unknown = samlify
    .IdentityProvider({ metadata })
    .entityMeta.getX509Certificate("signing");
  if (value === null || value === undefined) return null;
  const flat = (v: unknown): string[] =>
    Array.isArray(v) ? v.flatMap(flat) : typeof v === "string" ? [v] : [];
  return flat(value);
}

describe("F-28 (round 4) — samlify decides what the SAML signing trust root is", () => {
  it('pins samlify\'s single-KeyDescriptor collapse: a lone use="encryption" descriptor IS the signing certificate (as is a lone `Encryption`, `signing` or use-less one)', () => {
    for (const use of ["encryption", "Encryption", "signing", undefined]) {
      const signing = samlifySigning(metadataXml([{ cert: SP_CERT, use }]));
      expect(signing, `use=${String(use)}`).toEqual([body(SP_CERT)]);
    }
  });

  it("pins samlify's multi-descriptor pairing: `use` values are zipped with the certificates positionally, skipping descriptors without `use` — a use-less descriptor ahead of the signing one is what samlify trusts", () => {
    // [no use, signing] → samlify pairs "signing" with the FIRST certificate.
    expect(
      samlifySigning(metadataXml([{ cert: SP_CERT }, { cert: IDP_CERT, use: "signing" }])),
    ).toEqual([body(SP_CERT)]);
    // Two use-less or two encryption descriptors: no signing certificate at all.
    expect(samlifySigning(metadataXml([{ cert: IDP_CERT }, { cert: SP_CERT }]))).toBeNull();
    expect(
      samlifySigning(
        metadataXml([
          { cert: IDP_CERT, use: "encryption" },
          { cert: SP_CERT, use: "encryption" },
        ]),
      ),
    ).toBeNull();
  });

  it("the pinned set equals samlify's signing set: single signing descriptor, signing+encryption pair, lone encryption descriptor, use-less descriptor, several signing certificates (rotation)", () => {
    const shapes: Array<{ name: string; keys: Array<{ cert: string; use?: string }> }> = [
      { name: "single signing", keys: [{ cert: IDP_CERT, use: "signing" }] },
      {
        name: "signing + encryption pair",
        keys: [
          { cert: IDP_CERT, use: "signing" },
          { cert: SP_CERT, use: "encryption" },
        ],
      },
      { name: "lone encryption", keys: [{ cert: SP_CERT, use: "encryption" }] },
      { name: "no use", keys: [{ cert: IDP_CERT }] },
      {
        name: "rotation (two signing)",
        keys: [
          { cert: IDP_CERT, use: "signing" },
          { cert: SP_CERT, use: "signing" },
        ],
      },
    ];
    for (const { name, keys } of shapes) {
      const metadata = metadataXml(keys);
      const direct = samlifySigning(metadata);
      expect(direct, name).not.toBeNull();
      const expected = sorted(direct!.map((cert) => fp(cert)));
      const config = { idpMetadata: { metadata } };
      expect(sorted(samlifySigningCertificates(config)?.certificates.map(fp)), name).toEqual(
        expected,
      );
      expect(sorted(collectSamlTrustRoot(config, "https://sp")?.certFingerprints), name).toEqual(
        expected,
      );
      expect(collectSamlTrustRoot(config, "https://sp")?.entityIds, name).toEqual([ENTITY]);
    }
  });

  it("union: a certificate samlify pairs differently from its `use` is pinned from both readings; a document samlify reads no signing certificate from fails closed", () => {
    // samlify trusts SP (positional pairing); the literal reading sees both
    // as signing-position certificates → both must be pinned.
    expect(
      sorted(
        collectSamlTrustRoot(
          {
            idpMetadata: {
              metadata: metadataXml([{ cert: SP_CERT }, { cert: IDP_CERT, use: "signing" }]),
            },
          },
          "https://sp",
        )?.certFingerprints,
      ),
    ).toEqual(sorted([fp(IDP_CERT), fp(SP_CERT)]));
    // No signing certificate in samlify's reading → no trust root to pin.
    expect(
      collectSamlTrustRoot(
        { idpMetadata: { metadata: metadataXml([{ cert: IDP_CERT }, { cert: SP_CERT }]) } },
        "https://sp",
      )?.certFingerprints,
    ).toBeNull();
    // An inline `cert` alongside a metadata document is ignored by upstream
    // (the metadata path wins) but stays in the pinned set: the round-3
    // verifier's smuggle set `cert` to the pinned public certificate and
    // put its own key in the document — both are pinned now.
    expect(
      sorted(
        collectSamlTrustRoot(
          {
            cert: IDP_CERT,
            idpMetadata: { metadata: metadataXml([{ cert: SP_CERT, use: "encryption" }]) },
          },
          "https://sp",
        )?.certFingerprints,
      ),
    ).toEqual(sorted([fp(IDP_CERT), fp(SP_CERT)]));
  });

  it("manual configuration mirrors upstream's `resolveSigningCerts`: idpMetadata.cert wins over cert, a list is a rotation, PEM or bare base64; no entity id / no document, or a document samlify cannot parse, fails closed", () => {
    const manual = (samlConfig: Record<string, unknown>) =>
      sorted(samlifySigningCertificates(samlConfig)?.certificates.map(fp));
    expect(manual({ cert: IDP_CERT, idpMetadata: { entityID: "urn:idp" } })).toEqual([
      fp(IDP_CERT),
    ]);
    expect(manual({ cert: body(IDP_CERT), idpMetadata: { entityID: "urn:idp" } })).toEqual([
      fp(IDP_CERT),
    ]);
    expect(manual({ cert: [IDP_CERT, SP_CERT], idpMetadata: { entityID: "urn:idp" } })).toEqual(
      sorted([fp(IDP_CERT), fp(SP_CERT)]),
    );
    expect(manual({ cert: IDP_CERT, idpMetadata: { entityID: "urn:idp", cert: SP_CERT } })).toEqual(
      [fp(SP_CERT)],
    );
    expect(
      samlifySigningCertificates({ cert: IDP_CERT, idpMetadata: { entityID: "urn:idp" } })
        ?.entityId,
    ).toBe("urn:idp");
    expect(samlifySigningCertificates({ idpMetadata: { entityID: "urn:idp" } })).toBeNull();
    expect(samlifySigningCertificates({ cert: IDP_CERT })).toBeNull();
    expect(samlifySigningCertificates({ idpMetadata: { metadata: "<notxml" } })).toBeNull();
    expect(samlifySigningCertificates(undefined)).toBeNull();
  });
});
