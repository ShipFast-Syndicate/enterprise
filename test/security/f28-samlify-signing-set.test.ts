// GHSA-8p84-pc7q-69jr — F-28, round 4: the pinned SAML trust root is
// computed **through samlify**, not re-derived with a parser of our own.
//
// Round 3 read the certificates out of `idpMetadata.metadata` with a
// `use`-attribute regex. samlify <= 2.14 did not read the document that way
// (a lone `use="encryption"` descriptor was the signing certificate, several
// descriptors were paired with `use` values positionally), which is why the
// fix stopped re-implementing samlify: `samlifySigningCertificates` builds
// the IdP with the inputs upstream's `createIdP` uses and asks
// `entityMeta.getX509Certificate("signing")`; `collectSamlTrustRoot` pins the
// union of that and every literal signing-position source.
//
// samlify 2.15 (GHSA-w8r9-gp23-wcxp) changed the rule: `KeyDescriptor use` is
// honoured. `signing` and use-less descriptors are signing certificates, an
// `encryption` descriptor never is, and a document without a signing
// certificate has none. These cases pin samlify's own behaviour so an upgrade
// that changes it is noticed here, and prove the pinned set equals samlify's
// signing set for every shape.
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
  it('pins samlify 2.15\'s `use` handling: a lone use="encryption" descriptor is NOT a signing certificate; a lone `signing` or use-less one is; an unknown `use` value is neither', () => {
    expect(samlifySigning(metadataXml([{ cert: SP_CERT, use: "encryption" }]))).toBeNull();
    expect(samlifySigning(metadataXml([{ cert: SP_CERT, use: "Encryption" }]))).toBeNull();
    for (const use of ["signing", undefined]) {
      const signing = samlifySigning(metadataXml([{ cert: SP_CERT, use }]));
      expect(signing, `use=${String(use)}`).toEqual([body(SP_CERT)]);
    }
  });

  it("pins samlify 2.15's multi-descriptor reading: each descriptor is read by its own `use` (no positional pairing), use-less descriptors serve both uses, encryption-only descriptors are never signing", () => {
    // [no use, signing] → both are signing certificates.
    expect(
      sorted(
        samlifySigning(metadataXml([{ cert: SP_CERT }, { cert: IDP_CERT, use: "signing" }]))?.map(
          fp,
        ),
      ),
    ).toEqual(sorted([fp(SP_CERT), fp(IDP_CERT)]));
    // Two use-less descriptors: both serve signing.
    expect(
      sorted(samlifySigning(metadataXml([{ cert: IDP_CERT }, { cert: SP_CERT }]))?.map(fp)),
    ).toEqual(sorted([fp(IDP_CERT), fp(SP_CERT)]));
    // signing + encryption: only the signing one.
    expect(
      samlifySigning(
        metadataXml([
          { cert: IDP_CERT, use: "signing" },
          { cert: SP_CERT, use: "encryption" },
        ]),
      ),
    ).toEqual([body(IDP_CERT)]);
    // Two encryption descriptors: no signing certificate at all.
    expect(
      samlifySigning(
        metadataXml([
          { cert: IDP_CERT, use: "encryption" },
          { cert: SP_CERT, use: "encryption" },
        ]),
      ),
    ).toBeNull();
  });

  it("the pinned set equals samlify's signing set: single signing descriptor, signing+encryption pair, use-less descriptor, several signing certificates (rotation)", () => {
    const shapes: Array<{ name: string; keys: Array<{ cert: string; use?: string }> }> = [
      { name: "single signing", keys: [{ cert: IDP_CERT, use: "signing" }] },
      {
        name: "signing + encryption pair",
        keys: [
          { cert: IDP_CERT, use: "signing" },
          { cert: SP_CERT, use: "encryption" },
        ],
      },
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

  it("GHSA-w8r9-gp23-wcxp: a document that declares only a bare key (RSAKeyValue, no X.509 certificate) has no signing certificate — samlify no longer falls back to the certificate in the message, and neither does the pinned set", () => {
    const metadata = metadataXml([]).replace(
      "<md:SingleSignOnService",
      `<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:KeyValue><ds:RSAKeyValue><ds:Modulus>AQAB</ds:Modulus><ds:Exponent>AQAB</ds:Exponent></ds:RSAKeyValue></ds:KeyValue></ds:KeyInfo></md:KeyDescriptor><md:SingleSignOnService`,
    );
    expect(samlifySigning(metadata)).toBeNull();
    expect(samlifySigningCertificates({ idpMetadata: { metadata } })).toBeNull();
    expect(
      collectSamlTrustRoot({ idpMetadata: { metadata } }, "https://sp")?.certFingerprints,
    ).toBeNull();
  });

  it("a document samlify reads no signing certificate from fails closed (a lone or only-encryption descriptor, whatever else the configuration carries)", () => {
    for (const keys of [
      [{ cert: SP_CERT, use: "encryption" }],
      [
        { cert: IDP_CERT, use: "encryption" },
        { cert: SP_CERT, use: "encryption" },
      ],
    ]) {
      expect(
        samlifySigningCertificates({ idpMetadata: { metadata: metadataXml(keys) } }),
      ).toBeNull();
      expect(
        collectSamlTrustRoot({ idpMetadata: { metadata: metadataXml(keys) } }, "https://sp")
          ?.certFingerprints,
      ).toBeNull();
    }
    // An inline `cert` alongside a metadata document is ignored by upstream
    // (the metadata path wins) but must not rescue it: the document has no
    // signing certificate, so there is no trust root to pin.
    expect(
      collectSamlTrustRoot(
        {
          cert: IDP_CERT,
          idpMetadata: { metadata: metadataXml([{ cert: SP_CERT, use: "encryption" }]) },
        },
        "https://sp",
      )?.certFingerprints,
    ).toBeNull();
    // A signing descriptor next to the inline cert: both stay in the pinned
    // set (upstream ignores the inline one, the literal reading keeps it).
    expect(
      sorted(
        collectSamlTrustRoot(
          {
            cert: IDP_CERT,
            idpMetadata: { metadata: metadataXml([{ cert: SP_CERT, use: "signing" }]) },
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
