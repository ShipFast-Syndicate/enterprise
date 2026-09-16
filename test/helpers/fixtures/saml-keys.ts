// TEST-ONLY throwaway SAML key/cert material — never use these outside this
// test suite, never deploy them anywhere.
//
// Previously this file committed a static, pre-generated RSA key pair to
// the repo (see git history at commit `c8ec57eb` for the earlier version).
// A checked-in private key — even a test-only, 30-day, self-signed one used
// by nothing but an in-process fake IdP — trips gitleaks/GitHub secret
// scanning on every scan of this history forever, so the security audit
// (`.superpowers/sdd/2026-09-15-enterprise-v0.1/security-audit-part1-repo-
// supply-chain.md`, R8/X1) called for generating the pair at test start
// instead. `node:crypto` has no API for *generating* a self-signed X.509
// certificate (only `X509Certificate` for *parsing* one), so this uses
// `@peculiar/x509`'s `X509CertificateGenerator` against Node's global
// WebCrypto (`node:crypto`'s `webcrypto`, available unconditionally on
// Node >=22 — no `@peculiar/webcrypto` polyfill needed).
//
// Top-level `await` (this package targets `module: "ESNext"`, and vitest's
// esbuild-based transform supports it) generates both pairs once when this
// module is first imported — "at test start" in practice, since nothing
// imports it before a test file does — rather than fixing a signature at
// build time the way the old static fixture did. Each test run therefore
// gets a fresh pair; nothing is ever written to disk.
//
// IDP_KEY/IDP_CERT identify the fake test IdP `test/helpers/saml-idp.ts`
// signs SAMLResponses with. SP_KEY is reused by the "wrong signing key" test
// case (a response signed with the *SP's* key instead of the IdP's, which
// must fail signature verification) — it is never used as this package's own
// SP identity. Consumers (`test/helpers/saml-idp.ts`, `test/helpers/sso.ts`,
// `test/e2e/saml.test.ts`) import these four names exactly as before — only
// this module's implementation changed.

import { webcrypto } from "node:crypto";
// tsyringe (a transitive dependency of @peculiar/x509, used for its internal
// DI container) throws at import time without this polyfill registered
// first — see @peculiar/x509's own docs.
import "reflect-metadata";
import { X509CertificateGenerator, cryptoProvider } from "@peculiar/x509";

cryptoProvider.set(webcrypto as unknown as Crypto);

const RSA_ALGORITHM = {
  name: "RSASSA-PKCS1-v1_5",
  modulusLength: 2048,
  publicExponent: new Uint8Array([1, 0, 1]),
  hash: "SHA-256",
} as const;

const VALIDITY_DAYS = 30;

function toPem(der: ArrayBuffer, label: string): string {
  const base64 = Buffer.from(der).toString("base64");
  const lines = base64.match(/.{1,64}/g) ?? [base64];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}

interface GeneratedPair {
  key: string;
  cert: string;
}

/** Mints a fresh RSA-2048 key pair + self-signed X.509 cert (CN=`commonName`), PEM-encoded. */
async function generateSelfSigned(commonName: string): Promise<GeneratedPair> {
  const keys = await webcrypto.subtle.generateKey(RSA_ALGORITHM, true, ["sign", "verify"]);
  const cert = await X509CertificateGenerator.createSelfSigned({
    serialNumber: "01",
    name: `CN=${commonName}`,
    notBefore: new Date(),
    notAfter: new Date(Date.now() + VALIDITY_DAYS * 24 * 60 * 60 * 1000),
    signingAlgorithm: { name: RSA_ALGORITHM.name, hash: RSA_ALGORITHM.hash },
    keys,
  });
  const pkcs8 = await webcrypto.subtle.exportKey("pkcs8", keys.privateKey);
  return { key: toPem(pkcs8, "PRIVATE KEY"), cert: cert.toString("pem") };
}

const [idp, sp] = await Promise.all([
  generateSelfSigned("spike-idp"),
  generateSelfSigned("spike-sp"),
]);

export const IDP_KEY: string = idp.key;
export const IDP_CERT: string = idp.cert;
export const SP_KEY: string = sp.key;
export const SP_CERT: string = sp.cert;
