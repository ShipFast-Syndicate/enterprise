// C-04 — `secretsKey` was declared, documented (spec §7.4) and never used.
//
// Audit repro: `grep -rn secretsKey src/` found only the option's own
// declaration, and dumping `ssoProvider.oidcConfig` after a `/sso/register`
// call showed `{"clientId":"cid","clientSecret":"SUPERSECRET",…}` in the
// clear. Anyone with database read — a backup, a replica, a logged query,
// SQL injection elsewhere in the embedding product — had every tenant's IdP
// client secret.
//
// The fix is a transparent adapter wrapper (`src/server/secrets.ts`), so the
// assertions here are deliberately from both sides: ciphertext on disk (raw
// SQL), plaintext through the adapter (which is what upstream's OIDC
// callback reads — `test/e2e/oidc.test.ts` is the end-to-end proof that the
// real flow still works).

import { describe, expect, it } from "vitest";
import { makeAuth, signUpOwner, createOrg, type TestAuth } from "../helpers/auth";
import {
  decryptSecret,
  encryptSecret,
  isEncrypted,
  assertSecretsKey,
} from "../../src/server/secrets";

const SECRET = "SUPERSECRET-idp-client-secret";

async function registerOidc(t: TestAuth, cookie: string, orgId: string, providerId = "okta") {
  const res = await t.api.post(
    "/sso/register",
    {
      providerId,
      issuer: "https://idp.test",
      domain: "acme.test",
      organizationId: orgId,
      oidcConfig: {
        clientId: "cid",
        clientSecret: SECRET,
        skipDiscovery: true,
        authorizationEndpoint: "https://idp.test/authorize",
        tokenEndpoint: "https://idp.test/token",
        jwksEndpoint: "https://idp.test/jwks",
      },
    },
    { cookie },
  );
  if (!res.ok) throw new Error(`register failed: ${res.status} ${await res.text()}`);
}

async function rawOidcConfig(t: TestAuth, providerId: string): Promise<string> {
  const res = await t.client.execute({
    sql: `SELECT oidcConfig FROM "ssoProvider" WHERE providerId = ?`,
    args: [providerId],
  });
  return String(res.rows[0]!.oidcConfig);
}

describe("C-04 — IdP client secrets are encrypted at rest", () => {
  it("the stored row holds ciphertext, never the plaintext client secret", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);
    await registerOidc(t, cookie, orgId);

    const stored = await rawOidcConfig(t, "okta");
    expect(stored).not.toContain(SECRET);
    const parsed = JSON.parse(stored) as { clientId: string; clientSecret: string };
    expect(parsed.clientSecret.startsWith("enc:v1:")).toBe(true);
    // Non-secret fields stay readable so an operator can still inspect a row.
    expect(parsed.clientId).toBe("cid");
  });

  it("reads through the adapter still see the plaintext secret", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);
    await registerOidc(t, cookie, orgId, "okta2");

    const row = await t.auth.$context.then((c) =>
      c.adapter.findOne<{ oidcConfig: string }>({
        model: "ssoProvider",
        where: [{ field: "providerId", value: "okta2" }],
      }),
    );
    const parsed = JSON.parse(row!.oidcConfig) as { clientSecret: string };
    expect(parsed.clientSecret).toBe(SECRET);
  });

  it("round-trips, and leaves values that were never encrypted alone (migration)", async () => {
    const key = "k".repeat(32);
    const sealed = await encryptSecret("hunter2", key);
    expect(isEncrypted(sealed)).toBe(true);
    expect(sealed).not.toContain("hunter2");
    expect(await decryptSecret(sealed, key)).toBe("hunter2");
    // Two encryptions of the same value differ (random IV per call).
    expect(await encryptSecret("hunter2", key)).not.toBe(sealed);
    // A legacy plaintext row is returned untouched rather than mangled.
    expect(await decryptSecret("plaintext-legacy", key)).toBe("plaintext-legacy");
    // A wrong key is loud, not silently wrong.
    await expect(decryptSecret(sealed, "x".repeat(32))).rejects.toThrow();
  });

  it("secretsKey shorter than 32 characters is rejected at construction (L-08)", () => {
    expect(() => assertSecretsKey("too-short")).toThrow(/at least 32 characters/);
    expect(() => assertSecretsKey("s".repeat(32))).not.toThrow();
  });
});
