// `assertEnterpriseOptions` (`src/server/options.ts`) — every option block
// the 1.1.0 security release introduces is validated at construction, so a
// typo fails the boot rather than the first request that depends on it.
import { afterEach, describe, expect, it, vi } from "vitest";
import { assertEnterpriseOptions, resetOptionWarningsForTests } from "../../src/server/options";
import type { EnterpriseOptions } from "../../src/server/types";

function opts(overrides: Partial<EnterpriseOptions> = {}): EnterpriseOptions {
  return {
    product: "test",
    secretsKey: "s".repeat(32),
    scimCredentialHashSecret: "catalog-test-key-".repeat(3),
    resolveEntitlements: async () => [],
    ...overrides,
  };
}

// Lets each case pass a deliberately wrong-typed value without `any`.
function loose(overrides: Record<string, unknown>): EnterpriseOptions {
  return opts(overrides as Partial<EnterpriseOptions>);
}

afterEach(() => {
  vi.restoreAllMocks();
  resetOptionWarningsForTests();
});

describe("assertEnterpriseOptions — audit.chainKey", () => {
  it("accepts a >= 32 character key that differs from the other secrets", () => {
    expect(() =>
      assertEnterpriseOptions(opts({ audit: { chainKey: "k".repeat(32) } })),
    ).not.toThrow();
  });

  it("rejects a short key", () => {
    expect(() => assertEnterpriseOptions(opts({ audit: { chainKey: "k".repeat(31) } }))).toThrow(
      /chainKey.*32/,
    );
  });

  it("rejects a non-string key", () => {
    expect(() => assertEnterpriseOptions(loose({ audit: { chainKey: 12345 } }))).toThrow(
      /chainKey/,
    );
  });

  it("rejects reusing secretsKey or scimCredentialHashSecret as the chain key", () => {
    expect(() => assertEnterpriseOptions(opts({ audit: { chainKey: "s".repeat(32) } }))).toThrow(
      /independent/,
    );
    expect(() =>
      assertEnterpriseOptions(opts({ audit: { chainKey: "catalog-test-key-".repeat(3) } })),
    ).toThrow(/independent/);
  });
});

describe("assertEnterpriseOptions — sso", () => {
  it("accepts both domainBinding literals and rejects anything else", () => {
    expect(() =>
      assertEnterpriseOptions(opts({ sso: { domainBinding: "verified-domain" } })),
    ).not.toThrow();
    expect(() => assertEnterpriseOptions(opts({ sso: { domainBinding: "off" } }))).not.toThrow();
    expect(() => assertEnterpriseOptions(loose({ sso: { domainBinding: "on" } }))).toThrow(
      /domainBinding/,
    );
  });

  it('warns once per process, naming the advisory, when domainBinding is "off"', () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});

    assertEnterpriseOptions(opts({ sso: { domainBinding: "off" } }));
    assertEnterpriseOptions(opts({ sso: { domainBinding: "off" } }));

    expect(warn).toHaveBeenCalledTimes(1);
    expect(String(warn.mock.calls[0]?.[0])).toContain("GHSA-8p84-pc7q-69jr");
  });

  it('does not warn for the default or for "verified-domain"', () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});

    assertEnterpriseOptions(opts());
    assertEnterpriseOptions(opts({ sso: { domainBinding: "verified-domain" } }));

    expect(warn).not.toHaveBeenCalled();
  });

  it("validates trustVerifiedDomainEmail as a boolean", () => {
    expect(() =>
      assertEnterpriseOptions(opts({ sso: { trustVerifiedDomainEmail: false } })),
    ).not.toThrow();
    expect(() =>
      assertEnterpriseOptions(loose({ sso: { trustVerifiedDomainEmail: "no" } })),
    ).toThrow(/trustVerifiedDomainEmail/);
  });

  it("validates allowedIssuers as strings/RegExps or a predicate", () => {
    expect(() =>
      assertEnterpriseOptions(
        opts({ sso: { allowedIssuers: ["https://idp.test", /^https:\/\/.*\.okta\.test$/] } }),
      ),
    ).not.toThrow();
    expect(() =>
      assertEnterpriseOptions(opts({ sso: { allowedIssuers: async () => true } })),
    ).not.toThrow();
    expect(() => assertEnterpriseOptions(loose({ sso: { allowedIssuers: [42] } }))).toThrow(
      /allowedIssuers/,
    );
    expect(() =>
      assertEnterpriseOptions(loose({ sso: { allowedIssuers: "https://idp.test" } })),
    ).toThrow(/allowedIssuers/);
  });

  it("validates samlCertificateFingerprints as entityID → non-empty SHA-256 fingerprints (colons optional, case-insensitive)", () => {
    const sha256 = "ab".repeat(32);
    expect(() =>
      assertEnterpriseOptions(
        opts({
          sso: {
            samlCertificateFingerprints: {
              "https://idp.test/idp": [sha256, sha256.toUpperCase().match(/../g)!.join(":")],
            },
          },
        }),
      ),
    ).not.toThrow();
    expect(() =>
      assertEnterpriseOptions(loose({ sso: { samlCertificateFingerprints: [sha256] } })),
    ).toThrow(/samlCertificateFingerprints/);
    expect(() =>
      assertEnterpriseOptions(loose({ sso: { samlCertificateFingerprints: { "urn:idp": [] } } })),
    ).toThrow(/samlCertificateFingerprints\["urn:idp"\]/);
    expect(() =>
      assertEnterpriseOptions(
        loose({ sso: { samlCertificateFingerprints: { "urn:idp": sha256 } } }),
      ),
    ).toThrow(/samlCertificateFingerprints/);
    for (const bad of ["ab".repeat(20), "zz".repeat(32), 42]) {
      expect(() =>
        assertEnterpriseOptions(
          loose({ sso: { samlCertificateFingerprints: { "urn:idp": [bad] } } }),
        ),
      ).toThrow(/64 hex characters/);
    }
  });
});

describe("assertEnterpriseOptions — organization", () => {
  it("accepts booleans and a function for allowUserToCreateOrganization", () => {
    expect(() =>
      assertEnterpriseOptions(
        opts({
          organization: {
            requireEmailVerificationOnInvitation: false,
            allowUserToCreateOrganization: async () => false,
          },
        }),
      ),
    ).not.toThrow();
  });

  it("rejects truthy non-booleans", () => {
    expect(() =>
      assertEnterpriseOptions(
        loose({ organization: { requireEmailVerificationOnInvitation: "yes" } }),
      ),
    ).toThrow(/requireEmailVerificationOnInvitation/);
    expect(() =>
      assertEnterpriseOptions(loose({ organization: { allowUserToCreateOrganization: "yes" } })),
    ).toThrow(/allowUserToCreateOrganization/);
  });
});

describe("assertEnterpriseOptions — policy", () => {
  it("accepts signInMethods with path/prefix keys and snake_case method names", () => {
    expect(() =>
      assertEnterpriseOptions(
        opts({
          policy: { signInMethods: { "/sign-in/email-otp": "email_otp", "/phone/*": "phone" } },
        }),
      ),
    ).not.toThrow();
  });

  it("rejects a key that is not a path", () => {
    expect(() =>
      assertEnterpriseOptions(
        opts({ policy: { signInMethods: { "sign-in/email-otp": "email_otp" } } }),
      ),
    ).toThrow(/signInMethods.*starting with "\/"/);
  });

  it("rejects a method name outside [a-z_][a-z0-9_]*", () => {
    for (const bad of ["Email-OTP", "1otp", "otp!", ""]) {
      expect(() =>
        assertEnterpriseOptions(opts({ policy: { signInMethods: { "/sign-in/x": bad } } })),
      ).toThrow(/signInMethods/);
    }
  });

  it("rejects a non-object signInMethods", () => {
    expect(() => assertEnterpriseOptions(loose({ policy: { signInMethods: ["/x"] } }))).toThrow(
      /signInMethods/,
    );
  });

  it("validates twoFactor.satisfiedBy as method names and enrollmentPaths as paths", () => {
    expect(() =>
      assertEnterpriseOptions(
        opts({
          policy: { twoFactor: { satisfiedBy: ["sso", "passkey"], enrollmentPaths: ["/mfa/*"] } },
        }),
      ),
    ).not.toThrow();
    expect(() =>
      assertEnterpriseOptions(loose({ policy: { twoFactor: { satisfiedBy: ["SSO"] } } })),
    ).toThrow(/satisfiedBy/);
    expect(() =>
      assertEnterpriseOptions(loose({ policy: { twoFactor: { satisfiedBy: "sso" } } })),
    ).toThrow(/satisfiedBy/);
    expect(() =>
      assertEnterpriseOptions(loose({ policy: { twoFactor: { enrollmentPaths: ["mfa"] } } })),
    ).toThrow(/enrollmentPaths/);
  });
});

describe("assertEnterpriseOptions — apiKeys", () => {
  it("accepts finite positive bounds and null for never-expire", () => {
    expect(() =>
      assertEnterpriseOptions(opts({ apiKeys: { defaultExpiresInS: 3600, maxExpiresInDays: 30 } })),
    ).not.toThrow();
    expect(() =>
      assertEnterpriseOptions(opts({ apiKeys: { defaultExpiresInS: null } })),
    ).not.toThrow();
  });

  it("rejects zero, negative, non-finite and non-numeric values", () => {
    for (const bad of [0, -1, Number.NaN, Number.POSITIVE_INFINITY, "90d"]) {
      expect(() => assertEnterpriseOptions(loose({ apiKeys: { defaultExpiresInS: bad } }))).toThrow(
        /defaultExpiresInS/,
      );
      expect(() => assertEnterpriseOptions(loose({ apiKeys: { maxExpiresInDays: bad } }))).toThrow(
        /maxExpiresInDays/,
      );
    }
    expect(() => assertEnterpriseOptions(loose({ apiKeys: { maxExpiresInDays: null } }))).toThrow(
      /maxExpiresInDays/,
    );
  });
});
