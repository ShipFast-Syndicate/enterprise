import { beforeEach, describe, expect, it, vi } from "vitest";
import { sso } from "@better-auth/sso";
import {
  API_KEY_LIFECYCLE_PLUGIN_ID,
  API_KEY_STANDING_PLUGIN_ID,
  enterprisePreset,
} from "../../src/server/preset";
import { guardScimSsoProviderMutation, resolveScimSsoUser } from "../../src/server/scim-sso";
import type { EnterpriseOptions } from "../../src/server/types";
import { EXPECTED_TABLES } from "../../src/schema/expected";
import { makeAuth } from "../helpers/auth";

// Wraps (does not replace) upstream's `sso()`: every call still builds the real
// plugin, and the argument the preset passed is kept for inspection.
vi.mock("@better-auth/sso", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@better-auth/sso")>();
  return { ...actual, sso: vi.fn(actual.sso) };
});

const baseOptions = {
  product: "test",
  secretsKey: "s".repeat(32),
  scimCredentialHashSecret: "catalog-test-key-".repeat(3),
  resolveEntitlements: async () => new Set<never>(),
};

type SsoArgument = NonNullable<Parameters<typeof sso>[0]>;

function ssoArgumentFor(extra: Partial<EnterpriseOptions> = {}): SsoArgument {
  vi.mocked(sso).mockClear();
  enterprisePreset({ ...baseOptions, ...extra });
  const calls = vi.mocked(sso).mock.calls;
  expect(calls).toHaveLength(1);
  return calls[0]![0] as SsoArgument;
}

describe("enterprisePreset", () => {
  it("returns the upstream + enterprise plugins in order", () => {
    const plugins = enterprisePreset({
      product: "test",
      secretsKey: "s".repeat(32),
      scimCredentialHashSecret: "catalog-test-key-".repeat(3),
      resolveEntitlements: async () => new Set(),
    });

    expect(API_KEY_LIFECYCLE_PLUGIN_ID).toBe("enterprise-api-keys");
    expect(plugins.map((p) => p.id)).toEqual([
      "admin",
      "organization",
      "two-factor",
      "passkey",
      "api-key",
      API_KEY_LIFECYCLE_PLUGIN_ID, // "enterprise-api-keys": directly after upstream api-key, before sso
      "sso",
      "scim",
      "enterprise-gate",
      "enterprise-audit",
      "enterprise-policy",
      "enterprise-scim-membership",
      "enterprise-api",
    ]);
  });

  describe("the sso() configuration", () => {
    beforeEach(() => {
      vi.mocked(sso).mockClear();
    });

    // The 1.2.0 literal, spelled out: a consumer that passes none of the 1.3
    // options must get exactly this, with the resolver the same function.
    it("with no sso options, is the 1.2.0 literal and resolveUser is resolveScimSsoUser itself", () => {
      const provisionUser = vi.fn();
      const arg = ssoArgumentFor({ provisionUser });
      expect(arg).toStrictEqual({
        domainVerification: { enabled: true },
        organizationProvisioning: { disabled: false, defaultRole: "member" },
        disableImplicitSignUp: false,
        provisionUser,
        resolveUser: resolveScimSsoUser,
        guardProviderMutation: guardScimSsoProviderMutation,
        saml: { allowIdpInitiated: true },
      });
      expect(arg.resolveUser).toBe(resolveScimSsoUser);
    });

    it("an empty sso block, or every key at its documented default, is still the 1.2.0 literal (same resolver reference)", () => {
      const baseline = ssoArgumentFor();
      for (const ssoOptions of [
        {},
        {
          existingUsersOnly: false,
          organizationProvisioning: "member",
          oidcClaims: {},
          domainVerificationMode: "dns",
        },
        {
          oidcClaims: {
            requireEmailVerified: false,
            requireHostedDomain: false,
            requirePkce: false,
          },
        },
      ] as const) {
        const arg = ssoArgumentFor({ sso: ssoOptions as EnterpriseOptions["sso"] });
        expect(arg).toStrictEqual(baseline);
        expect(arg.resolveUser).toBe(resolveScimSsoUser);
      }
    });

    it("organizationProvisioning:'off' changes only organizationProvisioning (disabled:true)", () => {
      const baseline = ssoArgumentFor();
      const arg = ssoArgumentFor({ sso: { organizationProvisioning: "off" } });
      expect(arg).toStrictEqual({
        ...baseline,
        organizationProvisioning: { disabled: true, defaultRole: "member" },
      });
      expect(arg.resolveUser).toBe(resolveScimSsoUser);
    });

    it("existingUsersOnly changes only disableImplicitSignUp and the resolver", () => {
      const baseline = ssoArgumentFor();
      const arg = ssoArgumentFor({ sso: { existingUsersOnly: true } });
      expect(arg.disableImplicitSignUp).toBe(true);
      expect(typeof arg.resolveUser).toBe("function");
      expect(arg.resolveUser).not.toBe(resolveScimSsoUser);
      expect({ ...arg, disableImplicitSignUp: false, resolveUser: undefined }).toStrictEqual({
        ...baseline,
        resolveUser: undefined,
      });
    });

    it("an oidcClaims option changes only the resolver", () => {
      const baseline = ssoArgumentFor();
      for (const oidcClaims of [
        { requireEmailVerified: true },
        { requirePkce: true },
        { requireHostedDomain: ["acme.test"] },
      ]) {
        const arg = ssoArgumentFor({ sso: { oidcClaims } });
        expect(arg.resolveUser).not.toBe(resolveScimSsoUser);
        expect({ ...arg, resolveUser: undefined }).toStrictEqual({
          ...baseline,
          resolveUser: undefined,
        });
      }
    });

    it("domainVerificationMode:'operator' leaves every sso() key as it was", () => {
      const baseline = ssoArgumentFor();
      const arg = ssoArgumentFor({ sso: { domainVerificationMode: "operator" } });
      expect({ ...arg, resolveUser: undefined }).toStrictEqual({
        ...baseline,
        resolveUser: undefined,
      });
    });

    it("the plugin ids and their order do not depend on the sso options", () => {
      const ids = (extra: Partial<EnterpriseOptions>) =>
        enterprisePreset({ ...baseOptions, ...extra }).map((p) => p.id);
      expect(
        ids({
          sso: {
            existingUsersOnly: true,
            organizationProvisioning: "off",
            oidcClaims: { requireEmailVerified: true, requirePkce: true },
            domainVerificationMode: "operator",
          },
        }),
      ).toEqual(ids({}));
    });
  });

  it("with apiKeys.enableSessionForAPIKeys, the key-standing plugin sits directly before upstream api-key (its /get-session hook must run first); nothing else moves", () => {
    const base = {
      product: "test",
      secretsKey: "s".repeat(32),
      scimCredentialHashSecret: "catalog-test-key-".repeat(3),
      resolveEntitlements: async () => new Set<never>(),
    };
    const ids = enterprisePreset({ ...base, apiKeys: { enableSessionForAPIKeys: true } }).map(
      (p) => p.id,
    );
    expect(API_KEY_STANDING_PLUGIN_ID).toBe("enterprise-api-key-standing");
    expect(ids.indexOf(API_KEY_STANDING_PLUGIN_ID)).toBe(ids.indexOf("api-key") - 1);
    expect(ids.filter((id) => id !== API_KEY_STANDING_PLUGIN_ID)).toEqual(
      enterprisePreset(base).map((p) => p.id),
    );
  });

  // `getAuthTables()`'s (and hence `$context.tables`'s) own top-level keys
  // are each plugin's *schema key* (e.g. `orgPolicy`, `auditEvent`), not its
  // `modelName` — `test/schema/verify.test.ts`'s "EXPECTED_TABLES drift
  // guard" already established this and compares by `.modelName` for exactly
  // that reason. `EXPECTED_TABLES` (`src/schema/expected.ts`) is itself keyed
  // by `modelName` (snake_case for this package's own 3 tables, camelCase or
  // upstream's own spelling otherwise), so this assertion follows the same,
  // already-proven convention rather than comparing raw object keys, which
  // would spuriously fail for `org_policy`/`audit_event`/`scim_group` even
  // though those tables genuinely exist.
  it("auth.$context.tables includes every EXPECTED_TABLES entry", async () => {
    const t = await makeAuth();
    const context = await (
      t.auth as unknown as {
        $context: Promise<{ tables: Record<string, { modelName: string }> }>;
      }
    ).$context;

    const liveTableNames = new Set(Object.values(context.tables).map((table) => table.modelName));
    const missing = Object.keys(EXPECTED_TABLES).filter((name) => !liveTableNames.has(name));

    expect(missing).toEqual([]);
  });
});
