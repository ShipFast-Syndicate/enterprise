import { describe, expect, it } from "vitest";
import {
  API_KEY_LIFECYCLE_PLUGIN_ID,
  API_KEY_STANDING_PLUGIN_ID,
  enterprisePreset,
} from "../../src/server/preset";
import { EXPECTED_TABLES } from "../../src/schema/expected";
import { makeAuth } from "../helpers/auth";

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
