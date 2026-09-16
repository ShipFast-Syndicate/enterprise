import { describe, expect, it } from "vitest";
import { enterprisePreset } from "../../src/server/preset";
import { EXPECTED_TABLES } from "../../src/schema/expected";
import { makeAuth } from "../helpers/auth";

describe("enterprisePreset", () => {
  it("returns the upstream + enterprise plugins in order", () => {
    const plugins = enterprisePreset({
      product: "test",
      secretsKey: "s".repeat(32),
      resolveEntitlements: async () => new Set(),
    });

    expect(plugins.map((p) => p.id)).toEqual([
      "admin",
      "organization",
      "two-factor",
      "passkey",
      "api-key",
      "sso",
      "scim",
      "enterprise-gate",
      "enterprise-audit",
      "enterprise-policy",
      "enterprise-scim-groups",
      "enterprise-api",
    ]);
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
