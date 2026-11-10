import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";
import { IDP_CERT } from "./test/helpers/fixtures/saml-keys";

// The suites that also run on Postgres: makeAuth/buildDynamicSchema and the
// product-shaped harness, the preset, SCIM, policy, and the audit log
// (golden vectors and hash chain included).
const PG_CORE_SUITES = [
  "test/server/preset.test.ts",
  "test/server/policy.test.ts",
  "test/server/effective-policy.test.ts",
  "test/server/scim-groups.test.ts",
  "test/server/audit-chain.test.ts",
  "test/server/audit-golden-vectors.test.ts",
  "test/server/audit-plugin.test.ts",
  "test/security/audit-cluster.test.ts",
  "test/security/c02-retention-compaction.test.ts",
  "test/security/c03-scim-role-demotion.test.ts",
  "test/security/scim-catalog.test.ts",
  "test/security/gap2-require2fa-product-schema.test.ts",
  "test/security/org-lock.test.ts",
  "test/pg/audit-concurrency.test.ts",
];

export default defineConfig({
  test: {
    testTimeout: 20000,
    coverage: {
      provider: "v8",
      include: ["src/**"],
      // SQL migrations and the portal's Markdown design-token reference are
      // not executable JavaScript; V8 cannot instrument either file format.
      exclude: ["**/*.sql", "**/*.md"],
    },
    // vitest 4 silently ignores the old `environmentMatchGlobs` option (no
    // warning, no error — it just never applied happy-dom to test/portal/**).
    // `test.projects` is its replacement: each project gets its own
    // `include`/`environment`, while `coverage` and `testTimeout` stay
    // shared at the root. Vitest 4 requires extends: true for project-level
    // settings such as testTimeout to inherit. test/portal/env.test.ts guards
    // the portal environment; the CI contract test checks resolved timeouts.
    // samlify 2.15 added `build/src/xml.js`. Inside this project the pool's
    // module fallback resolves a CommonJS `require("xml")` made from
    // `build/src/metadata-*.js` to that sibling file (it probes
    // `<referrer dir>/xml` + `.js` before the package), so building SP/IdP
    // metadata threw `xml_1.default is not a function`. `patches/samlify@
    // 2.15.1.patch` makes the two requires explicit (`xml/lib/xml.js`). It
    // only affects this repo's tests: bundlers (wrangler/esbuild) resolve the
    // package correctly. Drop the patch once samlify fixes the import.
    // The `workerd` project boots `enterprisePreset` inside the real Workers
    // runtime (test/workerd/preset.test.ts). It is part of `pnpm test`, so
    // `ci / summary` gates the README's "runs on workerd" claim.
    projects: [
      {
        extends: true,
        test: {
          name: "server",
          include: ["test/**/*.test.ts"],
          exclude: ["test/portal/**", "test/workerd/**"],
          environment: "node",
        },
      },
      {
        // The core suites again, against Postgres: `TEST_DIALECT=pg` makes
        // `makeAuth` (test/helpers/auth.ts) build the Postgres schema and apply
        // `applyMigrationPg`. PGlite in-process by default; a real Postgres
        // when `TEST_DATABASE_URL` is set (the `postgres` CI job), where the
        // concurrency suite (test/pg/audit-concurrency.test.ts) also runs.
        // The files are the same ones the `server` project runs on SQLite,
        // not copies: a dialect-specific statement in one is guarded with
        // `isPg`/`ts()` from test/helpers/dialect.ts.
        extends: true,
        test: {
          name: "server-pg",
          include: PG_CORE_SUITES,
          environment: "node",
          env: { TEST_DIALECT: "pg" },
        },
      },
      {
        extends: true,
        test: {
          name: "portal",
          include: ["test/portal/**/*.test.ts"],
          environment: "happy-dom",
          setupFiles: ["./test/portal/setup.ts"],
        },
      },
      {
        extends: true,
        plugins: [
          cloudflareTest({
            miniflare: {
              compatibilityDate: "2026-08-01",
              compatibilityFlags: ["nodejs_compat"],
              // The IdP certificate is minted by the Node-side fixture
              // (@peculiar/x509 does not need to run inside workerd) and
              // handed in as a binding, so the SAML provider the tests
              // register carries a real, parseable X.509 certificate.
              bindings: { IDP_CERT },
            },
          }),
        ],
        test: {
          name: "workerd",
          include: ["test/workerd/**/*.test.ts"],
        },
      },
    ],
  },
});
