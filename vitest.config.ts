import { defineConfig } from "vitest/config";

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
    projects: [
      {
        extends: true,
        test: {
          name: "server",
          include: ["test/**/*.test.ts"],
          exclude: ["test/portal/**"],
          environment: "node",
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
    ],
  },
});
