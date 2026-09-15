import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    testTimeout: 20000,
    coverage: {
      provider: "v8",
      include: ["src/**"],
    },
    // vitest 4 silently ignores the old `environmentMatchGlobs` option (no
    // warning, no error — it just never applied happy-dom to test/portal/**).
    // `test.projects` is its replacement: each project gets its own
    // `include`/`environment`, while `coverage` and `testTimeout` stay
    // shared at the root. test/portal/env.test.ts guards this wiring.
    projects: [
      {
        test: {
          name: "server",
          include: ["test/**/*.test.ts"],
          exclude: ["test/portal/**"],
          environment: "node",
        },
      },
      {
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
