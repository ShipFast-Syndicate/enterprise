import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    environmentMatchGlobs: [["test/portal/**", "happy-dom"]],
    testTimeout: 20000,
    coverage: {
      provider: "v8",
      include: ["src/**"],
    },
  },
});
