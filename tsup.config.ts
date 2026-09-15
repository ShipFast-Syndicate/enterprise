import { defineConfig } from "tsup";

const external = [
  /^better-auth/,
  /^@better-auth\//,
  "drizzle-orm",
  "@libsql/client",
  "lit",
  /^lit\//,
];

export default defineConfig([
  {
    // Named (object-map) entries so each output lands at the exact path
    // package.json `exports` expects — a single-file array entry would
    // otherwise collapse to `dist/index.js` instead of `dist/<name>/index.js`.
    entry: {
      "server/index": "src/server/index.ts",
      "schema/index": "src/schema/index.ts",
      "client/index": "src/client/index.ts",
      "portal/index": "src/portal/index.ts",
    },
    format: ["esm"],
    dts: true,
    splitting: false,
    clean: true,
    external,
  },
  {
    // Separate config so only the CLI entry gets the shebang banner.
    entry: { "cli/index": "src/cli/index.ts" },
    format: ["esm"],
    dts: true,
    splitting: false,
    // clean: false — the first config object already wiped dist/ once; a
    // second `clean: true` here would delete the entries it just built.
    clean: false,
    external,
    banner: { js: "#!/usr/bin/env node" },
  },
]);
