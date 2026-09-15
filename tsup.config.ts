import { defineConfig } from "tsup";

const external = [
  /^better-auth/,
  /^@better-auth\//,
  "drizzle-orm",
  "@libsql/client",
  "lit",
  /^lit\//,
];

// A **single** config object with every entry (Task 13 leftover). Two
// sibling config objects run as two concurrent tsup builds sharing one
// `dist/`, and their DTS passes raced: the CLI build's `dist/cli/index.d.ts`
// was intermittently missing from a finished `pnpm build` (the first
// object's `clean` and the second object's DTS write interleaving), which
// broke `exports`-resolution for consumers non-deterministically. One
// config = one clean, one ordered DTS pass, one deterministic output tree.
//
// The shebang used to be the reason for the split — `banner` is global to a
// config. `esbuild`'s per-entry `banner` doesn't exist either, so the CLI
// entry gets its banner from `src/cli/index.ts`'s own leading `#!/usr/bin/env
// node` line, which esbuild preserves verbatim for an entry point.
export default defineConfig({
  // Named (object-map) entries so each output lands at the exact path
  // package.json `exports` expects — a single-file array entry would
  // otherwise collapse to `dist/index.js` instead of `dist/<name>/index.js`.
  entry: {
    "server/index": "src/server/index.ts",
    "schema/index": "src/schema/index.ts",
    "client/index": "src/client/index.ts",
    "portal/index": "src/portal/index.ts",
    "cli/index": "src/cli/index.ts",
  },
  format: ["esm"],
  dts: true,
  splitting: false,
  clean: true,
  external,
});
