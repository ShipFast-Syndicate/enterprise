// Alpha Bros enterprise layer — portal test setup (vitest `portal` project).
//
// Silences Lit's one-time "Lit is in dev mode. Not recommended for
// production!" console warning. This repo's `lit` dependency has no
// production build reachable via package `exports` (verified:
// `node_modules/lit/package.json`'s `exports` map has only a `"default"`
// condition — no `"production"`/`"development"` switch — so `lit`'s own
// `index.js` always resolves to the dev-mode `@lit/reactive-element` build).
// The documented suppression instead: seed `litIssuedWarnings` with the
// warning's *code* before `lit` is ever imported, which short-circuits Lit's
// own de-dupe check (`@lit/reactive-element/development/reactive-element.js`'s
// `issueWarning`: `if (!global.litIssuedWarnings.has(warning) &&
// !global.litIssuedWarnings.has(code)) { ...console.warn... }`). vitest loads
// `setupFiles` before it imports the test file itself, so this runs before
// any test module's own `import "lit"` (directly, or via `../../src/portal/*`).
(globalThis as unknown as { litIssuedWarnings?: Set<string> }).litIssuedWarnings = new Set([
  "dev-mode",
]);
