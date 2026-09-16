import { describe, expect, it } from "vitest";

// Guards the `portal` vitest project's environment wiring: the admin portal
// (Tasks 10-12) is Lit-based and needs a real DOM + custom elements registry
// to test. If this project's `environment: "happy-dom"` ever regresses back
// to the default `node` environment (e.g. a future vitest config-format
// change silently dropping it, as happened with `environmentMatchGlobs` in
// vitest 4), this is the first thing that fails.
describe("portal test environment", () => {
  it("runs under a DOM environment (document is defined)", () => {
    expect(typeof document).not.toBe("undefined");
  });

  it("has a custom elements registry", () => {
    expect(customElements).toBeDefined();
  });
});
