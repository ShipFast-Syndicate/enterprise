// Alpha Bros enterprise layer — portal theming contract (Task 10, controller
// ruling (a)): every colour/font/size/spacing value in `src/portal/**`
// component styles must be a `var(--ab-*)` reference with no fallback.
// Structural CSS (display, flex, grid, `width: 100%`, border-collapse, ...)
// is untouched by this contract and deliberately not scanned for.
//
// This is a plain static scan over the built source text (not a DOM/Lit
// test), so it belongs in the `portal` vitest project only because that's
// where every other `src/portal/**` test lives — it has no happy-dom
// dependency itself.

import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const PORTAL_DIR = join(dirname(fileURLToPath(import.meta.url)), "../../src/portal");

function sourceFiles(): string[] {
  return readdirSync(PORTAL_DIR)
    .filter((name) => name.endsWith(".ts"))
    .sort();
}

describe("portal theming contract (src/portal/*.ts)", () => {
  const files = sourceFiles();

  it("scans every known component/helper file (sanity check on the scan itself)", () => {
    expect(files).toEqual(
      expect.arrayContaining([
        "ab-api-keys.ts",
        "ab-audit-log.ts",
        "ab-members.ts",
        "ab-scim-tokens.ts",
        "ab-security-policy.ts",
        "ab-security-settings.ts",
        "ab-sso-wizard.ts",
        "api.ts",
        "base.ts",
        "index.ts",
      ]),
    );
  });

  for (const file of files) {
    const src = readFileSync(join(PORTAL_DIR, file), "utf8");

    it(`${file}: no raw hex colours (#rgb/#rrggbb/#rrggbbaa)`, () => {
      expect(src).not.toMatch(/#[0-9a-fA-F]{3,8}\b/);
    });

    it(`${file}: no rgb()/hsl() colour functions`, () => {
      expect(src).not.toMatch(/\brgb\(/);
      expect(src).not.toMatch(/\bhsl\(/);
    });

    it(`${file}: no px/rem/em size literals (bare "0" is fine)`, () => {
      expect(src).not.toMatch(/\d+(\.\d+)?(px|rem|em)\b/);
    });

    it(`${file}: font-family is always var(--ab-font-family), never a literal`, () => {
      const declarations = [...src.matchAll(/font-family\s*:\s*([^;]+);/g)];
      for (const [, value] of declarations) {
        expect(value!.trim()).toBe("var(--ab-font-family)");
      }
    });

    it(`${file}: the font shorthand (font:) is always "inherit", never a literal`, () => {
      // \b before "font" already excludes "font-family:"/"font-size:" (no
      // word boundary between "font" and the "-family"/"-size" that
      // immediately follows in those) — no negative lookahead needed.
      const declarations = [...src.matchAll(/\bfont\s*:\s*([^;]+);/g)];
      for (const [, value] of declarations) {
        expect(value!.trim()).toBe("inherit");
      }
    });

    it(`${file}: every var(--ab-*) reference has no fallback value`, () => {
      expect(src).not.toMatch(/var\(--ab-[a-z0-9-]+\s*,/);
    });
  }
});
