---
version: "alpha"
name: "Alpha Bros enterprise portal inheritance"
description: "Host-owned visual design contract for framework-independent enterprise portal elements."
omitted:
  - section: colors
    reason: "Portal components consume host --ab-color-* properties with no fallback and ship no color values."
  - section: typography
    reason: "Portal components consume host --ab-font-family and --ab-font-size properties and ship no font defaults."
  - section: spacing
    reason: "Portal components consume host --ab-space-1 through --ab-space-4 and ship no spacing values."
  - section: rounded
    reason: "Portal components consume host --ab-radius and ship no corner-radius value."
  - section: components
    reason: "Component style values are inherited through host --ab-* CSS properties, not same-document literal or reference tokens."
---

## Overview

`@alphabros/enterprise` supplies server/schema/client integrations and a framework-independent Lit admin portal. The portal has no standalone product brand. Its existing theming contract requires the embedding host to supply every color, font, spacing, border, radius and shadow through `--ab-*` CSS custom properties, with no fallbacks.

An embedding product's `DESIGN.md` owns those actual values. This package's guide records the contract and inherited component mechanics rather than fabricating a default palette.

## Colors

The host defines `--ab-color-text`, `--ab-color-text-muted`, `--ab-color-bg`, `--ab-color-surface`, `--ab-color-primary`, `--ab-color-on-primary`, `--ab-color-danger`, `--ab-color-success` and `--ab-color-border`. Primary/on-primary style actions and selected states; danger and success communicate existing error/positive states. No raw color or fallback is shipped by the portal.

## Typography

All portal elements consume `--ab-font-family` and `--ab-font-size`; buttons and copy-box code inherit the component font. Text should read as part of the embedding product. The package does not choose a font face, size scale or code face.

## Layout

Host spacing tokens are `--ab-space-1` through `--ab-space-4`. Shared buttons use space-2 vertically and space-3 horizontally; copy boxes use space-3; shared table cells use space-2. Structural flex/grid/table rules and 100% width are allowed source literals because they do not select host design values.

## Elevation & Depth

The host supplies `--ab-shadow`, the full `--ab-border` shorthand and the separate `--ab-color-border`. The package introduces no independent elevation palette.

## Shapes

Buttons, controls and copy boxes use host `--ab-radius`; no fixed radius is imposed.

## Components

The README lists the security settings, SSO wizard, members, SCIM tokens, API keys, audit log and security-policy elements. Shared `AbElement` styles apply inherited text/background, primary actions, muted loading copy and danger errors. Disabled buttons use the existing 0.6 opacity rule. Shared tables are full-width with collapsed borders and left-aligned cells.

Loading messages expose `role="status"`; errors expose `role="alert"`. The existing `not-entitled` slot lets the host replace fallback plan copy. Newly created secret copy boxes retain the existing shown-once message; their theme comes from the host surface/border/radius/spacing properties.

## Do's and Don'ts

- Do provide the complete `src/portal/tokens.md` contract from the embedding product's design system.
- Do preserve host identity across all portal elements and their loading, error and selected states.
- Do retain structural layout and existing accessibility semantics from the shared base.
- Don't introduce raw colors, literal font families, px/rem/em visual sizes or fallback values in portal styles; the documented theming test checks this boundary.
- Don't use unresolved YAML token references to pretend host values are defined by this package.

## Source references

Repository source: `develop` at `8c852ad9d55330f0a6582ed21fea12bc79a7582a`.

- [README.md](https://github.com/ShipFast-Syndicate/enterprise/blob/8c852ad9d55330f0a6582ed21fea12bc79a7582a/README.md)
- [package.json](https://github.com/ShipFast-Syndicate/enterprise/blob/8c852ad9d55330f0a6582ed21fea12bc79a7582a/package.json)
- [src/portal/tokens.md](https://github.com/ShipFast-Syndicate/enterprise/blob/8c852ad9d55330f0a6582ed21fea12bc79a7582a/src/portal/tokens.md)
- [src/portal/base.ts](https://github.com/ShipFast-Syndicate/enterprise/blob/8c852ad9d55330f0a6582ed21fea12bc79a7582a/src/portal/base.ts)
- [src/portal/ab-scim-tokens.ts](https://github.com/ShipFast-Syndicate/enterprise/blob/8c852ad9d55330f0a6582ed21fea12bc79a7582a/src/portal/ab-scim-tokens.ts)
