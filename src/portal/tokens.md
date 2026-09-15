# `@alphabros/enterprise` portal design tokens

Every colour, font, size, and spacing value used in `src/portal/**` component
styles is one of the CSS custom properties below, referenced as
`var(--ab-*)` with **no fallback value**. The embedding host application
defines these tokens however it wants (a global stylesheet, a `:root` block,
a theme provider) — the portal components only ever consume them. This
package ships no default values of its own for any of them.

Structural CSS — `display`, `flex`, `grid`, `width: 100%`,
`border-collapse`, and similar layout mechanics that carry no visual design
opinion — is not part of this contract and may use literals freely.

`test/portal/theming.test.ts` scans every `src/portal/*.ts` file and fails
if it finds: a raw `#hex` colour, an `rgb(`/`hsl(` colour function, a
`px`/`rem`/`em` size literal (a bare unitless `0`, e.g. `border-width: 0`,
is fine — it isn't a themed value), a literal `font-family` value, or a
`var(--ab-*, ...)` reference with a fallback.

| Token                   | Purpose                                                             |
| ----------------------- | ------------------------------------------------------------------- |
| `--ab-font-family`      | Base font stack for every portal component.                         |
| `--ab-font-size`        | Base font size.                                                     |
| `--ab-color-text`       | Primary text colour.                                                |
| `--ab-color-text-muted` | Secondary/muted text — hints, empty states, loading copy.           |
| `--ab-color-bg`         | Component background.                                               |
| `--ab-color-surface`    | Raised/secondary surface, e.g. an inactive tab button.              |
| `--ab-color-primary`    | Primary action / selected-state colour.                             |
| `--ab-color-on-primary` | Text/icon colour rendered on top of `--ab-color-primary`.           |
| `--ab-color-danger`     | Errors and destructive state.                                       |
| `--ab-color-success`    | Success / positive state, e.g. an accepted invitation.              |
| `--ab-color-border`     | Border colour used on its own, outside the `--ab-border` shorthand. |
| `--ab-border`           | Full border shorthand (width, style, colour).                       |
| `--ab-radius`           | Corner radius for buttons, panels, and controls.                    |
| `--ab-space-1`          | Smallest spacing increment, e.g. an inline icon's margin.           |
| `--ab-space-2`          | Small spacing — tight padding, control gaps.                        |
| `--ab-space-3`          | Medium spacing — default control padding.                           |
| `--ab-space-4`          | Large spacing — section margins.                                    |
| `--ab-shadow`           | Elevation shadow for panels/popovers.                               |
