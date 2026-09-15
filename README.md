# @alphabros/enterprise

Alpha Bros studio enterprise layer for [better-auth](https://www.better-auth.com/) `1.6.33`:
SSO (SAML + OIDC), SCIM 2.0 provisioning (Users + Groups), organizations, a tamper-evident
audit log, security policy enforcement, and a framework-agnostic admin portal — as one
package with four subpath entry points and a CLI.

## Status

**v0.1 — pilot-grade.** Server plugins, schema/CLI, client helpers, and all seven portal
elements are implemented and tested (330+ tests). Read [`docs/security.md`](./docs/security.md)
before deploying to a real customer — it documents the one accepted advisory, token storage,
audit chain limitations, and the retention/GDPR posture.

## Install

```sh
pnpm add @alphabros/enterprise
```

This package ships one dependency of its own (`zod`) and declares everything else as a
**peer dependency**, pinned to exact versions where a security advisory requires it:

```jsonc
{
  "@better-auth/api-key": "1.6.33",
  "@better-auth/core": "1.6.33",
  "@better-auth/passkey": "1.6.33",
  "@better-auth/scim": "1.6.33",
  "@better-auth/sso": "1.6.33",
  "better-auth": "1.6.33",
  "better-call": "1.4.0",
  "@libsql/client": "^0.15.15", // optional — only needed for ./schema and the CLI
  "drizzle-orm": "^0.45.2", // optional — only needed for ./schema
  "lit": "^3", // optional — only needed for ./portal
}
```

`better-auth` and its `@better-auth/*` plugin set are pinned to the exact `1.6.33` release
(not a caret range) because `@better-auth/scim` has an unpatched advisory below the `1.7`
line — see [`docs/security.md`](./docs/security.md#accepted-advisories) for why this
package's own defaults make it inapplicable here, and when the pin will move.

Requirements: Node `>=22`, pnpm 10 (or any package manager — pnpm is only this repo's own
dev toolchain).

## Package layout

| Entry point                    | What it's for                                                     |
| ------------------------------ | ----------------------------------------------------------------- |
| `@alphabros/enterprise/server` | better-auth plugin preset (`enterprisePreset`) and its pieces     |
| `@alphabros/enterprise/schema` | Drizzle table definitions + SQL migrations (Node-only, see below) |
| `@alphabros/enterprise/client` | better-auth client plugins + home-realm login helpers             |
| `@alphabros/enterprise/portal` | Lit web components for a security-settings admin UI               |
| `ab-enterprise` (bin)          | CLI: `migrate`, `verify`, `audit-verify` (Node-only)              |

## Quick start — server

```ts
import { betterAuth } from "better-auth";
import { enterprisePreset, type Feature } from "@alphabros/enterprise/server";

export const auth = betterAuth({
  database: /* your libSQL/Turso adapter */ myAdapter,
  plugins: enterprisePreset({
    product: "klar",
    // Reads your own billing/plan state — see "Entitlements" below.
    resolveEntitlements: async (orgId) => resolveEntitlementsFromStripe(orgId),
    // Encrypts IdP client secrets and SP private keys at rest. >=32 chars,
    // from your product's 1Password vault — never a literal in source.
    secretsKey: process.env.ENTERPRISE_SECRETS_KEY!,
    // Optional: one shared SP signing identity across every org's SAML
    // connection (see docs/sso.md) instead of a fresh key pair per org.
    samlSpKeys: {
      cert: process.env.ENTERPRISE_SAML_SP_CERT!,
      privateKey: process.env.ENTERPRISE_SAML_SP_KEY!,
    },
    // Optional: runs on every SSO-driven JIT signup (CRM sync, welcome email, ...).
    provisionUser: async (user) => trackNewEnterpriseUser(user),
    audit: { retentionDays: 365 },
    scim: { groupRoleMap: { "Acme-Admins": "admin" } },
  }),
});
```

`enterprisePreset` returns the full plugin list: `organization` (teams enabled), `sso`,
`scim`, `twoFactor`, `passkey`, `apiKey`, plus this package's own `enterpriseGate` (entitlement
enforcement), `auditLog`, `orgPolicy`, `scimGroups`, and `enterpriseApi` (the portal-facing
`/enterprise/*` wrapper endpoints). Every product already mounting the better-auth handler
needs **no per-framework server code** beyond this.

## Entitlements

`requireFeature(ctx, orgId, feature)` is the single choke point for plan-gated behaviour.
`enterpriseGate` already calls it in front of every path listed in `GATED_PATHS` (SSO/SCIM
registration, team creation, API key creation, audit reads, policy writes, and the portal's
`/enterprise/sso/*` and `/enterprise/scim/tokens*` wrappers) — you only need to implement
`resolveEntitlements`. `Feature` is `"sso" | "scim" | "audit_log" | "enforce_2fa" | "api_keys" | "teams"`.

A typical implementation maps a Stripe price/plan onto the feature set it unlocks:

```ts
import type { Feature } from "@alphabros/enterprise/server";

const PLAN_FEATURES: Record<string, Feature[]> = {
  free: [],
  team: ["teams", "api_keys"],
  business: ["teams", "api_keys", "audit_log"],
  enterprise: ["teams", "api_keys", "audit_log", "sso", "scim", "enforce_2fa"],
};

// price_... -> plan name, from your Stripe dashboard / pricing config.
const STRIPE_PRICE_TO_PLAN: Record<string, keyof typeof PLAN_FEATURES> = {
  price_1AbcTeam: "team",
  price_1AbcBusiness: "business",
  price_1AbcEnterprise: "enterprise",
};

export async function resolveEntitlementsFromStripe(orgId: string): Promise<Feature[]> {
  const org = await db.query.organization.findFirst({ where: eq(organization.id, orgId) });
  const plan = org?.stripePriceId ? (STRIPE_PRICE_TO_PLAN[org.stripePriceId] ?? "free") : "free";
  return PLAN_FEATURES[plan];
}
```

Entitlements are cached per request (one `resolveEntitlements` call per org per request, however
many gated paths/`requireFeature` calls it serves), so it's safe to hit your own database or a
cached plan lookup here without worrying about N+1 calls on a single request.

## Quick start — client

```ts
import { createAuthClient } from "better-auth/client";
import {
  enterpriseClient,
  ssoClient,
  organizationClient,
  twoFactorClient,
  passkeyClient,
  apiKeyClient,
  discoverHomeRealm,
} from "@alphabros/enterprise/client";

export const authClient = createAuthClient({
  plugins: [
    enterpriseClient(),
    ssoClient(),
    organizationClient(),
    twoFactorClient(),
    passkeyClient(),
    apiKeyClient(),
  ],
});

// Email-first login: ask for the email, then decide SSO vs. local sign-in.
const result = await discoverHomeRealm(email);
if (result.method === "sso") {
  await authClient.signIn.sso({ providerId: result.providerId, callbackURL: "/dashboard" });
} else {
  // fall back to your existing magic-link / password / social sign-in
}
```

See [`docs/sso.md`](./docs/sso.md#home-realm-discovery-email-first-login) for the full flow,
including what `org_policy.sso_enforced` does to non-SSO sign-in attempts.

## Portal — embedding the admin UI

`@alphabros/enterprise/portal` registers seven framework-agnostic Lit custom elements:
`<ab-members>`, `<ab-security-settings>` (tabbed shell), `<ab-sso-wizard>`, `<ab-scim-tokens>`,
`<ab-security-policy>`, `<ab-api-keys>`, `<ab-audit-log>`. They render a shadow DOM and talk to
the `/enterprise/*` API directly — no server code needed beyond `enterprisePreset` above.

**Import the elements only from a browser-only context.** Lit's browser build references
`HTMLElement`, which doesn't exist on the server; importing the module in server-rendered code
(SSR frontmatter, a Next Server Component) throws or bloats the server bundle. Import from a
client-only place instead — verified against the fleet's own three Cloudflare-targeted stacks
(spike report `2026-09-15-p0c-lit-portal-frameworks`):

### SvelteKit

```svelte
<script lang="ts">
  import { onMount } from "svelte";
  import { browser } from "$app/environment";
  let orgId = "acme";
  onMount(async () => {
    if (browser) await import("@alphabros/enterprise/portal");
  });
</script>

<main style="--ab-color-primary: #0f766e">
  <ab-security-settings org-id={orgId}></ab-security-settings>
</main>
```

### Astro

```astro
---
const orgId = "acme"; // do NOT import the portal module in frontmatter — see above
---
<main style="--ab-color-primary: #0f766e">
  <ab-security-settings org-id={orgId}></ab-security-settings>
</main>
<script>
  import "@alphabros/enterprise/portal"; // bundled by Vite, browser-only
</script>
```

### Next.js (App Router)

```tsx
"use client";
import { useEffect, useState } from "react";

export default function SecuritySettingsPage() {
  const [orgId] = useState("acme");
  useEffect(() => {
    import("@alphabros/enterprise/portal");
  }, []);
  return (
    <main style={{ "--ab-color-primary": "#0f766e" } as React.CSSProperties}>
      <ab-security-settings org-id={orgId} />
    </main>
  );
}
```

React needs a one-time JSX intrinsic-element declaration for each custom tag you use (put this
once in a `.d.ts`, not per page — a stray `@ts-expect-error` on it elsewhere becomes a hard
`next build` failure):

```ts
declare module "react" {
  namespace JSX {
    interface IntrinsicElements {
      "ab-security-settings": React.DetailedHTMLProps<
        React.HTMLAttributes<HTMLElement>,
        HTMLElement
      > & {
        "org-id"?: string;
      };
      // ...one entry per <ab-*> element you use
    }
  }
}
```

Net cost: lit 3 + the portal elements add about 6.5 kB gzip, code-split to whichever route
renders them, in all three frameworks.

### Theming

The portal ships **no colours, fonts, or spacing of its own** — every visual value is a
`var(--ab-*)` CSS custom property with no fallback, so it inherits your product's design
tokens (`DESIGN.md`) instead of imposing new ones:

| Token                           | Purpose                                                             |
| ------------------------------- | ------------------------------------------------------------------- |
| `--ab-font-family`              | Base font stack for every portal component.                         |
| `--ab-font-size`                | Base font size.                                                     |
| `--ab-color-text`               | Primary text colour.                                                |
| `--ab-color-text-muted`         | Secondary/muted text — hints, empty states, loading copy.           |
| `--ab-color-bg`                 | Component background.                                               |
| `--ab-color-surface`            | Raised/secondary surface, e.g. an inactive tab button.              |
| `--ab-color-primary`            | Primary action / selected-state colour.                             |
| `--ab-color-on-primary`         | Text/icon colour rendered on top of `--ab-color-primary`.           |
| `--ab-color-danger`             | Errors and destructive state.                                       |
| `--ab-color-success`            | Success / positive state, e.g. an accepted invitation.              |
| `--ab-color-border`             | Border colour used on its own, outside the `--ab-border` shorthand. |
| `--ab-border`                   | Full border shorthand (width, style, colour).                       |
| `--ab-radius`                   | Corner radius for buttons, panels, and controls.                    |
| `--ab-space-1` … `--ab-space-4` | Spacing scale, smallest to largest.                                 |
| `--ab-shadow`                   | Elevation shadow for panels/popovers.                               |

Define these once in a global stylesheet or `:root` block; the components consume them, they
don't ship defaults. Full reference: `src/portal/tokens.md`.

## CLI (`ab-enterprise`)

Node-only (reads/writes the local filesystem and talks to libSQL directly) — run it from a
deploy step or locally, not from an edge/Workers runtime:

```sh
# Copy this package's SQL migration into your product's drizzle migrations
# folder, numbered to follow whatever's already there.
ab-enterprise migrate --out ./drizzle/migrations

# Check a LIVE database has every table/column this package expects.
# Exits 1 and prints one line per gap if anything is missing.
ab-enterprise verify --url $TURSO_DATABASE_URL --token $TURSO_AUTH_TOKEN
# Prefer TURSO_DATABASE_URL / TURSO_AUTH_TOKEN env vars over --url/--token —
# CLI flags are visible in `ps` output and shell history.

# Recompute an org's audit_event hash chain and confirm nothing was tampered
# with (within the retention window — see docs/security.md).
ab-enterprise audit-verify --org org_123 --url $TURSO_DATABASE_URL
```

Run `ab-enterprise verify` after every deploy (fleet migrations have historically not reached
Turso even when the migration file itself was committed).

`@alphabros/enterprise/schema` is likewise Node-only — it reads the packaged SQL file from disk
at runtime and does not run on Cloudflare Workers/workerd. `./server`, `./client`, and
`./portal` have no Node built-ins and run anywhere better-auth itself does.

## Documentation

- [`docs/sso.md`](./docs/sso.md) — the SSO wizard flow, DNS TXT verification, SAML SP metadata
  URLs, and the `node:dns`-on-Workers caveat.
- [`docs/scim.md`](./docs/scim.md) — SCIM Users (upstream) vs. Groups (this package), the
  `ResourceTypes` limitation, and Okta/Entra ID setup notes.
- [`docs/security.md`](./docs/security.md) — the one accepted advisory, secrets/token storage,
  audit chain limits, retention/GDPR, and this package's trusted-publishing setup.

## Development

```sh
mise exec node@22 -- pnpm install
mise exec node@22 -- pnpm typecheck
mise exec node@22 -- pnpm lint
mise exec node@22 -- pnpm format:check
mise exec node@22 -- pnpm test
mise exec node@22 -- pnpm build
```

Node `>=22` is required for the toolchain itself, separately from the package's own
`engines.node` — Node 25 is known-broken for this repo's jsdom/happy-dom-based tests
(`mise exec node@22 -- <cmd>` pins the working version regardless of your global default).
