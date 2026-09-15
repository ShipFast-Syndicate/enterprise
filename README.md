# @alphabros/enterprise

Alpha Bros studio enterprise layer for [better-auth](https://www.better-auth.com/) 1.6.33:
SSO (SAML/OIDC), SCIM (Users + Groups), organizations, audit log, security policy, and an
admin portal.

## Status

v0.1 scaffold. This package does not yet export any functionality — see
`.superpowers/sdd/2026-09-15-enterprise-v0.1/` for the implementation plan.

## Package layout

- `./server` — better-auth server plugin (SSO/SCIM/orgs/audit/policy)
- `./schema` — drizzle table definitions + SQL migrations (`sql/`)
- `./client` — better-auth client plugin
- `./portal` — Lit-based admin portal components
- `ab-enterprise` (bin) — CLI for provisioning/migration

## Requirements

- Node >=22 (use `mise exec node@22 -- <cmd>` — Node 25 is broken for this toolchain's
  jsdom/happy-dom-based tests)
- pnpm 10 (`packageManager` field pins the exact version)
- `better-auth` and its `@better-auth/*` plugin set are peer dependencies, pinned to the
  exact version `1.6.33`

## Development

```sh
mise exec node@22 -- pnpm install
mise exec node@22 -- pnpm typecheck
mise exec node@22 -- pnpm lint
mise exec node@22 -- pnpm format:check
mise exec node@22 -- pnpm test
mise exec node@22 -- pnpm build
```
