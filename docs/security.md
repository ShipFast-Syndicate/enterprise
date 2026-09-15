# Security

## Accepted advisories

### GHSA-j8v8-g9cx-5qf4 — `@better-auth/scim` account/provider takeover via missing owner binding

- **Affected versions:** `@better-auth/scim` `>=1.5.0 <1.7.0-beta.4`. This package is pinned
  exact to `1.6.33` (see the [better-auth version pin](../README.md)); the fix ships only in
  the `1.7` line, which this repo does not yet track.
- **Why it does not apply here:** the advisory is that a SCIM provider created *without* an
  `organizationId` (a "personal" provider) has no owner binding and can be taken over. This
  package never allows that state to exist:
  - `enterpriseGate` (`src/server/gate.ts`) requires `organizationId` explicitly in the request
    body for `/scim/generate-token` and `/scim/delete-provider-connection` — unlike every other
    gated path, it never falls back to the session's active organization. A request without an
    explicit `organizationId` is rejected before it reaches `@better-auth/scim`, so no
    org-less ("personal") provider row is ever created.
  - The preset (`src/server/preset.ts`) additionally passes
    `scim({ providerOwnership: { enabled: true } })`, binding each provider connection to the
    user who generated its token as defense in depth.
- **Test that guards it:** `test/server/gate.test.ts`, describe block "SCIM provider paths
  never fall back to the session's active org" — specifically "POST /scim/generate-token
  without organizationId returns 400 ORG_REQUIRED, even with an active org, and creates no
  scimProvider row". If this test ever starts failing (or is removed), the advisory applies
  again and this acceptance must be revisited.
- **Suppressed via:** `pnpm.auditConfig.ignoreGhsas` in `package.json`, so `pnpm audit` — and
  the hub CI `quality / audit` gate — stay green without hiding any *other* finding.
- **Revisit trigger:** when the fleet moves its better-auth peer set off the `1.6.x` line onto
  `1.7.x` or later (which ships the fix), drop this entry and the `ignoreGhsas` suppression, and
  re-run `pnpm audit` to confirm it is clear on its own.
