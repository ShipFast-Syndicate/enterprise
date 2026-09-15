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
    user who generated its token as defense in depth, and `scim({ storeSCIMToken: "hashed" })`
    so a leaked database row is never itself a usable bearer token — neither flag is
    configurable through `EnterpriseOptions`.
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

## Secrets and token storage

- **SCIM bearer tokens** are stored hashed (`storeSCIMToken: "hashed"`, non-configurable — see
  above) and bound to the organization that generated them. A token is shown to the admin
  exactly once at creation time (`<ab-scim-tokens>`); it cannot be retrieved again, only revoked
  and replaced.
- **`secretsKey`** (`EnterpriseOptions.secretsKey`, minimum 32 characters) encrypts IdP client
  secrets (OIDC `clientSecret`, SAML SP private keys passed via `samlSpKeys`) at rest. Generate
  it once per deployment and store it the same way every other product secret is stored — a 1Password
  Service Account item, never checked into a repo or product config file.
- **The CLI's `--token` flag** (`ab-enterprise verify`/`audit-verify`) is visible in `ps` output
  and shell history. Prefer the `TURSO_AUTH_TOKEN` environment variable — every error message the
  CLI prints already names it, and both commands read it as the default when `--token` is
  omitted.
- No `console.*`/`logger.*` call site in `src/**` ever logs a `clientSecret`, `scimToken`,
  `privateKey`, or the contents of `secretsKey` — verified line-by-line for the 2026-09-15 audit
  (part 1, §7 "Code-adjacent quick checks"). `/sso/register`'s own redaction of `clientSecret`
  before it reaches a browser client is application logic in scope for that audit's part 2, not
  this document.

## Audit chain limits

- The hash chain (`audit_event.prev_hash`/`hash`) is **per organization**, not global — `seq`
  restarts at 1 for each org, and `ab-enterprise audit-verify --org <id>` verifies one org's
  chain at a time.
- **Retention deletes, it does not redact.** `purgeExpired` (`src/server/audit/plugin.ts`) hard-
  deletes rows older than `audit.retentionDays` (default 365) on a rolling basis. `verifyChain`
  only ever sees the rows still present: once the oldest rows in a chain have aged out, the
  remaining chain verifies as intact from its new first row onward. Retention and tamper-evidence
  are therefore two different guarantees — `audit-verify` proves nothing was altered **within the
  retention window**, not that nothing was ever deleted before it.
- **A sign-in-path audit write failure does not block sign-in.** Per the design's error-handling
  rule, an audit write failure on any admin/config-changing path fails that action; on the
  sign-in path specifically it is logged (`enterprise-audit: failed to write audit row`) and the
  sign-in proceeds — an IdP or database outage must never lock out users. That is a deliberate
  availability-over-completeness trade-off: a sign-in under those conditions can leave no audit
  row at all.
- Audit writes are not guaranteed to be transactional with the change they describe across every
  backing store — see the design spec (`2026-09-15-studio-enterprise-layer-design.md` §5, "Error
  handling") for which libSQL adapter behaviour this depends on.

## Retention and GDPR

`audit_event` rows carry personal data (actor id, IP address, user agent) and are governed by
the same `audit.retentionDays` setting described above (default 365 days, rolling deletion, per
org). A product embedding this package is responsible for setting a retention period consistent
with its own privacy policy and any data-subject-deletion obligations — this package has no
separate "delete this user's audit history on request" primitive; a full org-level purge (delete
the organization) removes its `audit_event` rows along with everything else scoped to that org.

## Trusted publishing and npm provenance

`@alphabros/enterprise` publishes via **npm trusted publishing** (OIDC), not a long-lived
`NPM_TOKEN`. `.github/workflows/release.yml`'s `publish` job runs on a GitHub-hosted
`ubuntu-latest` runner (npm's OIDC flow does not work on self-hosted runners) with
`permissions: { id-token: write, contents: read }` and the `npm` deployment environment, then
runs `npm publish --provenance --access public`. No npm token exists anywhere in this repo's
secrets, workflows, or history.

**Trusted publisher configuration** (set on npmjs.com against the `@alphabros/enterprise`
package, by whoever holds publish rights — org-admin/Bastien, not code):

| Setting | Value |
| --- | --- |
| Organization or user | `ShipFast-Syndicate` |
| Repository | `enterprise` |
| Workflow filename | `release.yml` |
| Environment | `npm` |

### Manual first publish (0.1.0)

npm's trusted-publisher configuration can only be attached to a package that **already exists**
on the registry — there is no trusted-publishing path for the very first version of a brand-new
package. The 0.1.0 release is therefore published manually, once, by Bastien:

1. Confirm the `@alphabros` npm organization/scope exists and the publishing account has rights
   to it (`npm org ls alphabros` or the npmjs.com org page).
2. `npm login` (interactive; never pipe a token into this).
3. From a clean checkout of the tagged `v0.1.0` commit: `pnpm install --frozen-lockfile && pnpm build`.
4. `npm publish --access public` (no `--provenance` on a manual publish from a local machine —
   provenance requires the CI OIDC identity; the first publish is the one exception).
5. Configure the trusted publisher (table above) on the now-existing package.
6. Every release after 0.1.0 goes through `release.yml`'s `publish` job automatically, with
   provenance.

### Before first publish — checklist

From the 2026-09-15 security audit
(`.superpowers/sdd/2026-09-15-enterprise-v0.1/security-audit-part1-repo-supply-chain.md`),
split by who does it:

**Done in this task (Claude, code/config):**

- [x] `publishConfig: { access: "public", provenance: true }` in `package.json`.
- [x] `LICENSE` file (MIT, Alpha Bros, 2026).
- [x] `repository`, `homepage`, `bugs`, `author`, `keywords` in `package.json`.
- [x] README rewritten for a public npm landing page (no `.superpowers/` reference).
- [x] Committed test SAML private key removed; keys generated at test runtime instead (see
  below) — verified clean on the working tree.
- [x] `sideEffects: ["./dist/portal/*"]`, `"./package.json"` added to `exports`,
  `peerDependenciesMeta` marking `lit`/`drizzle-orm`/`@libsql/client` optional,
  `@better-auth/core`/`better-call` promoted to `peerDependencies`.
- [x] `release.yml`: trusted publishing (no `NPM_TOKEN`), explicit secrets (no
  `secrets: inherit`), `concurrency` block added.
- [x] `.releaserc.json`: `conventionalcommits` preset set (matches the already-present,
  previously-unused `conventional-changelog-conventionalcommits` devDependency).
- [x] `vitest.config.ts` coverage excludes `**/*.sql`.

**Still needed — Bastien / org-admin, before the first publish:**

- [ ] Grant `STUDIO_ARTIFACT_S3` (+ `REVIEWER_APP_*`, `AUDITS_TG_*`, `CF_ACCESS_*`) to this repo
  so `ci / summary` can go green (R7).
- [ ] Grant `RELEASE_APP_ID` + `RELEASE_APP_PRIVATE_KEY` to this repo's Actions secrets, and
  confirm the release App is a bypass actor on the `main` branch ruleset (14754562) (P3, P7). No
  `NPM_TOKEN` is needed — publishing is trusted-publishing/OIDC only.
- [ ] Confirm the `@alphabros` npm scope exists and perform the manual 0.1.0 publish (above),
  then configure the trusted publisher on the now-existing package.
- [ ] Flip the repo to public — after every item above, and after deciding R6 below.
- [ ] Enable secret scanning + push protection, Dependabot alerts + security updates, and CodeQL
  default setup (R1).
- [ ] Decide whether `docs/superpowers/plans/2026-09-15-enterprise-v0.1.md` (internal design doc,
  no secrets, but exposes internal architecture/fleet conventions) stays committed once the repo
  goes public, or moves under the git-ignored `.superpowers/` path (R6).
- [ ] Turn off "Allow GitHub Actions to approve pull requests"; require ≥ 1 approval on `main`;
  add `non_fast_forward` to the `develop` ruleset; set `sha_pinning_required: true` (R4, R3, R2).

## Test key history note

The SAML end-to-end tests (`test/e2e/saml.test.ts`) previously ran against a static, committed
RSA key pair (`test/helpers/fixtures/saml-keys.ts`, added in commit `c8ec57eb`). That file has
been **removed**: the same module now generates a fresh RSA-2048 key pair and self-signed X.509
certificate at test time (`@peculiar/x509` + Node's built-in WebCrypto), keeping the same
exported names (`IDP_KEY`, `IDP_CERT`, `SP_KEY`, `SP_CERT`) so nothing importing them had to
change. The generated material:

- is never written to disk,
- is never used outside this repo's own test run,
- was never anything but a throwaway fixture even in its committed form (30-day validity,
  self-signed, `CN=spike-idp`/`CN=spike-sp` test-only common names).

**The old key pair still exists in this repository's git history** at commit `c8ec57eb` and
cannot be un-committed without a history rewrite (out of scope for this change). `gitleaks
detect` run against full history will continue to report it — this is expected and accepted:
the key was never used for anything but this test suite, was never deployed anywhere, and is
rotated by construction going forward (every test run mints a new pair). Do not allowlist the
historical path in `.gitleaks.toml`; the working tree itself is clean, which is what matters for
every scan of the current codebase (dependency review, `npm pack`, a fresh clone).
