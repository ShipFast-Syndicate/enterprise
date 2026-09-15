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
- **Retention deletes, it does not redact — and it leaves an anchor behind.** `compactChain`
  (`src/server/audit/chain.ts`) removes rows older than `audit.retentionDays` (default 365) on a
  rolling basis and replaces the whole removed prefix with one `audit.retention_compacted` row
  carrying `{compactedThroughSeq, compactedCount, lastHash}`. `verifyChain` re-anchors on that
  row, so a compacted chain still verifies `ok` (before the 2026-09-15 security pass this was a
  bare delete, and `verify` then reported tampering forever — see C-02 below). Retention and
  tamper-evidence remain two different guarantees: `audit-verify` proves nothing was altered
  **within the retention window**, and the anchor row records how many rows left it, not what
  they said.
- **Compaction is triggered by a read.** It runs on `GET /enterprise/audit/list` — already
  owner/admin-only and feature-gated — because a deployment with no scheduler has no other
  reliable trigger, and on demand via `POST /enterprise/audit/compact` (same authorization).
  So an owner or admin opening the audit viewer is what actually enforces `retentionDays`, and
  the destructive step happens inside a request they did not explicitly mark as destructive.
  That is deliberate; run the explicit endpoint from a job if you would rather control when it
  happens, and note that `audit.retentionDays` is validated (`>= 1`) at construction so a `0`
  cannot compact a whole chain on the next read.
- **What the anchor costs.** Within the limits already documented above, the anchor makes
  *prefix* deletion cheaper for an attacker who can write the database directly: instead of
  recomputing every surviving row's hash, they can forge one anchor whose `prev_hash` and
  `metadata.lastHash` match the next row's `prev_hash`, and its `compactedCount` is
  unverifiable. That is weaker than the pre-C-02 chain for that one scenario and much stronger
  for the one that actually happens (routine retention, which used to report tampering
  forever). A periodic signed off-box checkpoint is the post-v0.1 fix for both.
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
runs `npm publish --provenance --access public`. The `--provenance` flag is passed explicitly on
that command line — `package.json`'s own `publishConfig` only sets `access: "public"`, nothing
about provenance, since provenance is meaningful only from a CI OIDC identity and would be
misleading (or simply ignored) on a manual publish. No npm token exists anywhere in this repo's
secrets, workflows, or history. The `publish` job is also idempotent: before publishing it
checks `npm view "@alphabros/enterprise@<version>"` for the version in the checked-out tag's
`package.json`, and skips the publish step (with a notice) if that version already exists on the
registry — so re-running the job by hand is a safe no-op.

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
4. `npm publish --access public` — no `--provenance` flag on this manual step; provenance
   requires the CI OIDC identity, which a local `npm login` session doesn't have. This is the
   one and only manual, non-provenance publish this package ever gets.
5. Configure the trusted publisher (table above) on the now-existing package.
6. CI adds provenance from the second release on: every release after 0.1.0 goes through
   `release.yml`'s `publish` job automatically, which runs `npm publish --provenance --access public`.

### Before first publish — checklist

From the 2026-09-15 security audit
(`.superpowers/sdd/2026-09-15-enterprise-v0.1/security-audit-part1-repo-supply-chain.md`),
split by who does it:

**Done in this task (Claude, code/config):**

- [x] `publishConfig: { access: "public" }` in `package.json` (provenance is not a
  `publishConfig` setting here — `release.yml`'s `publish` job passes `--provenance` explicitly
  on the command line, since it's only meaningful from CI's OIDC identity).
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

## Fixed in the pre-publish security pass

The 2026-09-15 code-level security audit
(`.superpowers/sdd/2026-09-15-enterprise-v0.1/security-audit-part2-code.md`, 31 findings:
4 High, 8 Medium, 10 Low, 9 Info) ran against `feat/v0.1-package`. Everything below was fixed
before the first publish, each with a regression test in `test/security/` that reproduces the
audit's own exploit (failing before the fix, passing after).

### High

| id | finding | fix | test |
| --- | --- | --- | --- |
| C-01 | Any authenticated user could append rows to **any other tenant's** audit chain with `?orgId=<victim>`, with attacker-controlled `user_agent`, and `verify` still said `ok` | `resolveOrgId` (`src/server/audit/plugin.ts`) resolves the org from the SCIM bearer's own provider row, then the SSO provider row, then the session — a body/query org id is honoured **only** when the resolved actor holds a `member` row in it. Anything else skips the write with a warning. A `hooks.before` captures the caller's session so `/sign-out` (which deletes it) stays audited | `test/security/c01-audit-org-injection.test.ts` |
| C-02 | Retention deleted rows out from under the hash chain, so `verify` reported `{"ok":false,"brokenAtSeq":…}` **permanently** after any row aged out — during entirely normal operation | Retention is archival **compaction** now (`compactChain`, `src/server/audit/chain.ts`): the expired prefix is replaced by one `audit.retention_compacted` anchor row carrying `{compactedThroughSeq, compactedCount, lastHash}`, whose `prev_hash` is that `lastHash`; `verifyChain` re-anchors on it. Tampering *inside* the surviving window is still caught. Compaction still runs from `GET /enterprise/audit/list` (owner/admin, feature-gated) and is now also available deliberately as `POST /enterprise/audit/compact` | `test/security/c02-retention-compaction.test.ts` |
| C-03 | A SCIM group change rewrote `member.role` wholesale, so adding an existing **owner** or **admin** to any group demoted them to `member` (with two owners, either could be stripped) and multi-role values were flattened | `recomputeRoleForUser` (`src/server/scim-groups/plugin.ts`) never touches an `owner`, never overwrites a multi-role value, never touches a role outside `owner`/`admin`/`member`, always allows a *raise*, and only *lowers* a role the effective `groupRoleMap` itself grants somewhere. Every skip is audited as `scim.role_change_skipped` with a reason | `test/security/c03-scim-role-demotion.test.ts` |
| C-04 | `secretsKey` was declared, documented (spec §7.4) and **never read** — IdP `clientSecret` and SAML private keys sat in the database in plaintext | `src/server/secrets.ts` wraps `context.adapter` from `enterpriseGate`'s `init()` and transparently encrypts/decrypts `ssoProvider.oidcConfig.clientSecret` plus the `samlConfig` private-key fields with AES-256-GCM (Web Crypto; key = SHA-256 of `secretsKey`; random 12-byte IV; **AAD = the provider's `providerId`**, so a ciphertext copied onto another provider row fails to decrypt instead of silently re-pointing a live IdP credential; `enc:v1:<base64url>`). Values without the prefix are read back untouched, so existing rows migrate on next write. `enterpriseGate` validates the options too, so a hand-composed plugin list is covered | `test/security/c04-secrets-at-rest.test.ts` (ciphertext asserted with raw SQL; `test/e2e/oidc.test.ts` proves the real OIDC callback still gets plaintext) |

### Medium

| id | fix | test |
| --- | --- | --- |
| M-01 | `groupRoleMap` may target `admin`/`member` only — refused by the type, by `POST /enterprise/policy/set` (400 `GROUP_ROLE_MAP_OWNER_FORBIDDEN`), and at runtime in `resolveGroupRoleMap`, which drops an `owner` entry arriving from a stale policy row or the static `EnterpriseOptions.scim.groupRoleMap` with a warning; only an **owner** may write `groupRoleMap`/`breakGlassUserId` or mint a SCIM token (enforced on both `/enterprise/scim/tokens/create` and upstream `/scim/generate-token`). Admins keep list/revoke | `test/security/m01-privilege-escalation.test.ts` |
| M-02 | Every exported CSV cell starting with `= + - @ TAB CR` is prefixed with `'`, RFC 4180 quoting unchanged | `test/security/m02-csv-injection.test.ts` |
| M-03 | A global `hooks.before` on `/scim/v2/*` resolves the org from the bearer (`authenticateScimBearer`) and requires the `scim` feature, covering our Groups endpoints *and* upstream's Users endpoints; refusal is a SCIM-shaped 403 body. An unauthenticated call still gets the endpoint's own 401 | `test/security/m03-scim-entitlement-gate.test.ts` |
| M-04 | `parseFilter` and the `members[value eq "…"]` patch-path parser are hand-written linear tokenizers behind a 512-character cap; `members`/`Operations` arrays are capped at the schema boundary. The audit's 64 000-space input went from **9.3 s** to under 1 ms | `test/security/m04-filter-redos.test.ts` |
| M-05 | `/enterprise/audit/export` is capped (`audit.exportMaxRows`, default 100 000) and answers `413 AUDIT_EXPORT_TOO_LARGE` past it, pointing at `from`/`to` | `test/security/m05-m08-hardening.test.ts` |
| M-06 | `breakGlassUserId` must be an owner of the org on **every** write, not only when `ssoEnforced` is being turned on (`400 BREAK_GLASS_NOT_OWNER`) | same file |
| M-07 | Membership/role is checked **before** entitlement everywhere (gate hook and each endpoint), so a non-member never reaches the product's `resolveEntitlements` and cannot distinguish a real org from an invented one | same file |
| M-08 | `GET /enterprise/sso/providers`, `GET /enterprise/scim/tokens` and `GET /enterprise/policy` are owner/admin only | same file |

**Deviation from the audit's M-07 remediation, recorded per the controller ruling.** The audit
asked for "one indistinguishable `403` for both" membership and entitlement failures. This
package keeps `FEATURE_NOT_ENTITLED` distinct **for actual members of the org**, because the
design (§3, D3) makes entitlements a product-visible concept and the admin portal renders an
upgrade path from exactly that code. The oracle the finding describes is closed anyway: an
outsider gets `NOT_ORG_MEMBER` for every org id — real, entitled, unentitled or invented — and
`resolveEntitlements` is never invoked on their behalf. Only someone who already belongs to the
org can tell the two apart, and for them the plan is not a secret.

### Low — fixed

- **L-02** the per-org audit mutex `Map` evicts once an org's chain settles (`pendingOrgLockCount`
  guards it); the multi-instance caveat is unchanged and documented in the source.
- **L-03** unique-constraint detection matches driver codes (`SQLITE_CONSTRAINT_UNIQUE`, `23505`,
  `ER_DUP_ENTRY`, …) in addition to the message regex, which stays as the fallback because the
  drizzle/libsql path frequently rewraps the error.
- **L-04** `<ab-sso-wizard>`'s default `openWindow` passes `noopener,noreferrer` (reverse
  tabnabbing from the IdP page).
- **L-05** `orgId` is sanitised to `[A-Za-z0-9_-]` before it is interpolated into
  `content-disposition`.
- **L-06** `ab-enterprise --token` still works but prints a warning naming `TURSO_AUTH_TOKEN`.
- **L-08** `secretsKey` is validated (`>= 32` characters) in `enterprisePreset()`, now that C-04
  makes it load-bearing.

### Low — deferred (tracked for the nomi/klar pilot, none a publish blocker)

- **L-01 — audit-write failure becomes a 500 on non-sign-in paths.** Fixing it properly means
  allocating `seq` inside the same transaction as the write, which the generic better-auth
  adapter does not expose; the single retry plus the unique index stays the mitigation. Deferred
  to P2 with the transactional-audit question the design spec (§5, "Error handling") already
  parks.
- **L-07 — `POST /enterprise/home-realm` leaks `providerId`.** The endpoint is public by
  controller ruling; removing `providerId` from the response changes the published client
  contract (`src/client/home-realm.ts` and its consumers), so it is deferred to the next minor
  rather than slipped into the publish pass. Mitigation in place: 10 requests/minute/IP, and the
  response depends only on the domain, never on whether the email is a real user.
  **That rate limit only bites if the embedding product keeps better-auth's global
  `rateLimit.enabled` on.** It is a plugin-declared rule, and better-auth disables rate limiting
  outside production by default (`options.rateLimit?.enabled ?? isProduction`), so a product
  that ships with it off has an unmetered domain-enumeration endpoint — enable it in whatever
  environment faces traffic.
- **L-09 — `ab-sso-test-ok:<providerId>` survives provider reconfiguration.** Needs a config
  fingerprint keyed alongside the provider and invalidation on every `/sso/register` update — a
  design change to the test-login precondition, deferred to P2. Mitigation: the row can only be
  written by an owner/admin who completed a real SSO login against a *verified* domain.
- **L-10 — `findOrgByEmailDomain` is first-match-wins across providers claiming one domain.**
  Requires a uniqueness constraint on `(domain)` among `domainVerified` providers plus a
  migration; deferred to P2. Mitigation: a domain can only become `domainVerified` by proving
  DNS control of it, so two orgs claiming the same verified domain implies control of that
  domain by both.

### Info items adopted without a finding

- `policy.groupRoleMap ?? opts.scim?.groupRoleMap ?? {}` could never reach the second operand
  (`defaultPolicy` returns `{}`, which is not nullish), so `EnterpriseOptions.scim.groupRoleMap`
  silently did nothing. It is now used when the policy row's map is empty.
- The build is a single `tsup` config with all five entries. Two sibling configs sharing one
  `dist/` raced, and `dist/cli/index.d.ts` was intermittently missing from a finished build;
  `test/cli/cli.test.ts` now asserts every entry (JS and `.d.ts`) exists after `pnpm build`.
