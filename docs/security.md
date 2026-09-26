# Security

## Patched SCIM dependency

GHSA-j8v8-g9cx-5qf4 affects `@better-auth/scim >=1.5.0 <1.7.0-beta.4`.
The complete Better Auth peer set is now pinned to **1.7.5**. The audit suppression
has been removed. This is a breaking provisioning migration; see
[the migration guide](./migration-1-7.md). Legacy management endpoints and the
custom Groups bearer parser are no longer mounted or exported.

The portal authorizes every catalog request against the explicit organization.
Only owners mint, rotate or decommission tokens; owners and admins may list. A
decommission never bans a user who holds an `owner` membership anywhere (SCIM cannot
produce one, so it is always a manual grant) — the skipped ban is audited and their API
keys are still revoked like everyone else's (see "API keys" below).
Native bearer authentication binds a credential to one connection and provisioning
domain. Users and Groups enforce the same `scim` entitlement before mutation.

## Secrets and token storage

- **SCIM bearer tokens** use the native catalog's HMAC digest. Supply an independent
  `scimCredentialHashSecret` of at least 32 characters; never reuse `secretsKey`.
  Credentials expire after 365 days. Creation and rotation show the token once and
  return `Cache-Control: no-store`. Rotation invalidates old credentials in the same
  transaction as the new credential and audit write. Decommission revokes access
  and may require continuation until reconciliation completes.
- **`secretsKey`** (`EnterpriseOptions.secretsKey`, minimum 32 characters) encrypts the
  **per-provider** secret material on the `ssoProvider` row at rest: `oidcConfig.clientSecret`,
  and `samlConfig`'s `privateKey`, `privateKeyPass`, `decryptionPvk`, `encPrivateKey` and
  `encPrivateKeyPass` (including inside a nested `spMetadata`). Generate it once per deployment
  and store it the same way every other product secret is stored — a 1Password Service Account
  item, never checked into a repo or product config file.
- **What is _not_ encrypted.** Everything else on `ssoProvider` is stored exactly as upstream
  stores it, in the clear: `samlConfig`'s `cert`, `idpMetadata` and `entryPoint`, the issuer, the
  domain. That is public IdP material, not secrets. And the **`samlSpKeys` option is reserved and
  unused** — `enterprisePreset` cannot pass it to `@better-auth/sso@1.7.5`, which has no
  plugin-level slot for a shared SP signing identity, so its value never reaches the database and
  no at-rest guarantee applies to it. If you set it, read it back yourself and put it in your own
  `/sso/register` body's `samlConfig.spMetadata`, where the per-provider encryption above does
  cover the private-key fields. Wiring the option properly is a P2 item, gated on upstream.
- **The CLI's `--token` flag** (`ab-enterprise verify`/`audit-verify`) is visible in `ps` output
  and shell history. Prefer the `TURSO_AUTH_TOKEN` environment variable — every error message the
  CLI prints already names it, and both commands read it as the default when `--token` is
  omitted.
- No `console.*`/`logger.*` call site in `src/**` ever logs a `clientSecret`, `scimToken`,
  `privateKey`, or the contents of `secretsKey` — verified line-by-line for the 2026-09-15 audit
  (part 1, §7 "Code-adjacent quick checks"). `/sso/register`'s own redaction of `clientSecret`
  before it reaches a browser client is application logic in scope for that audit's part 2, not
  this document.

## Policy resolution and enforcement points

`org_policy` is enforced against the **union of every organization with a claim on the user**,
never against one "chosen" org:

- **Which orgs.** `resolvePolicyOrgsForUser` (`src/server/policy/enforcement.ts`) collects the
  request's active organization, every org the user holds a `member` row in, and every org owning
  a domain-verified SSO provider whose `domain` list authorises the user's e-mail domain
  (`findOrgsByEmailDomain` — comma-separated lists, case-insensitive, subdomains, the same rules
  upstream `@better-auth/sso` applies). An empty set means no policy applies (free agents are
  unchanged). A non-empty set is never narrowed by ambiguity: the old resolver returned _no_ org
  for a user in two or more orgs, so any member could shed their org's `ssoEnforced`/
  `allowedMethods` by creating a second organization (F-03). Self-serve org creation stays on
  (`organization.allowUserToCreateOrganization`, default `true`) precisely because it is no longer
  an escape hatch. The `member` scan (`memberOrgIds`, `src/server/policy/store.ts`) is paginated
  in upstream's 100-row `findMany` unit and fails closed past 5000 memberships
  (`POLICY_MEMBERSHIP_SCAN_OVERFLOW`, 500): an unpaginated scan silently dropped the 101st row, so
  a member who first self-created 100 orgs shed the restricted org's claim. The preset leaves
  upstream's `organization.organizationLimit` unset (unlimited self-serve orgs); that is a product
  decision each integrator can tighten, not a security control this layer relies on.
- **Effective policy** (`getEffectivePolicy`, `src/server/policy/store.ts`): `ssoEnforced` is OR
  over the orgs where the user is _not_ that org's break-glass user; `allowedMethods` is the
  intersection over the same orgs; `sessionMaxAgeS` is the minimum over all orgs; `require2fa` is
  OR over all orgs. **Break-glass is per org** — the break-glass owner of org A is still bound by
  org B's rules. Two orgs whose `allowedMethods` do not overlap lock their shared member out of
  every sign-in method; that is the configuration, not a bug — check the intersection before
  narrowing a list.
- **Where.** `databaseHooks.session.create.before` is the backstop every sign-in path funnels
  through _after_ upstream has checked the credential (password, social, passkey, magic link, the
  SSO callback itself). The only pre-authentication hook left is on `/magic-link/verify`, whose
  pending token — not a guessable address — is what identifies the user. `/sign-in/email` and
  `/sign-in/magic-link` are deliberately no longer pre-flighted: answering `SSO_REQUIRED` before
  the password was checked told a stranger "this address belongs to an SSO-enforced org" (audit
  gap 3); a wrong password is now a plain `401`.
- **Classification** (`classifySessionCreate`): the path creating the session maps to a method
  name (`password`, `magic_link`, `passkey`, `sso`, the social provider id) which `allowedMethods`
  binds once some org has narrowed the list; a _continuation_ (`/two-factor/verify-*`,
  `/two-factor/enable|disable`, `/change-password`, `/admin/impersonate-user`, and `/verify-email`
  **only for an already-signed-in user**) re-issues a session inside a flow whose method was already
  enforced and is never refused as a method; anything else is **unknown** and is refused
  (`METHOD_NOT_ALLOWED`) for a user under any restriction (audit gap 4). `/verify-email` is
  reachable unauthenticated — the emailed token is the whole credential — and upstream mints a
  brand-new session there for a user with no current session when
  `emailVerification.autoSignInAfterVerification` is set (the deferred sign-in of a
  `requireEmailVerification` sign-up, which itself creates no session) and in the change-e-mail
  branches; that session is enforced as `magic_link`, not exempted. A continuation is recognised only
  when the request already carries a session for the same user. A product that ships a sign-in
  plugin this preset does not (e-mail OTP, phone, username, generic OAuth, SIWE, …) declares it in
  `policy.signInMethods` (`"/sign-in/email-otp": "email_otp"`, or a prefix `"/phone/*": "phone"`);
  the declared names become valid `allowedMethods` values on `POST /enterprise/policy/set`. Whether
  an org _narrows_ sign-in is judged against the **full method vocabulary** (the 8 built-ins plus
  every declared name), not the built-ins alone: an org allows a declared method only if its stored
  `allowedMethods` list contains it, or the org has no `org_policy` row at all, or its row lists the
  full vocabulary. A row that stores exactly the 8 built-ins while the product declares `email_otp`
  excludes `email_otp` — an org must be able to exclude a declared method without also dropping a
  built-in. Consequently, declaring a new `signInMethods` entry requires every org with an existing
  `org_policy` row (written for _any_ field — the row stores the built-in default list when
  `allowedMethods` was never sent) to add the name before its members can sign in with it; orgs with
  no row are unaffected.
  - _Integrator note._ A product that sets `emailVerification.autoSignInAfterVerification` and an
    org that excludes `magic_link` from `allowedMethods` will see that org's members refused
    (`METHOD_NOT_ALLOWED`) on the verification link's auto-sign-in; the e-mail is still marked
    verified and the member signs in afterwards with an allowed method. Add `magic_link` to the
    org's list to keep the one-click flow.
- **Session cap.** `sessionMaxAgeS` is applied at creation (`expiresAt = min(requested, now +
cap)`) _and_ on every refresh: upstream `/get-session` rewrites `expiresAt = now + expiresIn`
  once `session.updateAge` has elapsed, which silently restored the global 7-day lifetime on the
  first authenticated request (F-05). `databaseHooks.session.update.before` now clamps that write to
  `createdAt + cap` for the session being refreshed. Tightening a cap below a live session's age
  ends that session at its next refresh. `session.disableSessionRefresh` and `updateAge` keep
  their upstream meaning; the cap is an upper bound on top of them, and the browser cookie's
  `Max-Age` may outlive the row (the server side is authoritative).
- **Two-factor requirement.** `require2fa` (OR over every org with a claim on the user; break-glass
  does not exempt from it) is enforced in two places (`src/server/policy/enforcement.ts`):
  - _At session creation_ (`twoFactorRefusal`): a session stands only when its sign-in method is in
    `policy.twoFactor.satisfiedBy` (default `["sso"]` — the IdP did the second factor), when
    upstream's `twoFactor()` challenge follows the path (`/sign-in/email` and the other paths that
    plugin's own after-hook names — read from the mounted plugin, so without it no path is treated as
    challenged), when the path is `/sign-up/email` (a brand-new user, confined to enrolment below), or
    when it is a continuation. Everything else — magic link, passkey, a social provider, an
    unclassified path — carries no second factor and gets none: `403 TWO_FACTOR_REQUIRED`
    (`METHOD_NOT_ALLOWED` for the unclassified path), enrolled or not. A product that ships a
    challenged sign-in plugin (`username`, `phone-number`) declares it in `policy.signInMethods` and
    it stands for the same reason; a method that carries a second factor by itself (a passkey policy,
    an OTP plugin the product vouches for) is named in `satisfiedBy`.
  - _On every request_ (`buildTwoFactorEnrollmentGate`, a `hooks.before` outside
    `TWO_FACTOR_ENROLLMENT_ALLOWED_PATHS`): a signed-in user who **holds a password** (upstream's
    `/two-factor/enable` re-authenticates with it — `findCredentialAccount`, the same read) and has
    not enrolled is answered `403 TWO_FACTOR_ENROLLMENT_REQUIRED` with the allow-list in the body:
    `/get-session`, `/sign-out`, `/enterprise/home-realm`, `/two-factor/enable|get-totp-uri|verify-totp|send-otp|verify-otp`,
    plus the product's `policy.twoFactor.enrollmentPaths`. The first successful
    `/two-factor/verify-totp` flips `twoFactorEnabled` and lifts the gate. A user with no password
    (SSO- or magic-link-only) cannot enrol here and is not gated; their second factor is the method
    that satisfied the policy. The gate reads nothing beyond one indexed `org_policy` probe on a
    deployment where no org requires a second factor.
  - `/get-session` carries `enterprise: { require2fa, twoFactorEnabled, enrollmentRequired }` for a
    user under such a policy; `enrollmentRequired` is exactly the state the gate refuses on, so a
    product redirects to its enrolment UI on that flag.
  - Switching `require2fa` on (`POST /enterprise/policy/set`, the `false → true` transition) needs a
    caller who is enrolled or cannot enrol (`400 REQUIRE_2FA_PRECONDITION` otherwise): an un-enrolled
    admin would lock themselves out of this very endpoint on the next request.
  - API keys are unaffected (a key never creates a session and reaches `/get-session` only).
- **SCIM-required JIT** (`src/server/policy/scim-required.ts`) refuses an SSO-callback account
  creation — from the per-provider `/sso/callback/:providerId`, the shared `/sso/callback` that
  `@better-auth/sso` registers unconditionally, or the SAML ACS — when _any_ org matched by the
  e-mail domain has a live SCIM connection; the SSO
  test-login finish and `/enterprise/sso/register` use the same domain matcher, and register stores
  the normalised list (trimmed, lower-cased, de-duplicated) or refuses one that could never match
  (`SSO_DOMAIN_INVALID`).
- **SSO domain binding** (`src/server/policy/sso-jit.ts`, F-01): before any policy logic, a
  session minted by an SSO callback — and a user row created by one — requires the signing
  provider to be domain-verified for the user's e-mail domain (`SSO_DOMAIN_NOT_ALLOWED`;
  `SSO_PROVIDER_UNRESOLVED` when the provider cannot be named from the route or the
  server-trusted OAuth state). `ssoEnforced` is then satisfied only by the enforcing org's own
  IdP: on an SSO callback the provider's org must be one of the orgs enforcing SSO on the user
  and, when verified providers claim the e-mail domain at all, one of those. Details and the
  opt-outs in [`sso.md`](./sso.md#domain-binding-ssodomainbinding-default-verified-domain).
- **API keys** (`src/server/api-keys.ts`). Policy governs _sessions_; an API key never creates
  one, so `ssoEnforced`, `allowedMethods`, `sessionMaxAgeS` and `require2fa` do not apply to a
  key. Keys are instead bound to the user at use time and bounded by expiry: the preset's
  `customAPIKeyValidator` re-reads the user row on every use (`/api-key/verify` and, if a product
  opts into `enableSessionForAPIKeys`, the `x-api-key` mock session) and refuses a banned user
  (`USER_BANNED`; an expired temporary ban is not a ban) or a key whose user no longer exists
  (`USER_NOT_FOUND`); an unknown key stays upstream's `INVALID_API_KEY`. New keys expire after
  `apiKeys.defaultExpiresInS` (90 days; `null` = never unless the caller asks) and may never be
  created for longer than `apiKeys.maxExpiresInDays` (365). Every deprovisioning path revokes the
  user's keys and audits `api_key.revoked` (one row per key) into every organization the user
  belonged to — captured before the rows go: `/admin/ban-user` and `/admin/remove-user` (actor =
  the admin, reason `admin.ban` / `admin.remove`) and a SCIM deactivation, IdP delete or
  connection decommission (actor `scim`, reason `scim.deactivate`; the provisioning organization
  is handed over by the SCIM projector in-transaction, since its membership row is already gone).
  Revoking sessions alone (`/admin/revoke-user-sessions`, `/revoke-sessions`) is deliberately not
  a key revocation: the identity is unchanged. The expiry bound also holds on update:
  `/api-key/update { expiresIn: null }` (which upstream accepts and writes as "never") is refused
  with `400 API_KEY_EXPIRY_REQUIRED` unless the operator chose `apiKeys.defaultExpiresInS: null`;
  a finite lifetime still goes through upstream's ceiling check. Finally, a request that carries
  an API key reaches an **allow-list** of endpoints and nothing else: over HTTP, `/get-session`
  only (`API_KEY_ALLOWED_PATHS` in `src/server/api-keys.ts`); server-side, upstream's own
  `auth.api.verifyApiKey` call (it has no HTTP route; the validator recognises it by the key it
  hands over in its body, `isApiKeyVerifyCall`). Every other better-auth endpoint answers
  `403 API_KEY_NOT_ALLOWED_HERE`, before any session or org resolution and whether or not the
  mock session is on — the management surface (`/enterprise/*`), every gated path
  (`GATED_PATHS`), every key, organization, SSO-provider, account and credential write, every
  other read (`/list-sessions`, which returns raw session tokens; `/list-accounts`,
  `/organization/*`, `/api-key/list|get`, `/sso/providers`, …), every sign-in flow, `/admin/*`,
  `/two-factor/*`, the other path-less server-only calls (`viewBackupCodes`, SCIM token minting,
  JWT signing, …) and every endpoint of a plugin you add that this package has never heard of
  (`jwt()`'s `/token`, `oneTimeToken()`'s `/one-time-token/generate`, your own). The list is an
  allow-list rather than a deny-list because a deny-list is fail-open for every endpoint it does
  not know; it was built from what the fleet products do with a key — each resolves the key's
  owner through `auth.api.getSession({ headers })` and nothing else — and widening it is a
  reviewed change to this package on evidence, not a per-product option. The refusal is enforced
  twice: inside `enterpriseApiKeyValidator` — before the key is even looked up, so it holds
  however the key is carried and a refused request never counts against the key's rate limit —
  and by the gate on the `x-api-key` header alone on every HTTP-routable path, so it also holds
  under the preset default (where upstream ignores the header) and next to a valid session
  cookie. `/get-session` with a stray `x-api-key` header next to a session cookie still answers
  the cookie's session under the default, so products that forward the whole incoming request
  into `getSession` are unaffected.
- **Opting into the mock session.** Set `apiKeys.enableSessionForAPIKeys: true` on the preset:
  it builds upstream's `apiKey()` with the validator, the header list and the expiry bound
  already in place, and that is the supported recipe. With it on, a key authenticates its owner
  to `/get-session` — the one thing a product's own API handler needs — and to nothing else (the
  allow-list above); with `bearer()` mounted the key is still not a session token. Upstream's
  per-key rate limit stays at its default of **10 requests per key per 24 h** unless you set
  `apiKeys.rateLimit` (`{ enabled, maxRequests, timeWindow }` in ms, forwarded as-is; validated
  at preset build): size it for your API or set `enabled: false` and rate-limit in your own
  layer — `maxRequests`/`timeWindow` are stamped on each key at create, `enabled: false` applies
  to every key at use, and a refused request never counts. A product that instead replaces the
  preset's `api-key` plugin with its own `apiKey({ enableSessionForAPIKeys: true, ... })` must
  keep `customAPIKeyValidator: enterpriseApiKeyValidator` (the one layer every carrier passes
  through), `apiKeyHeaders: [...API_KEY_HEADERS]` (so the gate's header-alone layer still sees
  the key) and a `keyExpiration` matching the preset (`defaultExpiresIn` in **seconds**,
  `maxExpiresIn` in days) — omitting it restores perpetual keys at create. A
  `customAPIKeyGetter` or another header name is still confined to the allow-list by the
  validator, but forfeits the header-alone layer.

## Upgrading from 1.0.x

1.0.x let any tenant's domain-verified IdP create and sign in accounts for **any** e-mail
address on the deployment (GHSA-8p84-pc7q-69jr). 1.1.0 binds every SSO sign-in to the signing
provider's verified domain, so an account a foreign IdP squatted before the upgrade can no
longer sign in through it — but the rows are still there, and the legitimate user is still
locked out of their own IdP until they are removed (upstream refuses to link a second provider
to an unverified account). Run this on each database before or right after upgrading:

```sql
-- account rows linked to an SSO provider that is not verified for the user's e-mail domain
SELECT a.id AS account_id, a.providerId, u.id AS user_id, u.email, p.domain, p.organizationId
FROM account a
JOIN user u ON u.id = a.userId
JOIN ssoProvider p ON p.providerId = a.providerId
WHERE p.domainVerified = 0
   OR NOT (
     ',' || lower(replace(p.domain, ' ', '')) || ',' LIKE '%,' || lower(substr(u.email, instr(u.email, '@') + 1)) || ',%'
     OR lower(substr(u.email, instr(u.email, '@') + 1)) LIKE '%.' || lower(replace(p.domain, ' ', ''))
   );
```

(The `LIKE` covers exact and single-entry subdomain matches; review comma-list providers by
hand.) For every row: delete the foreign `account` row, revoke the user's sessions
(`DELETE FROM session WHERE userId = ?`), and check `member` rows the squat's auto-join created
in the attacker's org. If the squatted address belongs to a real person, the account is theirs
once the foreign link is gone — the next sign-in through their own IdP links it.

Other pre-upgrade checks for this release:

```sql
-- providers without an organization (impossible to create in 1.1.0; skipped by every org read)
SELECT providerId, domain, domainVerified FROM ssoProvider WHERE organizationId IS NULL;
-- two organizations holding verified rows for one domain (e-mail sign-in is not pinned for them)
SELECT lower(domain) AS domain, count(DISTINCT organizationId) AS orgs
FROM ssoProvider WHERE domainVerified = 1 GROUP BY lower(domain) HAVING orgs > 1;
-- pending invitations whose invitee exists but is unverified (cannot accept until verified)
SELECT i.email FROM invitation i JOIN user u ON lower(u.email) = lower(i.email)
WHERE i.status = 'pending' AND u.emailVerified = 0;
```

`require2fa` is enforced from 1.1.0 on (it was surfaced on `/get-session` only before). Every org
whose `org_policy` row already has `require_2fa = 1` starts enforcing at upgrade: its members who
hold a password and have not enrolled are confined to the enrolment allow-list
(`TWO_FACTOR_ENROLLMENT_REQUIRED`) and its members who sign in with a magic link, a passkey or a
social provider are refused (`TWO_FACTOR_REQUIRED`) unless `policy.twoFactor.satisfiedBy` names
that method. There is no grace period. Check first, and add a redirect-to-enrolment on
`enterprise.enrollmentRequired` in the product before upgrading:

```sql
-- organizations that will start enforcing at upgrade
SELECT org_id FROM org_policy WHERE require_2fa = 1;
-- their members who hold a password and have not enrolled (confined to enrolment)
SELECT DISTINCT u.id, u.email FROM org_policy p
JOIN member m ON m.organizationId = p.org_id
JOIN user u ON u.id = m.userId
JOIN account a ON a.userId = u.id AND a.providerId = 'credential'
WHERE p.require_2fa = 1 AND (u.twoFactorEnabled IS NULL OR u.twoFactorEnabled = 0);
```

API keys minted before 1.1.0 keep the lifetime they were created with (none, unless the caller
chose one) — the new default applies to new keys only. A key whose user is banned or gone is
refused at use from the first request after the upgrade, but its row is still stored until the
user is deprovisioned again through one of the audited paths; to find and clear them, and to
review perpetual keys:

```sql
-- keys of banned users (refused at use as USER_BANNED) and orphan keys (USER_NOT_FOUND)
SELECT k.id, k.referenceId, k.name, k.expiresAt FROM apikey k
LEFT JOIN user u ON u.id = k.referenceId
WHERE u.id IS NULL OR (u.banned = 1 AND (u.banExpires IS NULL OR u.banExpires > strftime('%s','now') * 1000));
-- keys that never expire
SELECT k.id, k.referenceId, k.name, u.email FROM apikey k JOIN user u ON u.id = k.referenceId
WHERE k.expiresAt IS NULL;
```

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
  they said. The write path agrees with this: after compaction leaves an anchor as an org's last
  row (completed or still-`retention_compacting`), the next row appended to that org's chain
  chains its `prev_hash` from the anchor's `metadata.lastHash`, not the anchor's own `hash` —
  otherwise a full-chain compaction would leave the org reporting `ok:false` forever, from the
  very next write on.
- **Compaction is crash-safe without a transaction.** The anchor row is written **before** the
  delete, in three steps: insert it with `action: audit.retention_compacting`, delete the
  expired prefix, then flip the action to `audit.retention_compacted` (recomputing its hash,
  since `action` is part of the hashed payload). `verifyChain` reads both states — a pending
  anchor still sitting in front of its prefix means the delete never ran, so the original chain
  is verified from `GENESIS` and the anchor ignored; a pending anchor whose prefix is already
  gone is treated exactly like a completed one. Either way the chain verifies `ok` and the next
  compaction sweeps the stale pending anchor away with the prefix it stands for, because the
  anchor always takes the `seq` one below every row the org currently holds. (Before this, a
  crash between the delete and the anchor's creation left the prefix gone with nothing to
  re-anchor on, and `verify` reported tampering for that org permanently, with no recovery
  path.) The compaction algorithm remains unchanged; SCIM operations use native transactions.
- **Compaction is triggered by a read.** It runs on `GET /enterprise/audit/list` — already
  owner/admin-only and feature-gated — because a deployment with no scheduler has no other
  reliable trigger, and on demand via `POST /enterprise/audit/compact` (same authorization).
  So an owner or admin opening the audit viewer is what actually enforces `retentionDays`, and
  the destructive step happens inside a request they did not explicitly mark as destructive.
  That is deliberate; run the explicit endpoint from a job if you would rather control when it
  happens, and note that `audit.retentionDays` is validated (`>= 1`) at construction so a `0`
  cannot compact a whole chain on the next read.
- **What the anchor costs.** Within the limits already documented above, the anchor makes
  _prefix_ deletion cheaper for an attacker who can write the database directly: instead of
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

| Setting              | Value                |
| -------------------- | -------------------- |
| Organization or user | `ShipFast-Syndicate` |
| Repository           | `enterprise`         |
| Workflow filename    | `release.yml`        |
| Environment          | `npm`                |

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
(private audit archive, `bros-brain/projects/enterprise/audits/`),
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

- [x] `STUDIO_ARTIFACT_S3`, `REVIEWER_APP_*`, `AUDITS_TG_*` granted to this repo (2026-09-16); `ci / summary` green.
- [x] `RELEASE_APP_ID` + `RELEASE_APP_PRIVATE_KEY` granted (2026-09-16); the release App is the
      `main` ruleset's bypass actor. No `NPM_TOKEN` — publishing is trusted-publishing/OIDC only.
- [ ] Confirm the `@alphabros` npm scope exists and perform the manual 0.1.0 publish (above),
      then configure the trusted publisher on the now-existing package.
- [ ] Flip the repo to public — after every item above, and after deciding R6 below.
- [x] Secret scanning + push protection and Dependabot alerts + security updates enabled
      (2026-09-16); CodeQL default setup once the repo is public (R1).
- [x] The internal implementation plan moved out of the repo into the private vault (R6, 2026-09-16).
- [x] "Allow GitHub Actions to approve pull requests" turned off (2026-09-16).
- [ ] Require ≥ 1 approval on `main`;
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
(private audit archive `bros-brain/projects/enterprise/audits/`, 31 findings:
4 High, 8 Medium, 10 Low, 9 Info) ran against `feat/v0.1-package`. Everything below was fixed
before the first publish, each with a regression test in `test/security/` that reproduces the
audit's own exploit (failing before the fix, passing after).

### High

| id   | finding                                                                                                                                                                                                                  | fix                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | test                                                                                                                                                       |
| ---- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| C-01 | Any authenticated user could append rows to **any other tenant's** audit chain with `?orgId=<victim>`, with attacker-controlled `user_agent`, and `verify` still said `ok`                                               | `resolveOrgId` (`src/server/audit/plugin.ts`) resolves the org from the SCIM bearer's own provider row, then the SSO provider row, then the session — a body/query org id is honoured **only** when the resolved actor holds a `member` row in it. Anything else skips the write with a warning. A `hooks.before` captures the caller's session so `/sign-out` (which deletes it) stays audited                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | `test/security/c01-audit-org-injection.test.ts`                                                                                                            |
| C-02 | Retention deleted rows out from under the hash chain, so `verify` reported `{"ok":false,"brokenAtSeq":…}` **permanently** after any row aged out — during entirely normal operation                                      | Retention is archival **compaction** now (`compactChain`, `src/server/audit/chain.ts`): the expired prefix is replaced by one `audit.retention_compacted` anchor row carrying `{compactedThroughSeq, compactedCount, lastHash}`, whose `prev_hash` is that `lastHash`; `verifyChain` re-anchors on it. Tampering _inside_ the surviving window is still caught. Compaction still runs from `GET /enterprise/audit/list` (owner/admin, feature-gated) and is now also available deliberately as `POST /enterprise/audit/compact`                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | `test/security/c02-retention-compaction.test.ts`                                                                                                           |
| C-03 | A SCIM group change rewrote `member.role` wholesale, so adding an existing **owner** or **admin** to any group demoted them to `member` (with two owners, either could be stripped) and multi-role values were flattened | `recomputeRoleForUser` (`src/server/scim-groups/plugin.ts`) never touches an `owner`, never overwrites a multi-role value, never touches a role outside `owner`/`admin`/`member`, always allows a _raise_, and only _lowers_ a role the effective `groupRoleMap` itself grants somewhere. Every skip is audited as `scim.role_change_skipped` with a reason                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | `test/security/c03-scim-role-demotion.test.ts`                                                                                                             |
| C-04 | `secretsKey` was declared, documented (spec §7.4) and **never read** — IdP `clientSecret` and SAML private keys sat in the database in plaintext                                                                         | `src/server/secrets.ts` wraps `context.adapter` from `enterpriseGate`'s `init()` and transparently encrypts/decrypts `ssoProvider.oidcConfig.clientSecret` plus the `samlConfig` private-key fields with AES-256-GCM (Web Crypto; key = SHA-256 of `secretsKey`; random 12-byte IV; **AAD = the provider's `providerId`**, so a ciphertext copied onto another provider row never yields the plaintext instead of silently re-pointing a live IdP credential; `enc:v1:<base64url>`). Values without the prefix are read back untouched, so existing rows migrate on next write. The write path **always** encrypts — an `enc:v1:` prefix in caller data is never trusted as "already sealed" (F-06, audit 3) — and a field that cannot be decrypted (rotated key, corrupted or transplanted ciphertext) is reported through the logger and left sealed for that one provider rather than failing every unfiltered read. `enterpriseGate` validates the options too, so a hand-composed plugin list is covered | `test/security/c04-secrets-at-rest.test.ts` (ciphertext asserted with raw SQL; `test/e2e/oidc.test.ts` proves the real OIDC callback still gets plaintext) |

### Medium

| id   | fix                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | test                                              |
| ---- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------- |
| M-01 | `groupRoleMap` may target `admin`/`member` only — refused by the type, by `POST /enterprise/policy/set` (400 `GROUP_ROLE_MAP_OWNER_FORBIDDEN`), and at runtime in `resolveGroupRoleMap`, which drops an `owner` entry arriving from a stale policy row or the static `EnterpriseOptions.scim.groupRoleMap` with a warning; only an **owner** may write `groupRoleMap`/`breakGlassUserId` or mint a SCIM token (enforced on both `/enterprise/scim/tokens/create` and upstream `/scim/generate-token`). Admins keep the listing; revoke (a decommission since 1.7) became owner-only in 1.1.0 (F-07, audit 3, `test/security/f07-scim-revoke-owner-only.test.ts`) | `test/security/m01-privilege-escalation.test.ts`  |
| M-02 | Every exported CSV cell starting with `= + - @ TAB CR` is prefixed with `'`, RFC 4180 quoting unchanged                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | `test/security/m02-csv-injection.test.ts`         |
| M-03 | A global `hooks.before` on `/scim/v2/*` resolves the org from the bearer (`authenticateScimBearer`) and requires the `scim` feature, covering our Groups endpoints _and_ upstream's Users endpoints; refusal is a SCIM-shaped 403 body. An unauthenticated call still gets the endpoint's own 401                                                                                                                                                                                                                                                                                                                                                                | `test/security/m03-scim-entitlement-gate.test.ts` |
| M-04 | `parseFilter` and the `members[value eq "…"]` patch-path parser are hand-written linear tokenizers behind a 512-character cap; `members`/`Operations` arrays are capped at the schema boundary. The audit's 64 000-space input went from **9.3 s** to under 1 ms                                                                                                                                                                                                                                                                                                                                                                                                 | `test/security/m04-filter-redos.test.ts`          |
| M-05 | `/enterprise/audit/export` is capped (`audit.exportMaxRows`, default 100 000) and answers `413 AUDIT_EXPORT_TOO_LARGE` past it, pointing at `from`/`to`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | `test/security/m05-m08-hardening.test.ts`         |
| M-06 | `breakGlassUserId` must be an owner of the org on **every** write, not only when `ssoEnforced` is being turned on (`400 BREAK_GLASS_NOT_OWNER`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | same file                                         |
| M-07 | Membership/role is checked **before** entitlement everywhere (gate hook and each endpoint), so a non-member never reaches the product's `resolveEntitlements` and cannot distinguish a real org from an invented one                                                                                                                                                                                                                                                                                                                                                                                                                                             | same file                                         |
| M-08 | `GET /enterprise/sso/providers`, `GET /enterprise/scim/tokens` and `GET /enterprise/policy` are owner/admin only                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | same file                                         |

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
  written by an owner/admin who completed a real SSO login against a _verified_ domain.
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
