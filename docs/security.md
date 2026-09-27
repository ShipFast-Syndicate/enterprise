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
    `TWO_FACTOR_ENROLLMENT_ALLOWED_PATHS`): a policy that came to apply **after** the session was
    minted (an org switches `require2fa` on, or the user later joins — or is domain-claimed by — an
    org that already required it) is enforced on the standing session, not only at the next sign-in.
    A signed-in user who **holds a password** (upstream's `/two-factor/enable` re-authenticates with
    it — `findCredentialAccount`, the same read) and has not enrolled is confined to the enrolment
    allow-list (`403 TWO_FACTOR_ENROLLMENT_REQUIRED` with the list in the body): `/get-session`,
    `/sign-out`, `/enterprise/home-realm`, `/two-factor/enable|get-totp-uri|verify-totp|send-otp|verify-otp`,
    plus the product's `policy.twoFactor.enrollmentPaths`. The first successful
    `/two-factor/verify-totp` flips `twoFactorEnabled` and lifts the gate. A user with **no password**
    (SSO-, magic-link-, social- or passkey-only) cannot enrol here: their session stands only when it
    was **judged under the requirement when it was created** — see the next point — and is otherwise
    refused (`403 TWO_FACTOR_REQUIRED`); the user signs in again, through a method that satisfies the
    policy or not at all. An impersonation session (upstream's `impersonatedBy`) is admitted as a
    continuation of the admin's sign-in and never judged for the impersonated user, so impersonating
    such a user yields a refused session. The session is resolved through the same path the endpoint
    will use, so a session carried by `Authorization: Bearer` (upstream's `bearer()` plugin) is judged
    like a cookie one. The gate reads nothing beyond one small `org_policy` probe on a deployment where
    no org requires a second factor.
  - _Which sessions were judged — timestamps, no new column._ Every session created while the
    requirement applies to its user went through the creation rule above. So the requirement has an
    **onset** per user — the latest, over the orgs that require it, of the org's
    `org_policy.updated_at` and the user's `member.createdAt` in it — and a no-password session
    stands only if its `session.createdAt` is **strictly after** that onset. Timestamps are compared in
    epoch milliseconds whatever unit a product keeps them in (a `session.created_at` in whole seconds
    next to millisecond policy and membership stamps is a common Drizzle layout); a stamp that falls on a
    whole second is read as the last millisecond of that second, and a stamp that cannot be read makes
    the session not stand. The creation rule stamps each session it admits for a named method with a
    `createdAt` at the start of the second after next, so a judged session never reads as "not after"
    its onset — even in a seconds column, and even when `@better-auth/sso` provisions the membership
    just after creating the session in the same callback. Consequences, all fail-closed:
    - switching `require2fa` on signs out, once, every member who holds no password and is not
      enrolled (their next sign-in is judged) — the admin who switched it included;
    - **any** later edit of a requiring org's policy (any field) moves `updated_at` and does the same
      for every session admitted more than about two seconds before the edit — a session admitted
      within that window carries a `createdAt` stamp still later than the edit and keeps standing (no
      privilege follows: the creation rule admitted it whichever org imposes the requirement);
    - joining a requiring org re-judges the joiner's older sessions;
    - an org that claims a user only through its verified e-mail domain, without a membership,
      contributes its `updated_at` alone (`ssoProvider` records no time for a domain verification).
      Such a claim gives no access to that org's data; the org's members are judged by membership.
      The refresh clamp does not extend a session that does not stand, so `/get-session` cannot renew one
      indefinitely.
  - `/get-session` — and therefore `auth.api.getSession({ headers })`, which is what products
    authorize their own routes with — answers **`null`** for a session that does not stand (a
    no-password user's session that was never judged under the requirement): the product sees a
    signed-out visitor, with no flag to interpret. For any other user under such a policy it carries
    `enterprise: { require2fa, twoFactorEnabled, enrollmentRequired }`; `enrollmentRequired: true` is
    the enrolment-only session of a password holder who has not enrolled — the only session under the
    requirement that is presented while confined — so a product that offers password sign-in
    redirects to its enrolment UI on that flag and must not treat such a session as fully signed in.
  - Switching `require2fa` on (`POST /enterprise/policy/set`, the `false → true` transition) needs a
    caller who can sign in again afterwards (`400 REQUIRE_2FA_PRECONDITION` otherwise, row
    unchanged): the caller has enrolled a second factor, **or** `policy.twoFactor.satisfiedBy`
    includes `sso` and this org owns a verified SSO provider for the caller's e-mail domain. A
    magic-link- or social-only admin cannot switch it on — they could never sign in under it, and the
    org would be left with nobody able to switch it off.
  - API keys: a key stands in for its owner's session, so with the opt-in mock session
    (`apiKeys.enableSessionForAPIKeys`) — and on `auth.api.verifyApiKey` — the key's **owner** is
    judged by the same rule, with the `apikey` row's own `createdAt` in place of the session's
    (`apiKeyOwnerTwoFactorStanding`, run inside `enterpriseApiKeyValidator` before upstream builds
    the mock session): an enrolled owner stands; an owner who holds a password and has not enrolled
    is refused (a key cannot carry `enrollmentRequired`); a no-password owner's key stands only if it
    was created strictly after the requirement's onset for them (`/api-key/create` is refused to a
    session that does not stand, so such a key was minted by a judged session). A refused key yields
    no session: `/get-session` with it answers `null` over HTTP and through
    `auth.api.getSession({ headers })`, as for a cookie session that does not stand, and
    `verifyApiKey` answers `{ valid: false }` with `TWO_FACTOR_REQUIRED` or
    `TWO_FACTOR_ENROLLMENT_REQUIRED`. Consequences: switching `require2fa` on, a later policy edit and
    joining a requiring org make a no-password member's older keys stop working (they mint a new one
    from a session that satisfies the policy); an un-enrolled password holder's keys work again once
    they enrol. A key minted within the same whole second as the onset, in a product whose `apikey`
    timestamps keep whole seconds, reads as not after it and is refused.
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
- **API keys** (`src/server/api-keys.ts`). An API key never signs in and never creates a session,
  so `ssoEnforced`, `allowedMethods` and `sessionMaxAgeS` — which govern sign-in and a session's
  lifetime — do not apply to a key. `require2fa` does: a key stands in for its owner's session, so
  its owner is judged on every use by the session rule (previous section, "API keys"). Keys are
  also bound to the user at use time and bounded by expiry: the preset's `customAPIKeyValidator`
  re-reads the user row on every use (`/api-key/verify` and, if a product opts into
  `enableSessionForAPIKeys`, the `x-api-key` mock session) and refuses a banned user
  (`USER_BANNED`; an expired temporary ban is not a ban), a key whose user no longer exists
  (`USER_NOT_FOUND`), or an owner who does not stand under `require2fa`
  (`TWO_FACTOR_ENROLLMENT_REQUIRED`, `TWO_FACTOR_REQUIRED`); an unknown key stays upstream's
  `INVALID_API_KEY`. New keys expire after
  `apiKeys.defaultExpiresInS` (90 days; `null` = never unless the caller asks) and may never be
  created for longer than `apiKeys.maxExpiresInDays` (365). The following deprovisioning paths
  revoke the user's keys and audit `api_key.revoked` (one row per key) into every organization
  the user belonged to — captured before the rows go: `/admin/ban-user` and `/admin/remove-user`
  (actor = the admin, reason `admin.ban` / `admin.remove`) and a SCIM deactivation, IdP delete or
  connection decommission (actor `scim`, reason `scim.deactivate`; the provisioning organization
  is handed over by the SCIM projector in-transaction, since its membership row is already gone).
  Revoking sessions alone (`/admin/revoke-user-sessions`, `/revoke-sessions`) or removing an
  organization membership is deliberately not a key revocation: the identity is unchanged.
  Removing a user at the identity provider without SCIM does not revoke keys either: the
  application receives no signal. Ban the user or delete their keys. The expiry bound also holds
  on update:
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
  not know; it was built from how integrators use a key — resolving the key's
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
  `maxExpiresIn` in days) — omitting it restores perpetual keys at create — and should mount
  `apiKeySessionStanding()` directly before its `apiKey()` (the preset does): that plugin's
  `/get-session` hook withdraws a key whose owner does not stand under `require2fa` before
  upstream's hook answers from it, so the product sees `null`. Without it the validator still
  refuses such a key, as a `403` (`auth.api.getSession` then throws instead of returning
  `null`). A `customAPIKeyGetter` or another header name is still confined to the allow-list
  and judged by the validator, but forfeits the header-alone layer and the `null` answer.

## SSO providers without an organization

Changing or deleting an SSO provider (`/sso/update-provider`, `/sso/delete-provider`) needs the
`sso` entitlement of the organization that owns the provider, like registering one (F-17). The
org is the stored provider's `organizationId` — never one the request names — and the caller
must be a member of it (upstream then requires owner or admin); anyone else gets
`403 NOT_ORG_MEMBER`, an unentitled org `403 FEATURE_NOT_ENTITLED`.

A provider without an organization — a "personal" provider that `/sso/register` accepted before
1.1.0 required `organizationId` (docs/sso.md, "Providers belong to organizations") — has no org
to be entitled, so it is refused with `403 NOT_ORG_MEMBER`, its creator included. The gate is a
`hooks.before` handler, so a server-side `auth.api.updateSSOProvider` / `deleteSSOProvider` call
made with a user's headers is refused the same way. Find such rows with
`SELECT "providerId", "domain" FROM "ssoProvider" WHERE "organizationId" IS NULL` (column names
as in your schema); a deployment that never registered a provider without an organization has
none. An operator manages one in either of two ways:

- **Bind it to the organization it serves**:
  `UPDATE "ssoProvider" SET "organizationId" = '<org id>' WHERE "providerId" = '<provider id>'`.
  From then on it is that org's provider — its owners and admins update or delete it through the
  gated endpoints, under the org's `sso` entitlement, and the domain rules of docs/sso.md apply
  to it like to any other.
- **Remove it and register it again under the organization**: delete the legacy row directly —
  the two deletes upstream's `/sso/delete-provider` performs,
  `DELETE FROM "account" WHERE "providerId" = '<provider id>'` then
  `DELETE FROM "ssoProvider" WHERE "providerId" = '<provider id>'` — and register the provider
  through `/sso/register` with `organizationId`, as an owner or admin of that org.

Either change happens outside the application, so no audit row records it; note it in your own
change log.

## Upgrading from 1.0.x

The step-by-step guide, the full behaviour table, the new options and the error codes are in
[`docs/upgrading-to-1.1.md`](./upgrading-to-1.1.md); this section holds the details it links to.
Table and column names in the queries below are this package's and better-auth's defaults;
adjust them to your schema if the package's tables were created under other names.

1.1.0 binds every SSO sign-in to the signing provider's verified domain (GHSA-8p84-pc7q-69jr).
An `account` row that links a user to a provider **not** verified for that user's e-mail domain
can no longer sign in, but the row stays in the database until it is removed, and while it is
there the user cannot link their own organization's provider (upstream refuses to link a second
provider to an unverified account). Run this on each database before or right after upgrading:

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
hand.) For every row: delete the `account` row, revoke the user's sessions
(`DELETE FROM session WHERE userId = ?`), and review the `member` rows the provider's JIT
auto-join created in the provider's organization. Once the row is gone, the user's next sign-in
through their own organization's IdP links that provider.

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
that method. There is no grace period.

The upgrade changes **no schema** — no column is added to `session`, `member`, `user` or
`org_policy`, so a product's hand-maintained Drizzle tables need no edit. It ships one **data-only**
migration, `0003_require2fa.sql`: it moves `org_policy.updated_at` of every `require_2fa = 1` row to
the moment it runs (keeping the column's unit, rounded up). Sessions that exist at that moment were
minted by 1.0.x, which never judged them against the requirement; moving the onset past them makes
them unjudged, so a member who holds no password and is not enrolled signs in again once (an SSO
sign-in then satisfies the policy). Apply it as part of the upgrade, **once**, through the product's
own migrator:

- **A product whose package tables came from its own migration** (for example a hand-written
  `NNNN_enterprise_pilot.sql`, possibly followed by its own copy of `0002`) runs
  `ab-enterprise migrate --out <drizzle migrations folder> --from 0003`, once for **every**
  folder it migrates from (one per environment lineage, if it keeps several). It writes exactly one
  file, `NNNN_enterprise_0003_require2fa.sql`, next-numbered and registered in
  `meta/_journal.json` after the product's own entries, and a second run writes nothing. Never
  the full emit: `0001` and `0002` would re-run `ALTER TABLE`s that product's own migration
  already applied (or target tables it named differently), and its migrator stops on the first
  one (`no such table: organization`, `duplicate column name: id`). Alternatively add `0003`'s
  statement as a hand-numbered migration of the product's own. If a full emit already happened,
  remove every emitted file other than `NNNN_enterprise_0003_require2fa.sql` **and** its
  `meta/_journal.json` entry — deleting the file alone makes the migrator fail on the missing
  file.
- **Any other 1.0.x install runs `--from 0003` too, whatever wrote its `0001`** — including a
  folder that holds the `NNNN_enterprise.sql` an earlier release of this command wrote. Every
  release up to 1.0.x wrote `0001` only, and the 1.0.0 upgrade
  ([`docs/migration-1-7.md`](./migration-1-7.md) step 4) applied `0002` through
  `applyMigration()` or a product migration of its own, so the database already has `0002`'s
  `org_policy.id` column; emitting `0002` again stops the migrator on
  `duplicate column name: id`. Only a folder coming straight from **0.1.x**, which never applied
  `0002`, takes both: `ab-enterprise migrate --out <folder> --from 0002`. A plain run on a folder
  holding this command's `0001` but no `0002` of its own cannot tell the two apart, so it stops
  with exit 1, writes nothing and names both `--from 0003` (from 1.0.x) and `--from 0002` (from
  0.1.x).

The command recognises nothing it cannot prove: a file counts as an earlier emission only when it
carries the name this command gives that migration **and** the package file's own content
(breakpoint markers aside — every release wrote exactly that). Without `--from`, a folder holding
any other `*enterprise*.sql` file is refused with exit 1 and nothing written, naming the file and
`--from`, and so is a folder holding this command's `0001` without its `0002` (above); a file
under an emitted name with other content is refused whatever `--from` says. A plain run is for an
empty folder (a new install) or one whose `0002` this command wrote.
Journal entries it adds start after the newest `when` already in the journal, so the migrator never
skips them. `applyMigration()` runs every file on each call, and a second run of `0003` signs those
members out once more. Where no org has `require_2fa = 1`, `0003` changes nothing.

Check first, and add a redirect-to-enrolment on `enterprise.enrollmentRequired` in a product that
offers password sign-in before upgrading:

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

## Audit log coverage

Every endpoint the preset mounts is in exactly one of three tables in
`src/server/audit/routes.ts` — audited by the plugin (`AUDITED_PATHS`), auditing itself
(`SELF_AUDITED_PATHS`), or deliberately unaudited with the reason (`UNAUDITED_PATHS`,
`UNAUDITED_SERVER_ONLY_ENDPOINTS`) — and `test/security/audit-cluster-routes.test.ts` fails for
any mounted endpoint and method in none of them, so an upstream bump that adds an endpoint is a
failing test until someone decides. Independently of the tables, **any** request that mints a
session is recorded as `auth.sign_in` (with `metadata.path` when the path is not in the table)
and any request that ends in a policy refusal as `auth.sign_in_refused` — a product's own
sign-in plugin (email OTP, generic OAuth, …) is never a silent way in.

**Which chain a row goes to — one row per organization, each in its own chain.** A caller's
`?orgId=` / body `orgId` is never consulted, except by the two endpoints that themselves
require the caller to be an owner or admin of exactly that org (`/enterprise/policy/set`, and
the export, which records itself).

| Scope         | Organizations written to                                                                                                                                                                                                                                                 |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `subject`     | every org with a claim on the user the event is about — their memberships **and** every org owning a verified SSO domain for their e-mail (the union policy uses); for a failed sign-in of an unknown address, the domain orgs only                                      |
| `target-user` | every org of the user an `/admin/*` action targets, resolved before the endpoint runs (removal deletes the memberships)                                                                                                                                                  |
| `resource`    | the org of the member/invitation/team/organization the endpoint acted on, read from that resource (a join lands in the org joined); never an org the request names — not the body's, not `?organizationId=`, not the active org                                          |
| `provider`    | the org owning the SSO provider the endpoint acts on — the `:providerId` route parameter where the route has one, else `body.providerId` (read before the endpoint runs, so a deletion is still attributed); SSO sign-ins go to the provider's org as well as the user's |
| `scim`        | the SCIM bearer's own provisioning org                                                                                                                                                                                                                                   |
| `request-org` | the org in the body field the endpoint reads (`orgId` on `/enterprise/policy/set`), written only when the endpoint (owner/admin of exactly that org) succeeded                                                                                                           |

**Actions.** Sign-in steps (`*`): success = a session was minted (a refreshed or re-issued
session is not); a 2FA challenge instead of a session is `auth.sign_in_2fa_pending`; an error is
`auth.sign_in_failed` (`auth.sso_sign_in_failed` on the SSO callbacks), or
`auth.sign_in_refused` when this package refused it with a policy code (`SSO_REQUIRED`,
`METHOD_NOT_ALLOWED`, `TWO_FACTOR_REQUIRED`, `TWO_FACTOR_ENROLLMENT_REQUIRED`,
`SSO_DOMAIN_NOT_ALLOWED`, `SSO_PROVIDER_UNRESOLVED`, `SSO_ISSUER_NOT_ALLOWED`,
`SCIM_PROVISIONING_REQUIRED`, `SCIM_USER_NOT_ACTIVE` — `POLICY_REFUSAL_CODES`). A refusal is
recognised only from the package's own code, which marks the request it refuses
(`policyRefusal`), never from the text of the error: a redirect's `error=` starts from a
callback URL the caller chose, and an IdP error response names whatever code it likes, so a
policy code arriving that way is a failed sign-in with that code as its label. On a redirect the
recorded code is the **last** `error` parameter (upstream appends its own after the caller's
URL). A refused SSO sign-in reaches the org owning
the asserted address's domain too, not only the signing provider's org. A refusal thrown by a
`hooks.before` handler (the `/magic-link/verify` pre-flight) is written by `auditRefusal` before
the throw and flagged, so it is recorded once; the `require2fa` enrolment gate records
`auth.session_refused` once per user, code and org every 10 minutes per process, not on every
request of a confined session.

| Scope         | Path → action                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `subject`     | `/sign-in/email`\*, `/sign-in/social`\* (idToken), `/callback/:id`\*, `/magic-link/verify`\*, `/passkey/verify-authentication`\*, `/two-factor/verify-totp\|otp\|backup-code`\* → `auth.sign_in` (with a session already present, TOTP/OTP enrolment → `two_factor.enabled`); `/sign-up/email`\* → `auth.sign_up`; `/verify-email`\* → `auth.sign_in` or `user.email_verified`; `/sso/callback[/:providerId]`\*, `/sso/saml2/sp/acs/:providerId`\* → `auth.sso_sign_in`; `/sign-in/magic-link` → `auth.magic_link_requested`; `/request-password-reset` → `user.password_reset_requested`; `/reset-password` → `user.password_reset`; `/sign-out`, `/sso/saml2/logout/:providerId` → `auth.sign_out`; `/change-password` → `user.password_changed`; `/change-email` → `user.email_change_requested`; `/update-user` → `user.updated`; `/delete-user[/callback]` → `user.deleted` / `user.deletion_requested`; `/revoke-session[s]`, `/revoke-other-sessions` → `session.revoked[_all\|_others]` (never a token); `/link-social` → `account.link_requested`; `/unlink-account` → `account.unlinked`; `/two-factor/enable` → `two_factor.enrollment_started`; `/two-factor/disable` → `two_factor.disabled`; `/two-factor/generate-backup-codes` → `two_factor.backup_codes_generated`; `/passkey/verify-registration\|update-passkey\|delete-passkey` → `passkey.registered\|updated\|deleted`; `/api-key/create\|update\|delete` → `api_key.created\|updated\|revoked` |
| `resource`    | `/organization/update` → `org.updated`; `/organization/delete` → `org.deleted` (the org's terminal row — rows outlive the organization); `/organization/leave` → `member.left`; `/organization/invite-member\|cancel-invitation\|reject-invitation\|accept-invitation\|remove-member\|update-member-role` → `member.invited\|invitation_canceled\|invitation_rejected\|joined\|removed\|role_changed`; `/organization/create-team\|update-team\|remove-team\|add-team-member\|remove-team-member` → `team.created\|updated\|removed\|member_added\|member_removed`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `target-user` | `/admin/create-user\|update-user\|set-role\|set-user-password\|ban-user\|unban-user\|remove-user\|revoke-user-session\|revoke-user-sessions` → `admin.user_created\|user_updated\|user_role_changed\|user_password_set\|user_banned\|user_unbanned\|user_removed\|user_session_revoked\|user_sessions_revoked`; `/admin/impersonate-user` → `admin.impersonation_started`; `/admin/stop-impersonating` → `admin.impersonation_stopped` (actor = the staff member — the only trace once upstream deletes the impersonation session)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `provider`    | `/sso/register\|update-provider\|delete-provider\|request-domain-verification\|verify-domain` → `sso.provider_registered\|provider_updated\|provider_deleted\|domain_verification_requested\|domain_verified` (`provider_updated` records the changed keys, never a value; `provider_deleted` the number of linked accounts deleted with it); `/sso/saml2/sp/slo/:providerId` → `auth.sso_logout`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `scim`        | `/scim/v2/Users` POST → `scim.user_created`; `/scim/v2/Users/:userId` PUT/PATCH/DELETE → `scim.user_updated\|user_deleted`; `/scim/v2/Groups[/:groupId]` → `scim.group_created\|group_updated\|group_deleted`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `request-org` | `/enterprise/policy/set` → `policy.updated` (changed keys)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |

Self-audited: `/enterprise/audit/export` → `audit.exported` (row count and range, written after
the CSV is built, so an export never contains its own row; an export that cannot be recorded is
not handed out); `/enterprise/audit/compact` and the compaction `/enterprise/audit/list`
triggers → the retention anchor names the caller as its actor; `/enterprise/scim/tokens/*` →
`scim.token_created|rotated|revoked`; `/enterprise/sso/test-login/finish` →
`sso.test_login_passed`; `/enterprise/sso/register` forwards to `/sso/register`.

**Actors.** The actor is the session making the request, never a field of the response (a role
change is attributed to the admin who made it; the member whose role changed is the target,
their user id in `metadata.targetUserId`). A request made through an impersonation session is
`actorType: "impersonated"` with `actorId` = the impersonated user and
`metadata.impersonatedBy` = the staff member; the explicit writers (`scim.token_*`,
`sso.test_login_passed`, `api_key.revoked` from `/admin/*`) follow the same rule, and so does a
retention anchor written under an impersonation session (`metadata.impersonatedBy` next to the
anchor's own keys). Failed and refused sign-ins and 2FA-pending sign-ins are
`actorType: "system"`, `actorId: null`, the user (when known) as the target, the address in
`metadata.email` only when no user exists.

**What a row takes from the request is bounded** (`src/server/audit/bounds.ts`). An address is
recorded — and used to find the organizations a request is about — only when it is a valid
e-mail address of at most 254 characters, lower-cased; a request whose address is not one (a
400 validation failure, an IdP asserting a malformed address) names no subject and writes no
row. `metadata.changed` lists at most 64 key names, each a short identifier, with the total in
`metadata.changedCount` whenever anything was left out; `metadata.role`
(`/organization/update-member-role`, `/admin/set-role`) holds at most 16 distinct role names of
at most 64 characters, comma-joined as upstream stores a role, with the number of names the
request gave in `metadata.roleCount` whenever anything was left out; error codes are recorded
only as short tokens (`UNRECOGNIZED_ERROR` otherwise); every id taken from the request — provider
ids (`target_id` of the `sso.*` rows), member, team, invitation, key, passkey and user ids,
SCIM route parameters — is recorded only as a token of at most 128 characters, else as the
marker `(unrecorded)`; the user agent is cut at 512 characters. As a backstop, `writeAudit`
itself bounds every row, whoever writes it — the plugin, refused sign-ins, SCIM, API keys, the
enterprise SCIM and SSO endpoints (including `sso.test_login_passed`) and the export row: a
`target_id`, `actor_id` or `ip` of more than 128 characters is stored as `(unrecorded)`, the
user agent is cut at 512 characters, and metadata values are kept to at most 10,000 characters
each and 16 KiB in total (a larger value is stored as `(unrecorded)`).
`test/security/audit-cluster-request-values.test.ts` sends oversized strings and lists to every
audited route and checks every stored row; `test/security/audit-cluster-writers-bounded.test.ts`
does the same for the self-audited endpoints and a direct `writeAudit` call, and checks that no
other module writes an audit row. The log's own read endpoints bound their filters the same
way: `from`/`to` on `/enterprise/audit/list` and `/enterprise/audit/export` must be whole
milliseconds in `[0, 8.64e15]` (the range a `Date` holds), else `400` before any query runs.

**Organization ids from a request.** Every organization id taken from a request — `orgId` or
`organizationId`, in the body or the query string, on every gated path and every
`/enterprise/*` endpoint — is used only when it is a non-empty string of at most 128
characters. Anything else is refused with `400` before any query runs: the gate answers
`400 ORG_ID_INVALID` (it checks every such field of the body and the query string, before it
looks up the session), and the enterprise endpoints' own validation answers `400
VALIDATION_ERROR`. A duplicated query parameter (`?orgId=A&orgId=B`) parses to a list and is
refused the same way. `test/security/audit-cluster-org-id-types.test.ts` walks every gated path
and every `/enterprise/*` endpoint with lists, objects, numbers, booleans, `null` and oversized
strings in every org-id field.

**The organization the gate checks is the one the endpoint acts on.** Each gated path declares
where its endpoint takes its organization (`GATE_ORG_SOURCES` in `src/server/gate.ts`, each entry
citing the handler line that reads it), and the gate checks membership and the entitlement for
that organization only; every other org-id field of the request is ignored, as the endpoint
ignores it. `/organization/create-team` and `/api-key/create` read `body.organizationId`, else
the session's active organization; `/sso/register` reads `body.organizationId` (required);
`/sso/update-provider`, `/sso/delete-provider`, `/sso/request-domain-verification` and
`/sso/verify-domain` read the stored provider that `body.providerId` names; each `/enterprise/*`
endpoint reads the one field its schema declares (`?orgId`, body `orgId`, or body
`organizationId` on `/enterprise/sso/register`). A gated path without a declared source is
refused with `403 GATE_ORG_SOURCE_UNDECLARED`. The gate used to take the first of
`body.organizationId`, `body.orgId`, `?orgId` and the active organization on every path, so
`/organization/create-team?orgId=<an entitled org>` created a team in an unentitled active org.
`test/security/gate-org-source.test.ts` sends, for every gated path, a request that acts on an
unentitled org and names an entitled one in every other carrier, and checks for `403` and an
unchanged database.

**Failed queries are logged without their SQL.** better-auth logs whatever error a request
throws, through the auth logger and again through `console.error`; an error from a SQL adapter
(drizzle's `DrizzleQueryError`) carries the statement and every value bound to it. `enterpriseGate`
wraps the auth adapter so that an error carrying a query leaves it as a `DatabaseQueryError`
naming only the model, the adapter method, the driver's error code (`code`, `errno`, `errcode`
and `number` are kept, so unique-violation checks still work) and, for a missing table or
column, the driver's own hint (`no such table: member`). The statement, its parameters and the
driver error it wrapped are not kept. An error carries a query when it, or an error in its
`cause` chain, has a `query`, `sql` or `params` property or drizzle's "Failed query" message.
Every other error — `APIError`s, the secrets wrapper's own errors, better-auth's own adapter
errors such as the schema mismatch or an empty `incrementOne` update — passes through unchanged,
message included. A driver error raised without any of these (for example a Postgres error
surfaced by an adapter that does not attach the statement) is not rewritten; its `detail` can
carry a value.

**Which rows can hold up a response, and which can fail it.** Rows about an address the caller
chose — failed, refused and 2FA-pending sign-ins, `/sign-in/magic-link`,
`/request-password-reset`, `/reset-password`, and a sign-up or e-mail verification that did not
mint a session — are always written off the response path through better-auth's
`runInBackground`, so a response takes the same time whether or not the address has an account
or organizations. With `advanced.backgroundTasks.handler` set, the product's handler receives
them; without it they run as detached promises. **On a serverless host (Vercel, Cloudflare
Workers, …) set `advanced.backgroundTasks: { handler: waitUntil }`** (or your platform's
equivalent): a detached promise can be cut short when the instance is frozen after the
response, and the row is then lost. `flushAuditWrites()` (server export) resolves once every
such row this process started has been written — for graceful shutdown and tests. A failure to
write one of these rows is logged, never answered. The other rows are written before the
response:

- **Soft — logged, never answered:** every sign-in step (`*` above) and any session minted on
  an unlisted path, `/sign-out`, `/sign-in/magic-link`, `/request-password-reset`,
  `/reset-password`, `/sso/saml2/logout/:providerId`, `/sso/saml2/sp/slo/:providerId`, and
  refusal rows (`auth.sign_in_refused`, `auth.session_refused`).
- **Hard — 500 `AUDIT_WRITE_FAILED`:** every other path in `AUDITED_PATHS` — among them
  `/update-user`, `/change-password`, `/change-email`, `/delete-user[/callback]`,
  `/revoke-session[s]`, `/revoke-other-sessions`, `/link-social`, `/unlink-account`,
  `/two-factor/enable|disable|generate-backup-codes`, `/passkey/*`, `/api-key/*`, every
  `/admin/*` entry, `/sso/register|update-provider|delete-provider|request-domain-verification|verify-domain`,
  every `/organization/*` entry, `/scim/v2/*` and `/enterprise/policy/set`. The after-hook runs
  once the endpoint has returned, so the change **is already committed** when this 500 is
  answered: it reports a change the log does not hold, it does not undo it. A client that sees
  it should re-read the state rather than retry blindly. The 500 holds whatever status the
  endpoint set: SCIM `POST /scim/v2/Users` (201) and `/sso/request-domain-verification` (201)
  used to answer their success status with `{"code":"AUDIT_WRITE_FAILED"}` as the body. A
  server-side `auth.api.*` call without a `Request` gets the error thrown. The failure is also
  logged (without SQL). `/enterprise/audit/export` answers the
  same 500 instead of the CSV when its `audit.exported` row cannot be written.

**Not audited, by decision** (reasons in `UNAUDITED_PATHS`): reads, flow starts
(`/sign-in/sso`, passkey option generation, `/two-factor/send-otp`, …), session preferences
(`/organization/set-active`, `/update-session`), `/organization/create` (a new tenant; its chain
starts with its first governed change), and path-less server-only endpoints (`auth.api.*`
calls the product's own code makes — audit those where they are made). A social account link
completes at `/callback/:id` without a session being minted and is recorded at
`/link-social` only.

**Refused requests leave no row, except refused sign-ins.** Event rows record changes that
happened (success only). A request refused by authorization changes nothing and writes nothing:
a `403` on a privileged endpoint (a plain member's `/organization/remove-member`, a non-staff
`/admin/*` call, an unentitled `/sso/update-provider`, a stranger's `/enterprise/policy/set`),
and a request carrying an API key refused with `403 API_KEY_NOT_ALLOWED_HERE`. The one kind of
refusal that is recorded is a sign-in refused by policy (`auth.sign_in_refused`,
`auth.session_refused`). If you need a trace of refused attempts, keep it in your HTTP access
logs.

## Audit chain limits

- **Unkeyed by default, which proves consistency, not authenticity.** Without
  `audit.chainKey`, `hash = sha256(prev_hash + "\n" + canonical(row))`: anyone with database
  write access — the DBA, a leaked database token, the very insider the log is meant to catch —
  can rewrite an org's whole chain consistently (or drop its newest rows) and `verify` still
  says `ok`. Two opt-in controls close that: **`audit.chainKey`** (≥ 32 characters, from your
  secret store, independent of `secretsKey`/`scimCredentialHashSecret`) turns every link into
  `hmac:` + HMAC-SHA256, which cannot be recomputed without the key — every writer in the
  package uses it (the plugin, refusal rows, SCIM, API-key revocation, the portal wrappers;
  they read it off the running instance, so none can forget it), and `/enterprise/audit/verify`
  and `ab-enterprise audit-verify` (key from `AB_AUDIT_CHAIN_KEY`, never argv) verify under
  it (`/enterprise/audit/verify` answers `{ ok: true, keyed }`, where `keyed` says whether the
  newest row is an HMAC link — the same flag `/enterprise/audit/head` reports; an `ok` with
  `keyed: false` proves consistency only); and **head export** — `GET /enterprise/audit/head?orgId=` (owner/admin, `audit_log`)
  returns the newest row's `seq`/`hash` and, with a key, a signature over them — which you store
  off-box on a schedule and later check with `ab-enterprise audit-verify --org <id>
--expect-head '<the JSON>'` (or `<seq>:<hash>`): a truncated or rewritten chain no longer holds
  that row. **Adoption is monotonic**: once an org's chain has a keyed row, an unkeyed row after
  it (or verification without the key) is reported as broken — so set the key once and never
  remove it; rows written before it stay unkeyed and still verify.
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
  forever). With `audit.chainKey` the forged anchor needs the key; a head exported before the
  compaction (`--expect-head`) is still checked against the anchor's `lastHash` when it was the
  last row compacted, and is reported as unconfirmable otherwise.
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
separate "delete this user's audit history on request" primitive. Deleting an organization does
**not** delete its `audit_event` rows — its chain ends with an `org.deleted` row, so the
deletion itself stays on record; a full purge deletes the org's `audit_event` rows explicitly
(`DELETE FROM audit_event WHERE org_id = ?`) once your retention obligations allow it.

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
(private audit archive),
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

## Fixed in 1.1.0

The 2026-09-25 security audit (private audit archive) of 1.0.1 and its completeness review
("gap" items) led to the changes below, released in 1.1.0 together with the GitHub security
advisories named in [the release notes](./releases/1.1.0.md). Each has regression tests that
fail on 1.0.1 and pass on 1.1.0; what an integrator sees is in
[`docs/upgrading-to-1.1.md`](./upgrading-to-1.1.md).

| id               | change in 1.1.0                                                                                                                                                                                                                                                   | tests                                                                                                                                                                                       |
| ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| F-01             | JIT user creation and every SSO session require the signing provider to be domain-verified for the user's e-mail domain (`sso.domainBinding`); `ssoEnforced` is satisfied only by the enforcing org's own IdP; accepting an invitation requires a verified e-mail | `test/security/f01-jit-domain-binding.test.ts`, `test/security/f01-invitation-verified-email.test.ts`, `test/e2e/jit.test.ts`                                                               |
| F-03             | Policy is the union over every organization with a claim on the user (active org, memberships, verified-domain claims); membership scan paginated, fail closed                                                                                                    | `test/security/ghsa-policy-bypass.test.ts`, `test/server/effective-policy.test.ts`, `test/server/policy.test.ts`                                                                            |
| F-04             | One domain matcher shared with upstream (comma lists, case-insensitive, subdomains) for home-realm, policy, JIT and SCIM rules; provider domains stored normalised                                                                                                | `test/server/domains.test.ts`, `test/server/home-realm.test.ts`, `test/security/ghsa-policy-bypass.test.ts`                                                                                 |
| F-05             | `sessionMaxAgeS` bounds session refresh as well as creation                                                                                                                                                                                                       | `test/security/ghsa-policy-bypass.test.ts`                                                                                                                                                  |
| F-06             | `ssoProvider` secret fields always encrypted on write; a field that cannot be decrypted is reported and left sealed for its own row                                                                                                                               | `test/security/f06-enc-prefix-poison.test.ts`, `test/security/c04-secrets-at-rest.test.ts`                                                                                                  |
| F-07             | SCIM decommission owner-only; an owner membership is never banned by SCIM                                                                                                                                                                                         | `test/security/f07-scim-revoke-owner-only.test.ts`, `test/security/m01-privilege-escalation.test.ts`                                                                                        |
| F-08             | Sign-in, sign-out, failed, refused and 2FA-pending sign-ins audited into every organization of the user, resolved server-side                                                                                                                                     | `test/security/audit-cluster.test.ts`, `test/security/audit-cluster-bounds.test.ts`                                                                                                         |
| F-09, F-10, F-11 | Rows attributed to the acting user and filed in the organization acted on (role changes, joins, domain verification)                                                                                                                                              | `test/security/audit-cluster.test.ts`, `test/security/audit-cluster-resource-org.test.ts`                                                                                                   |
| F-12             | Actions under impersonation recorded as `actorType: "impersonated"` with `metadata.impersonatedBy`; impersonation start/stop audited                                                                                                                              | `test/security/audit-cluster.test.ts`                                                                                                                                                       |
| F-13             | Every mounted endpoint is audited, self-audited or listed as unaudited with a reason; IdP, `/admin/*`, organization, credential, session, API-key, export and compaction changes audited                                                                          | `test/security/audit-cluster-routes.test.ts`, `test/security/audit-cluster.test.ts`, `test/security/audit-cluster-request-values.test.ts`                                                   |
| F-17             | `/sso/update-provider`, `/sso/delete-provider` gated on the stored provider's organization and its `sso` entitlement                                                                                                                                              | `test/security/f17-provider-mutation-gate.test.ts`, `test/security/gate-org-source.test.ts`                                                                                                 |
| F-21 (inverse)   | `/admin/ban-user`, `/admin/remove-user` and SCIM deprovisioning revoke the user's API keys, audited per organization                                                                                                                                              | `test/security/gap1-api-keys.test.ts`, `test/server/deprovision.test.ts`                                                                                                                    |
| F-23 (part)      | A SCIM ban skipped for an owner is audited (`scim.user_deactivation_skipped`)                                                                                                                                                                                     | `test/security/f07-scim-revoke-owner-only.test.ts`                                                                                                                                          |
| F-27 (part)      | Organization deletion is audited (`org.deleted` ends the chain); the rows are kept (see "Retention and GDPR")                                                                                                                                                     | `test/security/audit-cluster-resource-org.test.ts`                                                                                                                                          |
| F-28             | `sso.allowedIssuers` applies to the issuer, every OIDC endpoint and the SAML signing certificates (`sso.samlCertificateFingerprints`), on write and at sign-in; `trustedOrigins` documented as an SSRF/redirect boundary                                          | `test/security/f28-issuer-allowlist.test.ts`, `test/security/f28-saml-trust-root.test.ts`, `test/security/f28-samlify-signing-set.test.ts`                                                  |
| F-30             | One organization per verified domain (`SSO_DOMAIN_TAKEN`); e-mail `/sign-in/sso` pinned to the verified provider                                                                                                                                                  | `test/security/f30-domain-uniqueness.test.ts`                                                                                                                                               |
| F-38             | `ab-enterprise migrate` writes every package migration and takes `--from`                                                                                                                                                                                         | `test/cli/cli.test.ts`                                                                                                                                                                      |
| gap 1            | API keys bound to the live user, expiring by default, revoked on deprovisioning, confined to `/get-session`                                                                                                                                                       | `test/security/gap1-api-keys.test.ts`, `test/security/api-key-root-route.test.ts`, `test/portal/api-keys.test.ts`                                                                           |
| gap 2            | `require2fa` enforced at session creation, on every request and for API-key owners                                                                                                                                                                                | `test/security/gap2-require2fa*.test.ts`                                                                                                                                                    |
| gap 3            | No policy answer before the credential is checked on `/sign-in/email` and `/sign-in/magic-link`                                                                                                                                                                   | `test/security/ghsa-policy-bypass.test.ts`                                                                                                                                                  |
| gap 4            | Unclassified sign-in paths fail closed under a restricted `allowedMethods`; `policy.signInMethods`                                                                                                                                                                | `test/security/ghsa-policy-bypass.test.ts`, `test/server/policy.test.ts`                                                                                                                    |
| gap 5            | `/sso/register` requires `organizationId`                                                                                                                                                                                                                         | `test/security/gap5-personal-providers.test.ts`, `test/server/gate.test.ts`                                                                                                                 |
| gap 6            | Optional HMAC-keyed audit chain (`audit.chainKey`), head export (`GET /enterprise/audit/head`) and `audit-verify --expect-head`                                                                                                                                   | `test/server/audit-chain.test.ts`, `test/server/audit-plugin.test.ts`                                                                                                                       |
| hardening        | Organization ids from a request validated before any query; the gate checks the organization each endpoint acts on; audit rows bounded; failed adapter queries logged without SQL                                                                                 | `test/security/audit-cluster-org-id-types.test.ts`, `test/security/gate-org-source.test.ts`, `test/security/audit-cluster-writers-bounded.test.ts`, `test/security/db-errors-scope.test.ts` |

## Fixed in the pre-publish security pass

The 2026-09-15 code-level security audit
(private audit archive, 31 findings:
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

### Low — deferred (none a publish blocker)

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
  domain by both. **Since 1.1.0** a second organization can no longer register or verify a
  domain another one verified (`409 SSO_DOMAIN_TAKEN`), policy resolution uses every matching
  organization (`findOrgsByEmailDomain`), and e-mail SSO sign-in is pinned only when one
  organization holds the domain; rows written before 1.1.0 are left as they are and logged.

### Info items adopted without a finding

- `policy.groupRoleMap ?? opts.scim?.groupRoleMap ?? {}` could never reach the second operand
  (`defaultPolicy` returns `{}`, which is not nullish), so `EnterpriseOptions.scim.groupRoleMap`
  silently did nothing. It is now used when the policy row's map is empty.
- The build is a single `tsup` config with all five entries. Two sibling configs sharing one
  `dist/` raced, and `dist/cli/index.d.ts` was intermittently missing from a finished build;
  `test/cli/cli.test.ts` now asserts every entry (JS and `.d.ts`) exists after `pnpm build`.
