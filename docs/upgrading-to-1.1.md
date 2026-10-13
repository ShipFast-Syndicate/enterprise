# Upgrading to 1.1

1.1.0 is a minor release. It tightens how the package applies the controls it already
documented — SSO domain ownership, organization policy, API-key lifetime, SCIM decommission and
the audit log — and adds options for the few places where an integrator may legitimately choose
otherwise. Every change is **on by default** in the plugins `enterprisePreset()` mounts; nothing
needs to be configured to get it. A plugin your auth config mounts **in place of** one of the
preset's (replaced or filtered out by id) does not carry the preset's settings — step 2 lists
what such a plugin must set.

- **No schema change.** No column is added to any table the auth adapter writes, so a product's
  hand-maintained Drizzle tables need no edit.
- **One data-only migration**, `0003_require2fa.sql`, applied with
  `ab-enterprise migrate --out <folder> --from 0003` (step 3 below).
- **One new peer dependency**, `samlify` (step 1).
- The upgrade applies to every release from 0.1.0 to 1.0.1. Upgrade from any of them; the
  release notes list what changed ([`docs/releases/1.1.0.md`](./releases/1.1.0.md)).
- **From 0.1.x**, first follow [`docs/migration-1-7.md`](./migration-1-7.md) (the better-auth
  1.6.33 → 1.7.5 peer set and SCIM connection catalog that 1.0.0 introduced), then this guide.
  That guide's `0002` is applied once: either there (through `applyMigration()`, then
  `--from 0003` in step 3) or through `--from 0002` in step 3, not both.

Read the whole [behaviour table](#3-behaviour-changes) before upgrading a deployment with real
users: a handful of rows change what existing users see on their first request after the
upgrade (`require2fa`, invitation acceptance, API-key expiry, SCIM decommission).

## 1. Before you upgrade — checks

Run these against each production database. Table and column names below are this package's
and better-auth's defaults; adjust them to your schema (a product that created the package's
tables through a migration of its own may have prefixed table names, snake_case user columns or
a differently named organization table). Each query is read-only.

```sql
-- (a) SSO account rows linked to a provider that is not verified for the user's e-mail
--     domain: they stop signing in at upgrade (row 1). Review, then clean up as described in
--     docs/security.md, "Upgrading from 1.0.x".
SELECT a.id AS account_id, a.providerId, u.id AS user_id, u.email, p.domain, p.organizationId
FROM account a
JOIN user u ON u.id = a.userId
JOIN ssoProvider p ON p.providerId = a.providerId
WHERE p.domainVerified = 0
   OR NOT (
     ',' || lower(replace(p.domain, ' ', '')) || ',' LIKE '%,' || lower(substr(u.email, instr(u.email, '@') + 1)) || ',%'
     OR lower(substr(u.email, instr(u.email, '@') + 1)) LIKE '%.' || lower(replace(p.domain, ' ', ''))
   );

-- (b) organizations that will start enforcing two-factor authentication (row 10)
SELECT org_id FROM org_policy WHERE require_2fa = 1;

-- (c) SSO providers without an organization (rows 5 and 18; expected: none)
SELECT providerId, domain, domainVerified FROM ssoProvider WHERE organizationId IS NULL;

-- (d) one domain verified by two organizations (row 6; e-mail SSO sign-in is not pinned for it)
SELECT lower(domain) AS domain, count(DISTINCT organizationId) AS orgs
FROM ssoProvider WHERE domainVerified = 1 GROUP BY lower(domain) HAVING orgs > 1;

-- (e) provider domains that are comma lists, mixed-case or padded (row 8)
SELECT providerId, domain FROM ssoProvider
WHERE domain LIKE '%,%' OR domain <> lower(domain) OR domain LIKE '% %';

-- (f) pending invitations whose invitee exists but has not verified an e-mail (row 4)
SELECT i.email FROM invitation i JOIN user u ON lower(u.email) = lower(i.email)
WHERE i.status = 'pending' AND u.emailVerified = 0;

-- (g) users in more than one organization (row 7), to cross-check with org_policy
SELECT userId, count(*) AS orgs FROM member GROUP BY userId HAVING orgs > 1;

-- (h) organizations with a session cap (row 9)
SELECT org_id, session_max_age_s FROM org_policy WHERE session_max_age_s IS NOT NULL;

-- (i) API keys that never expire (row 13; they keep working, new keys expire)
SELECT count(*) FROM apikey WHERE expiresAt IS NULL;

-- (j) owners who are also SCIM-managed members (row 15)
SELECT m.userId FROM member m JOIN enterprise_scim_member s ON s.member_id = m.id
WHERE m.role LIKE '%owner%';

-- (k) organization ids longer than 128 characters (row 19; expected: none)
SELECT id FROM organization WHERE length(id) > 128;

-- (l) organizations that enforce SSO (row 3): their members who also belong to another
--     organization are sent to this organization's own IdP
SELECT org_id FROM org_policy WHERE sso_enforced = 1;
```

In the product's own code, check for:

- a preset plugin replaced or filtered out by id — `organization`, `api-key` or `admin`, e.g.
  `.map((p) => (p.id === "organization" ? organization({ … }) : p))` or
  `.filter((p) => p.id !== "api-key")` followed by a mount of your own (step 2);
- a second `apiKey()` plugin mounted next to `enterprisePreset()` (step 2);
- sign-in or session-minting plugins beyond the preset's (e-mail and password, magic link,
  social providers, passkey, SSO): e-mail OTP, generic OAuth, anonymous, one-tap, an OAuth
  proxy, or a plugin of your own that creates sessions. Declare their paths in
  `policy.signInMethods`, or they are refused for users under a restricted `allowedMethods`
  (row 12);
- `advanced.backgroundTasks` in the auth config if the product runs on a serverless host
  (step 4);
- any code that sends an `x-api-key` header to `/api/auth/*` other than `/get-session`
  (row 14; a browser never sends one);
- calls to `/organization/create-team` or `/api-key/create` that pass `orgId` rather than
  `organizationId` (row 21);
- consumers of the audit log that switch exhaustively on `actorType`, parse `metadata.role` as
  an array, or compare the `/enterprise/audit/verify` body to `{ ok: true }` exactly (row 17).

## 2. Upgrade steps

1. **Dependencies.** Bump `@alphabros/enterprise` to `^1.1.0`. The better-auth peer set stays
   pinned at `1.7.5`. `samlify` (`^2.13.1`) is a new peer dependency: the package now asks
   samlify which certificates a SAML configuration will be verified against. `@better-auth/sso`
   already depends on it, so it is usually present; add it explicitly
   (`pnpm add samlify@^2.13.1`) if your package manager does not install peer dependencies
   automatically or runs with strict peer checks.
2. **Preset plugins you replace, filter out or mount twice.** `enterprisePreset()` returns a
   plugin list; the settings below are applied to the preset's own entries only.
   - **`organization()`.** The preset mounts
     `organization({ teams: { enabled: true }, requireEmailVerificationOnInvitation, allowUserToCreateOrganization })`,
     with `organization.requireEmailVerificationOnInvitation` (default `true`) and
     `organization.allowUserToCreateOrganization` (default `true`) taken from the preset's
     options. If your config replaces that entry by id or filters it out and mounts its own
     `organization()`, those two options are ignored and upstream's defaults apply — for the
     invitation check that is `false`, so row 4 does not hold. Your own call must carry the
     preset's settings:

     ```ts
     organization({
       teams: { enabled: true },
       requireEmailVerificationOnInvitation: true,
       allowUserToCreateOrganization: true, // or your own boolean / predicate
       // …your other settings
     });
     ```

   - **`apiKey()`.** The preset mounts `apiKey()` with the enterprise validator, header list and
     expiry bound. If your config filters the preset's `api-key` plugin out and mounts its own
     `apiKey()`, remove **both** the filter and your own mount wherever the preset is mounted;
     keep a plain `apiKey()` only in configurations where `enterprisePreset()` is not mounted
     (e.g. `...(enterpriseEnabled ? [] : [apiKey()])`), since the preset already mounts it. Removing
     only your own mount leaves such a config with no API-key plugin at all. Likewise, if your
     auth config mounts a second `apiKey()` next to the preset's, remove that mount:
     better-auth merges plugin endpoints last-wins, so a second mount replaces the preset's
     `/api-key/*` endpoints and `verifyApiKey`, and the default expiry and the banned-owner
     refusal (rows 13 and 14) would not apply. The header allow-list (row 14) holds either way.
     To let a key authenticate as its owner, set `apiKeys.enableSessionForAPIKeys: true` on the
     preset instead.
   - **`admin()`** is mounted with upstream's defaults, so a replacement changes only what it
     configures itself.

3. **Data migration.** Apply `0003_require2fa.sql` once, through the product's own migrator:

   ```sh
   # any 1.0.x install — whatever wrote the folder's 0001 (this command, or a
   # migration the product wrote itself when it adopted the package)
   ab-enterprise migrate --out <drizzle migrations folder> --from 0003
   # only a folder coming straight from 0.1.x whose database never applied 0002
   # (not through applyMigration() either)
   ab-enterprise migrate --out <drizzle migrations folder> --from 0002
   ```

   `--from 0003` writes exactly one file, `NNNN_enterprise_0003_require2fa.sql`, registered in
   `meta/_journal.json` after the product's own entries; a second run writes nothing. **Never
   run the full emit on an existing install**: `0001` and `0002` would re-run `ALTER TABLE`s the
   database already has (`duplicate column name: id`, `no such table: organization`). A plain
   run refuses a folder it cannot prove it wrote (exit 1, nothing written) and names the
   `--from` value to use. Run the step against **every** folder the product migrates from — a
   product that keeps one migrations lineage per environment runs it once per lineage. If a full
   emit already happened, remove every emitted file other than the `0003` one **and** its
   journal entry (deleting the file alone makes the migrator fail on the missing file). Where
   no organization has `require_2fa = 1` the migration changes nothing. Details:
   [`docs/security.md`](./security.md#upgrading-from-10x).

4. **Serverless hosts: `advanced.backgroundTasks`.** Audit rows about a caller-chosen address
   (failed, refused and 2FA-pending sign-ins, magic-link and password-reset requests) are
   written off the response path, so response time does not depend on whether the address has
   an account. On a host that freezes the instance after the response (Vercel, Cloudflare
   Workers, …) set `advanced: { backgroundTasks: { handler: waitUntil } }` in the better-auth
   config — `waitUntil` from `@vercel/functions` on Vercel, from `cloudflare:workers` on
   Cloudflare Workers, or the platform's equivalent — or such rows can be lost. `flushAuditWrites()` drains
   pending writes on a graceful shutdown.
5. **Product UI.**
   - A product that offers password sign-in redirects to its two-factor enrolment UI when
     `/get-session` reports `enterprise.enrollmentRequired: true` (row 10). A passwordless
     product (e-mail and password disabled) has no enrolment step: under `require2fa`, its
     members sign in through SSO only, unless `policy.twoFactor.satisfiedBy` also names
     `magic_link`, `passkey` or a social provider.
   - `auth.api.getSession()` may now answer `null` for a session that does not stand under
     `require2fa`; treat it as signed out (row 10).
   - A custom SSO registration UI surfaces `409 SSO_DOMAIN_TAKEN` (row 6) and
     `400 ORG_REQUIRED` (row 5); the bundled portal already does.
6. **SSO providers without an organization.** If check (c) returned rows, bind each to the
   organization it serves or delete and re-register it before upgrading —
   [`docs/security.md`](./security.md#sso-providers-without-an-organization).
7. **Deploy.** Where the package's tables use its default table and column names (they were
   created by `ab-enterprise migrate` or `applyMigration()`), run `ab-enterprise verify`
   against the live database; 1.1.0 adds no table or column, so a schema that verified under
   1.0.x verifies unchanged. A schema whose package tables were created under other names
   fails `verify` whatever the release; skip the command there.
8. **Watch the logs for 48 hours** for `auth.sign_in_refused` audit rows,
   `TWO_FACTOR_ENROLLMENT_REQUIRED`, `could not be decrypted` and `DatabaseQueryError`.

## 3. Behaviour changes

The table is the summary; rows marked "(details)" continue below it. "Check" letters refer to
the queries in section 1.

| #   | Change (default)                                                                                                                                                                                                                                   | What an integrator sees                                                                                                                                                                                                                      | Opt-out                                                                                                                             |
| --- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| 1   | **SSO domain binding** (`sso.domainBinding: "verified-domain"`): JIT user creation and every session an SSO callback mints require the signing provider to be domain-verified for the user's e-mail domain                                         | an IdP that signs in addresses outside its organization's verified domains (external contractors on a public mail domain) is refused for them (`SSO_DOMAIN_NOT_ALLOWED`); account rows linked to such a provider stop signing in — check (a) | `sso.domainBinding: "off"` — only safe with `sso.allowedIssuers` and, for SAML, `sso.samlCertificateFingerprints`; warns at startup |
| 2   | Domain-bound JIT users are stored with `emailVerified: true`                                                                                                                                                                                       | a "verify your e-mail after SSO" step becomes unnecessary                                                                                                                                                                                    | `sso.trustVerifiedDomainEmail: false`                                                                                               |
| 3   | `ssoEnforced` is satisfied only by the enforcing organization's own IdP                                                                                                                                                                            | a user in two organizations is sent to the enforcing organization's IdP (`SSO_REQUIRED`); break-glass unchanged — check (l)                                                                                                                  | none                                                                                                                                |
| 4   | Accepting or rejecting an invitation requires a verified e-mail (in the preset's own `organization()`; a replaced one sets it itself, step 2)                                                                                                      | a password sign-up without e-mail verification cannot accept invitations (upstream's `EMAIL_VERIFICATION_REQUIRED_BEFORE_ACCEPTING_OR_REJECTING_INVITATION`) — check (f)                                                                     | `organization.requireEmailVerificationOnInvitation: false`                                                                          |
| 5   | `/sso/register` requires `organizationId`                                                                                                                                                                                                          | `400 ORG_REQUIRED` without it; the portal already sends it — check (c)                                                                                                                                                                       | none                                                                                                                                |
| 6   | One organization per verified domain; e-mail `/sign-in/sso` pinned to the verified provider                                                                                                                                                        | `409 SSO_DOMAIN_TAKEN` on register, update and verify-domain; domains two organizations already verified keep upstream's lookup (logged) — check (d)                                                                                         | none                                                                                                                                |
| 7   | A user in several organizations gets the **union** of their policies                                                                                                                                                                               | any `ssoEnforced` applies, `allowedMethods` intersect (no overlap = no method), smallest `sessionMaxAgeS`, any `require2fa` — check (g)                                                                                                      | none (per-org break-glass)                                                                                                          |
| 8   | Provider domains matched like upstream (comma list, any case, subdomains) and stored normalised                                                                                                                                                    | home-realm may answer `sso` where it answered `local`; policy and SCIM rules reach secondary and subdomain users; an unmatchable list is refused (`400 SSO_DOMAIN_INVALID`) — check (e)                                                      | none                                                                                                                                |
| 9   | `sessionMaxAgeS` also bounds session refresh                                                                                                                                                                                                       | the portal's 1 h / 8 h / 24 h caps hold; lowering a cap ends older sessions at their next refresh — check (h)                                                                                                                                | none                                                                                                                                |
| 10  | **`require2fa` is enforced**, no grace period (details)                                                                                                                                                                                            | organizations with `require_2fa = 1` start enforcing at upgrade — check (b); add the enrolment redirect (step 5) and apply `0003` (step 3)                                                                                                   | `policy.twoFactor.satisfiedBy`, `policy.twoFactor.enrollmentPaths`                                                                  |
| 11  | A wrong password under a policy is a plain `401` (was `403`); `/sign-in/magic-link` always sends the link and `/magic-link/verify` applies the policy                                                                                              | sign-in UIs keep calling `/enterprise/home-realm` first                                                                                                                                                                                      | none                                                                                                                                |
| 12  | Sign-in paths the package cannot classify are refused under a restricted `allowedMethods`                                                                                                                                                          | only products that mount extra sign-in or session-minting plugins (e-mail OTP, generic OAuth, …): `METHOD_NOT_ALLOWED` — code check in section 1                                                                                             | declare them in `policy.signInMethods`                                                                                              |
| 13  | New API keys expire after 90 days (at most 365); an expiry cannot be removed (`400 API_KEY_EXPIRY_REQUIRED`)                                                                                                                                       | automation assuming perpetual keys rotates them; existing keys keep their lifetime — check (i)                                                                                                                                               | `apiKeys.defaultExpiresInS: null`, `apiKeys.maxExpiresInDays`                                                                       |
| 14  | Keys of banned or deleted users are refused (`USER_BANNED`, `USER_NOT_FOUND`); ban and removal delete the user's keys (audited `api_key.revoked`); a request carrying a key reaches `/get-session` only (`403 API_KEY_NOT_ALLOWED_HERE` elsewhere) | routes branching on `valid` need nothing; `getSession({ headers })` with a forwarded `x-api-key` next to a cookie answers the cookie's session                                                                                               | none                                                                                                                                |
| 15  | SCIM decommission (`/enterprise/scim/tokens/revoke`) is owner-only; an owner membership is never banned by SCIM                                                                                                                                    | admins get `403 NOT_ORG_OWNER`; for owners, sessions and API keys are still revoked and the skipped ban is audited (`scim.user_deactivation_skipped`) — check (j)                                                                            | none                                                                                                                                |
| 16  | `ssoProvider` secret fields always encrypted on write; an undecryptable field is logged and left sealed for its own provider                                                                                                                       | after a `secretsKey` rotation: `could not be decrypted` log lines and an IdP-side `invalid_client` for that provider, other provider reads unaffected                                                                                        | none                                                                                                                                |
| 17  | **Audit log** records every sign-in and change into the right organizations (details)                                                                                                                                                              | `audit_event` grows; see the details for consumer-visible changes                                                                                                                                                                            | `audit.chainKey` is opt-in                                                                                                          |
| 18  | `/sso/update-provider`, `/sso/delete-provider` require the `sso` entitlement of the stored provider's organization and membership in it                                                                                                            | `403 FEATURE_NOT_ENTITLED` / `403 NOT_ORG_MEMBER` (also for a provider without an organization and an unknown `providerId`, where upstream answered `404`), including `auth.api.*` calls — check (c)                                         | none                                                                                                                                |
| 19  | Organization ids from a request must be non-empty strings of at most 128 characters (details)                                                                                                                                                      | `400` before any query instead of `500` — check (k)                                                                                                                                                                                          | none                                                                                                                                |
| 20  | A failed adapter query with its statement attached is logged as `DatabaseQueryError` without the SQL or its parameters                                                                                                                             | e.g. `Database query failed (member.findOne) [SQLITE_CONSTRAINT_PRIMARYKEY]`; `error.code` / `errno` keep the driver code                                                                                                                    | none                                                                                                                                |
| 21  | The entitlement gate checks the organization the endpoint acts on (details)                                                                                                                                                                        | organization ids in other request fields no longer decide the entitlement                                                                                                                                                                    | none                                                                                                                                |
| 22  | A hard audited change whose audit row cannot be written answers `500 AUDIT_WRITE_FAILED`, whatever status the endpoint set                                                                                                                         | SCIM `POST /scim/v2/Users` and `/sso/request-domain-verification` no longer answer `201` with that error body; the change is still committed                                                                                                 | none                                                                                                                                |

Rows 13 and 14 apply when the preset's own `apiKey()` serves the key endpoints, and row 4
when the preset's own `organization()` is mounted or yours sets
`requireEmailVerificationOnInvitation: true` (step 2).

**Row 10 — `require2fa`.**

- A member who holds a password and has not enrolled is confined to the enrolment endpoints
  (`403 TWO_FACTOR_ENROLLMENT_REQUIRED` elsewhere); `/get-session` reports
  `enterprise.enrollmentRequired: true` for that session.
- Magic-link, social and passkey sessions are refused (`403 TWO_FACTOR_REQUIRED`) unless the
  method is listed in `policy.twoFactor.satisfiedBy` (default `["sso"]`).
- A no-password member's session older than the organization's last policy write, or than
  their membership, is refused, and `/get-session` / `auth.api.getSession` answer `null` for it.
  Switching the policy on — or any later edit of it — therefore signs such members out once.
- Switching it on requires an enrolled caller, or `sso` in `satisfiedBy` plus a verified SSO
  provider of the organization for the caller's domain (`400 REQUIRE_2FA_PRECONDITION`).
- With the opt-in API-key session, a key's owner is judged the same way: a no-password owner's
  key must postdate the requirement, an un-enrolled password holder's key yields `null`.

**Row 17 — audit log.**

- One row per organization membership for sign-in, sign-out, failed, refused (`auth.sign_in_refused`,
  `auth.session_refused`) and 2FA-pending (`auth.sign_in_2fa_pending`) sign-ins and for password
  and session events; the organization is resolved server-side, and `?orgId` is ignored except by
  `/enterprise/policy/set` and `/enterprise/audit/export`.
- New actions (IdP, `/admin/*`, organization, team, invitation, two-factor, password, e-mail,
  passkey, session and API-key changes, `audit.exported`, `org.deleted`); actions under staff
  impersonation carry `actorType: "impersonated"` and `metadata.impersonatedBy` — exhaustive
  `actorType` switches need a default branch.
- Rows about a caller-chosen address (failed, refused and 2FA-pending sign-ins, magic-link and
  password-reset requests) are written off the response path — serverless hosts set
  `advanced.backgroundTasks` (step 4).
- Newly audited non-sign-in paths answer `500 AUDIT_WRITE_FAILED` when their row cannot be
  written, after the change is committed (row 22); a client re-reads state rather than retrying
  blindly. Sign-in, sign-out and the unauthenticated account flows stay soft
  ([`docs/security.md`](./security.md#audit-log-coverage) lists both sets).
- `metadata.role` on role changes is always a comma-joined string (at most 16 names,
  `metadata.roleCount` when names were dropped); a request value that cannot be recorded is
  stored as `(unrecorded)`; every row is bounded (ids and IP ≤ 128 characters, user agent ≤ 512,
  metadata ≤ 16 KiB).
- `/enterprise/audit/verify` answers `{ ok: true, keyed }`; `from`/`to` on audit list and export
  must be whole milliseconds in `[0, 8.64e15]` (the portal's date filter answers `400` for a date
  before 1970).
- `audit.chainKey` is opt-in and monotonic: once set, removing it makes verification fail.

**Row 19 — organization ids.** An array (a duplicated query parameter included), object,
number, boolean, `null` or a string longer than 128 characters in `orgId` / `organizationId`
(body or query) answers `400` before any query: `ORG_ID_INVALID` from the gate on gated paths —
also for an anonymous caller — and `VALIDATION_ERROR` from an `/enterprise/*` endpoint's
schema. An empty `orgId` answers `400` too (`VALIDATION_ERROR`, or `ORG_REQUIRED` from the gate
on a gated path). `/api-key/create` with a numeric `organizationId` answers `400`.

**Row 21 — entitlement organization.** `/organization/create-team` and `/api-key/create` →
`body.organizationId`, else the active organization; `/sso/register` → `body.organizationId`;
provider management → the stored provider's organization; each `/enterprise/*` endpoint → the
one field its schema reads. So a create-team request naming an entitled organization in
`?orgId` or `body.orgId` while the active organization is unentitled answers
`403 FEATURE_NOT_ENTITLED`; `/api-key/create` with `orgId` and no active organization answers
`400 ORG_REQUIRED` (send `organizationId`, or set an active organization); a gated
`/enterprise/*` request without its declared field answers `400 ORG_REQUIRED` from the gate.

## 4. New options

All new options are optional and default to the stricter behaviour.

| Option                                              | Default             | Purpose                                                                                                                                                                                                              |
| --------------------------------------------------- | ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `sso.domainBinding`                                 | `"verified-domain"` | bind SSO user creation and sessions to the signing provider's verified domain; `"off"` restores upstream behaviour (row 1)                                                                                           |
| `sso.trustVerifiedDomainEmail`                      | `true`              | store domain-bound JIT users as `emailVerified` (row 2)                                                                                                                                                              |
| `sso.allowedIssuers`                                | unset (any IdP)     | array of strings/`RegExp`s or a predicate restricting which identity providers may be registered and signed in through ([`sso.md`](./sso.md#oidc-provider-origins-trustedorigins-and-the-issuer-allow-list))         |
| `sso.samlCertificateFingerprints`                   | unset               | SHA-256 pins of each SAML IdP's signing certificates; with an array `allowedIssuers`, a SAML provider without pins is refused                                                                                        |
| `organization.requireEmailVerificationOnInvitation` | `true`              | invitation accept/reject requires a verified e-mail (row 4); configures the preset's own `organization()` only (step 2)                                                                                              |
| `organization.allowUserToCreateOrganization`        | `true`              | self-serve organization creation (boolean or predicate); policy resolution no longer depends on it; configures the preset's own `organization()` only (step 2)                                                       |
| `policy.signInMethods`                              | `{}`                | name the sign-in paths of plugins the preset does not ship, so `allowedMethods` can allow them (row 12)                                                                                                              |
| `policy.twoFactor.satisfiedBy`                      | `["sso"]`           | sign-in methods accepted as carrying a second factor (row 10)                                                                                                                                                        |
| `policy.twoFactor.enrollmentPaths`                  | `[]`                | product endpoints an un-enrolled user may still reach while enrolling                                                                                                                                                |
| `apiKeys.defaultExpiresInS`                         | `7776000` (90 d)    | lifetime of a new key in seconds; `null` = no default expiry (row 13)                                                                                                                                                |
| `apiKeys.maxExpiresInDays`                          | `365`               | longest lifetime a caller may request                                                                                                                                                                                |
| `apiKeys.enableSessionForAPIKeys`                   | `false`             | let a key authenticate its owner to `/get-session` (the supported way to opt into upstream's key session)                                                                                                            |
| `apiKeys.rateLimit`                                 | upstream default    | `{ enabled, maxRequests, timeWindow }` forwarded to `apiKey()`; upstream's default is 10 requests per key per 24 h                                                                                                   |
| `audit.chainKey`                                    | unset (unkeyed)     | ≥ 32 characters, distinct from `secretsKey` and `scimCredentialHashSecret`; HMAC-keys new audit rows; export the head with `GET /enterprise/audit/head` and check it with `ab-enterprise audit-verify --expect-head` |

New in the API: `GET /enterprise/audit/head?orgId=` (owner/admin, `audit_log`), the CLI's
`AB_AUDIT_CHAIN_KEY` environment variable and `--expect-head`, `ab-enterprise migrate --from`,
and the server exports `flushAuditWrites`, `enterpriseApiKeyValidator`, `apiKeyLifecycle`,
`apiKeySessionStanding`, `API_KEY_ALLOWED_PATHS`, `API_KEY_HEADERS`, `AUDITED_PATHS`,
`POLICY_REFUSAL_CODES`, `normalizeProviderDomains`, `domainMatches` and `emailDomain`.

## 5. Error codes introduced or re-scoped

| Code                                                                              | HTTP                                 | Where                                                                                                                                                               |
| --------------------------------------------------------------------------------- | ------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `SSO_DOMAIN_NOT_ALLOWED`                                                          | 403 → SSO callback redirect `error=` | JIT user creation and every SSO session (row 1)                                                                                                                     |
| `SSO_PROVIDER_UNRESOLVED`                                                         | 403 → callback redirect `error=`     | SSO callback when the signing provider cannot be named (fail closed; not expected on the preset's routes)                                                           |
| `SSO_REQUIRED` (message names "its own identity provider")                        | 403                                  | session creation (row 3)                                                                                                                                            |
| `ORG_REQUIRED`                                                                    | 400                                  | `/sso/register` without `organizationId`; a gated path without the organization field it acts on (row 21)                                                           |
| `SSO_DOMAIN_TAKEN`                                                                | 409                                  | `/sso/register`, `/sso/update-provider`, `/sso/verify-domain` (row 6)                                                                                               |
| `SSO_DOMAIN_INVALID`                                                              | 400                                  | `/enterprise/sso/register`, `/sso/register`, `/sso/update-provider` with a domain list that can never match                                                         |
| `SSO_ISSUER_NOT_ALLOWED`                                                          | 403; at sign-in a callback redirect  | register/update with `sso.allowedIssuers`, and every SSO sign-in against the stored provider                                                                        |
| `SSO_DOMAIN_CHECK_OVERFLOW`                                                       | 500                                  | more than 5000 verified provider rows to scan (fail closed)                                                                                                         |
| `POLICY_MEMBERSHIP_SCAN_OVERFLOW`                                                 | 500                                  | a user with more than 5000 memberships (fail closed)                                                                                                                |
| `EMAIL_VERIFICATION_REQUIRED_BEFORE_ACCEPTING_OR_REJECTING_INVITATION` (upstream) | 403                                  | invitation accept/reject (row 4)                                                                                                                                    |
| `METHOD_NOT_ALLOWED` (now also for an unclassified sign-in path)                  | 403                                  | session creation (row 12)                                                                                                                                           |
| `TWO_FACTOR_REQUIRED`, `TWO_FACTOR_ENROLLMENT_REQUIRED`                           | 403                                  | session creation and every request under `require2fa` (row 10); for an API key, `{ valid: false }` from `verifyApiKey`, `null` from `/get-session` under the opt-in |
| `REQUIRE_2FA_PRECONDITION`                                                        | 400                                  | `/enterprise/policy/set` switching `require2fa` on (row 10)                                                                                                         |
| `USER_BANNED`, `USER_NOT_FOUND`                                                   | `{ valid: false }` / 401             | API-key validation (row 14)                                                                                                                                         |
| `API_KEY_NOT_ALLOWED_HERE`                                                        | 403                                  | any request carrying an API key outside `/get-session` (row 14)                                                                                                     |
| `API_KEY_EXPIRY_REQUIRED`                                                         | 400                                  | `/api-key/update { expiresIn: null }` (row 13)                                                                                                                      |
| `NOT_ORG_OWNER`                                                                   | 403                                  | `/enterprise/scim/tokens/revoke` for a non-owner (row 15)                                                                                                           |
| `FEATURE_NOT_ENTITLED`, `NOT_ORG_MEMBER`                                          | 403                                  | `/sso/update-provider`, `/sso/delete-provider` (row 18); the gate on the organization the endpoint acts on (row 21)                                                 |
| `ORG_ID_INVALID`                                                                  | 400                                  | the gate, for a malformed organization id (row 19)                                                                                                                  |
| `GATE_ORG_SOURCE_UNDECLARED`                                                      | 403                                  | a gated path with no declared organization source (fail closed; unreachable with the shipped table)                                                                 |
| `AUDIT_WRITE_FAILED`                                                              | 500                                  | a hard audited path whose row cannot be written (rows 17 and 22)                                                                                                    |
| `keyed_row_without_key` (verify reason, not an HTTP code)                         | —                                    | `/enterprise/audit/verify` and `audit-verify` on a keyed chain without the key                                                                                      |
| `DatabaseQueryError` (log only)                                                   | — (the request still answers 500)    | a failed adapter query with its statement attached (row 20)                                                                                                         |

## 6. Decisions and known limitations in 1.1.0

- **`require2fa` has no grace period.** Organizations that already had it on start enforcing at
  upgrade (row 10).
- **Staff impersonation stays enabled** in the preset (`admin()`), and is fully audited: an
  action under impersonation is recorded with `actorType: "impersonated"` and
  `metadata.impersonatedBy`, and starting and stopping impersonation are audited into every
  organization of the impersonated user.
- **Domain binding is an operator-level switch only.** There is no per-organization list of
  external mail domains an IdP may sign in: such a list would be set by the tenant the binding
  constrains. Invite external collaborators and let them sign in with another allowed method.
- **Self-serve organization creation stays on** (`organization.allowUserToCreateOrganization:
true`); creating an organization no longer changes which policies apply to a user.
- **A user holding an owner membership anywhere is not banned by SCIM**, including an owner of
  an organization they created themselves; their sessions and API keys are revoked and the
  skipped ban is audited.
- **API keys reach `/get-session` only.** Key-driven reads of organizations, providers or
  accounts are refused; resolve them from the owner's id in your own code. `POST /get-session`
  with a key answers like `GET` (a cookie gets `405`). On `/api-key/create`, the entitlement
  organization for a user-owned key is `body.organizationId` when sent — any organization the
  caller belongs to — since a user key belongs to the user and reaches only `/get-session`.
- **API keys are per user, not per organization.** Organization-scoped keys and per-organization
  key policy need a schema change and are planned for a later minor.
- **An audit row is written after the change it describes is committed.** On a hard path a
  failed write answers `500 AUDIT_WRITE_FAILED` with the change in place; the write is not
  transactional with upstream endpoints.
- **Only errors that carry a statement are redacted** (`DatabaseQueryError`); a driver error
  surfaced by another adapter without a statement property passes through unchanged.
- **Domain and membership scans are paginated and fail closed at 5000 rows**
  (`SSO_DOMAIN_CHECK_OVERFLOW`, `POLICY_MEMBERSHIP_SCAN_OVERFLOW`); an indexed exact-domain
  lookup is planned.
- **`trustedOrigins` is also better-auth's redirect allow-list.** Every IdP origin you add there
  becomes a permitted `callbackURL` target; keep it narrow.
- **`/enterprise/home-realm` is rate-limited only when better-auth's `rateLimit.enabled` is on**
  (off outside production by default).
- **Foreign account rows are not removed automatically.** Rows linked before the upgrade to a
  provider that is not verified for the user's domain can no longer sign in; delete them with
  the query in [`docs/security.md`](./security.md#upgrading-from-10x).

## 7. Rolling back

Rolling the package back to 1.0.1 needs no schema change. Changes made while 1.1.0 ran stay:
revoked API keys are deleted, audit rows written by 1.1.0 remain in the chain, and a chain
keyed with `audit.chainKey` does not verify under 1.0.x (it computes unkeyed hashes). The
behaviour listed above reverts with the code.
