# SSO (SAML + OIDC)

## The wizard flow

`<ab-sso-wizard>` (`@alphabros/enterprise/portal`) walks an org owner/admin
through registering a provider end to end, as a single-`step` state
machine (`WizardStep` in `src/portal/ab-sso-wizard.ts`):

1. **`choose`** — paste SAML IdP metadata, or enter an OIDC issuer +
   client id/secret.
2. **`register`** — `POST /enterprise/sso/register` (a thin, org-scoped
   wrapper around upstream `POST /sso/register` that strips
   `clientSecret`/certificate material out of what it returns to the
   browser). Transient, in-flight step.
3. **`verify-domain`** — shows the DNS TXT record from
   `GET /enterprise/sso/providers`'s `verificationRecord` field, a "Check
   DNS" button that calls upstream `POST /sso/verify-domain` directly (there
   is no `/enterprise/*` wrapper for this one), and auto-polls it every
   `pollIntervalMs` up to `maxPollMs`.
4. **`test-login`** — opens `POST /enterprise/sso/test-login/start`'s
   returned `url` (via the overridable `openWindow`), then detects
   completion either via a `storage` event keyed `ab_sso_test` (written by
   the test-login finish redirect's landing page — outside this component's
   scope, a product wires that page itself) or by the admin clicking "I
   completed the test", which re-fetches providers and reads
   `testLoginPassedAt`.
5. **`enforce`** — a toggle that calls
   `POST /enterprise/policy/set { ssoEnforced, breakGlassUserId }`
   (`breakGlassUserId` defaults to the signed-in admin's own id via
   `GET /get-session`). Disabled until `testLoginPassedAt` is set — **a
   successful test login is mandatory before enforcement can be switched
   on**, so an org can never lock itself out of its own SSO setup.
6. **`done`**.

Every step writes an `audit_event` row (via the underlying
`/enterprise/sso/*` endpoints and `/enterprise/policy/set`, both wrapped by
`auditLog()`).

### Who may do which step

Steps 1–4 are open to an org **owner or admin**. Step 5 is split, because
`breakGlassUserId` names the one person who keeps signing in when SSO
enforcement locks everyone else out:

| Action | Owner | Admin |
|---|---|---|
| Register a provider, verify the domain, run the test login | yes | yes |
| Set or change `breakGlassUserId` (including clearing it) | yes | **no** — `403 NOT_ORG_OWNER` |
| Enable `ssoEnforced` while leaving `breakGlassUserId` alone | yes | yes |
| Write `groupRoleMap` | yes | **no** — `403 NOT_ORG_OWNER` |

So the supported admin path through step 5 is: an owner sets the break-glass
user once (`POST /enterprise/policy/set { orgId, breakGlassUserId }`), and an
admin can then enable enforcement with `{ orgId, ssoEnforced: true }` —
omitting `breakGlassUserId`, or repeating the current value unchanged.

`<ab-sso-wizard>` always sends `breakGlassUserId` (defaulted to the signed-in
user), so an admin running the wizard before an owner has chosen one gets
"An organization owner must set the break-glass user first" on that step
rather than the server's bare "Owner role required."

Raw SAML/OIDC diagnostics (HTTP status + error code, not just a friendly
message) are shown **only** in the `test-login` step, per the design's error
handling rule — every other step renders through the same generic error UI
every other portal component uses.

## DNS record

The verification identifier reuses `@better-auth/sso`'s own format exactly
(reproduced in `src/server/enterprise-api/sso.ts` rather than imported,
since it isn't exported by the upstream package):

```
identifier = "_" + (tokenPrefix ?? "better-auth-token") + "-" + providerId
record name = identifier + "." + domain
```

So for a provider `providerId: "acme-okta"` and domain `acme.com`, the org
admin creates a TXT record at:

```
_better-auth-token-acme-okta.acme.com   TXT   <value from verificationRecord>
```

`GET /enterprise/sso/providers` returns this pre-computed as
`verificationRecord: { name, value }` so the wizard (and any custom UI) never
has to re-derive it.

## SP metadata URLs (SAML)

For a SAML provider registered with `providerId`, against a better-auth
instance mounted at `baseUrl` (e.g. `https://app.example.com/api/auth`):

| Purpose | URL |
| --- | --- |
| SP entity ID | `{baseUrl}/sso/saml2/sp/{providerId}` |
| Assertion Consumer Service (ACS) | `{baseUrl}/sso/saml2/sp/acs/{providerId}` |
| SP metadata XML | `GET {baseUrl}/sso/saml2/sp/metadata?providerId={providerId}` |

Paste the SP metadata URL (or its downloaded XML) into the IdP when
configuring the SAML application; the ACS URL is what the IdP posts signed
`SAMLResponse`s back to.

IdP-initiated SAML (a response with no prior `AuthnRequest`) is accepted —
`enterprisePreset` sets `sso({ saml: { allowIdpInitiated: true } })`
explicitly (matching upstream's own default, made explicit so the intent is
visible in this repo rather than relying on a default that could change).

## `node:dns` on Workers — a v0.1 caveat

`POST /sso/verify-domain` (upstream `@better-auth/sso`) resolves the TXT
record with `node:dns`. That module does not exist on Cloudflare Workers —
a product running its better-auth instance entirely on `workerd` cannot call
domain verification from the Worker itself. Two workarounds, neither
implemented by this package in v0.1 (documented here for P2 to pick up):

1. Run the `/sso/verify-domain` call (only that one endpoint) on a Node
   leg — e.g. a small Node-runtime API route/edge-exempt function that
   proxies just this call, while everything else stays on Workers.
2. Resolve the TXT record yourself over DNS-over-HTTPS (`fetch()` to
   `https://cloudflare-dns.com/dns-query` or a similar resolver, which works
   fine on Workers) and skip upstream's endpoint entirely, writing
   `domainVerified` directly the way this package's own test helpers do for
   fixtures (`UPDATE "ssoProvider" SET domainVerified = 1 WHERE ...`) —
   **only appropriate once you've actually verified the record yourself**,
   never as a shortcut in production.

v0.1 does not choose between these for you — pick whichever fits your
deployment target, or run domain verification during local/CI setup only
where a Node runtime is available.

## Just-in-time (JIT) provisioning

`enterprisePreset` enables `disableImplicitSignUp: false` and forwards
`opts.provisionUser` to `sso()` verbatim. On a first SSO login from a
verified domain, the user is created and auto-joins that domain's
organization with the default role `member` in one step. A pending
invitation takes precedence over domain-based auto-join (upstream's own
behaviour, unchanged).

## Home-realm discovery (email-first login)

`discoverHomeRealm(email)` (`@alphabros/enterprise/client`) calls the public
`POST /enterprise/home-realm { email }` endpoint and returns either
`{ method: "sso", providerId }` or `{ method: "local" }`. The response never
reveals whether the email belongs to an existing user — only whether its
*domain* has a verified SSO provider, which is public information about an
organization, not an individual account. Wire your sign-in page to call this
before rendering a password/magic-link field; see the README's client
snippet.
