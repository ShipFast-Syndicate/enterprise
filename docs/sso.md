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
   `pollIntervalMs` up to `maxPollMs`. With `domainVerificationMode: "operator"`
   this step cannot complete from the wizard; see
   [SSO on Cloudflare Workers](#sso-on-cloudflare-workers).
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

Every step that changes something writes an `audit_event` row into the
provider's own organization — whatever organization the admin's session has
active: `sso.provider_registered` (step 2, via `/sso/register`),
`sso.domain_verification_requested` and `sso.domain_verified` (step 3),
`sso.test_login_passed` (step 4) and `policy.updated` (step 5). Later changes
to the provider are recorded too (`sso.provider_updated` with the changed keys,
never a value; `sso.provider_deleted` with the number of linked accounts it took
with it), and every SSO sign-in lands in the provider's org and the user's own
(`auth.sso_sign_in`, `auth.sso_sign_in_failed`, `auth.sign_in_refused`) — see
`docs/security.md`, "Audit log coverage".

### Who may do which step

Steps 1–4 are open to an org **owner or admin**. Step 5 is split, because
`breakGlassUserId` names the one person who keeps signing in when SSO
enforcement locks everyone else out:

| Action                                                      | Owner | Admin                        |
| ----------------------------------------------------------- | ----- | ---------------------------- |
| Register a provider, verify the domain, run the test login  | yes   | yes                          |
| Set or change `breakGlassUserId` (including clearing it)    | yes   | **no** — `403 NOT_ORG_OWNER` |
| Enable `ssoEnforced` while leaving `breakGlassUserId` alone | yes   | yes                          |
| Write `groupRoleMap`                                        | yes   | **no** — `403 NOT_ORG_OWNER` |

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

## OIDC provider origins (`trustedOrigins`) and the issuer allow-list

Better Auth 1.7 validates the discovery URL and the endpoint origins advertised
by its discovery document against the application's trusted origins. Before
registering an OIDC provider, configure its exact HTTPS origin on the server:

```sh
BETTER_AUTH_TRUSTED_ORIGINS=https://idp.example.com
```

Better Auth reads this comma-separated environment variable directly. You can
also pass `trustedOrigins: ["https://idp.example.com"]` to `betterAuth(...)`.
Include any additional origins used by the provider's discovery endpoints,
and deploy the configuration to the environment where registration will run.
The application's own origin remains trusted automatically.

**`trustedOrigins` is not an issuer allow-list.** It is Better Auth's SSRF
boundary for the discovery and token/JWKS endpoints a provider points at (an
`Untrusted OIDC discovery URL` response means an operator must review and
configure that origin), and it doubles as Better Auth's redirect/callback
allow-list. The `issuer` an org admin enters is stored as entered, and a
provider whose endpoints already sit on a trusted origin (or that skips
discovery with explicit endpoints) registers whatever its issuer string says.
Keep the list narrow — explicitly trusting private-network IdPs also changes
their SSRF validation boundary, and every origin on it is also a permitted
redirect target — but do not rely on it to restrict _which_ IdPs tenants may
use.

To restrict which identity providers tenants may register, set
`sso.allowedIssuers` on `EnterpriseOptions`: an array of exact strings
and/or `RegExp`s, or a predicate
`(issuer, { organizationId, endpoints, samlCertFingerprints }) => boolean | Promise<boolean>`.

The list binds the **IdP**, not merely the `issuer` string — and what
"the IdP" is differs by protocol:

- **OIDC.** Upstream verifies an id_token's `iss` against the stored issuer
  but fetches the signing keys from the tenant-supplied `jwksEndpoint`, so
  a tenant allowed to write `issuer: "https://idp.allowed.example"` could
  point every endpoint (`skipDiscovery`) at an IdP of their own and sign in
  through it under the "allowed" string. The list is applied to the issuer
  **and** to `discoveryEndpoint`, `authorizationEndpoint`, `tokenEndpoint`,
  `jwksEndpoint` and `userInfoEndpoint`. The endpoints _are_ the trust
  root: whoever serves the JWKS signs the tokens.
- **SAML.** The trust root is the **signing certificate**, not a URL. An
  assertion is verified against the certificate the tenant supplied —
  inline (`cert`, `idpMetadata.cert`) or embedded in an
  `idpMetadata.metadata` document — so a tenant can claim an allowed
  `entityID` and `entryPoint` word for word while supplying a keypair of
  their own, and the URL strings alone would let that through. The list is
  applied to the issuer (which upstream treats as the _service provider's_
  id), `entryPoint`, `idpMetadata.entityID`, the
  `singleSignOnService`/`singleLogoutService` locations and the
  `entityID`/locations inside a metadata document, **and every
  certificate the configuration carries must be pinned**:
  `sso.samlCertificateFingerprints` maps the IdP's entity id
  (`idpMetadata.entityID`, or the metadata document's `entityID`) to the
  SHA-256 fingerprints of its signing certificates (DER form — what
  `openssl x509 -in idp.pem -noout -fingerprint -sha256` prints; hex,
  colons optional, case-insensitive). The set that must be pinned is not
  re-derived by a parser of this layer's own: it is the **union** of (a)
  the signing certificates samlify itself returns for the configuration —
  built with the same `IdentityProvider(...)` inputs `@better-auth/sso`
  uses at the ACS (the metadata document when `idpMetadata.metadata` is
  set, otherwise `idpMetadata.cert`, falling back to `cert`) and read back
  with `getX509Certificate("signing")` — and (b) every certificate the
  configuration carries in a signing position: `cert`, `idpMetadata.cert`
  and each `KeyDescriptor` of the metadata document with `use="signing"`
  or no `use`. A `use="encryption"` descriptor is left out unless samlify
  treats it as a signing certificate; as of samlify 2.15 it never does
  (the metadata's `use` is honoured, and only certificates declared in the
  metadata are trusted at all). When samlify cannot build the IdP from the
  configuration, or returns no signing certificate, the provider is refused
  (fail closed). List every certificate during a rotation.

Forms:

- **Array form.** The issuer must match an entry (exact string, or a
  `RegExp` test). Each endpoint must then be the issuer itself, sit on the
  issuer's origin, or match an entry — by its full value or by its origin.
  An IdP that serves endpoints from several origins needs those origins
  listed (Google, for instance, issues from `https://accounts.google.com`
  but exchanges tokens at `https://oauth2.googleapis.com`). For SAML, the
  provider's `issuer` string — the service provider's id under upstream —
  must itself match an entry like any issuer; list it, the IdP's
  `entityID` and entry-point origin, **and pin its certificates
  — fail closed**: with an array allow-list, a SAML provider whose entity
  id has no pins (including the case where `samlCertificateFingerprints`
  is not set at all), one of whose certificates is not pinned, or from
  which no certificate can be read, is refused. The pins are ignored
  without an allow-list.
- **Predicate form.** Called once with the issuer and
  `{ organizationId, endpoints, samlCertFingerprints }` (the fingerprints
  normalised to lowercase hex, empty for OIDC) and decides alone; a throw
  or a non-`true` verdict refuses. Unreadable endpoints or certificates
  are refused before the predicate is consulted.

It is checked on `/sso/register`; on `/sso/update-provider` whenever
`issuer`, `oidcConfig` or `samlConfig` is sent — against the provider as it
would be stored after the update, so an endpoint swap with the issuer
untouched, an issuer change over endpoints the list no longer covers, or a
SAML certificate swap (`cert`, `idpMetadata.cert`, or a replaced metadata
document) is refused; **and at every SSO sign-in against the stored row**
(the SAML ACS and the OIDC callback, before any user row or session is
written), so an operator who configures or tightens the list or the pins
after providers were registered also refuses the rows written before. A
refusal at write time is `403 SSO_ISSUER_NOT_ALLOWED` and nothing is stored;
at sign-in no session is minted, the callback redirects with
`error=SSO_ISSUER_NOT_ALLOWED`, and the attempt is audited as
`auth.sign_in_refused` (`metadata.code: "SSO_ISSUER_NOT_ALLOWED"`) in the
provider's organization, like every other policy refusal (the refused row's
`providerId` is logged at warn so it can be fixed or removed). Absent,
anything is accepted (upstream behaviour).

The allow-list restricts _which identity providers_ may exist on the
deployment. It is not a per-tenant control over _whose accounts_ an IdP may
sign in — that remains [domain binding](#domain-binding-ssodomainbinding-default-verified-domain),
which is on by default and independent of the list.

```ts
enterprisePreset({
  // ...
  sso: {
    allowedIssuers: [
      /^https:\/\/[a-z0-9-]+\.okta\.com$/,
      "https://login.microsoftonline.com/common/v2.0",
      // Google issues from accounts.google.com but serves its endpoints
      // from other origins — list them.
      "https://accounts.google.com",
      "https://oauth2.googleapis.com",
      "https://www.googleapis.com",
      "https://openidconnect.googleapis.com",
      // A SAML IdP: its entityID (upstream's `issuer` is the SP id — list
      // that too if it differs) …
      "https://idp.acme.example/saml",
    ],
    // … and the SHA-256 fingerprints of its signing certificates, keyed by
    // that entityID. Without this entry every SAML provider claiming it is
    // refused (fail closed).
    samlCertificateFingerprints: {
      "https://idp.acme.example/saml": [
        "3A:1F:…:9C", // openssl x509 -in idp.pem -noout -fingerprint -sha256
        "b0c4…e2", // the next certificate during a rotation
      ],
    },
  },
});
```

## Domain ownership and uniqueness

A provider's `domain` is a comma-separated list of hostnames, matched
case-insensitively and including subdomains — `acme.test` covers
`eu.acme.test` mail. Both halves of the system (upstream's own matching and
this layer's home-realm, policy resolution and JIT guards) apply exactly
these rules (`src/server/policy/domains.ts`), and `/sso/register` and
`/sso/update-provider` now store the **normalised** list (trimmed,
lower-cased, de-duplicated, trailing dot dropped), refusing one that could
never match (`400 SSO_DOMAIN_INVALID` — a URL, a path, whitespace inside an
entry).

**One organization per verified domain.** `/sso/register`,
`/sso/update-provider` (when the domain changes) and `/sso/verify-domain`
answer `409 SSO_DOMAIN_TAKEN` when the domain list overlaps — equal, or a
subdomain in either direction — a domain **another** organization has
already verified. The refusal names only the caller's own colliding entries,
never the other organization's verified list. An org may register several
providers for its own domains. The check is at verification time too, so a
provider registered _before_ another org verified the same domain cannot be
verified afterwards. Upstream does not check this, and its e-mail
`/sign-in/sso` resolves the provider with an exact `findOne({ domain })`
that also considers unverified rows — hence the pinning below.

**E-mail sign-in is pinned.** `POST /sign-in/sso { email }` (or `{ domain }`)
without a `providerId` is pinned by this layer to the verified provider that
`findOrgsByEmailDomain` ranks first — most specific matched domain, then
`providerId` — but only when every provider at that specificity belongs to
one organization. If two orgs hold verified rows for the same domain (legacy
data written before this rule), the request is left to upstream's own lookup
and the ambiguity is logged at `warn`; de-duplicate such rows before
upgrading (query in [`security.md`](./security.md#upgrading-from-10x)).

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

| Purpose                          | URL                                                           |
| -------------------------------- | ------------------------------------------------------------- |
| SP entity ID                     | `{baseUrl}/sso/saml2/sp/{providerId}`                         |
| Assertion Consumer Service (ACS) | `{baseUrl}/sso/saml2/sp/acs/{providerId}`                     |
| SP metadata XML                  | `GET {baseUrl}/sso/saml2/sp/metadata?providerId={providerId}` |

Paste the SP metadata URL (or its downloaded XML) into the IdP when
configuring the SAML application; the ACS URL is what the IdP posts signed
`SAMLResponse`s back to.

IdP-initiated SAML (a response with no prior `AuthnRequest`) is accepted —
`enterprisePreset` sets `sso({ saml: { allowIdpInitiated: true } })`
explicitly (matching upstream's own default, made explicit so the intent is
visible in this repo rather than relying on a default that could change).

## SSO on Cloudflare Workers

Three things differ from a Node deployment, and the first one decides whether
SSO sign-in works at all.

**Native transactions.** The preset's `resolveUser` (SCIM pairing in 1.2, and
the 1.3 options below) runs inside the sign-in transaction, and upstream
refuses to run it on an adapter without native transactions
(`SSO_USER_RESOLUTION_REQUIRES_NATIVE_TRANSACTIONS`). On Workers that means a
Postgres driver that opens real transactions over a connection or a socket
(`node-postgres` or `postgres` through Hyperdrive, for example). An HTTP-only
driver such as `neon-http` has no interactive transactions, and **every** SSO
sign-in would fail with that error; better-auth's `memoryAdapter` fails the same
way, which is why `test/workerd/preset.test.ts` boots the preset there but does
not run a sign-in. Prove sign-in against a staging deployment on your real
driver, not against this repository's CI.

**DNS verification.** `POST /sso/verify-domain` uses
`node:dns/promises.resolveTxt`. A probe in `test/workerd/preset.test.ts` (the
real workerd runtime, `nodejs_compat`, compatibility date `2026-08-01`) records
that the module imports, `resolveTxt` is a function, and a name that does not
exist ends in an ordinary `ENOTFOUND`; see the
[Cloudflare DNS compatibility documentation](https://developers.cloudflare.com/workers/runtime-apis/nodejs/dns/).
So the standard flow is available there, and it is the one to keep when it
works for you: a database flag set by a test fixture does not prove control of
a customer's domain. Verify the real TXT challenge in your deployed runtime
once. When it cannot run — a runtime without `node:dns`, a resolver you cannot
reach — use **operator mode**:

```ts
enterprisePreset({ ...options, sso: { domainVerificationMode: "operator" } });

// after registering the provider, from your own server code (never an HTTP route):
import { verifySsoDomainOperator } from "@alphabros/enterprise/server";
await verifySsoDomainOperator(auth, {
  providerId: "acme-google",
  evidence: "gamesaccessibilityhub.com is our own domain; DNS checked in the registrar, OPS-123",
  actor: "ops:alice",
});
```

In operator mode `POST /sso/request-domain-verification` and
`POST /sso/verify-domain` answer `403 SSO_DOMAIN_VERIFICATION_OPERATOR_ONLY`
(one way to verify, never both), and the function sets `domainVerified` with the
same write upstream makes. It throws unless the mode is on, refuses a provider
that does not exist, one already verified, one with no organization, and a
domain another organization has verified (`409 SSO_DOMAIN_TAKEN`, the rule of
"Domain ownership and uniqueness"), and writes one `sso.domain_verified` row in
the provider's organization chain with `metadata` `{ method: "operator", actor,
evidence }` (`evidence`: 1–500 characters; `actor`: 1–200). It is an
**assertion by the operator, not a proof** — nothing checks DNS — so keep it
server-only, and keep the evidence honest: the row is what a later reader has.
A DNS-over-HTTPS check is not part of 1.3.

**`<ab-sso-wizard>` in operator mode.** The wizard's `verify-domain` step cannot
complete there. A freshly registered provider is not `domainVerified`, so the
wizard lands on that step, shows the DNS TXT record (which operator mode never
checks) and polls `POST /sso/verify-domain` every `pollIntervalMs`; each poll is
answered `403 SSO_DOMAIN_VERIFICATION_OPERATOR_ONLY`, which the wizard shows as
an error until `maxPollMs` runs out. The wizard never calls
`verifySsoDomainOperator` and cannot. The flow in operator mode is: the admin
registers the provider in the wizard (steps 1–2), the operator calls
`verifySsoDomainOperator` from server code, and the admin reloads the wizard.
Its step is derived from the stored provider, so with `domainVerified` now true
it opens on `test-login` and continues from there. Until a product has its own
screen for that wait, tell the admin to ignore the TXT record and the error on
that step.

**PKCE and nonce.** Upstream sends PKCE (`S256`) and the signed `state`, and
authenticates the client at the token endpoint, but it sends **no OIDC `nonce`**
(and refuses `nonce` as an `additionalParams` key), so the ID token is not bound
to the browser session by a nonce. The remaining binding is state, PKCE, client
authentication and the `iss`/`aud`/`azp` checks. A test
(`test/security/sso-existing-users-only.test.ts`) asserts the authorization URL
carries no nonce so the gap stays documented; the fix belongs upstream.
`sso.oidcClaims.requirePkce` makes the PKCE half a requirement.

## Just-in-time (JIT) provisioning

By default (none of the 1.3 options in
["Pre-provisioned users only"](#pre-provisioned-users-only) set),
`enterprisePreset` enables `disableImplicitSignUp: false` and forwards
`opts.provisionUser` to `sso()` verbatim. On a first SSO login from a
verified domain, the user is created and auto-joins that domain's
organization with the default role `member` in one step. A pending
invitation takes precedence over domain-based auto-join (upstream's own
behaviour, unchanged). This is the behaviour of 1.2 and it is what every
deployment gets until it opts out of it.

### Domain binding (`sso.domainBinding`, default `"verified-domain"`)

An SSO sign-in is honoured only when the signing provider is domain-verified
**for the user's e-mail domain** — applied at JIT user creation _and_ at
every session an SSO callback mints (`src/server/policy/sso-jit.ts`,
`src/server/policy/enforcement.ts`). Upstream `@better-auth/sso` binds
account _linking_ to a trusted provider but not account _creation_; this
layer binds both, and every session a callback mints:

- **`SSO_DOMAIN_NOT_ALLOWED`** (the callback redirects with
  `error=SSO_DOMAIN_NOT_ALLOWED`): the provider is not verified for that
  e-mail domain. No user row is written (the callback's transaction rolls
  back) and no session is minted. This applies to _existing_ users too — an
  `account` row linked before the upgrade to a provider that is not verified
  for the user's domain stays in the database but can no longer sign in; see
  the detection SQL in
  [`security.md`](./security.md#upgrading-from-10x).
- **`SSO_PROVIDER_UNRESOLVED`**: the signing provider could not be named —
  neither the route's `providerId` nor the server-trusted OAuth state
  (the shared `/sso/callback`) identifies one, or they disagree. Fail-closed
  canary; it should never fire on the routes this preset registers.
- **`emailVerified: true`** on a domain-bound JIT user: the IdP owns that
  domain and vouched for the address, which is exactly what an e-mail
  round-trip would prove. `sso.trustVerifiedDomainEmail: false` leaves
  upstream's own claim handling in charge (the binding still applies).
- **`ssoEnforced`** is satisfied only by the enforcing org's **own** IdP
  (`SSO_REQUIRED`, "through its own identity provider"): a sign-in through
  another organization's provider does not satisfy it, whatever that
  organization's own policy says.

`sso.domainBinding: "off"` restores the upstream behaviour — every tenant's
IdP can sign in and create any e-mail address on the deployment — and logs a
warning naming the advisory at construction. **`"off"` is only safe when
`sso.allowedIssuers` is configured and, for SAML,
`sso.samlCertificateFingerprints` pins the IdP signing certificates**: with
the binding off, which identity providers exist on the deployment is the
only thing that limits whose accounts an IdP may sign in, and the
allow-list with its pins is the only control over that. A second one-time
warning is logged through the auth logger when the binding is off and
`allowedIssuers` is not configured. It is an operator-level switch on
purpose: a per-org allow-list of "external" domains would be controlled by
the very tenant the binding protects against. Contractors on external mail
domains (gmail etc.) therefore cannot use a tenant's SSO in 1.1.0; invite
them and let them sign in with another allowed method.

### Providers belong to organizations

`/sso/register` requires `organizationId` in the body (`400 ORG_REQUIRED`
from the gate, before any fallback to the session's active organization).
Upstream runs its owner/admin check only when the field is present and
otherwise stores a "personal" (`organizationId: null`) provider; this layer
no longer lets one be created. Existing rows cannot be domain-verified through this layer,
are skipped by every org-scoped read, and are refused by the test-login
finish. `/sso/update-provider` and `/sso/delete-provider` are gated on the
`sso` entitlement of the provider's own organization, so a provider without
one is refused there too (`403 NOT_ORG_MEMBER`); docs/security.md, "SSO
providers without an organization", has the operator path for such rows.

### Invitations require a verified e-mail

The preset sets `organization({ requireEmailVerificationOnInvitation: true })`:
accepting or rejecting an invitation requires the session's e-mail to be
verified (`403 EMAIL_VERIFICATION_REQUIRED_BEFORE_ACCEPTING_OR_REJECTING_INVITATION`,
upstream's code). A domain-bound SSO user is verified and claims the invited
role at once; a password sign-up without a verification e-mail is not. Opt
out with `organization.requireEmailVerificationOnInvitation: false` only when
every sign-up path in the product verifies e-mail some other way.

## Pre-provisioned users only

For a deployment whose users exist before they sign in through SSO (an internal
tool behind one company's identity provider), SSO should be a way to sign in as
an existing account, never a way to create one or to join an organization. Five
opt-in keys under `EnterpriseOptions.sso` do that. **Every key is off by
default and a no-op when absent**: with none set, the `sso({...})` configuration
the preset builds is the 1.2 one, and `resolveUser` is the same function
reference as before (pinned by `test/server/preset.test.ts`).

```ts
enterprisePreset({
  ...options,
  sso: {
    existingUsersOnly: true,
    requireMembership: true, // the default with existingUsersOnly
    organizationProvisioning: "off",
    oidcClaims: { requireEmailVerified: true, requireHostedDomain: true, requirePkce: true },
    domainVerificationMode: "operator",
  },
});
```

| Key                                  | What it does                                                                                                                                                                                  |
| ------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `existingUsersOnly`                  | An OIDC sign-in never creates a user: it links a user that already exists (found by the ID token's e-mail) or is refused. Implies `requireEmailVerified`. Sets `disableImplicitSignUp: true`. |
| `requireMembership` (default `true`) | With `existingUsersOnly`: the user must already be a member of the provider's organization. Setting it without `existingUsersOnly` is a construction error.                                   |
| `organizationProvisioning: "off"`    | Stops both of upstream's automatic org joins: the provider-bound `member` row, and the verified-domain join after a social `/callback/` sign-in. Default `"member"` is today's behaviour.     |
| `oidcClaims.requireEmailVerified`    | `email_verified` must be the boolean `true` in the verified ID token (upstream also accepts the string `"true"`).                                                                             |
| `oidcClaims.requireHostedDomain`     | The `hd` claim must match (see [the next section](#google-workspace-and-the-hd-claim)). `true`, or an array of lower-case hostnames as an explicit allow-list.                                |
| `oidcClaims.requirePkce`             | Refuses a provider without PKCE at registration, at update, and at every sign-in.                                                                                                             |
| `domainVerificationMode: "operator"` | Replaces the DNS check with `verifySsoDomainOperator` ([SSO on Cloudflare Workers](#sso-on-cloudflare-workers)).                                                                              |

### How it is enforced

One composed `resolveUser` (`src/server/sso-resolve.ts`) is the single
enforcement point. Upstream runs it on **every** SSO sign-in — first logins and
returning ones, inside the transaction that links the account and mints the
session — and it is the only layer that sees `verifiedIdTokenClaims`, the claims
of the signature-verified ID token. The claims are never read from the userinfo
response or the profile. In order, an OIDC sign-in is checked for:

1. the provider being persisted (`SSO_PROVIDER_UNRESOLVED` otherwise — a
   `defaultSSO` entry has no row to judge, so strict mode refuses it);
2. the ID-token e-mail equalling the e-mail upstream is about to sign in
   (`SSO_EMAIL_CLAIM_MISMATCH`) — with a `userInfoEndpoint` upstream takes the
   profile from the userinfo response, which the ID-token signature does not
   cover; the claim name follows the provider's `mapping.email`;
3. `email_verified` (`SSO_EMAIL_NOT_VERIFIED`), `hd` (`SSO_HOSTED_DOMAIN_MISMATCH`)
   and PKCE (`SSO_PKCE_REQUIRED`) as configured;
4. with `existingUsersOnly`: the provider being domain-verified for the e-mail's
   domain (`SSO_DOMAIN_NOT_ALLOWED`);
5. SCIM, exactly as in 1.2 — a SCIM-managed org still requires an active SCIM
   user (`SCIM_PROVISIONING_REQUIRED`, `SCIM_USER_NOT_ACTIVE`); a SCIM link is
   kept but still gets step 6;
6. the user: it must exist (`SSO_USER_NOT_PROVISIONED`), not be banned
   (`SSO_USER_BANNED`: `banned` and no `banExpires`, or one in the future; a
   missing `banned` column counts as not banned), be a member of the provider's
   organization when `requireMembership` is on (`SSO_NOT_MEMBER`), and have no
   conflicting account: the same IdP subject linked to another user, or this
   user already linked to a different subject through the same provider
   (`SSO_ACCOUNT_CONFLICT`).

Every refusal is a redirect with `?error=<code>`, no session, no row written, and
an `auth.sign_in_refused` audit row naming the code and the provider. A database
error becomes upstream's `SSO_USER_RESOLUTION_FAILED`, which also refuses. With
`existingUsersOnly` on, the resolver never lets an OIDC sign-in continue. A SAML
sign-in (when no `oidcClaims` option is on) is handed to the 1.2 resolver, which
can let it continue; it still cannot create a user, because
`disableImplicitSignUp` and the `user.create.before` backstop below refuse the
creation.

Two backstops sit beside it: a `user.create.before` hook that refuses any user
created from an SSO callback (`SSO_SIGNUP_DISABLED`), because upstream computes
`disableSignUp = disableImplicitSignUp && !requestSignUp` and `requestSignUp` is
client-controlled; and the registration guards, which refuse a SAML provider
while an `oidcClaims` option is on and `pkce: false` while `requirePkce` is on
(`SSO_POLICY_UNSUPPORTED_PROTOCOL`, `SSO_PKCE_REQUIRED`).

### Linking, and why account linking can stay off

The resolver returns `{ action: "link", userId, profile: "preserve" }`.
Upstream skips its `account.accountLinking.enabled === false` refusal when a
user is selected by a resolver, so the product's global `accountLinking` stays
`{ enabled: false }`: nothing but this resolver, after every check above, can
link an SSO account. That also makes the resolver the only thing standing
between an IdP assertion and somebody else's account, so a bug in it is an
account-takeover path; the suite in `test/security/sso-existing-users-only.test.ts`
and the unit tests in `test/server/sso-resolve.test.ts` pin every branch.

The local `user.emailVerified` is neither required nor changed: the IdP is the
e-mail authority, and `profile: "preserve"` leaves the user's name, image and
e-mail alone. If you need the local flag too, that is a separate decision
(`requireLocalEmailVerified` is not part of 1.3).

SAML is **not** linked by this option. A SAML assertion for an existing, unlinked
user still ends in upstream's "account not linked", and no SAML sign-in creates
a user. With any `oidcClaims` option set, SAML is refused outright.

Email reassignment (the IdP gives an address to a new person) ends in
`SSO_ACCOUNT_CONFLICT` for the new subject; there is no unlink procedure in 1.3,
so an admin resolves it by deleting the stale `account` row.

### The wizard's test login is a real sign-in

`<ab-sso-wizard>`'s `test-login` step starts a real SSO sign-in
(`POST /enterprise/sso/test-login/start` hands off to `/sign-in/sso`), so it goes
through the composed resolver like any other. `test-login/finish` passes only
when the session that comes back belongs to the admin who started it. With
`existingUsersOnly` the admin's own IdP identity must therefore already be
provisioned **before** the test login: a `user` row for the IdP e-mail, a
`member` row in the provider's organization (unless `requireMembership: false`),
not banned, and no account conflict. Otherwise the test login is refused
(`?error=SSO_USER_NOT_PROVISIONED`, `SSO_NOT_MEMBER`, …), creates nothing and is
not recorded as passed, and enforcement, which requires a passed test login,
cannot be switched on. Create the admin's user and membership first.
(`test/security/sso-existing-users-only.test.ts` pins the refusal.)

### Peer floor

The resolver depends on upstream behaviour that was read in
`@better-auth/sso` **1.7.19** only: `verifiedIdTokenClaims` on the resolver
input, the `link` action with `profile: "preserve"`, the account-linking refusal
being skipped for a resolver-selected user, and `organizationProvisioning.disabled`.
That these exist at the `^1.7.10` peer floor is **not verified**. If a resolver
call arrives without `verifiedIdTokenClaims`, the sign-in is refused
`SSO_EMAIL_CLAIM_MISMATCH` rather than failing with a TypeError. Run 1.7.19 or
newer before turning a 1.3 option on.

### What a refusal tells the caller

The error code reaches the browser in the redirect. `SSO_USER_NOT_PROVISIONED`
therefore tells an IdP-authenticated person whether an account exists for their
address. The audience is limited to people the IdP just authenticated, but it is
an enumeration oracle for that audience; if that matters, put the same message
on every code in your error page.

## Google Workspace and the `hd` claim

`oidcClaims.requireHostedDomain` reads the `hd` (hosted domain) claim Google puts
in the ID token for Workspace accounts. With `true`, `hd` must be present, a
string, and equal (lower-cased) to one of the provider's domains — the stored
list is comma-separated and is split and trimmed — and the e-mail's domain must
equal `hd` too. **There is no subdomain matching**, unlike the provider's own
domain match: `eu.acme.test` does not satisfy `hd: acme.test`. An array of
lower-case hostnames is an explicit allow-list instead; entries are hostnames,
never regular expressions.

It is Google-specific. `hd` is absent for personal Google accounts and for every
non-Google IdP, and a Workspace alias domain does not match, so those sign-ins
are refused with `SSO_HOSTED_DOMAIN_MISMATCH`. The claim is read from the
verified ID token only; whether Google's userinfo response carries `hd` was not
verified, which is why nothing else is consulted. A one-time warning at
construction says as much.

## Using a single-tenant Google Workspace IdP

A product whose users are all on one Google Workspace domain, with accounts
created ahead of time:

1. **Preset options**, as in the example above, with `allowedIssuers` listing
   Google's issuer and the origins of its authorization, token and JWKS
   endpoints. `account.accountLinking` stays `{ enabled: false }` and
   `emailAndPassword.disableSignUp` stays `true`.
2. **Register the provider** from server code, with `domain` your Workspace
   domain, `issuer` `https://accounts.google.com`, and `scopes`
   `["openid", "email", "profile"]` — the default list adds `offline_access`,
   and how Google answers it was not verified. Google can also present the issuer
   without its scheme; upstream compares `iss` exactly, so confirm the string in
   a real ID token before relying on it.
3. **Verify the domain**: the DNS flow, or `verifySsoDomainOperator` in operator
   mode ([SSO on Cloudflare Workers](#sso-on-cloudflare-workers)).
4. **Pre-provision** each user: the `user` row and a `member` row in the
   provider's organization must exist before the first sign-in.
5. **Allow the routes** `/sign-in/sso` and `/sso/callback/*` through whatever
   allow-list fronts `/api/auth/*`.
6. **Entitlements**: `/sso/register` is gated on the `sso` entitlement of the
   organization, so an organization that cannot hold it must register the provider
   through your own seam.
7. **Driver**: the resolver needs a native-transaction Postgres driver on Workers
   (see above).

## Home-realm discovery (email-first login)

`discoverHomeRealm(email)` (`@alphabros/enterprise/client`) calls the public
`POST /enterprise/home-realm { email }` endpoint and returns either
`{ method: "sso", providerId }` or `{ method: "local" }`. The response never
reveals whether the email belongs to an existing user — only whether its
_domain_ has a verified SSO provider, which is public information about an
organization, not an individual account. Wire your sign-in page to call this
before rendering a password/magic-link field; see the README's client
snippet.

## `samlSpKeys` — reserved, not wired

`EnterpriseOptions.samlSpKeys` is typed and documented, but **not consumed by
`enterprisePreset`**, and it is not encrypted at rest because it never reaches
the database at all.

`@better-auth/sso@1.6.x`'s `sso()` constructor has no plugin-level slot for a
default or shared SP (service provider) signing identity — the only place SP
key material exists upstream is a _per-provider_ `samlConfig.spMetadata`, set
at `/sso/register` time for that one organization's connection. There is
therefore nothing for the preset to pass it to.

If you want one shared SP identity across every org's SAML connection, read
the option back yourself and put it in your own registration body:

```ts
await authClient.$fetch("/enterprise/sso/register", {
  method: "POST",
  body: {
    organizationId: orgId,
    providerId,
    issuer,
    domain,
    samlConfig: {
      entryPoint,
      cert,
      spMetadata: { entityID, privateKey: mySpPrivateKey, cert: mySpCert },
    },
  },
});
```

The private-key fields of a registered `samlConfig` (`privateKey`,
`privateKeyPass`, `decryptionPvk`, `encPrivateKey`, `encPrivateKeyPass`,
including inside `spMetadata`) **are** encrypted at rest with `secretsKey` —
see [`security.md`](./security.md#secrets-and-token-storage). The rest of
`samlConfig` (certificates, IdP metadata, entry point) is public material and
is stored as upstream stores it.

Wiring the option into the preset properly needs upstream support; it is a P2
item, kept typed so the shape does not change when that lands.
