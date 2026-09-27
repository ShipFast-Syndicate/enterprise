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
  or no `use`. A `use="encryption"` descriptor is left out only when
  samlify does not treat it as a signing certificate — samlify reads a
  document with a single `KeyDescriptor` as one shared certificate for
  both uses whatever its `use` says, so a lone `encryption` descriptor is
  pinned like any other. When samlify cannot build the IdP from the
  configuration, or returns no signing certificate, the provider is refused
  (fail closed). List every certificate during a rotation.

Forms:

- **Array form.** The issuer must match an entry (exact string, or a
  `RegExp` test). Each endpoint must then be the issuer itself, sit on the
  issuer's origin, or match an entry — by its full value or by its origin.
  An IdP that serves endpoints from several origins needs those origins
  listed (Google, for instance, issues from `https://accounts.google.com`
  but exchanges tokens at `https://oauth2.googleapis.com`). For SAML, list
  the IdP's `entityID` and entry-point origin, **and pin its certificates
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
`auth.sso_sign_in_failed` like every other SSO refusal (the refused row's
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
never the other organization's verified list (a tenant who registers one
domain it happens to know must not learn every domain the victim org has
verified). An org may register several providers for its own domains.
The check is at verification time too, so a provider registered _before_
another org verified the same domain cannot be verified afterwards. Upstream
never checked this: any tenant could register a second, unverified provider
for a domain some other org had verified, and because upstream's e-mail
`/sign-in/sso` resolves the provider with an exact `findOne({ domain })`
over unverified rows too, the squat row won that lookup and broke the
legitimate org's e-mail sign-in ("domain has not been verified").

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

## DNS verification on Cloudflare Workers

`POST /sso/verify-domain` uses `node:dns/promises.resolveTxt`. Cloudflare
Workers supports `resolveTxt` when `nodejs_compat` is enabled; see the
[Cloudflare DNS compatibility documentation](https://developers.cloudflare.com/workers/runtime-apis/nodejs/dns/).
Use a supported compatibility date and verify the real TXT challenge in the
deployed runtime. The old v0.1 statement that Workers has no `node:dns` support
is no longer accurate.

Keep the provider's normal domain-verification flow. A database flag set by a
test fixture does not prove control of a customer's domain.

## Just-in-time (JIT) provisioning

`enterprisePreset` enables `disableImplicitSignUp: false` and forwards
`opts.provisionUser` to `sso()` verbatim. On a first SSO login from a
verified domain, the user is created and auto-joins that domain's
organization with the default role `member` in one step. A pending
invitation takes precedence over domain-based auto-join (upstream's own
behaviour, unchanged).

### Domain binding (`sso.domainBinding`, default `"verified-domain"`)

An SSO sign-in is honoured only when the signing provider is domain-verified
**for the user's e-mail domain** — applied at JIT user creation _and_ at
every session an SSO callback mints (`src/server/policy/sso-jit.ts`,
`src/server/policy/enforcement.ts`). Upstream `@better-auth/sso` does not
bind the create branch: a tenant's verified IdP could assert `ceo@acme.test`
and mint that account on the deployment — locking the real user out of their
own IdP (the account is linked to the wrong provider), satisfying acme's
`ssoEnforced`, and accepting acme's invitations. The fix:

- **`SSO_DOMAIN_NOT_ALLOWED`** (the callback redirects with
  `error=SSO_DOMAIN_NOT_ALLOWED`): the provider is not verified for that
  e-mail domain. No user row is written (the callback's transaction rolls
  back) and no session is minted. This applies to _existing_ users too — an
  `account` row that a foreign IdP linked before the upgrade stays in the
  database but can no longer sign in; see the detection SQL in
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
  (`SSO_REQUIRED`, "through its own identity provider"): another tenant
  flipping their org to `ssoEnforced` does not satisfy yours for a user they
  linked to their IdP.

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
Upstream ran its owner/admin check only when the field was present, so any
signed-in user could create a "personal" (`organizationId: null`) provider
claiming any domain. Such rows cannot be domain-verified through this layer,
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
