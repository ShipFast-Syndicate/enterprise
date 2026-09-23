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

## Trust the OIDC provider origin

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

Entering an issuer in the portal does not grant it server-side trust. An
`Untrusted OIDC discovery URL` response means the operator must review and
configure that origin. Keep the allowlist narrow: these are Better Auth trust
settings, and explicitly trusting private-network IdPs also changes their SSRF
validation boundary. Do not use a wildcard to make arbitrary issuers pass.

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
