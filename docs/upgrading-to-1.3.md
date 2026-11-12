# Upgrading to 1.3

1.3.0 is a minor release (semantic-release computes it from the `feat` commits since 1.2.0, with no
breaking-change footer). The release number is the maintainer's call; this guide is written for
whichever minor carries these changes. It adds one thing, **additive and opt-in**: stricter SSO
sign-in options under `EnterpriseOptions.sso`:

1. **Pre-provisioned users only** (`existingUsersOnly`, `requireMembership`).
2. **No automatic organization joins** (`organizationProvisioning: "off"`).
3. **Claim checks on the verified ID token** (`oidcClaims`).
4. **Operator-attested domain verification** (`domainVerificationMode: "operator"`) and the
   server-only `verifySsoDomainOperator()`.

A deployment that sets none of them is unaffected: no schema change, no migration, no new
dependency, no new HTTP route, the same plugin list in the same order, and the same configuration
passed to `@better-auth/sso` (`resolveUser` is still the very same function). SQLite, libSQL and
Postgres behave as before. The peer ranges are unchanged (`^1.7.10`), but the 1.3 options were
written and tested against `@better-auth/sso` 1.7.19 only: whether `verifiedIdTokenClaims`, the
resolver's `link` / `profile: "preserve"` action and `organizationProvisioning.disabled` exist at
1.7.10 is **not verified**. Run 1.7.19 or newer before turning any 1.3 option on (a resolver call
without `verifiedIdTokenClaims` is refused `SSO_EMAIL_CLAIM_MISMATCH`, not crashed). Nothing changes
when no option is set.

Upgrading from 1.1.x or earlier: do [`docs/upgrading-to-1.2.md`](./upgrading-to-1.2.md) first.

## 1. Pre-provisioned users only (opt-in)

By default an SSO sign-in from a verified domain creates the user and joins the organization
([JIT provisioning](./sso.md#just-in-time-jit-provisioning)). If your users exist before they sign
in:

```ts
enterprisePreset({
  ...options,
  sso: { existingUsersOnly: true }, // requireMembership defaults to true
});
```

An OIDC sign-in then links the existing user found by the ID token's e-mail, or is refused
(`?error=SSO_USER_NOT_PROVISIONED`, `SSO_NOT_MEMBER`, `SSO_USER_BANNED`, `SSO_ACCOUNT_CONFLICT`, …).
It never creates a user. Before turning it on:

- Every person who should sign in has a `user` row **and**, with `requireMembership`, a `member`
  row in the provider's organization. Create them first; the first sign-in does not.
- The provider is domain-verified, and its domain covers the e-mail's domain.
- **The admin who runs the wizard's test login is provisioned too.** The test login is a real SSO
  sign-in that goes through the same resolver: the admin's IdP e-mail needs a `user` row and a
  `member` row in the provider's organization, and must not be banned, before step 4 of the wizard.
  A refused test login creates nothing and is not recorded as passed, so enforcement cannot be
  switched on until it succeeds ([`docs/sso.md`](./sso.md#the-wizards-test-login-is-a-real-sign-in)).
- Keep `account.accountLinking` as it is, including `{ enabled: false }`: the link comes from the
  resolver, not from better-auth's implicit linking.
- SAML providers are not linked by this option (upstream's "account not linked" still applies) and
  create no user. A SAML account that is already linked keeps signing in.
- `requireMembership: false` drops the membership check; it is refused at construction without
  `existingUsersOnly`.

The local `user.emailVerified` is not required and not changed: the IdP is the e-mail authority.

## 2. No automatic organization joins (opt-in)

`sso: { organizationProvisioning: "off" }` stops both automatic joins upstream performs: the
provider-bound `member` row at the end of an SSO sign-in, and the verified-domain join after a
social sign-in. Membership is then only what an admin, an invitation or SCIM grants. The default,
`"member"`, is today's behaviour.

## 3. Claim checks (opt-in)

```ts
sso: { oidcClaims: { requireEmailVerified: true, requireHostedDomain: true, requirePkce: true } }
```

- `requireEmailVerified`: `email_verified` must be the boolean `true` (implied by
  `existingUsersOnly`).
- `requireHostedDomain`: Google Workspace's `hd` claim must equal a provider domain (or an entry
  of the array you pass), with the e-mail on exactly that domain. Google-only; personal accounts
  and other IdPs are refused. Logs a one-time warning at construction.
- `requirePkce`: a provider without PKCE is refused at registration, at update and at sign-in.
  Providers registered earlier with `pkce: false` stop signing in (`SSO_PKCE_REQUIRED`); re-register
  or update them first.
- **SAML providers are refused while any `oidcClaims` option is on** (at registration and update,
  and at sign-in: `SSO_POLICY_UNSUPPORTED_PROTOCOL`). Check `SELECT "providerId" FROM "ssoProvider"
WHERE "samlConfig" IS NOT NULL` before you turn one on.

See [`docs/sso.md`](./sso.md#google-workspace-and-the-hd-claim) for the exact rules.

## 4. Operator domain verification (opt-in)

`sso: { domainVerificationMode: "operator" }` closes `POST /sso/request-domain-verification` and
`POST /sso/verify-domain` (`403 SSO_DOMAIN_VERIFICATION_OPERATOR_ONLY`) and makes
`verifySsoDomainOperator(auth, { providerId, evidence, actor })` usable from server code. It is for
runtimes where the DNS lookup cannot run; where it can, keep the DNS flow, which proves control of
the domain and this does not. The call writes one `sso.domain_verified` audit row with
`method: "operator"`. If your product mirrors the audit route table, nothing changes: the function
is not an endpoint. See [`docs/sso.md`](./sso.md#sso-on-cloudflare-workers).

If you mount `<ab-sso-wizard>`, note that its `verify-domain` step cannot complete in this mode:
it polls `POST /sso/verify-domain`, which now answers `403`, and shows the TXT record the mode never
checks. The operator calls `verifySsoDomainOperator`, then the admin reloads the wizard, which opens
on `test-login` because the provider is now verified (details in the same `docs/sso.md` section).

## New error codes

Registered in `POLICY_REFUSAL_CODES` (a sign-in ending in one is `auth.sign_in_refused`, not
`auth.sso_sign_in_failed`): `SSO_EMAIL_NOT_VERIFIED`, `SSO_EMAIL_CLAIM_MISMATCH`,
`SSO_HOSTED_DOMAIN_MISMATCH`, `SSO_USER_NOT_PROVISIONED`, `SSO_USER_BANNED`, `SSO_NOT_MEMBER`,
`SSO_ACCOUNT_CONFLICT`, `SSO_SIGNUP_DISABLED`, `SSO_PKCE_REQUIRED`,
`SSO_POLICY_UNSUPPORTED_PROTOCOL`. Not a sign-in refusal: `SSO_DOMAIN_VERIFICATION_OPERATOR_ONLY`
(403), and the operator function's own errors (`SSO_DOMAIN_VERIFICATION_NOT_OPERATOR_MODE`,
`SSO_DOMAIN_VERIFICATION_INPUT_INVALID`, `SSO_PROVIDER_NOT_FOUND`, `DOMAIN_VERIFIED`,
`SSO_PROVIDER_NOT_ORG_SCOPED`, `SSO_DOMAIN_INVALID`, `SSO_DOMAIN_TAKEN`, `SSO_PROVIDER_CHANGED`).
If your error page shows `?error=` codes, map the new ones; `SSO_USER_NOT_PROVISIONED` tells a
signed-in IdP user that no account exists for their address
([`docs/security.md`](./security.md#sso-sign-in-options-13-threat-model)).

## Things that did not change

- `domainBinding`, `trustVerifiedDomainEmail`, `allowedIssuers` and `samlCertificateFingerprints`.
- The session-time checks (`SSO_DOMAIN_NOT_ALLOWED`, `SSO_REQUIRED`, `SCIM_*`) still run after the
  resolver.
- No nonce is sent (upstream sends none), and there is no DNS-over-HTTPS verification in this
  release.
- `defaultSSO` providers are not supported by `existingUsersOnly` or `oidcClaims`: they have no
  stored row to judge, so the resolver refuses them (`SSO_PROVIDER_UNRESOLVED`). The preset does not
  configure any.

## Checklist

- [ ] Nothing opted in: upgrade the package, nothing else.
- [ ] Any 1.3 option on: `@better-auth/sso` is 1.7.19 or newer (the `^1.7.10` floor is not verified).
- [ ] `existingUsersOnly`: users and (with `requireMembership`) members exist, **including the admin
      who runs the wizard's test login**; provider is domain-verified; `accountLinking` untouched;
      SAML providers understood.
- [ ] `organizationProvisioning: "off"`: nobody relied on the automatic join.
- [ ] `oidcClaims`: no SAML providers, no `pkce: false` providers, `hd` understood as Google-only.
- [ ] `domainVerificationMode: "operator"`: the call sits in server code only, with real evidence;
      admins using `<ab-sso-wizard>` know its `verify-domain` step waits for the operator and the
      wizard is reloaded afterwards.
- [ ] Error page maps the new `?error=` codes.
