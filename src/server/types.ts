// Alpha Bros enterprise layer — shared server-side types.
//
// `Feature` is the entitlement vocabulary the gate plugin (`./gate.ts`) and
// `requireFeature` (`./entitlements.ts`) speak. `EnterpriseOptions` is the
// single config object every consumer (preset, gate, and — in later tasks —
// the audit/policy/SCIM plugins) is constructed from.

import type { sso } from "@better-auth/sso";

export type Feature = "sso" | "scim" | "audit_log" | "enforce_2fa" | "api_keys" | "teams";

export type ResolveEntitlements = (orgId: string) => Promise<Iterable<Feature>>;

export interface EnterpriseOptions {
  /** Product slug this deployment belongs to, e.g. "klar". */
  product: string;
  /** Resolves the set of features an org is entitled to (billing/plan lookup). */
  resolveEntitlements: ResolveEntitlements;
  /**
   * Reserved — not yet consumed by `enterprisePreset` (`./preset.ts`).
   * `@better-auth/sso@1.7.5`'s `sso()` constructor has no plugin-level slot
   * for a default/shared SP signing identity (verified directly against
   * `node_modules/@better-auth/sso/dist/index-CMcY1z4e.d.mts`'s `SSOOptions`
   * interface — only a *per-provider* `samlConfig.spMetadata`, set at
   * `/sso/register` time for that one org's connection, exists at all), so
   * this can't be wired into `preset.ts`'s `sso(...)` call the way
   * `provisionUser` is. Kept here for a product to read when it builds its
   * own `/sso/register` (or `./enterprise-api/sso.ts`'s
   * `/enterprise/sso/register`) request body, to reuse one shared SP signing
   * identity across every org's SAML connection instead of generating a
   * fresh key pair per org.
   */
  samlSpKeys?: { cert: string; privateKey: string };
  /** Symmetric key used to encrypt stored secrets. Must be >= 32 chars. */
  secretsKey: string;
  /** Independent >=32 character HMAC key for managed SCIM credentials. */
  scimCredentialHashSecret: string;
  /**
   * Audit log retention, export bounds and chain keying.
   *
   * `retentionDays` (default 365) drives archival compaction: rows older
   * than the window are replaced by a single signed
   * `audit.retention_compacted` anchor row, so the chain still verifies
   * (C-02). `exportMaxRows` (default 100 000) caps one
   * `/enterprise/audit/export` call — past it the endpoint answers `413`
   * and asks the caller to narrow the range (M-05).
   *
   * `chainKey` (opt-in, `>= 32` characters, independent of `secretsKey` and
   * `scimCredentialHashSecret`) turns the per-org hash chain into an
   * HMAC-SHA256 chain. Without it the chain only proves internal
   * consistency: anyone with database write can rewrite an org's whole
   * chain consistently. With it, a rewrite needs the key. Adoption is
   * monotonic — once an org's chain has a keyed row, an unkeyed row after
   * it (or verification without the key) reports the chain as broken, so
   * treat the key like the other two secrets: set once from a secret store,
   * never remove it. Keep it out of the database.
   */
  audit?: { retentionDays?: number; exportMaxRows?: number; chainKey?: string };
  /**
   * SSO trust boundaries.
   *
   * `domainBinding` (default `"verified-domain"`): an SSO sign-in — the JIT
   * user creation *and* every session the provider signs in — is only
   * honoured when the signing provider is domain-verified for the user's
   * e-mail domain. `"off"` restores the upstream behaviour in which any
   * tenant's IdP can sign in (and create) accounts for **any** e-mail
   * address on the platform — the cross-tenant account-squatting class
   * GHSA-8p84-pc7q-69jr describes. It is an operator-level switch on
   * purpose (a per-org allow-list would be controlled by the very tenant
   * the binding protects against); a warning is logged at construction
   * when it is off. **`"off"` is only safe when `allowedIssuers` is
   * configured and, for SAML, `samlCertificateFingerprints` pins the IdP
   * signing certificates** — with the binding off, the allow-list and the
   * pins are the only control over which identity providers can sign
   * users in; a second one-time warning is logged through the auth logger
   * when the binding is off without `allowedIssuers`.
   *
   * `trustVerifiedDomainEmail` (default `true`): a user created through a
   * domain-bound SSO sign-in is stored `emailVerified: true` — the IdP owns
   * that domain and vouched for the address, which is exactly what an
   * e-mail round-trip would prove. `false` leaves upstream's own claim
   * handling in charge.
   *
   * `allowedIssuers`: an allow-list for the identity providers an org admin
   * may register or update a provider to — and that a stored provider must
   * still pass at every SSO sign-in. What it binds differs by protocol,
   * because the `issuer` string alone binds nothing:
   *
   * - **OIDC** — upstream fetches the signing keys from the tenant-supplied
   *   `jwksEndpoint`, so the list is applied to the `issuer` **and** to
   *   `discoveryEndpoint`/`authorizationEndpoint`/`tokenEndpoint`/
   *   `jwksEndpoint`/`userInfoEndpoint`. Array form: the issuer must match
   *   an entry (exact string or `RegExp`), and each endpoint must be the
   *   issuer, sit on the issuer's origin, or match an entry itself or by
   *   origin — an IdP that serves endpoints from several origins needs
   *   those origins listed.
   * - **SAML** — the trust root is the signing certificate, not a URL: a
   *   tenant may claim an allowed `entityID`/`entryPoint` while supplying
   *   a keypair of their own. The list is applied to the `issuer` (the SP
   *   id, under upstream), `entryPoint`, `idpMetadata.entityID`, the
   *   `singleSignOnService`/`singleLogoutService` locations and the
   *   `entityID`/locations inside `idpMetadata.metadata`, **and** every
   *   certificate a sign-in could be verified against must be pinned in
   *   `samlCertificateFingerprints` under the configuration's entity id
   *   (its `idpMetadata.entityID` / metadata `entityID`). That set is the
   *   union of what samlify itself returns as the signing certificates for
   *   the configuration — built with the inputs upstream uses at the ACS
   *   — and every certificate carried in a signing position (`cert`,
   *   `idpMetadata.cert`, each `use="signing"`/use-less `KeyDescriptor`
   *   of the document); a `use="encryption"` descriptor is left out only
   *   when samlify does not treat it as a signing certificate. **Fail
   *   closed**: with an array allow-list and no pins for that entity id,
   *   a certificate that is not pinned, no readable certificate, or a
   *   configuration samlify cannot build an IdP from, the SAML provider
   *   is refused.
   *
   * Predicate form: called once with the issuer and `{ organizationId,
   * endpoints, samlCertFingerprints }` (normalised lowercase hex, empty for
   * OIDC) and decides alone; unreadable endpoints or certificates are
   * refused before it is consulted. Checked on `/sso/register`, on
   * `/sso/update-provider` whenever `issuer`, `oidcConfig` or `samlConfig`
   * is sent (against the merged result), and on every SSO sign-in against
   * the stored row (SAML ACS and OIDC callback — an operator tightening the
   * list or the pins also refuses rows registered before). Refusal is `403
   * SSO_ISSUER_NOT_ALLOWED`; at sign-in no session is minted and the
   * failure is audited like every other SSO refusal. Absent = anything
   * (upstream behaviour). `trustedOrigins` is **not** an issuer allow-list;
   * this is. It restricts *which IdPs* exist on the deployment — the
   * per-tenant control over *whose accounts* an IdP may sign in remains
   * `domainBinding`.
   *
   * `samlCertificateFingerprints`: the pins the array form of
   * `allowedIssuers` requires for SAML — a map from the IdP's entity id to
   * the SHA-256 fingerprints of the DER form of its signing certificates
   * (`openssl x509 -in idp.pem -noout -fingerprint -sha256`; hex, colons
   * optional, case-insensitive; list every certificate during a rotation).
   * Ignored without `allowedIssuers`, and by the predicate form (which
   * receives the fingerprints instead).
   */
  sso?: {
    domainBinding?: "verified-domain" | "off";
    trustVerifiedDomainEmail?: boolean;
    allowedIssuers?:
      | Array<string | RegExp>
      | ((
          issuer: string,
          ctx: {
            organizationId: string | null;
            endpoints: string[];
            samlCertFingerprints: string[];
          },
        ) => boolean | Promise<boolean>);
    samlCertificateFingerprints?: Record<string, string[]>;
  };
  /**
   * Forwarded to the upstream `organization()` plugin by the preset.
   *
   * `requireEmailVerificationOnInvitation` (default `true` here; upstream
   * defaults it to `false` for opaque invitation ids): accepting or
   * rejecting an invitation requires the session's e-mail to be verified,
   * so an account minted for someone else's address cannot cash in an
   * invitation meant for the real owner. Opt out only when every sign-up
   * path in the product verifies e-mail some other way.
   *
   * `allowUserToCreateOrganization` (default `true`, the upstream default —
   * kept deliberately: self-serve org creation is a product feature, and
   * the policy layer now applies the union of every org's policy, so a
   * second organization is no longer an escape hatch).
   */
  organization?: {
    requireEmailVerificationOnInvitation?: boolean;
    allowUserToCreateOrganization?:
      boolean | ((user: { id: string; email: string }) => boolean | Promise<boolean>);
  };
  /**
   * Sign-in policy classification.
   *
   * `signInMethods`: extra endpoint → method-name mappings for sign-in
   * plugins this preset does not ship (`"/sign-in/email-otp": "email_otp"`,
   * or a prefix `"/phone/*": "phone"`). A session created from a path the
   * layer cannot classify is **refused** for a user under a restricted
   * policy, so a product adding such a plugin declares it here and lists the
   * method in the org's `allowedMethods`. Method names are `[a-z_][a-z0-9_]*`.
   *
   * `twoFactor.satisfiedBy` (default `["sso"]`): sign-in methods that count
   * as having satisfied `require2fa` on their own (the IdP did MFA).
   * `twoFactor.enrollmentPaths`: extra request paths an un-enrolled user of
   * a `require2fa` org may still call (the product's enrolment UI backend).
   */
  policy?: {
    signInMethods?: Record<string, string>;
    twoFactor?: { satisfiedBy?: string[]; enrollmentPaths?: string[] };
  };
  /**
   * API-key lifetime bounds forwarded to the upstream `apiKey()` plugin:
   * `defaultExpiresInS` (default 90 days, in **seconds**; `null` = keys
   * never expire unless the caller asks) and `maxExpiresInDays` (default
   * 365) — the longest lifetime a caller may request.
   */
  apiKeys?: {
    defaultExpiresInS?: number | null;
    maxExpiresInDays?: number;
    /**
     * Let an `x-api-key` header authenticate as its owner (upstream's
     * `enableSessionForAPIKeys` mock session) so a product's own API
     * handlers can resolve the key's owner through `/get-session` with the
     * key. @default false
     *
     * This is the supported way to opt in: the preset builds the upstream
     * plugin with the enterprise validator, header list and expiry bound
     * already in place. A key authenticates to `API_KEY_ALLOWED_PATHS` only
     * (`/get-session` and `/api-key/verify`); every other endpoint —
     * management, credential minting, every write, every other read and any
     * endpoint of a plugin you add — answers `403 API_KEY_NOT_ALLOWED_HERE`
     * whichever way the key is carried (`isApiKeyRefusedPath` in
     * `./api-keys.ts`; see `docs/security.md`).
     */
    enableSessionForAPIKeys?: boolean;
    /**
     * Upstream's per-key rate limit (`apiKey({ rateLimit })`), forwarded
     * as-is. Upstream's default is **10 requests per key per 24 h**
     * (`enabled: true`, `maxRequests: 10`, `timeWindow: 86_400_000` ms) —
     * sized for an occasional script, not for a product API driving the
     * mock session above; set `maxRequests`/`timeWindow` to what your API
     * needs, or `enabled: false` to rely on your own limiter.
     * `maxRequests` and `timeWindow` are stamped on each key row at create
     * (`rateLimitMax`, `rateLimitTimeWindow`), so changing them affects keys
     * created afterwards; `enabled: false` applies to every key at use
     * time. A refused request (`API_KEY_NOT_ALLOWED_HERE`) never counts.
     * @default upstream's (10 per 24 h)
     */
    rateLimit?: { enabled?: boolean; timeWindow?: number; maxRequests?: number };
  };
  /**
   * SCIM Groups behavior — the static fallback used when an org's
   * `org_policy.group_role_map` is empty. @default groupRoleMap {}
   *
   * `"owner"` is **not** a legal target (M-01): an IdP group that confers org
   * ownership is the payload of the admin→owner escalation the 2026-09-15
   * audit reproduced. The type refuses it, and the native projection
   * (`./scim.ts`) additionally drops any `"owner"` entry that
   * reaches it at runtime — from a stale policy row written before this rule,
   * or from untyped JavaScript.
   */
  scim?: { groupRoleMap?: Record<string, "admin" | "member"> };
  /**
   * Forwarded verbatim to `sso()` in the preset (`./preset.ts`) so callers
   * configure JIT user provisioning in one place.
   */
  provisionUser?: NonNullable<Parameters<typeof sso>[0]>["provisionUser"];
}
