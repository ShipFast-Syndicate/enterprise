// Alpha Bros enterprise layer — `EnterpriseOptions` validation.
//
// One place every entry point calls, so a misconfiguration fails at
// construction time rather than at the first request that happens to depend
// on it. Called from `enterprisePreset` (`./preset.ts`) *and* from
// `enterpriseGate` (`./gate.ts`) — a product that hand-composes the plugin
// list instead of using the preset still gets the checks, since the gate is
// the one plugin the rest of the layer cannot work without
// (`requireFeature` reads its `options` back off the auth context).

import type { EnterpriseOptions } from "./types";
import { assertSecretsKey } from "./secrets";
import { normalizeFingerprint } from "./sso-domain";

const PREFIX = "@alphabros/enterprise:";

function fail(message: string): never {
  throw new Error(`${PREFIX} ${message}`);
}

function assertPositiveFinite(name: string, value: unknown): void {
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
    fail(`"${name}" must be a finite number > 0 (got ${String(value)}).`);
  }
}

// Method names `allowedMethods` can hold: lower-case snake_case identifiers,
// the same shape as the built-in set (`sso`, `magic_link`, `password`, …).
const METHOD_NAME_RE = /^[a-z_][a-z0-9_]*$/;

// `sso.domainBinding: "off"` is warned about once per process, not once per
// `betterAuth()` construction — test suites and hot reloads build many
// instances, and the point is that an operator reads it once.
let warnedDomainBindingOff = false;
let warnedDomainBindingOffUnlisted = false;
// `sso.oidcClaims.requireHostedDomain` (Google-only) — same once-per-process rule.
let warnedHostedDomain = false;

/** Test-only: forget that the `domainBinding:"off"` and `requireHostedDomain` warnings were already emitted. */
export function resetOptionWarningsForTests(): void {
  warnedDomainBindingOff = false;
  warnedDomainBindingOffUnlisted = false;
  warnedHostedDomain = false;
}

// One DNS label: lower-case letters, digits and inner hyphens, at most 63 characters.
const HOSTNAME_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

/** A non-empty, lower-case, plain hostname: dot-separated labels, no scheme, port, path or wildcard. */
function isLowerCaseHostname(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length <= 253 &&
    value.split(".").every((label) => HOSTNAME_LABEL.test(label))
  );
}

const OIDC_CLAIM_BOOLEANS = ["requireEmailVerified", "requirePkce"] as const;
const OIDC_CLAIM_KEYS: ReadonlySet<string> = new Set([
  ...OIDC_CLAIM_BOOLEANS,
  "requireHostedDomain",
]);

/** `sso.existingUsersOnly`, `requireMembership`, `organizationProvisioning`, `oidcClaims` and `domainVerificationMode` (all 1.3, all opt-in). */
function assertSsoTightening(sso: NonNullable<EnterpriseOptions["sso"]>): void {
  const existingUsersOnly: unknown = sso.existingUsersOnly;
  if (existingUsersOnly !== undefined && typeof existingUsersOnly !== "boolean") {
    fail(`"sso.existingUsersOnly" must be a boolean.`);
  }
  const requireMembership: unknown = sso.requireMembership;
  if (requireMembership !== undefined) {
    if (typeof requireMembership !== "boolean") fail(`"sso.requireMembership" must be a boolean.`);
    if (existingUsersOnly !== true) {
      fail(
        `"sso.requireMembership" only applies with "sso.existingUsersOnly: true"; set that too, or remove it.`,
      );
    }
  }
  const provisioning: unknown = sso.organizationProvisioning;
  if (provisioning !== undefined && provisioning !== "member" && provisioning !== "off") {
    fail(
      `"sso.organizationProvisioning" must be "member" or "off" (got ${JSON.stringify(provisioning)}).`,
    );
  }
  const mode: unknown = sso.domainVerificationMode;
  if (mode !== undefined && mode !== "dns" && mode !== "operator") {
    fail(`"sso.domainVerificationMode" must be "dns" or "operator" (got ${JSON.stringify(mode)}).`);
  }

  const claims: unknown = sso.oidcClaims;
  if (claims === undefined) return;
  if (typeof claims !== "object" || claims === null || Array.isArray(claims)) {
    fail(`"sso.oidcClaims" must be an object.`);
  }
  const record = claims as Record<string, unknown>;
  for (const key of Object.keys(record)) {
    if (!OIDC_CLAIM_KEYS.has(key)) {
      fail(`"sso.oidcClaims.${key}" is not an option (known: ${[...OIDC_CLAIM_KEYS].join(", ")}).`);
    }
  }
  for (const key of OIDC_CLAIM_BOOLEANS) {
    if (record[key] !== undefined && typeof record[key] !== "boolean") {
      fail(`"sso.oidcClaims.${key}" must be a boolean.`);
    }
  }
  const hosted = record.requireHostedDomain;
  if (hosted === undefined) return;
  if (Array.isArray(hosted)) {
    if (hosted.length === 0 || !hosted.every(isLowerCaseHostname)) {
      fail(
        `"sso.oidcClaims.requireHostedDomain" as an array must be a non-empty list of lower-case hostnames (no RegExp, scheme, port or path).`,
      );
    }
  } else if (typeof hosted !== "boolean") {
    fail(
      `"sso.oidcClaims.requireHostedDomain" must be a boolean or an array of lower-case hostnames.`,
    );
  }
  if (hosted !== false && !warnedHostedDomain) {
    warnedHostedDomain = true;
    console.warn(
      `${PREFIX} "sso.oidcClaims.requireHostedDomain" checks the Google Workspace "hd" claim: it is absent for personal Google accounts and for every non-Google identity provider, and a Workspace alias domain does not match, so those sign-ins are refused (SSO_HOSTED_DOMAIN_MISMATCH).`,
    );
  }
}

/**
 * The one-time startup warning for `sso.domainBinding: "off"` **without**
 * `sso.allowedIssuers` — returned once per process (then `null`) so the
 * caller with a logger at hand (`enterpriseGate`'s `init`, which runs
 * with the auth context's `logger`) emits it; validation itself has no
 * logger. With the binding off, the issuer allow-list — and, for SAML, the
 * certificate pins — is the only control over which identity providers
 * can sign users in on the deployment, so running without it is worth one
 * line in the operator's log. No behaviour changes.
 */
export function takeDomainBindingOffUnlistedWarning(opts: EnterpriseOptions): string | null {
  if (opts.sso?.domainBinding !== "off" || opts.sso.allowedIssuers !== undefined) return null;
  if (warnedDomainBindingOffUnlisted) return null;
  warnedDomainBindingOffUnlisted = true;
  return `${PREFIX} "sso.domainBinding" is "off" and "sso.allowedIssuers" is not configured. With the binding off, the issuer allow-list — and, for SAML, "sso.samlCertificateFingerprints" — is the only control over which identity providers can sign users in on this deployment; "off" is only safe with both configured.`;
}

/**
 * Validates the options that are load-bearing for security or for data
 * retention:
 *
 * - `secretsKey` — `>= 32` characters (L-08); it derives the AES-256-GCM key
 *   that encrypts IdP secrets at rest (C-04), so a short or missing key is a
 *   silent downgrade of that protection.
 * - `scimCredentialHashSecret` — `>= 32` characters and not the same value as
 *   `secretsKey`.
 * - `resolveEntitlements` / `entitlements` — at least one of them (a function,
 *   or `{ store: "table" }` with optional non-empty `staffRoles`), so the gate
 *   never has nowhere to resolve entitlements from.
 * - `audit.retentionDays` — at least 1. `0` or a negative value puts the
 *   retention cutoff at or after "now", so the very next
 *   `GET /enterprise/audit/list` would compact the org's entire chain down to
 *   a single anchor row — a total, irreversible loss of the compliance log
 *   from a typo.
 * - `audit.exportMaxRows` — at least 1, since the export cap is compared
 *   against a row count.
 * - `audit.chainKey` — `>= 32` characters and independent of the other two
 *   secrets: reusing `secretsKey` would let whoever recovers one key forge
 *   the other's artefacts too.
 * - `database.dialect` — `"sqlite"` or `"pg"`.
 * - `sso.domainBinding` — one of the two literals; `"off"` re-opens the
 *   cross-tenant squatting class GHSA-8p84-pc7q-69jr describes, so it is
 *   accepted but warned about, naming the advisory.
 * - `sso.allowedIssuers` — an array of strings/RegExps or a function.
 * - `sso.existingUsersOnly` / `requireMembership` — booleans, the second only
 *   with the first; `sso.organizationProvisioning` — `"member"` or `"off"`;
 *   `sso.domainVerificationMode` — `"dns"` or `"operator"`; `sso.oidcClaims` —
 *   an object of known keys only (`requireEmailVerified`, `requirePkce`
 *   booleans; `requireHostedDomain` a boolean or a non-empty array of
 *   lower-case hostnames, warned about once since `hd` is Google-only).
 * - `organization.*` — a boolean (or, for `allowUserToCreateOrganization`, a
 *   function), never a truthy string that would silently mean "on";
 *   `organization.creation` — `"self-service"`, `"staff-only"` or a function;
 *   `organization.metadata` — `"open"` or `"staff-only"`.
 * - `policy.signInMethods` — every key is a request path (`/…`, optionally
 *   ending in `/*`) and every value a `[a-z_][a-z0-9_]*` method name.
 * - `policy.twoFactor.satisfiedBy` — method names; `enrollmentPaths` — paths.
 * - `apiKeys.defaultExpiresInS` — finite `> 0` or `null` (never expire);
 *   `apiKeys.maxExpiresInDays` — finite `> 0`; `apiKeys.rateLimit` — an
 *   object whose `enabled` is a boolean and whose `timeWindow` /
 *   `maxRequests` are finite `> 0` when present.
 */
export function assertEnterpriseOptions(opts: EnterpriseOptions): void {
  assertSecretsKey(opts.secretsKey);
  if (
    typeof opts.scimCredentialHashSecret !== "string" ||
    opts.scimCredentialHashSecret.length < 32 ||
    opts.scimCredentialHashSecret === opts.secretsKey
  ) {
    throw new Error(
      "scimCredentialHashSecret must be an independent secret of at least 32 characters",
    );
  }

  const resolveEntitlements = opts.resolveEntitlements;
  if (resolveEntitlements !== undefined && typeof resolveEntitlements !== "function") {
    fail(`"resolveEntitlements" must be a function.`);
  }
  const entitlements = opts.entitlements;
  if (entitlements !== undefined) {
    if (
      typeof entitlements !== "object" ||
      entitlements === null ||
      entitlements.store !== "table"
    ) {
      fail(`"entitlements.store" must be "table" (got ${JSON.stringify(entitlements?.store)}).`);
    }
    const staffRoles = entitlements.staffRoles;
    if (
      staffRoles !== undefined &&
      (!Array.isArray(staffRoles) ||
        staffRoles.length === 0 ||
        !staffRoles.every((role) => typeof role === "string" && /^[^,\s]+$/.test(role)))
    ) {
      fail(`"entitlements.staffRoles" must be a non-empty array of role names without commas.`);
    }
  }
  if (resolveEntitlements === undefined && entitlements === undefined) {
    fail(`either "resolveEntitlements" or "entitlements: { store: 'table' }" is required.`);
  }

  const retentionDays = opts.audit?.retentionDays;
  if (retentionDays !== undefined && (!Number.isFinite(retentionDays) || retentionDays < 1)) {
    fail(
      `"audit.retentionDays" must be a finite number >= 1 (got ${String(retentionDays)}) — a smaller value would compact an organization's entire audit chain on the next read.`,
    );
  }

  const exportMaxRows = opts.audit?.exportMaxRows;
  if (exportMaxRows !== undefined && (!Number.isFinite(exportMaxRows) || exportMaxRows < 1)) {
    fail(`"audit.exportMaxRows" must be a finite number >= 1 (got ${String(exportMaxRows)}).`);
  }

  const chainKey = opts.audit?.chainKey;
  if (chainKey !== undefined) {
    if (typeof chainKey !== "string" || chainKey.length < 32) {
      fail(`"audit.chainKey" must be a string of at least 32 characters.`);
    }
    if (chainKey === opts.secretsKey || chainKey === opts.scimCredentialHashSecret) {
      fail(`"audit.chainKey" must be independent of "secretsKey" and "scimCredentialHashSecret".`);
    }
  }

  const dialect = opts.database?.dialect;
  if (dialect !== undefined && dialect !== "sqlite" && dialect !== "pg") {
    fail(`"database.dialect" must be "sqlite" or "pg" (got ${JSON.stringify(dialect)}).`);
  }

  const domainBinding = opts.sso?.domainBinding;
  if (
    domainBinding !== undefined &&
    domainBinding !== "verified-domain" &&
    domainBinding !== "off"
  ) {
    fail(
      `"sso.domainBinding" must be "verified-domain" or "off" (got ${JSON.stringify(domainBinding)}).`,
    );
  }
  if (domainBinding === "off" && !warnedDomainBindingOff) {
    warnedDomainBindingOff = true;
    console.warn(
      `${PREFIX} "sso.domainBinding" is "off" — SSO sign-ins and JIT-created users are no longer bound to the signing provider's verified domain. This re-opens the cross-tenant account-squatting class of GHSA-8p84-pc7q-69jr; every tenant's IdP can sign in any e-mail address on this deployment.`,
    );
  }

  const trustVerifiedDomainEmail = opts.sso?.trustVerifiedDomainEmail;
  if (trustVerifiedDomainEmail !== undefined && typeof trustVerifiedDomainEmail !== "boolean") {
    fail(`"sso.trustVerifiedDomainEmail" must be a boolean.`);
  }

  const allowedIssuers = opts.sso?.allowedIssuers;
  if (allowedIssuers !== undefined && typeof allowedIssuers !== "function") {
    if (
      !Array.isArray(allowedIssuers) ||
      !allowedIssuers.every((entry) => typeof entry === "string" || entry instanceof RegExp)
    ) {
      fail(`"sso.allowedIssuers" must be an array of strings/RegExps or a predicate function.`);
    }
  }

  const pins = opts.sso?.samlCertificateFingerprints;
  if (pins !== undefined) {
    if (typeof pins !== "object" || pins === null || Array.isArray(pins)) {
      fail(
        `"sso.samlCertificateFingerprints" must map a SAML IdP entity id to its SHA-256 certificate fingerprints.`,
      );
    }
    for (const [entityId, list] of Object.entries(pins)) {
      if (
        !Array.isArray(list) ||
        list.length === 0 ||
        !list.every((entry) => typeof entry === "string" && normalizeFingerprint(entry) !== null)
      ) {
        fail(
          `"sso.samlCertificateFingerprints[${JSON.stringify(entityId)}]" must be a non-empty array of SHA-256 certificate fingerprints (64 hex characters, colons optional).`,
        );
      }
    }
  }

  if (opts.sso !== undefined) assertSsoTightening(opts.sso);

  const requireEmailVerificationOnInvitation =
    opts.organization?.requireEmailVerificationOnInvitation;
  if (
    requireEmailVerificationOnInvitation !== undefined &&
    typeof requireEmailVerificationOnInvitation !== "boolean"
  ) {
    fail(`"organization.requireEmailVerificationOnInvitation" must be a boolean.`);
  }
  const allowUserToCreateOrganization = opts.organization?.allowUserToCreateOrganization;
  if (
    allowUserToCreateOrganization !== undefined &&
    typeof allowUserToCreateOrganization !== "boolean" &&
    typeof allowUserToCreateOrganization !== "function"
  ) {
    fail(`"organization.allowUserToCreateOrganization" must be a boolean or a function.`);
  }
  const creation = opts.organization?.creation;
  if (
    creation !== undefined &&
    creation !== "self-service" &&
    creation !== "staff-only" &&
    typeof creation !== "function"
  ) {
    fail(
      `"organization.creation" must be "self-service", "staff-only" or a function (got ${JSON.stringify(creation)}).`,
    );
  }
  const organizationMetadata = opts.organization?.metadata;
  if (
    organizationMetadata !== undefined &&
    organizationMetadata !== "open" &&
    organizationMetadata !== "staff-only"
  ) {
    fail(
      `"organization.metadata" must be "open" or "staff-only" (got ${JSON.stringify(organizationMetadata)}).`,
    );
  }

  const signInMethods = opts.policy?.signInMethods;
  if (signInMethods !== undefined) {
    if (
      typeof signInMethods !== "object" ||
      signInMethods === null ||
      Array.isArray(signInMethods)
    ) {
      fail(`"policy.signInMethods" must be an object mapping request paths to method names.`);
    }
    for (const [path, method] of Object.entries(signInMethods)) {
      if (!path.startsWith("/")) {
        fail(
          `"policy.signInMethods" key ${JSON.stringify(path)} must be a path starting with "/".`,
        );
      }
      if (typeof method !== "string" || !METHOD_NAME_RE.test(method)) {
        fail(
          `"policy.signInMethods" value for ${JSON.stringify(path)} must match [a-z_][a-z0-9_]* (got ${JSON.stringify(method)}).`,
        );
      }
    }
  }

  const satisfiedBy = opts.policy?.twoFactor?.satisfiedBy;
  if (
    satisfiedBy !== undefined &&
    (!Array.isArray(satisfiedBy) ||
      !satisfiedBy.every((m) => typeof m === "string" && METHOD_NAME_RE.test(m)))
  ) {
    fail(`"policy.twoFactor.satisfiedBy" must be an array of method names ([a-z_][a-z0-9_]*).`);
  }
  const enrollmentPaths = opts.policy?.twoFactor?.enrollmentPaths;
  if (
    enrollmentPaths !== undefined &&
    (!Array.isArray(enrollmentPaths) ||
      !enrollmentPaths.every((p) => typeof p === "string" && p.startsWith("/")))
  ) {
    fail(`"policy.twoFactor.enrollmentPaths" must be an array of paths starting with "/".`);
  }

  const defaultExpiresInS = opts.apiKeys?.defaultExpiresInS;
  if (defaultExpiresInS !== undefined && defaultExpiresInS !== null) {
    assertPositiveFinite("apiKeys.defaultExpiresInS", defaultExpiresInS);
  }
  const maxExpiresInDays = opts.apiKeys?.maxExpiresInDays;
  if (maxExpiresInDays !== undefined) {
    assertPositiveFinite("apiKeys.maxExpiresInDays", maxExpiresInDays);
  }
  const rateLimit = opts.apiKeys?.rateLimit;
  if (rateLimit !== undefined) {
    if (typeof rateLimit !== "object" || rateLimit === null) {
      fail(`"apiKeys.rateLimit" must be an object (got ${String(rateLimit)}).`);
    }
    if (rateLimit.enabled !== undefined && typeof rateLimit.enabled !== "boolean") {
      fail(`"apiKeys.rateLimit.enabled" must be a boolean (got ${String(rateLimit.enabled)}).`);
    }
    if (rateLimit.timeWindow !== undefined) {
      assertPositiveFinite("apiKeys.rateLimit.timeWindow", rateLimit.timeWindow);
    }
    if (rateLimit.maxRequests !== undefined) {
      assertPositiveFinite("apiKeys.rateLimit.maxRequests", rateLimit.maxRequests);
    }
  }
}
