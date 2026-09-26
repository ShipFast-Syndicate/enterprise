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

/** Test-only: forget that the `domainBinding:"off"` warning was already emitted. */
export function resetOptionWarningsForTests(): void {
  warnedDomainBindingOff = false;
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
 * - `sso.domainBinding` — one of the two literals; `"off"` re-opens the
 *   cross-tenant squatting class GHSA-8p84-pc7q-69jr describes, so it is
 *   accepted but warned about, naming the advisory.
 * - `sso.allowedIssuers` — an array of strings/RegExps or a function.
 * - `organization.*` — a boolean (or, for `allowUserToCreateOrganization`, a
 *   function), never a truthy string that would silently mean "on".
 * - `policy.signInMethods` — every key is a request path (`/…`, optionally
 *   ending in `/*`) and every value a `[a-z_][a-z0-9_]*` method name.
 * - `policy.twoFactor.satisfiedBy` — method names; `enrollmentPaths` — paths.
 * - `apiKeys.defaultExpiresInS` — finite `> 0` or `null` (never expire);
 *   `apiKeys.maxExpiresInDays` — finite `> 0`.
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
}
