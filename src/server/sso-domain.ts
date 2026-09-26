// Alpha Bros enterprise layer — SSO domain ownership, uniqueness and the
// issuer allow-list (GHSA-8p84-pc7q-69jr, F-30 and F-28), installed by
// `./gate.ts` as a `hooks.before` on the four upstream `@better-auth/sso`
// endpoints that write or resolve a provider `domain`:
//
// - `/sso/register`, `/sso/update-provider` — a domain list is normalised
//   (`normalizeProviderDomains`, `./policy/domains.ts`; the upstream row
//   stores it verbatim while every match is normalised, F-04/R15), refused
//   when it cannot be normalised (`SSO_DOMAIN_INVALID`), refused when it
//   overlaps a domain **another** org has already verified
//   (`SSO_DOMAIN_TAKEN`, 409 — naming only the caller's own colliding
//   entries, never the other org's list), and the issuer **and the IdP
//   endpoints the configuration points at** must pass `sso.allowedIssuers`
//   when the operator set one (`SSO_ISSUER_NOT_ALLOWED`; on update whenever
//   `issuer`, `oidcConfig` or `samlConfig` is sent). For SAML the trust
//   root is the signing certificate, not a URL, so under an allow-list
//   every certificate the configuration carries must also be pinned by
//   `sso.samlCertificateFingerprints` (`collectSamlTrustRoot`; fail closed),
//   and a stored row is re-judged at every SSO sign-in
//   (`storedProviderAllowed`, called from `./policy/sso-jit.ts` and
//   `./policy/enforcement.ts`). Upstream never
//   checked uniqueness at all: any tenant could register a second provider
//   for a domain some other org had verified, and — because upstream's
//   e-mail `/sign-in/sso` resolves the provider with an exact `findOne({
//   domain })` over *unverified* rows too — the squat row won that lookup
//   and broke the legitimate org's e-mail sign-in ("domain has not been
//   verified"), F-30.
// - `/sso/verify-domain` — the same overlap check at verification time, so
//   two orgs can never both hold a verified claim on one domain even if the
//   second registered before the first verified.
// - `/sign-in/sso` with an `email`/`domain` and no `providerId` — the
//   request is *pinned* to the verified provider `findOrgsByEmailDomain`
//   ranks first (most specific matched domain, then `providerId`), but only
//   when every provider at that specificity belongs to one org; otherwise
//   upstream's own lookup is left alone and the ambiguity is logged
//   (legacy data written before uniqueness was enforced — see §6 of the
//   upgrade notes in `docs/security.md`).
//
// `trustedOrigins` was documented as the way to control which IdPs an org
// admin may point a provider at. It is not: it is better-auth's SSRF
// boundary for discovery/endpoint origins (and doubles as its redirect
// allow-list), and an org admin's `issuer` is stored whatever it is.
// `sso.allowedIssuers` is the allow-list (F-28).

import { X509Certificate } from "node:crypto";
import { APIError, createAuthMiddleware, getSessionFromCtx } from "better-auth/api";
import type { GenericEndpointContext } from "better-auth";
import type { EnterpriseOptions } from "./types";
import {
  findOrgsByEmailDomain,
  listVerifiedProviders,
  normalizeProviderDomains,
  type VerifiedProviderRow,
} from "./policy/domains";
import { getMemberRoles } from "./policy/store";

export const SSO_DOMAIN_GUARD_PATHS = new Set([
  "/sso/register",
  "/sso/update-provider",
  "/sso/verify-domain",
  "/sign-in/sso",
]);

/** Two normalised hostnames overlap when equal or when one is a subdomain of the other — either direction, since a provider for `acme.test` also matches `eu.acme.test` mail. */
function domainsOverlap(a: string, b: string): boolean {
  return a === b || a.endsWith(`.${b}`) || b.endsWith(`.${a}`);
}

/**
 * Every domain-verified `ssoProvider` row — other than the excluded org's
 * own rows and the excluded provider itself — whose normalised `domain` list
 * overlaps any of `domains`. Rows without an `organizationId` (legacy
 * "personal" providers) count as another party's claim. Fails closed past
 * the scan limit like every other caller of `listVerifiedProviders`.
 */
export async function findVerifiedProvidersOverlapping(
  ctx: GenericEndpointContext,
  domains: readonly string[],
  options: { excludeOrgId?: string | null; excludeProviderId?: string | null } = {},
): Promise<VerifiedProviderRow[]> {
  if (domains.length === 0) return [];
  const rows = await listVerifiedProviders(ctx);
  return rows.filter((row) => {
    if (options.excludeProviderId && row.providerId === options.excludeProviderId) return false;
    if (options.excludeOrgId && row.organizationId === options.excludeOrgId) return false;
    const theirs = normalizeProviderDomains(row.domain);
    if (!theirs) return false;
    return domains.some((mine) => theirs.some((other) => domainsOverlap(mine, other)));
  });
}

/**
 * The IdP-defining values of a provider configuration — the URLs and
 * entity ids that decide *whose* keys and endpoints a sign-in through the
 * provider will trust. The `issuer` string alone binds nothing: upstream
 * verifies an OIDC id_token's `iss` against the stored `issuer` but fetches
 * the signing keys from the tenant-supplied `jwksEndpoint`, and a SAML
 * assertion is checked against the tenant-supplied `cert`/`entryPoint`/
 * `idpMetadata` — so a tenant could satisfy a string-only allow-list while
 * pointing every endpoint at an IdP of their own. The allow-list therefore
 * covers these too (`issuerAllowed`).
 *
 * OIDC: `discoveryEndpoint`, `authorizationEndpoint`, `tokenEndpoint`,
 * `jwksEndpoint`, `userInfoEndpoint`. SAML: `entryPoint`,
 * `idpMetadata.entityID`, every `idpMetadata.singleSignOnService[]` /
 * `singleLogoutService[]` `Location`, and — when the IdP is given as a
 * metadata XML document — the `EntityDescriptor`'s `entityID` and the
 * `SingleSignOnService`/`SingleLogoutService` locations inside it. Returns
 * `null` (fail closed) for a metadata document without an extractable
 * `entityID`. Non-string values are ignored (upstream's schema refuses them).
 */
export function collectIdpEndpoints(oidcConfig: unknown, samlConfig: unknown): string[] | null {
  const out = new Set<string>();
  const add = (value: unknown) => {
    if (typeof value === "string" && value.length > 0) out.add(value);
  };
  if (isRecord(oidcConfig)) {
    for (const key of OIDC_ENDPOINT_FIELDS) add(oidcConfig[key]);
  }
  if (isRecord(samlConfig)) {
    add(samlConfig.entryPoint);
    const idp = samlConfig.idpMetadata;
    if (isRecord(idp)) {
      add(idp.entityID);
      for (const key of ["singleSignOnService", "singleLogoutService"] as const) {
        const services = idp[key];
        if (Array.isArray(services)) {
          for (const service of services) if (isRecord(service)) add(service.Location);
        }
      }
      if (typeof idp.metadata === "string" && idp.metadata.length > 0) {
        const entity = SAML_METADATA_ENTITY_ID.exec(idp.metadata);
        const entityId = (entity?.[1] ?? entity?.[2])?.trim();
        if (!entityId) return null;
        out.add(entityId);
        for (const match of idp.metadata.matchAll(SAML_METADATA_SERVICE_LOCATION)) {
          add(match[1] ?? match[2]);
        }
      }
    }
  }
  return [...out];
}

const OIDC_ENDPOINT_FIELDS = [
  "discoveryEndpoint",
  "authorizationEndpoint",
  "tokenEndpoint",
  "jwksEndpoint",
  "userInfoEndpoint",
] as const;

// `<md:EntityDescriptor … entityID="…">` (any/no namespace prefix, either
// quote style, any attribute order); `<md:SingleSignOnService … Location="…">`.
const SAML_METADATA_ENTITY_ID =
  /<(?:[\w.-]+:)?EntityDescriptor\b[^>]*?\sentityID\s*=\s*(?:"([^"]*)"|'([^']*)')/;
const SAML_METADATA_SERVICE_LOCATION =
  /<(?:[\w.-]+:)?Single(?:SignOn|Logout)Service\b[^>]*?\sLocation\s*=\s*(?:"([^"]*)"|'([^']*)')/g;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * The SAML trust root of a provider configuration. A SAML sign-in trusts
 * whoever holds the key behind the configured signing certificate — the
 * `entityID`/`entryPoint` strings only *name* an IdP, they do not bind it —
 * so under an allow-list the certificates are what must be pinned.
 */
export interface SamlTrustRoot {
  /** The entity ids the pins are looked up under: `idpMetadata.entityID` and/or the metadata document's `entityID`; the `issuer` when the configuration names neither (upstream's own fallback at the ACS). */
  entityIds: string[];
  /**
   * Normalised SHA-256 fingerprints (lowercase hex, no colons) of the DER
   * form of every certificate the configuration carries: `cert`,
   * `idpMetadata.cert` (string or list) and every `X509Certificate` inside
   * a `KeyDescriptor` of `idpMetadata.metadata` whose `use` is `signing`
   * or unset (unset = both uses, per the SAML metadata spec). `null` when
   * no certificate can be extracted at all, one cannot be parsed, or a
   * metadata document has no `entityID` — the caller fails closed.
   */
  certFingerprints: string[] | null;
}

/** `AB:cd:…` / `abcd…` → `abcd…` (64 lowercase hex characters); `null` for anything that is not a SHA-256 fingerprint. */
export function normalizeFingerprint(value: string): string | null {
  const hex = value.replace(/[:\s]/g, "").toLowerCase();
  return /^[0-9a-f]{64}$/.test(hex) ? hex : null;
}

/** SHA-256 fingerprint of a PEM certificate, or — as upstream accepts — a bare base64 body; `null` when it does not parse. */
function certificateFingerprint(material: string): string | null {
  const pem = material.includes("-----BEGIN")
    ? material
    : `-----BEGIN CERTIFICATE-----\n${material.replace(/\s+/g, "")}\n-----END CERTIFICATE-----`;
  try {
    return normalizeFingerprint(new X509Certificate(pem).fingerprint256);
  } catch {
    return null;
  }
}

// `<md:KeyDescriptor use="signing"> … </md:KeyDescriptor>` (any/no prefix;
// `use` optional) and the `<ds:X509Certificate>` bodies inside one.
const SAML_METADATA_KEY_DESCRIPTOR =
  /<(?:[\w.-]+:)?KeyDescriptor\b([^>]*)>([\s\S]*?)<\/(?:[\w.-]+:)?KeyDescriptor\s*>/g;
const SAML_METADATA_KEY_USE = /\suse\s*=\s*(?:"([^"]*)"|'([^']*)')/;
const SAML_METADATA_X509 =
  /<(?:[\w.-]+:)?X509Certificate\b[^>]*>([\s\S]*?)<\/(?:[\w.-]+:)?X509Certificate\s*>/g;

/**
 * `SamlTrustRoot` of `samlConfig` (see the interface), or `null` when the
 * configuration is not a SAML one (an OIDC provider has no certificate to
 * pin). Every certificate source upstream honours is read — the inline
 * `cert`, `idpMetadata.cert` (which wins over `cert` upstream) and the
 * signing `KeyDescriptor`s of `idpMetadata.metadata` (which samlify reads
 * when the IdP is given as a document) — so a certificate cannot be slipped
 * in through a source the check did not look at.
 */
export function collectSamlTrustRoot(samlConfig: unknown, issuer: string): SamlTrustRoot | null {
  if (!isRecord(samlConfig)) return null;
  const entityIds = new Set<string>();
  const materials: string[] = [];
  let unreadable = false;
  const addCert = (value: unknown): void => {
    if (typeof value === "string") {
      if (value.trim().length > 0) materials.push(value);
      else unreadable = true;
    } else if (Array.isArray(value)) {
      for (const entry of value) addCert(entry);
    } else if (value !== undefined && value !== null) {
      unreadable = true;
    }
  };
  addCert(samlConfig.cert);
  const idp = samlConfig.idpMetadata;
  if (isRecord(idp)) {
    if (typeof idp.entityID === "string" && idp.entityID.length > 0) entityIds.add(idp.entityID);
    addCert(idp.cert);
    if (typeof idp.metadata === "string" && idp.metadata.length > 0) {
      const entity = SAML_METADATA_ENTITY_ID.exec(idp.metadata);
      const entityId = (entity?.[1] ?? entity?.[2])?.trim();
      if (entityId) entityIds.add(entityId);
      else unreadable = true;
      for (const descriptor of idp.metadata.matchAll(SAML_METADATA_KEY_DESCRIPTOR)) {
        const use = SAML_METADATA_KEY_USE.exec(descriptor[1] ?? "");
        if ((use?.[1] ?? use?.[2])?.trim() === "encryption") continue;
        for (const cert of (descriptor[2] ?? "").matchAll(SAML_METADATA_X509)) {
          addCert(cert[1]);
        }
      }
    }
  }
  if (entityIds.size === 0) entityIds.add(issuer);
  const fingerprints = new Set<string>();
  for (const material of materials) {
    const fingerprint = certificateFingerprint(material);
    if (!fingerprint) {
      unreadable = true;
      break;
    }
    fingerprints.add(fingerprint);
  }
  return {
    entityIds: [...entityIds],
    certFingerprints: unreadable || fingerprints.size === 0 ? null : [...fingerprints],
  };
}

/**
 * Array-form verdict on a SAML trust root: every entity id the
 * configuration names must have pins under `sso.samlCertificateFingerprints`
 * and every certificate it carries must be one of them. No pins at all, an
 * entity id without pins, or an unreadable trust root → `false`.
 */
function samlTrustRootPinned(
  pins: Record<string, string[]> | undefined,
  saml: SamlTrustRoot,
): boolean {
  if (!pins || saml.certFingerprints === null || saml.certFingerprints.length === 0) return false;
  const pinned = new Set<string>();
  for (const entityId of saml.entityIds) {
    // Own properties only — `constructor`/`__proto__` as an entity id must
    // not resolve to `Object.prototype` members.
    if (!Object.hasOwn(pins, entityId)) return false;
    const entries = pins[entityId];
    if (!Array.isArray(entries) || entries.length === 0) return false;
    for (const entry of entries) {
      const fingerprint = typeof entry === "string" ? normalizeFingerprint(entry) : null;
      if (fingerprint) pinned.add(fingerprint);
    }
  }
  return saml.certFingerprints.every((fingerprint) => pinned.has(fingerprint));
}

/** `https://idp.example/path` → `https://idp.example`; `null` for a value with no origin (a URN, a bare name). */
function originOf(value: string): string | null {
  try {
    const origin = new URL(value).origin;
    return origin === "null" ? null : origin;
  } catch {
    return null;
  }
}

function entryMatches(entry: string | RegExp, value: string): boolean {
  return typeof entry === "string" ? entry === value : entry.test(value);
}

/**
 * An IdP-defining value passes an array allow-list when it *is* the (already
 * allowed) issuer, sits on the issuer's origin, or is itself — or its origin
 * is — an entry of the list. Operators whose IdP serves endpoints from
 * several origins (e.g. Google: `accounts.google.com` issues, `oauth2.
 * googleapis.com` exchanges) list those origins alongside the issuer.
 */
function endpointAllowed(
  allowed: ReadonlyArray<string | RegExp>,
  issuer: string,
  endpoint: string,
): boolean {
  if (endpoint === issuer) return true;
  const endpointOrigin = originOf(endpoint);
  const issuerOrigin = originOf(issuer);
  if (endpointOrigin && issuerOrigin && endpointOrigin === issuerOrigin) return true;
  return allowed.some(
    (entry) =>
      entryMatches(entry, endpoint) || (!!endpointOrigin && entryMatches(entry, endpointOrigin)),
  );
}

export interface IssuerCheckContext {
  organizationId: string | null;
  /** The IdP-defining values of the configuration being stored (`collectIdpEndpoints`); `null` when they could not be read (a metadata document without an `entityID`). */
  endpoints: string[] | null;
  /** The SAML trust root (`collectSamlTrustRoot`) — absent or `null` for an OIDC configuration. */
  saml?: SamlTrustRoot | null;
}

/**
 * Whether `issuer` **and the IdP it actually points at** pass
 * `sso.allowedIssuers` for a provider bound to `ctx.organizationId`: no
 * allow-list → anything (upstream behaviour); an array → the issuer must
 * match an entry (exact string or `RegExp`), every one of `ctx.endpoints`
 * must pass `endpointAllowed` and, for a SAML configuration, its trust root
 * must be pinned (`samlTrustRootPinned` — no pins means no SAML provider,
 * fail closed); a predicate → its verdict on `(issuer, { organizationId,
 * endpoints, samlCertFingerprints })` (`false` on a throw — fail closed).
 * Unreadable endpoints or an unreadable SAML trust root (`null`) fail every
 * configured list before any predicate is consulted.
 */
export async function issuerAllowed(
  opts: EnterpriseOptions | undefined,
  issuer: string,
  ctx: IssuerCheckContext,
): Promise<boolean> {
  const allowed = opts?.sso?.allowedIssuers;
  if (allowed === undefined) return true;
  const endpoints = ctx.endpoints;
  if (endpoints === null) return false;
  const saml = ctx.saml ?? null;
  if (saml && saml.certFingerprints === null) return false;
  const samlCertFingerprints = saml?.certFingerprints ?? [];
  if (typeof allowed === "function") {
    try {
      const verdict = await allowed(issuer, {
        organizationId: ctx.organizationId,
        endpoints,
        samlCertFingerprints,
      });
      return verdict === true;
    } catch {
      return false;
    }
  }
  if (!allowed.some((entry) => entryMatches(entry, issuer))) return false;
  if (!endpoints.every((endpoint) => endpointAllowed(allowed, issuer, endpoint))) return false;
  if (!saml) return true;
  return samlTrustRootPinned(opts?.sso?.samlCertificateFingerprints, saml);
}

function domainInvalidError(): APIError {
  return new APIError("BAD_REQUEST", {
    code: "SSO_DOMAIN_INVALID",
    message:
      "domain must be a comma-separated list of plain hostnames (e.g. acme.test, acme-two.test).",
  });
}

/**
 * Names only the **caller's own** submitted entries that collide. The other
 * organization's verified list is never echoed: a tenant who registers one
 * domain it happens to know must not learn every other domain the victim
 * org has verified (a cross-tenant disclosure oracle).
 */
function domainTakenError(mine: readonly string[], taken: VerifiedProviderRow[]): APIError {
  const theirs = taken.flatMap((row) => normalizeProviderDomains(row.domain) ?? []);
  const colliding = mine.filter((domain) => theirs.some((other) => domainsOverlap(domain, other)));
  return new APIError("CONFLICT", {
    code: "SSO_DOMAIN_TAKEN",
    message: `Another organization has already verified a domain overlapping ${colliding.join(", ")}.`,
  });
}

export function issuerNotAllowedError(issuer: string): APIError {
  return new APIError("FORBIDDEN", {
    code: "SSO_ISSUER_NOT_ALLOWED",
    message: `The issuer ${JSON.stringify(issuer)}, an identity-provider endpoint the configuration points at, or a SAML signing certificate it carries, is not on this deployment's SSO issuer allow-list.`,
  });
}

type Body = Record<string, unknown>;
type HookResult = { context: { body: Body } } | undefined;

function stringField(body: Body, key: string): string | null {
  const value = body[key];
  return typeof value === "string" && value.length > 0 ? value : null;
}

interface GuardedProviderRow extends VerifiedProviderRow {
  issuer: string;
  userId: string | null;
  /** JSON as upstream stores it (a string), or `null`. */
  oidcConfig?: string | null;
  samlConfig?: string | null;
}

function parseStoredConfig(raw: unknown): Record<string, unknown> | null {
  if (isRecord(raw)) return raw; // an adapter that already decoded the JSON column
  if (typeof raw !== "string" || raw.length === 0) return null;
  try {
    const parsed: unknown = JSON.parse(raw);
    return isRecord(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

/** The `ssoProvider` columns a stored row is re-judged on. */
export interface StoredProviderTrust {
  issuer: string;
  organizationId: string | null;
  oidcConfig?: unknown;
  samlConfig?: unknown;
}

/**
 * Whether an **already-stored** provider still passes `sso.allowedIssuers`
 * (issuer, endpoints and — for SAML — the certificate pins), judged on the
 * row exactly as `/sso/register`/`/sso/update-provider` would judge the same
 * configuration. Called at every SSO sign-in (`./policy/sso-jit.ts` before
 * a JIT user row is written, `./policy/enforcement.ts` before any session
 * is minted) so an operator who configures or tightens the allow-list after
 * a row was registered also refuses that row, instead of only rows written
 * afterwards. `true` when no allow-list is configured.
 */
export async function storedProviderAllowed(
  opts: EnterpriseOptions | undefined,
  provider: StoredProviderTrust,
): Promise<boolean> {
  if (opts?.sso?.allowedIssuers === undefined) return true;
  const oidcConfig = parseStoredConfig(provider.oidcConfig);
  const samlConfig = parseStoredConfig(provider.samlConfig);
  return issuerAllowed(opts, provider.issuer, {
    organizationId: provider.organizationId,
    endpoints: collectIdpEndpoints(oidcConfig, samlConfig),
    saml: collectSamlTrustRoot(samlConfig, provider.issuer),
  });
}

/** The configuration `/sso/update-provider` will store: upstream merges the body over the stored config (one level; `idpMetadata` one level deeper), so the allow-list judges the merged result. */
function mergedProviderConfig(
  provider: GuardedProviderRow,
  body: Body,
): { oidcConfig: unknown; samlConfig: unknown } {
  const storedOidc = parseStoredConfig(provider.oidcConfig);
  const storedSaml = parseStoredConfig(provider.samlConfig);
  const bodyOidc = isRecord(body.oidcConfig) ? body.oidcConfig : null;
  const bodySaml = isRecord(body.samlConfig) ? body.samlConfig : null;
  const oidcConfig = bodyOidc ? { ...(storedOidc ?? {}), ...bodyOidc } : storedOidc;
  let samlConfig: unknown = storedSaml;
  if (bodySaml) {
    const storedIdp = isRecord(storedSaml?.idpMetadata) ? storedSaml.idpMetadata : {};
    const bodyIdp = isRecord(bodySaml.idpMetadata) ? bodySaml.idpMetadata : null;
    samlConfig = {
      ...(storedSaml ?? {}),
      ...bodySaml,
      ...(bodyIdp ? { idpMetadata: { ...storedIdp, ...bodyIdp } } : {}),
    };
  }
  return { oidcConfig, samlConfig };
}

async function findProvider(
  ctx: GenericEndpointContext,
  providerId: string,
): Promise<GuardedProviderRow | null> {
  return ctx.context.adapter.findOne<GuardedProviderRow>({
    model: "ssoProvider",
    where: [{ field: "providerId", value: providerId }],
  });
}

/** Mirrors upstream `checkProviderAccess`: an owner/admin of the provider's org, or — for a legacy org-less row — its creator. */
async function callerMayMutate(
  ctx: GenericEndpointContext,
  provider: GuardedProviderRow,
  userId: string,
): Promise<boolean> {
  if (provider.organizationId) {
    const roles = await getMemberRoles(ctx, provider.organizationId, userId);
    return roles.includes("owner") || roles.includes("admin");
  }
  return provider.userId === userId;
}

async function guardRegister(
  ctx: GenericEndpointContext,
  body: Body,
  opts: EnterpriseOptions | undefined,
): Promise<HookResult> {
  // `ORG_REQUIRED` is the entitlement gate's job and it runs first; a
  // missing org here (a hand-composed plugin list) simply means "no org's
  // own rows are excluded" — still fail-closed.
  const organizationId = stringField(body, "organizationId");
  const issuer = stringField(body, "issuer");
  if (issuer) {
    const endpoints = collectIdpEndpoints(body.oidcConfig, body.samlConfig);
    const saml = collectSamlTrustRoot(body.samlConfig, issuer);
    if (!(await issuerAllowed(opts, issuer, { organizationId, endpoints, saml }))) {
      throw issuerNotAllowedError(issuer);
    }
  }
  const domains = normalizeProviderDomains(stringField(body, "domain"));
  if (!domains) throw domainInvalidError();
  const taken = await findVerifiedProvidersOverlapping(ctx, domains, {
    excludeOrgId: organizationId,
  });
  if (taken.length > 0) throw domainTakenError(domains, taken);
  return { context: { body: { ...body, domain: domains.join(",") } } };
}

async function guardUpdate(
  ctx: GenericEndpointContext,
  body: Body,
  opts: EnterpriseOptions | undefined,
  userId: string,
): Promise<HookResult> {
  const providerId = stringField(body, "providerId");
  if (!providerId) return; // upstream's schema answers 400
  const provider = await findProvider(ctx, providerId);
  if (!provider) return; // upstream answers 404
  // A caller upstream would refuse (403) must not get to probe the domain
  // scan or the allow-list through this hook either.
  if (!(await callerMayMutate(ctx, provider, userId))) return;

  // The allow-list judges the provider as it will be *after* the update: a
  // new issuer against the (stored or replaced) endpoints, and replaced
  // endpoints against the (stored or new) issuer — `oidcConfig`/`samlConfig`
  // alone, with the issuer untouched, is the endpoint-swap this exists for.
  // For SAML the merged configuration's certificates (a `cert`-only swap, an
  // `idpMetadata.cert` that would win over a pinned `cert`, a replaced
  // metadata document) are re-pinned the same way.
  const issuer = stringField(body, "issuer");
  const configSent = isRecord(body.oidcConfig) || isRecord(body.samlConfig);
  if ((issuer || configSent) && opts?.sso?.allowedIssuers !== undefined) {
    const effectiveIssuer = issuer ?? provider.issuer;
    const merged = mergedProviderConfig(provider, body);
    const endpoints = collectIdpEndpoints(merged.oidcConfig, merged.samlConfig);
    const allowed = await issuerAllowed(opts, effectiveIssuer, {
      organizationId: provider.organizationId,
      endpoints,
      saml: collectSamlTrustRoot(merged.samlConfig, effectiveIssuer),
    });
    if (!allowed) throw issuerNotAllowedError(effectiveIssuer);
  }
  const domain = stringField(body, "domain");
  // An unchanged domain (repeated verbatim) is not a domain change: upstream
  // keeps `domainVerified` only when the stored string is repeated exactly,
  // so it is passed through untouched rather than re-normalised.
  if (domain === null || domain === provider.domain) return;
  const domains = normalizeProviderDomains(domain);
  if (!domains) throw domainInvalidError();
  const taken = await findVerifiedProvidersOverlapping(ctx, domains, {
    excludeOrgId: provider.organizationId,
    excludeProviderId: provider.providerId,
  });
  if (taken.length > 0) throw domainTakenError(domains, taken);
  return { context: { body: { ...body, domain: domains.join(",") } } };
}

async function guardVerify(ctx: GenericEndpointContext, body: Body): Promise<HookResult> {
  const providerId = stringField(body, "providerId");
  if (!providerId) return;
  const provider = await findProvider(ctx, providerId);
  // Not found → upstream 404; already verified → upstream 409 DOMAIN_VERIFIED.
  if (!provider || provider.domainVerified) return;
  const domains = normalizeProviderDomains(provider.domain);
  if (!domains) throw domainInvalidError();
  const taken = await findVerifiedProvidersOverlapping(ctx, domains, {
    excludeOrgId: provider.organizationId,
    excludeProviderId: provider.providerId,
  });
  if (taken.length > 0) throw domainTakenError(domains, taken);
  return;
}

async function pinEmailSignIn(ctx: GenericEndpointContext, body: Body): Promise<HookResult> {
  if (stringField(body, "providerId")) return; // explicit provider: upstream's own lookup
  if (stringField(body, "organizationSlug")) return; // org-scoped lookup: upstream's own
  // Upstream resolves `body.domain || email.split("@")[1]`; the same domain
  // is handed to the shared matcher as an address so one lookup serves both
  // forms (`findOrgsByEmailDomain` only ever reads the domain part).
  const domain = stringField(body, "domain");
  const email = stringField(body, "email");
  const address = domain ? `probe@${domain}` : email;
  if (!address) return;
  const matches = await findOrgsByEmailDomain(ctx, address);
  const first = matches[0];
  if (!first) return; // no verified claim: upstream decides (404 or an unverified row's 401)
  const top = matches.filter((m) => m.matchedDomain.length === first.matchedDomain.length);
  const orgs = new Set(top.map((m) => m.orgId));
  if (orgs.size !== 1) {
    ctx.context.logger.warn(
      `enterprise-gate: ${orgs.size} organizations hold a verified SSO provider for the same domain (${first.matchedDomain}) — leaving the e-mail sign-in lookup to upstream; de-duplicate the legacy rows`,
    );
    return;
  }
  return { context: { body: { ...body, providerId: first.providerId } } };
}

/**
 * The `hooks.before` entry `./gate.ts` installs after its entitlement gate.
 * Anonymous calls to the three provider-mutating paths are let through
 * untouched (their `sessionMiddleware` answers 401 — the scan is never run
 * for a stranger); `/sign-in/sso` is public by design.
 */
export function buildSsoDomainGuardHook(opts?: EnterpriseOptions) {
  return {
    matcher: (ctx: { path?: string }) => !!ctx.path && SSO_DOMAIN_GUARD_PATHS.has(ctx.path),
    handler: createAuthMiddleware(async (ctx) => {
      const fullCtx = ctx as unknown as GenericEndpointContext;
      const body = (ctx.body && typeof ctx.body === "object" ? ctx.body : {}) as Body;
      if (ctx.path === "/sign-in/sso") return pinEmailSignIn(fullCtx, body);

      const session = await getSessionFromCtx(fullCtx);
      if (!session) return;
      if (ctx.path === "/sso/register") return guardRegister(fullCtx, body, opts);
      if (ctx.path === "/sso/update-provider") {
        return guardUpdate(fullCtx, body, opts, session.user.id);
      }
      if (ctx.path === "/sso/verify-domain") return guardVerify(fullCtx, body);
      return;
    }),
  };
}
