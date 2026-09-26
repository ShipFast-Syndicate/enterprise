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
//   (`SSO_DOMAIN_TAKEN`, 409), and the issuer must pass `sso.allowedIssuers`
//   when the operator set one (`SSO_ISSUER_NOT_ALLOWED`). Upstream never
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
 * Whether `issuer` passes `sso.allowedIssuers` for a provider bound to
 * `organizationId`: no allow-list → any issuer (upstream behaviour); an
 * array → an exact string match or a `RegExp` test; a predicate → its
 * verdict (`false` on a throw — fail closed).
 */
export async function issuerAllowed(
  opts: EnterpriseOptions | undefined,
  issuer: string,
  organizationId: string | null,
): Promise<boolean> {
  const allowed = opts?.sso?.allowedIssuers;
  if (allowed === undefined) return true;
  if (typeof allowed === "function") {
    try {
      return (await allowed(issuer, { organizationId })) === true;
    } catch {
      return false;
    }
  }
  return allowed.some((entry) =>
    typeof entry === "string" ? entry === issuer : entry.test(issuer),
  );
}

function domainInvalidError(): APIError {
  return new APIError("BAD_REQUEST", {
    code: "SSO_DOMAIN_INVALID",
    message:
      "domain must be a comma-separated list of plain hostnames (e.g. acme.test, acme-two.test).",
  });
}

function domainTakenError(taken: VerifiedProviderRow[]): APIError {
  const domains = [...new Set(taken.flatMap((row) => normalizeProviderDomains(row.domain) ?? []))];
  return new APIError("CONFLICT", {
    code: "SSO_DOMAIN_TAKEN",
    message: `Another organization has already verified an overlapping domain (${domains.join(", ")}).`,
  });
}

function issuerNotAllowedError(issuer: string): APIError {
  return new APIError("FORBIDDEN", {
    code: "SSO_ISSUER_NOT_ALLOWED",
    message: `The issuer ${JSON.stringify(issuer)} is not on this deployment's SSO issuer allow-list.`,
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
  if (issuer && !(await issuerAllowed(opts, issuer, organizationId))) {
    throw issuerNotAllowedError(issuer);
  }
  const domains = normalizeProviderDomains(stringField(body, "domain"));
  if (!domains) throw domainInvalidError();
  const taken = await findVerifiedProvidersOverlapping(ctx, domains, {
    excludeOrgId: organizationId,
  });
  if (taken.length > 0) throw domainTakenError(taken);
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

  const issuer = stringField(body, "issuer");
  if (issuer && !(await issuerAllowed(opts, issuer, provider.organizationId))) {
    throw issuerNotAllowedError(issuer);
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
  if (taken.length > 0) throw domainTakenError(taken);
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
  if (taken.length > 0) throw domainTakenError(taken);
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
