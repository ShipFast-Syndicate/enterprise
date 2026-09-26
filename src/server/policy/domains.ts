// Alpha Bros enterprise layer — provider-domain matching (leaf module).
//
// The single implementation of "does this e-mail domain belong to this SSO
// provider's `domain` list" for the whole package. `@better-auth/sso` stores a
// provider's `domain` as free text — a comma-separated list, any case, and it
// matches e-mail domains with `domainMatches` (exact or dot-suffix, i.e.
// subdomains match). Every enterprise read path that resolves an e-mail to an
// org used to do an exact, case-sensitive `findOne({domain})` instead, so a
// multi-domain or mixed-case provider — or a user on a subdomain — silently
// fell outside home-realm discovery, SSO enforcement and the SCIM-required
// JIT guard while upstream still matched them (F-04). These helpers mirror
// upstream's `parseProviderDomains`/`domainMatches` semantics so both halves
// of the system agree on membership, with one deliberate difference: an entry
// that is not a plain hostname (a URL, a path, whitespace inside, …) makes the
// whole list invalid and match *nothing*, never "something".
//
// Imports nothing from the rest of `./policy` so `./home-realm.ts`,
// `./enforcement.ts`, `./scim-required.ts` and `../enterprise-api/sso.ts` can
// all import it without a cycle.

import type { GenericEndpointContext } from "better-auth";
import { APIError } from "better-auth/api";

// RFC 1123 hostname labels, joined by dots. Lower-case only because the caller
// lower-cases first. Underscores are refused (they are not valid in e-mail
// domains, and an entry with one is almost certainly a typo).
const HOSTNAME_RE =
  /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;

function normalizeHostname(entry: string): string | null {
  const trimmed = entry.trim().toLowerCase().replace(/\.$/, "");
  if (!trimmed || trimmed.length > 253) return null;
  return HOSTNAME_RE.test(trimmed) ? trimmed : null;
}

/**
 * The e-mail domains a provider's stored `domain` value authorizes: split on
 * `,`, trimmed, lower-cased, trailing dot dropped, de-duplicated. `null` when
 * the list is empty or **any** entry is not a plain hostname — a `null` list
 * matches nothing (mirrors upstream `parseProviderDomains`, which also
 * rejects the whole list on one bad entry).
 */
export function normalizeProviderDomains(domain: string | null | undefined): string[] | null {
  if (typeof domain !== "string") return null;
  const entries = domain
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);
  if (entries.length === 0) return null;
  const domains = new Set<string>();
  for (const entry of entries) {
    const hostname = normalizeHostname(entry);
    if (!hostname) return null;
    domains.add(hostname);
  }
  return [...domains];
}

/** The lower-cased domain part of an e-mail address, or `null` when there isn't exactly one. */
export function emailDomain(email: string | null | undefined): string | null {
  if (typeof email !== "string") return null;
  const parts = email.trim().toLowerCase().split("@");
  if (parts.length !== 2 || !parts[0] || !parts[1]) return null;
  return normalizeHostname(parts[1]!);
}

/**
 * Whether `emailDomain` is authorized by the provider `domain` list: exact
 * match or a subdomain of a listed entry (`eu.acme.test` matches
 * `acme.test`; `evilacme.test` does not). Returns the list entry that
 * matched — the *most specific* one when several do, so callers can rank
 * matches (`findOrgsByEmailDomain`) — or `null`.
 */
export function domainMatches(
  emailDomain: string | null | undefined,
  providerDomain: string | null | undefined,
): { matched: string } | null {
  const search = typeof emailDomain === "string" ? normalizeHostname(emailDomain) : null;
  const domains = normalizeProviderDomains(providerDomain);
  if (!search || !domains) return null;
  let best: string | null = null;
  for (const candidate of domains) {
    if (search === candidate || search.endsWith(`.${candidate}`)) {
      if (best === null || candidate.length > best.length) best = candidate;
    }
  }
  return best === null ? null : { matched: best };
}

export interface VerifiedProviderRow {
  providerId: string;
  domain: string;
  organizationId: string | null;
  domainVerified: boolean;
}

/**
 * Upstream caps one `findMany` page at 100 rows, so the verified-provider
 * scan pages in that unit (`offset` stepping), sorted by `providerId` for a
 * stable walk.
 */
const VERIFIED_PROVIDER_PAGE_SIZE = 100;

/** Default `max` for `listVerifiedProviders` — 5000 verified rows is ≥ 500 DNS-verified orgs, not an attacker-cheap number. */
export const VERIFIED_PROVIDER_SCAN_MAX = 5000;

/**
 * Every `ssoProvider` row with `domainVerified = true`, paginated. Fails
 * **closed** past `max`: a deployment with more verified providers than the
 * scan is willing to walk gets a 500 `SSO_DOMAIN_CHECK_OVERFLOW` (and a
 * `logger.error`) on every path that needs the answer — read and write —
 * rather than a silently truncated match set that could let an unmatched
 * domain through. An indexed exact-domain query is the follow-up for that
 * scale; no pilot is near it.
 */
export async function listVerifiedProviders(
  ctx: GenericEndpointContext,
  options: { max?: number } = {},
): Promise<VerifiedProviderRow[]> {
  const max = options.max ?? VERIFIED_PROVIDER_SCAN_MAX;
  const rows: VerifiedProviderRow[] = [];
  let offset = 0;
  for (;;) {
    const page = await ctx.context.adapter.findMany<VerifiedProviderRow>({
      model: "ssoProvider",
      where: [{ field: "domainVerified", value: true }],
      limit: VERIFIED_PROVIDER_PAGE_SIZE,
      offset,
      sortBy: { field: "providerId", direction: "asc" },
    });
    rows.push(...page);
    if (rows.length > max) {
      ctx.context.logger.error(
        `enterprise-policy: more than ${max} verified SSO providers — refusing the domain check rather than truncating it (SSO_DOMAIN_CHECK_OVERFLOW)`,
      );
      throw new APIError("INTERNAL_SERVER_ERROR", {
        code: "SSO_DOMAIN_CHECK_OVERFLOW",
        message: "Too many verified SSO providers to resolve the e-mail domain safely.",
      });
    }
    if (page.length < VERIFIED_PROVIDER_PAGE_SIZE) return rows;
    offset += page.length;
  }
}

export interface EmailDomainMatch {
  orgId: string;
  providerId: string;
  /** The provider `domain` list entry that matched (the most specific one). */
  matchedDomain: string;
}

/**
 * Every org-scoped, domain-verified provider whose `domain` list authorizes
 * `email`'s domain — the multi-match successor of `findOrgByEmailDomain`
 * (`./home-realm.ts`, now a "first row or null" wrapper over this).
 *
 * Ordering is the tie-break rule the e-mail `/sign-in/sso` pin and the
 * home-realm answer rely on: most specific matched domain first (longer
 * entry = more specific: `eu.acme.test` beats `acme.test`), then
 * `providerId` ascending so the result is deterministic across adapters.
 * Providers without an `organizationId` (legacy "personal" rows) are
 * skipped — they can't carry an org policy.
 */
export async function findOrgsByEmailDomain(
  ctx: GenericEndpointContext,
  email: string,
): Promise<EmailDomainMatch[]> {
  const domain = emailDomain(email);
  if (!domain) return [];
  const providers = await listVerifiedProviders(ctx);
  const matches: EmailDomainMatch[] = [];
  for (const provider of providers) {
    if (!provider.organizationId) continue;
    const match = domainMatches(domain, provider.domain);
    if (!match) continue;
    matches.push({
      orgId: provider.organizationId,
      providerId: provider.providerId,
      matchedDomain: match.matched,
    });
  }
  matches.sort(
    (a, b) =>
      b.matchedDomain.length - a.matchedDomain.length || a.providerId.localeCompare(b.providerId),
  );
  return matches;
}
