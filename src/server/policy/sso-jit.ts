// Alpha Bros enterprise layer — SSO domain binding for JIT-created users
// (GHSA-8p84-pc7q-69jr, F-01).
//
// `@better-auth/sso` lets *any* tenant's domain-verified IdP sign in — and
// implicitly sign up — **any** e-mail address on the platform: the callback's
// create branch ignores `isTrustedProvider` (the link branch honours it), so
// an org admin whose IdP asserts `ceo@acme.test` mints that account on the
// deployment, locks the real user out of their own SSO (the account is
// linked to the wrong provider) and, downstream, satisfies acme's
// `ssoEnforced` and cashes in acme's invitations. The fix is a binding that
// upstream does not have: an SSO sign-in is honoured only when the signing
// provider is domain-verified **for the user's e-mail domain**. It is applied
// twice —
//
// - here, at `databaseHooks.user.create.before`, for the JIT creation itself
//   (no user row is ever written for a foreign domain; the transaction the
//   callback runs in rolls back), and
// - in `./enforcement.ts`'s `databaseHooks.session.create.before`, for every
//   session an SSO callback mints — which also makes a *legacy* squat (an
//   `account` row already linked to the wrong provider) inert without a
//   migration (R4 of the fix plan).
//
// Both read the provider through `resolveSsoCallbackProvider` below, which
// names the provider the way upstream itself does — `ctx.params.providerId`
// on the per-provider routes, and the server-trusted OAuth state
// (`ssoProviderReference`, set by `/sign-in/sso` and re-read by the callback
// through `parseState`) on the shared `/sso/callback` — and **fails closed**
// (`SSO_PROVIDER_UNRESOLVED`) when neither names one or they disagree.
//
// Both hooks also re-judge the resolved provider row against
// `sso.allowedIssuers` (`assertStoredProviderAllowed` → `../sso-domain.ts`'s
// `storedProviderAllowed`): the allow-list is enforced when a provider is
// written, and again at every sign-in, so a row registered before the
// operator configured (or tightened) the list — or the SAML certificate
// pins — is refused too, `SSO_ISSUER_NOT_ALLOWED`, never a session.
//
// Imports `./domains` (leaf), `./scim-required` (leaf), `../sso-domain`
// (which imports only `./domains`, `./store` and `better-auth/api`) and
// `better-auth/api`, so `./enforcement.ts` and `./plugin.ts` can both import
// it without a cycle.

import type { GenericEndpointContext } from "better-auth";
import { APIError, getOAuthState } from "better-auth/api";
import type { EnterpriseOptions } from "../types";
import { issuerNotAllowedError, storedProviderAllowed } from "../sso-domain";
import { domainMatches, emailDomain } from "./domains";
import { isSsoCallbackPath } from "./scim-required";

/** The `ssoProvider` columns the binding and the allow-list re-check need. */
export interface SsoCallbackProvider {
  providerId: string;
  organizationId: string | null;
  domain: string;
  domainVerified: boolean;
  issuer: string;
  /** JSON as upstream stores it (a string), or `null`. */
  oidcConfig?: unknown;
  samlConfig?: unknown;
}

/** Whether the allow-list re-check at sign-in time has anything to do. */
export function issuerAllowListEnabled(opts: EnterpriseOptions | undefined): boolean {
  return opts?.sso?.allowedIssuers !== undefined;
}

/**
 * Refuses the sign-in (`SSO_ISSUER_NOT_ALLOWED`, logged at warn so an
 * operator sees which stored row their allow-list now excludes) unless the
 * resolved provider row still passes `sso.allowedIssuers`. No-op without a
 * list.
 */
export async function assertStoredProviderAllowed(
  ctx: GenericEndpointContext,
  opts: EnterpriseOptions | undefined,
  provider: SsoCallbackProvider,
): Promise<void> {
  if (!issuerAllowListEnabled(opts)) return;
  if (await storedProviderAllowed(opts, provider)) return;
  ctx.context.logger.warn(
    `enterprise-policy: refusing an SSO sign-in through provider ${JSON.stringify(provider.providerId)} — its stored issuer, endpoints or SAML signing certificate no longer pass sso.allowedIssuers / sso.samlCertificateFingerprints (SSO_ISSUER_NOT_ALLOWED)`,
  );
  throw issuerNotAllowedError(provider.issuer);
}

/** `@better-auth/sso`'s own key for the provider reference it stores in the OAuth state (`SSO_PROVIDER_STATE_KEY`; not exported upstream). */
const SSO_PROVIDER_STATE_KEY = "ssoProviderReference";

const SSO_CALLBACK_CONCRETE_RE = /^\/sso\/(?:callback|saml2\/sp\/acs)\/([^/?#]+)$/;

function nonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

/** The provider id the OAuth state carries for the current request, or `null` outside an OAuth callback (or outside a request altogether). */
async function providerIdFromOAuthState(): Promise<string | null> {
  try {
    const state = (await getOAuthState()) as {
      serverContext?: Record<string, unknown> | null;
    } | null;
    const reference = state?.serverContext?.[SSO_PROVIDER_STATE_KEY] as
      { providerId?: unknown } | null | undefined;
    return nonEmptyString(reference?.providerId) ? reference.providerId : null;
  } catch {
    // `getOAuthState` throws when no request state is active (a hook driven
    // outside a request) — there is simply no state to read.
    return null;
  }
}

/**
 * The `providerId` of the SSO callback creating this user/session, resolved
 * the way upstream resolves it, or `null` when it cannot be named
 * unambiguously:
 *
 * 1. `ctx.params.providerId` — the per-provider routes
 *    (`/sso/callback/:providerId`, `/sso/saml2/sp/acs/:providerId`); when
 *    `ctx.path` is the *concrete* form and `params` is absent, the path's
 *    last segment.
 * 2. the OAuth state's `ssoProviderReference.providerId` — the only source
 *    for the shared `/sso/callback` (no provider in the URL), and a
 *    cross-check for the OIDC per-provider route (upstream refuses the
 *    callback itself when the two disagree, `sso_provider_changed_during_
 *    authentication`).
 *
 * Two sources naming different providers is treated as unresolved: the
 * caller fails closed rather than trusting either.
 */
export async function resolveSsoCallbackProviderId(ctx: {
  path?: string;
  params?: Record<string, string | undefined> | undefined;
}): Promise<string | null> {
  const candidates = new Set<string>();
  const fromParams = ctx.params?.providerId;
  if (nonEmptyString(fromParams)) {
    candidates.add(fromParams);
  } else if (typeof ctx.path === "string") {
    const segment = SSO_CALLBACK_CONCRETE_RE.exec(ctx.path)?.[1];
    if (nonEmptyString(segment) && !segment.startsWith(":")) candidates.add(segment);
  }
  const fromState = await providerIdFromOAuthState();
  if (fromState) candidates.add(fromState);
  if (candidates.size !== 1) return null;
  return [...candidates][0] ?? null;
}

/** `resolveSsoCallbackProviderId` + the provider row, or `null` when either step fails. */
export async function resolveSsoCallbackProvider(
  ctx: GenericEndpointContext,
): Promise<SsoCallbackProvider | null> {
  const providerId = await resolveSsoCallbackProviderId(ctx);
  if (!providerId) return null;
  const row = await ctx.context.adapter.findOne<SsoCallbackProvider>({
    model: "ssoProvider",
    where: [{ field: "providerId", value: providerId }],
  });
  return row ?? null;
}

/**
 * The binding itself: the provider is domain-verified and its `domain` list
 * authorises the e-mail's domain (`domainMatches`, `./domains.ts` — comma
 * lists, case-insensitive, subdomains, an unparsable list matches nothing).
 */
export function providerAuthorizesEmail(
  provider: Pick<SsoCallbackProvider, "domain" | "domainVerified">,
  email: string | null | undefined,
): boolean {
  return (
    provider.domainVerified === true && domainMatches(emailDomain(email), provider.domain) !== null
  );
}

export function ssoProviderUnresolvedError(): APIError {
  return new APIError("FORBIDDEN", {
    code: "SSO_PROVIDER_UNRESOLVED",
    message: "The SSO provider for this sign-in could not be determined.",
  });
}

export function ssoDomainNotAllowedError(): APIError {
  return new APIError("FORBIDDEN", {
    code: "SSO_DOMAIN_NOT_ALLOWED",
    message: "This identity provider is not verified for your e-mail domain.",
  });
}

/** `true` unless the operator switched the binding off (`sso.domainBinding: "off"`, warned about at construction — `../options.ts`). */
export function domainBindingEnabled(opts: EnterpriseOptions | undefined): boolean {
  return opts?.sso?.domainBinding !== "off";
}

type UserCreateBeforeHook = (
  user: { email?: unknown } & Record<string, unknown>,
  ctx: GenericEndpointContext | null,
) => Promise<false | void | { data: Record<string, unknown> }>;

/**
 * `databaseHooks.user.create.before` — refuses a user row being created from
 * an SSO callback unless the signing provider still passes the issuer
 * allow-list (`SSO_ISSUER_NOT_ALLOWED`, when one is configured) and is
 * domain-verified for the new user's e-mail domain
 * (`SSO_DOMAIN_NOT_ALLOWED`, unless `sso.domainBinding: "off"`), or the
 * provider cannot be named at all (`SSO_PROVIDER_UNRESOLVED`). On success
 * the user is stored `emailVerified: true` (the IdP owns that domain and
 * vouched for the address — exactly what an e-mail round-trip would prove)
 * unless `sso.trustVerifiedDomainEmail` is `false`. Never touches a row
 * created from any other path (password sign-up, magic link, social, SCIM,
 * …), and does nothing when both the binding and the allow-list are off.
 */
export function buildDomainBindingUserCreateBeforeHook(
  opts?: EnterpriseOptions,
): UserCreateBeforeHook {
  return async (user, ctx) => {
    if (!ctx) return;
    const bindingOn = domainBindingEnabled(opts);
    if (!bindingOn && !issuerAllowListEnabled(opts)) return;
    if (!isSsoCallbackPath(ctx.path)) return;

    const provider = await resolveSsoCallbackProvider(ctx);
    if (!provider) {
      ctx.context.logger.error(
        `enterprise-policy: refusing an SSO JIT sign-up from ${JSON.stringify(ctx.path)} — the signing provider could not be resolved (SSO_PROVIDER_UNRESOLVED)`,
      );
      throw ssoProviderUnresolvedError();
    }
    await assertStoredProviderAllowed(ctx, opts, provider);
    if (!bindingOn) return;
    const email = typeof user.email === "string" ? user.email : null;
    if (!providerAuthorizesEmail(provider, email)) throw ssoDomainNotAllowedError();

    if (opts?.sso?.trustVerifiedDomainEmail === false) return;
    return { data: { ...user, emailVerified: true } };
  };
}

/**
 * Runs several `user.create.before` hooks in order as one better-auth hook
 * (a plugin's `init()` returns a single `databaseHooks` object, so the
 * domain binding and the SCIM-required guard — both this plugin's — have to
 * share the slot). Each hook sees the row as modified by the ones before it;
 * the first `false` short-circuits; the merged `data` is returned only when
 * some hook changed something.
 */
export function composeUserCreateBeforeHooks(
  ...hooks: UserCreateBeforeHook[]
): UserCreateBeforeHook {
  return async (user, ctx) => {
    let current = user;
    let changed = false;
    for (const hook of hooks) {
      const result = await hook(current, ctx);
      if (result === false) return false;
      if (result && typeof result === "object" && "data" in result) {
        current = { ...current, ...result.data };
        changed = true;
      }
    }
    return changed ? { data: current } : undefined;
  };
}
