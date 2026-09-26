// Alpha Bros enterprise layer — sign-in enforcement, session-creation
// backstop, session-refresh clamp, and policy-org resolution.
//
// Depends only on `./home-realm` (a leaf), `./store` (a leaf) and
// `../audit/refusal` (a leaf) — not on `./plugin.ts` — so `./plugin.ts` can
// import everything here without a cycle.
//
// Where each policy field is enforced:
//
// - `ssoEnforced` / `allowedMethods` — `buildSessionCreateBeforeHook`
//   (`databaseHooks.session.create.before`), the one place every sign-in
//   path funnels through *after* the credential has been checked. The only
//   pre-authentication hook left is the `/magic-link/verify` pre-flight
//   (`buildSignInBeforeHook`), whose "credential" — the pending token — is
//   what resolves the e-mail, so refusing there reveals nothing a stranger
//   could not already learn. `/sign-in/email` and `/sign-in/magic-link` are
//   deliberately *not* pre-flighted any more: answering `SSO_REQUIRED` before
//   the password was checked told anyone "this address is a member of an
//   SSO-enforced org" (audit gap 3).
// - `sessionMaxAgeS` — the same create hook (cap at creation) plus
//   `buildSessionUpdateBeforeHook` (`databaseHooks.session.update.before`),
//   which clamps the refresh `/get-session` writes back (F-05).
// - SSO domain binding (F-01, `./sso-jit.ts`) — the create hook again, for
//   every session an SSO callback mints: the signing provider must be
//   domain-verified for the user's e-mail domain, *before* any policy logic
//   and independent of it (a legacy `account` row linked to a foreign IdP
//   stays in the database but can no longer sign in — R4 of the fix plan).
//   `ssoEnforced` is then satisfied only by the enforcing org's **own**
//   IdP (R3), never by another tenant flipping their own org to enforce.

import type { GenericEndpointContext } from "better-auth";
import { APIError, createAuthMiddleware } from "better-auth/api";
import { auditRefusal } from "../audit/refusal";
import type { EnterpriseOptions } from "../types";
import { findOrgsByEmailDomain } from "./home-realm";
import { isSsoCallbackPath } from "./scim-required";
import {
  assertStoredProviderAllowed,
  domainBindingEnabled,
  issuerAllowListEnabled,
  providerAuthorizesEmail,
  resolveSsoCallbackProvider,
  ssoDomainNotAllowedError,
  ssoProviderUnresolvedError,
  type SsoCallbackProvider,
} from "./sso-jit";
import { getEffectivePolicy, memberOrgIds, type EffectivePolicy } from "./store";

// --- policy-org resolution -------------------------------------------------

/**
 * Every org that has a claim on a user's sign-in policy — the **union** of
 * the request's active organization, every org the user is a member of, and
 * every org owning a verified SSO provider for the user's e-mail domain
 * (`findOrgsByEmailDomain`, upstream-parity matching). De-duplicated, in that
 * order. Feed the result to `getEffectivePolicy` (`./store.ts`).
 *
 * This replaced the single-org, priority-ordered `resolvePolicyOrgForUser`,
 * which returned `null` — no policy at all — for a user in two or more orgs
 * and let any member escape `ssoEnforced`/`allowedMethods` by creating a
 * second organization (F-03). An empty result still means "no policy
 * applies" (free agents unchanged); a non-empty one is never narrowed by
 * ambiguity.
 */
export async function resolvePolicyOrgsForUser(
  ctx: GenericEndpointContext,
  params: { userId: string | null; email: string; activeOrganizationId?: string | null },
): Promise<string[]> {
  return (await resolvePolicyClaims(ctx, params)).orgIds;
}

/**
 * `resolvePolicyOrgsForUser` plus the *identity* orgs on their own — the
 * orgs owning a verified provider for the user's e-mail domain — which the
 * `ssoEnforced` rule needs separately (R3): one domain scan serves both.
 */
async function resolvePolicyClaims(
  ctx: GenericEndpointContext,
  params: { userId: string | null; email: string; activeOrganizationId?: string | null },
): Promise<{ orgIds: string[]; identityOrgIds: string[] }> {
  const orgIds = new Set<string>();
  if (params.activeOrganizationId) orgIds.add(params.activeOrganizationId);
  if (params.userId) {
    for (const orgId of await memberOrgIds(ctx, params.userId)) orgIds.add(orgId);
  }
  const identityOrgIds = new Set<string>();
  for (const match of await findOrgsByEmailDomain(ctx, params.email)) {
    orgIds.add(match.orgId);
    identityOrgIds.add(match.orgId);
  }
  return { orgIds: [...orgIds], identityOrgIds: [...identityOrgIds] };
}

// --- sign-in method classification ---------------------------------------

export type SessionCreateClassification =
  /** A sign-in method this layer knows by name; subject to `allowedMethods`. */
  | { kind: "method"; method: string }
  /**
   * A session (re)issued inside a flow the user already authenticated for —
   * a 2FA challenge answered, an already-signed-in user's e-mail verified,
   * password changed, 2FA toggled, an admin impersonating. The sign-in
   * method was classified and enforced when the flow started; the
   * continuation itself is not a method and is never refused as one.
   */
  | { kind: "continuation"; path: string }
  /**
   * A session-creating path this layer cannot name. Refused for a user under
   * a restricted policy (fail closed, audit gap 4); a product that ships such
   * a plugin declares it in `policy.signInMethods`.
   */
  | { kind: "unknown"; path: string | null };

/**
 * Session-creating paths that are not a sign-in method of their own (see
 * `SessionCreateClassification["kind"] === "continuation"`). Every entry was
 * traced to an `internalAdapter.createSession` call in the pinned
 * better-auth 1.7.5 or one of the preset's plugins. The `/two-factor/verify-*`
 * endpoints run without a session (the challenge cookie stands in for it);
 * the rest sit behind `sessionMiddleware`.
 *
 * `/verify-email` is deliberately **not** here: it is a continuation only
 * for an already-signed-in user (`isVerifyEmailContinuation`).
 */
const CONTINUATION_PATHS = new Set<string>([
  "/two-factor/verify-totp",
  "/two-factor/verify-otp",
  "/two-factor/verify-backup-code",
  "/two-factor/enable",
  "/two-factor/disable",
  "/change-password",
  "/admin/impersonate-user",
]);

/**
 * Upstream `/verify-email` is reachable **unauthenticated** — the emailed
 * token is the whole credential — and mints a brand-new session for a user
 * with no current one under `emailVerification.autoSignInAfterVerification`
 * (the deferred sign-in of a `requireEmailVerification` sign-up, whose
 * `/sign-up/email` created no session for the backstop to classify) and in
 * the two change-e-mail branches. Treating every `/verify-email` session as
 * a continuation let a member of an `allowedMethods`-narrowed org sign in
 * through the verification link (audit gap 4, second cut). Every upstream
 * branch calls `getSessionFromCtx(ctx)` — which sets `ctx.context.session`
 * to the result or `null` — before `createSession`, so the field is reliably
 * populated at the hook call site: the call is a continuation only when the
 * request already carries a session **for the same user** (upstream still
 * mints a new session when the current one belongs to someone else).
 * Otherwise it is a first sign-in whose credential is e-mail possession —
 * classified as `magic_link`, the closed-set name for exactly that.
 */
function isVerifyEmailContinuation(
  ctx: { context?: { session?: unknown } | null },
  subject: { userId?: unknown } | undefined,
): boolean {
  const current = ctx.context?.session as { user?: { id?: unknown } } | null | undefined;
  const currentUserId = current?.user?.id;
  if (typeof currentUserId !== "string") return false;
  return subject?.userId === undefined || subject.userId === currentUserId;
}

function classifyFromOptions(path: string, opts: EnterpriseOptions | undefined): string | null {
  const map = opts?.policy?.signInMethods;
  if (!map) return null;
  const exact = map[path];
  if (typeof exact === "string") return exact;
  for (const [key, method] of Object.entries(map)) {
    if (!key.endsWith("/*")) continue;
    const prefix = key.slice(0, -1); // keep the trailing slash: "/phone/*" -> "/phone/"
    if (path.startsWith(prefix)) return method;
  }
  return null;
}

/**
 * Classifies the endpoint whose call is creating a session. `ctx.path`
 * inside a request handler can be either the endpoint's registered
 * *pattern* (`/callback/:id`, with the provider in `ctx.params.id`) or a
 * *concrete* resolved path (`/callback/google`) — `../audit/plugin.ts`'s
 * header comment documents this ambiguity across better-auth dispatch
 * layers — so both forms are handled here rather than assuming one.
 *
 * Order: the product's `policy.signInMethods` first (so a product can
 * re-name or add a path), then the built-in map for the methods this
 * preset's own plugins expose, then continuations, then `unknown`.
 *
 * `session` is the row being created (its `userId`), which `/verify-email`
 * needs to tell a continuation from a first sign-in — see
 * `isVerifyEmailContinuation`.
 */
export function classifySessionCreate(
  ctx: {
    path?: string;
    params?: Record<string, string | undefined>;
    body?: unknown;
    context?: { session?: unknown } | null;
  },
  opts?: EnterpriseOptions,
  session?: { userId?: unknown },
): SessionCreateClassification {
  const path = ctx.path;
  if (!path) return { kind: "unknown", path: null };

  const configured = classifyFromOptions(path, opts);
  if (configured) return { kind: "method", method: configured };

  if (path === "/sign-in/email" || path === "/sign-up/email") {
    return { kind: "method", method: "password" };
  }
  if (path === "/magic-link/verify") return { kind: "method", method: "magic_link" };
  if (path === "/verify-email") {
    return isVerifyEmailContinuation(ctx, session)
      ? { kind: "continuation", path }
      : { kind: "method", method: "magic_link" };
  }
  if (path === "/passkey/verify-authentication" || path === "/passkey/verify-registration") {
    return { kind: "method", method: "passkey" };
  }
  if (path.startsWith("/sso/")) return { kind: "method", method: "sso" };
  if (path === "/sign-in/social") {
    const body = ctx.body as { provider?: unknown } | undefined;
    return typeof body?.provider === "string"
      ? { kind: "method", method: body.provider }
      : { kind: "unknown", path };
  }
  const callbackMatch = /^\/callback\/(.+)$/.exec(path);
  if (callbackMatch) {
    const segment = callbackMatch[1];
    if (segment && segment !== ":id") return { kind: "method", method: segment }; // concrete: /callback/google
    const id = ctx.params?.id;
    return typeof id === "string" ? { kind: "method", method: id } : { kind: "unknown", path }; // pattern: /callback/:id
  }
  if (CONTINUATION_PATHS.has(path)) return { kind: "continuation", path };
  return { kind: "unknown", path };
}

/**
 * The sign-in *method* a session-creating call carries, or `null` when the
 * path is a continuation or unknown — a thin wrapper over
 * `classifySessionCreate` kept for callers (and tests) that only need the
 * name. `null` no longer means "never blocked": see the hook below.
 */
export function deriveSessionCreateMethod(
  ctx: {
    path?: string;
    params?: Record<string, string | undefined>;
    body?: unknown;
    context?: { session?: unknown } | null;
  },
  opts?: EnterpriseOptions,
  session?: { userId?: unknown },
): string | null {
  const classified = classifySessionCreate(ctx, opts, session);
  return classified.kind === "method" ? classified.method : null;
}

// --- shared refusal helpers ------------------------------------------------

function ssoRequiredError(): APIError {
  return new APIError("FORBIDDEN", {
    code: "SSO_REQUIRED",
    message: "Your organization requires SSO through its own identity provider",
  });
}

function methodNotAllowedError(method: string): APIError {
  return new APIError("FORBIDDEN", {
    code: "METHOD_NOT_ALLOWED",
    message: `Sign-in method "${method}" is not allowed for this organization.`,
  });
}

/**
 * `allowedMethods` binds only once some contributing org actually narrowed
 * the list (`sources.allowedMethodsBy`, computed by `getEffectivePolicy`
 * against the **full** method vocabulary — the 8 built-ins plus every
 * `policy.signInMethods` name the product declared, `allowedMethodValues`).
 * The rule per org: a declared method is allowed only if the org's stored
 * list contains it, or the org has no `org_policy` row at all, or its row
 * lists the full vocabulary. A row that stores exactly the 8 built-ins while
 * the product declares `email_otp` therefore *excludes* `email_otp` — an org
 * must be able to exclude a declared method without also dropping a
 * built-in — and declaring a new `signInMethods` entry means orgs with an
 * existing row must add the name before their members can use it. Only a
 * method name outside the vocabulary altogether (a social provider id the
 * product never declared) is left alone for an un-narrowed org.
 */
function methodRefusedBy(eff: EffectivePolicy, method: string): boolean {
  return eff.sources.allowedMethodsBy.length > 0 && !eff.allowedMethods.includes(method);
}

// --- sign-in pre-flight (hooks.before on /magic-link/verify) --------------

/**
 * The only sign-in path still pre-flighted. Password sign-in is enforced by
 * the session-creation backstop after the credential check; the magic-link
 * *request* is left alone (it must not reveal whether the address belongs
 * to a policy-bound member — gap 3). The *verify* step is safe to pre-flight
 * because the pending token, not a guessable e-mail, is what identifies the
 * user — and refusing before the real handler runs keeps the single-use
 * token unconsumed, which the audit row and the user's next attempt both
 * want.
 */
const SIGNIN_ENFORCEMENT_PATHS = new Set<string>(["/magic-link/verify"]);

/** Web-Crypto reimplementation of `magicLink`'s default `storeToken: "hashed"` hasher (see `resolveSignInEmail` below for why). */
async function hashMagicLinkToken(token: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
  let binary = "";
  for (const byte of new Uint8Array(digest)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Resolves the email a `/magic-link/verify` request (a GET with a
 * `?token=`, no email in the request) is *for*, best-effort via a
 * non-destructive `findVerificationValue` read of the still-pending token
 * (never `consumeVerificationValue` — that's the real endpoint's job, and
 * consuming it here would burn the token before the user's actual
 * verification request).
 *
 * `magicLink`'s `storeToken` option controls what identifier the
 * verification row is actually keyed by
 * (`node_modules/better-auth/dist/plugins/magic-link/index.mjs`): `"plain"`
 * (the default) stores the raw token as the identifier; `"hashed"` stores
 * `defaultKeyHasher(token)` — SHA-256, base64url, unpadded
 * (`./utils.mjs`'s `defaultKeyHasher`), reimplemented here via Web Crypto
 * since this plugin has no access to the `magicLink` plugin instance's
 * options (it's configured by the product, not by `orgPolicy`) to call the
 * real one. A custom `{type: "custom-hasher", hash}` function can't be
 * replicated at all. So this tries the raw token first, then the default
 * hash — covering `"plain"` and `"hashed"` — and returns `null` (deferring
 * to the `databaseHooks.session.create.before` backstop) for a custom
 * hasher or an already-consumed/unknown token.
 */
async function resolveMagicLinkEmail(
  ctx: GenericEndpointContext,
  query: { token?: unknown } | undefined,
): Promise<string | null> {
  const token = typeof query?.token === "string" ? query.token : null;
  if (!token) return null;
  const candidates = [token, await hashMagicLinkToken(token)];
  for (const identifier of candidates) {
    const verification = await ctx.context.internalAdapter
      .findVerificationValue(identifier)
      .catch(() => null);
    if (!verification) continue;
    try {
      const parsed = JSON.parse(verification.value) as { email?: unknown };
      if (typeof parsed.email === "string") return parsed.email;
    } catch {
      // malformed verification value — fall through to the backstop
    }
  }
  return null;
}

async function enforceForEmail(
  ctx: GenericEndpointContext,
  path: string,
  email: string,
  method: string,
  opts: EnterpriseOptions | undefined,
): Promise<void> {
  const targetUser = await ctx.context.internalAdapter.findUserByEmail(email);
  const userId = targetUser?.user.id ?? null;
  const orgIds = await resolvePolicyOrgsForUser(ctx, { userId, email });
  if (orgIds.length === 0) return;
  const eff = await getEffectivePolicy(ctx, orgIds, userId, opts);

  const refuse = async (error: APIError): Promise<never> => {
    await auditRefusal(ctx, {
      path,
      code: String(error.body?.code ?? ""),
      orgIds: eff.orgIds,
      userId,
      email,
      method,
    });
    throw error;
  };

  if (eff.ssoEnforced) await refuse(ssoRequiredError());
  if (methodRefusedBy(eff, method)) await refuse(methodNotAllowedError(method));
}

export function buildSignInBeforeHook(opts?: EnterpriseOptions) {
  return {
    matcher: (ctx: { path?: string }) => !!ctx.path && SIGNIN_ENFORCEMENT_PATHS.has(ctx.path),
    handler: createAuthMiddleware(async (ctx) => {
      const path = ctx.path as string;
      const fullCtx = ctx as unknown as GenericEndpointContext;
      const email = await resolveMagicLinkEmail(
        fullCtx,
        ctx.query as { token?: unknown } | undefined,
      );
      if (!email) return; // custom hasher or an already-consumed/unknown token: the backstop still applies
      await enforceForEmail(fullCtx, path, email, "magic_link", opts);
    }),
  };
}

// --- session-creation backstop ---------------------------------------------

function sessionExpiryMs(session: { expiresAt?: unknown }, ctx: GenericEndpointContext): number {
  const requested = session.expiresAt;
  if (requested instanceof Date && Number.isFinite(requested.getTime())) return requested.getTime();
  if (typeof requested === "number" && Number.isFinite(requested)) return requested;
  return Date.now() + ctx.context.sessionConfig.expiresIn * 1000;
}

/**
 * `databaseHooks.session.create.before` — the backstop every sign-in path
 * (including the ones no pre-flight hook can cover: password, social,
 * passkey, and the SSO callback itself) ultimately funnels through, *after*
 * upstream has checked the credential. Wired via `init()` in `./plugin.ts`
 * (see that file's header comment for why — `BetterAuthPlugin` has no
 * top-level `databaseHooks` field).
 *
 * Rules, in order:
 * 0. **SSO provider trust** (before any policy and independent of it): on
 *    an SSO callback the signing provider is resolved once
 *    (`resolveSsoCallbackProvider`, fail-closed `SSO_PROVIDER_UNRESOLVED`);
 *    with `sso.allowedIssuers` configured its stored row must still pass
 *    the allow-list — issuer, endpoints and, for SAML, the pinned signing
 *    certificates (F-28, `SSO_ISSUER_NOT_ALLOWED`); and, unless
 *    `sso.domainBinding: "off"`, it must be domain-verified for the user's
 *    e-mail domain (F-01) → otherwise `SSO_DOMAIN_NOT_ALLOWED`. This is what
 *    makes a legacy squat — an `account` row already linked to a foreign
 *    tenant's IdP — inert: the row stays, the session is never minted.
 * Then, against the **effective** policy of every org with a claim on the
 * user (`resolvePolicyOrgsForUser` + `getEffectivePolicy`):
 * 1. `ssoEnforced` and this is not an SSO callback → `SSO_REQUIRED`. On an
 *    SSO callback the provider's org must be one of the orgs enforcing SSO
 *    on this user **and**, when the e-mail domain is claimed by verified
 *    providers at all, one of the orgs claiming it (R3) — so a tenant who
 *    flips *their own* org to `ssoEnforced` cannot satisfy another org's
 *    rule for a user they linked to their IdP. Otherwise `SSO_REQUIRED`
 *    ("through its own identity provider").
 * 2. a named method some org excluded → `METHOD_NOT_ALLOWED` (`methodRefusedBy`;
 *    narrowing is judged against the full method vocabulary, `opts` threaded
 *    into `getEffectivePolicy`).
 * 3. a path this layer cannot classify, for a user under any restriction →
 *    `METHOD_NOT_ALLOWED` (fail closed; declare it in
 *    `policy.signInMethods`). Continuations are never refused here — and a
 *    `/verify-email` session for a user with no current session is not one
 *    (`isVerifyEmailContinuation`): it is enforced as `magic_link`.
 * 4. `sessionMaxAgeS` → `expiresAt = min(requested, now + cap)`; never
 *    extends a session past the global lifetime.
 * Break-glass is honoured per org inside `getEffectivePolicy`.
 */
export function buildSessionCreateBeforeHook(opts?: EnterpriseOptions) {
  return async (
    session: { userId: string; expiresAt?: unknown } & Record<string, unknown>,
    ctx: GenericEndpointContext | null,
  ) => {
    if (!ctx) return;
    const user = await ctx.context.internalAdapter.findUserById(session.userId);
    if (!user?.email) return;

    // Rule 0 — the provider is looked up once and reused by rule 1. With the
    // binding and the allow-list both off it is still needed by rule 1 (and
    // only refused as unresolved there, when a decision actually depends on
    // it). With an allow-list configured the stored row is re-judged first
    // (`assertStoredProviderAllowed`, `SSO_ISSUER_NOT_ALLOWED`): a provider
    // the operator no longer trusts is refused before its domain claim is
    // even considered.
    const ssoCallback = isSsoCallbackPath(ctx.path);
    let provider: SsoCallbackProvider | null = null;
    if (ssoCallback) {
      provider = await resolveSsoCallbackProvider(ctx);
      const bindingOn = domainBindingEnabled(opts);
      if (bindingOn || issuerAllowListEnabled(opts)) {
        if (!provider) {
          ctx.context.logger.error(
            `enterprise-policy: refusing an SSO session from ${JSON.stringify(ctx.path)} — the signing provider could not be resolved (SSO_PROVIDER_UNRESOLVED)`,
          );
          throw ssoProviderUnresolvedError();
        }
        await assertStoredProviderAllowed(ctx, opts, provider);
        if (bindingOn && !providerAuthorizesEmail(provider, user.email)) {
          throw ssoDomainNotAllowedError();
        }
      }
    }

    const activeOrganizationId =
      typeof session.activeOrganizationId === "string" ? session.activeOrganizationId : null;
    const { orgIds, identityOrgIds } = await resolvePolicyClaims(ctx, {
      userId: session.userId,
      email: user.email,
      activeOrganizationId,
    });
    if (orgIds.length === 0) return;
    const eff = await getEffectivePolicy(ctx, orgIds, session.userId, opts);

    if (eff.ssoEnforced) {
      if (!ssoCallback) throw ssoRequiredError();
      if (!provider) throw ssoProviderUnresolvedError();
      const providerOrgId = provider.organizationId;
      if (!providerOrgId || !eff.sources.ssoEnforcedBy.includes(providerOrgId)) {
        throw ssoRequiredError();
      }
      if (identityOrgIds.length > 0 && !identityOrgIds.includes(providerOrgId)) {
        throw ssoRequiredError();
      }
    }

    const classified = classifySessionCreate(ctx, opts, session);
    if (classified.kind === "method" && methodRefusedBy(eff, classified.method)) {
      throw methodNotAllowedError(classified.method);
    }
    if (classified.kind === "unknown" && eff.restricted) {
      ctx.context.logger.warn(
        `enterprise-policy: refusing a session from unclassified path ${JSON.stringify(classified.path)} for a user under a restricted policy — declare it in policy.signInMethods (METHOD_NOT_ALLOWED)`,
      );
      throw methodNotAllowedError(classified.path ?? "unknown");
    }

    if (eff.sessionMaxAgeS != null) {
      const cap = Date.now() + eff.sessionMaxAgeS * 1000;
      const expiresAt = new Date(Math.min(sessionExpiryMs(session, ctx), cap));
      return { data: { ...session, expiresAt } };
    }
    return;
  };
}

// --- session-refresh clamp -------------------------------------------------

/**
 * `databaseHooks.session.update.before` — F-05. Upstream `/get-session`
 * refreshes a session by writing `expiresAt = now + expiresIn` (the global
 * 7-day lifetime) whenever `updateAge` has elapsed, which silently undid the
 * cap the create hook applied on the first authenticated request. This hook
 * sees that write (`data.expiresAt`) and clamps it to
 * `createdAt + sessionMaxAgeS` for the session being refreshed — the one
 * `/get-session` has already loaded into `ctx.context.session` — so a
 * capped session can be refreshed within its window but never past it.
 * Writes that do not touch `expiresAt` (`/organization/set-active`, …) and
 * writes outside a request context pass through untouched.
 */
export function buildSessionUpdateBeforeHook(opts?: EnterpriseOptions) {
  return async (
    data: { expiresAt?: unknown } & Record<string, unknown>,
    ctx: GenericEndpointContext | null,
  ) => {
    if (!ctx) return;
    const requested = data.expiresAt;
    if (!(requested instanceof Date) || !Number.isFinite(requested.getTime())) return;
    const current = ctx.context.session;
    if (!current?.session || !current.user?.email) return;

    const orgIds = await resolvePolicyOrgsForUser(ctx, {
      userId: current.session.userId,
      email: current.user.email,
      activeOrganizationId: current.session.activeOrganizationId ?? null,
    });
    if (orgIds.length === 0) return;
    const eff = await getEffectivePolicy(ctx, orgIds, current.session.userId, opts);
    if (eff.sessionMaxAgeS == null) return;

    const createdAt = new Date(current.session.createdAt).getTime();
    if (!Number.isFinite(createdAt)) return;
    const cap = createdAt + eff.sessionMaxAgeS * 1000;
    if (requested.getTime() <= cap) return;
    return { data: { ...data, expiresAt: new Date(cap) } };
  };
}
