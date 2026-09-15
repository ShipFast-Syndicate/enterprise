// Alpha Bros enterprise layer — sign-in enforcement, session-creation
// backstop, and policy-org resolution (controller ruling (d)).
//
// Depends only on `./home-realm` (a leaf) and `./store` (a leaf) — not on
// `./plugin.ts` — so `./plugin.ts` can import everything here without a
// cycle.

import type { GenericEndpointContext } from "better-auth";
import { APIError, createAuthMiddleware } from "better-auth/api";
import { findOrgByEmailDomain } from "./home-realm";
import { getOrgPolicy, memberOrgIds } from "./store";

// --- policy-org resolution -------------------------------------------------

/**
 * Resolves which org's policy applies to a user, in priority order:
 *
 * 1. The session/request's active organization, if one is known —
 *    trustworthy as-is, same convention `../gate.ts`'s `GATED_PATHS`
 *    resolver already uses for `session.activeOrganizationId`.
 * 2. The org the user is a member of, *if they belong to exactly one* — an
 *    unambiguous single-org membership is a much stronger signal than a
 *    shared SSO domain (a domain match only tells you the *domain* has SSO
 *    configured somewhere, not that this particular user is that org's
 *    member). Zero or multiple memberships fall through — this resolver
 *    can't disambiguate which of several orgs a policy check should target,
 *    so it defers to the domain signal instead of guessing.
 * 3. The org owning a verified `ssoProvider` for the user's email domain
 *    (`findOrgByEmailDomain`, `./home-realm.ts`) — the only signal available
 *    pre-authentication (no session/membership exists yet) or for a user
 *    who isn't a member of any org at all yet (SCIM/SSO JIT provisioning).
 * 4. `null` — no policy is resolvable, so no enforcement applies.
 */
export async function resolvePolicyOrgForUser(
  ctx: GenericEndpointContext,
  params: { userId: string; email: string; activeOrganizationId?: string | null },
): Promise<string | null> {
  if (params.activeOrganizationId) return params.activeOrganizationId;

  const orgIds = await memberOrgIds(ctx, params.userId);
  if (orgIds.length === 1) return orgIds[0]!;

  const match = await findOrgByEmailDomain(ctx, params.email);
  return match?.orgId ?? null;
}

// --- sign-in pre-flight (hooks.before on the sign-in paths) ---------------

const SIGNIN_ENFORCEMENT_PATHS = new Set<string>([
  "/sign-in/email",
  "/sign-in/social",
  "/sign-in/magic-link",
  "/sign-in/passkey",
  "/magic-link/verify",
]);

// Only `/sign-in/email`/`/sign-in/magic-link`/`/magic-link/verify` ever
// resolve an email pre-authentication (see `resolveSignInEmail` below);
// `/sign-in/social`/`/sign-in/passkey` always resolve `null` there, so
// `enforceForEmail` never runs for them from this hook — enforcement for
// those two (and for `allowedMethods` generally, which needs the org
// resolved via the *authenticated* user, not just an unauthenticated email
// guess) is `buildSessionCreateBeforeHook`'s job below.
function deriveMethod(path: string): "password" | "magic_link" | null {
  switch (path) {
    case "/sign-in/email":
      return "password";
    case "/sign-in/magic-link":
    case "/magic-link/verify":
      return "magic_link";
    default:
      return null;
  }
}

/** Web-Crypto reimplementation of `magicLink`'s default `storeToken: "hashed"` hasher (see `resolveSignInEmail` below for why). */
async function hashMagicLinkToken(token: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
  let binary = "";
  for (const byte of new Uint8Array(digest)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Resolves the email a sign-in request is *for* — straightforward for
 * `/sign-in/email`/`/sign-in/magic-link` (`body.email`); for
 * `/magic-link/verify` (a GET with a `?token=`, no email in the request)
 * best-effort via a non-destructive `findVerificationValue` read of the
 * still-pending token (never `consumeVerificationValue` — that's the real
 * endpoint's job, and consuming it here would burn the token before the
 * user's actual verification request).
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
async function resolveSignInEmail(
  ctx: GenericEndpointContext,
  path: string,
  body: { email?: unknown } | undefined,
  query: { token?: unknown } | undefined,
): Promise<string | null> {
  if (path === "/sign-in/email" || path === "/sign-in/magic-link") {
    return typeof body?.email === "string" ? body.email : null;
  }
  if (path === "/magic-link/verify") {
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
  return null;
}

async function enforceForEmail(
  ctx: GenericEndpointContext,
  email: string,
  method: "password" | "magic_link" | null,
): Promise<void> {
  if (!method) return;
  const targetUser = await ctx.context.internalAdapter.findUserByEmail(email);
  const orgId = targetUser
    ? await resolvePolicyOrgForUser(ctx, { userId: targetUser.user.id, email })
    : ((await findOrgByEmailDomain(ctx, email))?.orgId ?? null);
  if (!orgId) return;
  const policy = await getOrgPolicy(ctx, orgId);

  const isBreakGlass = !!policy.breakGlassUserId && targetUser?.user.id === policy.breakGlassUserId;

  if (policy.ssoEnforced && !isBreakGlass) {
    throw new APIError("FORBIDDEN", {
      code: "SSO_REQUIRED",
      message: "Your organization requires SSO",
    });
  }
  if (!isBreakGlass && !policy.allowedMethods.includes(method)) {
    throw new APIError("FORBIDDEN", {
      code: "METHOD_NOT_ALLOWED",
      message: `Sign-in method "${method}" is not allowed for this organization.`,
    });
  }
}

export function buildSignInBeforeHook() {
  return {
    matcher: (ctx: { path?: string }) => !!ctx.path && SIGNIN_ENFORCEMENT_PATHS.has(ctx.path),
    handler: createAuthMiddleware(async (ctx) => {
      const path = ctx.path as string;
      const fullCtx = ctx as unknown as GenericEndpointContext;
      const email = await resolveSignInEmail(
        fullCtx,
        path,
        ctx.body as { email?: unknown } | undefined,
        ctx.query as { token?: unknown } | undefined,
      );
      if (!email) return; // social/passkey (no email pre-auth), or an unresolvable magic-link token
      await enforceForEmail(fullCtx, email, deriveMethod(path));
    }),
  };
}

// --- session-creation backstop ---------------------------------------------

/**
 * Derives the sign-in *method* from the endpoint whose call is creating the
 * session — the only place `allowedMethods` can be enforced for
 * `/sign-in/social`/`/sign-in/passkey`/SSO, since none of those resolve an
 * email pre-authentication (`resolveSignInEmail` above always returns
 * `null` for them, so `buildSignInBeforeHook` never reaches
 * `enforceForEmail`). Exported standalone so it's unit-testable against a
 * fake `ctx` without driving a real OAuth/passkey round trip.
 *
 * `ctx.path` inside a request handler can be either the endpoint's
 * registered *pattern* (`/callback/:id`, with the provider in
 * `ctx.params.id`) or a *concrete* resolved path (`/callback/google`) —
 * `../audit/plugin.ts`'s header comment documents this ambiguity existing
 * across different better-auth dispatch layers (hook handlers reliably see
 * the pattern; `databaseHooks`, sourced from `getCurrentAuthContext()`
 * inside the live endpoint call, is not verified against the same evidence)
 * — so both forms are handled here rather than assuming one.
 *
 * Unknown/unrecognized paths return `null` and are never blocked — only the
 * methods this preset's own plugins expose are enforceable at all.
 */
export function deriveSessionCreateMethod(ctx: {
  path?: string;
  params?: Record<string, string | undefined>;
  body?: unknown;
}): string | null {
  const path = ctx.path;
  if (!path) return null;
  if (path === "/sign-in/email") return "password";
  if (path === "/magic-link/verify") return "magic_link";
  if (path === "/passkey/verify-authentication") return "passkey";
  if (path.startsWith("/sso/")) return "sso";
  if (path === "/sign-in/social") {
    const body = ctx.body as { provider?: unknown } | undefined;
    return typeof body?.provider === "string" ? body.provider : null;
  }
  const callbackMatch = /^\/callback\/(.+)$/.exec(path);
  if (callbackMatch) {
    const segment = callbackMatch[1];
    if (segment && segment !== ":id") return segment; // concrete: /callback/google
    return typeof ctx.params?.id === "string" ? ctx.params.id : null; // pattern: /callback/:id
  }
  return null;
}

/**
 * `databaseHooks.session.create.before` — the backstop every sign-in path
 * (including the ones the pre-flight hook above can't cover: social,
 * passkey, and the SSO callback itself) ultimately funnels through. Wired
 * via `init()` in `./plugin.ts` (see that file's header comment for why —
 * `BetterAuthPlugin` has no top-level `databaseHooks` field).
 */
export function buildSessionCreateBeforeHook() {
  return async (
    session: { userId: string; expiresAt?: unknown } & Record<string, unknown>,
    ctx: GenericEndpointContext | null,
  ) => {
    if (!ctx) return;
    const user = await ctx.context.internalAdapter.findUserById(session.userId);
    if (!user?.email) return;

    const activeOrganizationId =
      typeof session.activeOrganizationId === "string" ? session.activeOrganizationId : null;
    const orgId = await resolvePolicyOrgForUser(ctx, {
      userId: session.userId,
      email: user.email,
      activeOrganizationId,
    });
    if (!orgId) return;
    const policy = await getOrgPolicy(ctx, orgId);

    const isSsoPath = typeof ctx.path === "string" && ctx.path.startsWith("/sso/");
    const isBreakGlass = !!policy.breakGlassUserId && session.userId === policy.breakGlassUserId;
    if (policy.ssoEnforced && !isSsoPath && !isBreakGlass) {
      throw new APIError("FORBIDDEN", {
        code: "SSO_REQUIRED",
        message: "Your organization requires SSO",
      });
    }

    const method = deriveSessionCreateMethod(ctx);
    if (method && !isBreakGlass && !policy.allowedMethods.includes(method)) {
      throw new APIError("FORBIDDEN", {
        code: "METHOD_NOT_ALLOWED",
        message: `Sign-in method "${method}" is not allowed for this organization.`,
      });
    }

    if (policy.sessionMaxAgeS != null) {
      return {
        data: { ...session, expiresAt: new Date(Date.now() + policy.sessionMaxAgeS * 1000) },
      };
    }
    return;
  };
}
