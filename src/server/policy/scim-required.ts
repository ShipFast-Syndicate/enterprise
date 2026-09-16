// Alpha Bros enterprise layer — "SSO only for SCIM-active users" (Task 8,
// controller ruling (e)).
//
// Once an org has provisioned any SCIM connection (a `scimProvider` row
// exists for it — SCIM is how its IT admin manages that org's user
// lifecycle), JIT account creation via a plain SSO sign-in must not run
// behind SCIM's back: an employee off-boarded in the IdP but not yet
// deprovisioned through SCIM could otherwise still JIT a fresh account back
// in through SSO the moment they're removed from one system but not the
// other. Upstream `sso({ disableImplicitSignUp })` is a single switch for the
// whole plugin instance (or per explicit `requestSignUp` override), not
// something scoped per org — so this can't be expressed as an `sso()` option
// from a shared preset. It's enforced instead as a
// `databaseHooks.user.create.before`, the same mechanism `./enforcement.ts`'s
// session-creation backstop already uses for policy enforcement that has no
// upstream per-org knob: it only inspects requests whose path names one of
// the two SSO callback route families, resolves the org via the new user's
// *verified* email domain (`findOrgByEmailDomain`, `./home-realm.ts` — the
// same lookup the home-realm endpoint and `./enforcement.ts`'s policy
// resolution both already use), and refuses account creation when that org
// has any `scimProvider` row.
//
// `ctx.path` at a `databaseHooks` call site cannot be trusted to be either
// the registered route *pattern* or the concrete resolved path (see
// `./enforcement.ts`'s header comment on the identical ambiguity for
// `databaseHooks.session.create.before`, and `deriveSessionCreateMethod`'s
// handling of both forms) — `isSsoCallbackPath` below matches with
// `startsWith` so both `/sso/callback/:providerId` (pattern) /
// `/sso/callback/okta` (concrete) and `/sso/saml2/sp/acs/:providerId` /
// `/sso/saml2/sp/acs/okta` match regardless of which form this hook actually
// observes.
//
// Wired into `orgPolicy`'s `init()` (`./plugin.ts`) alongside the existing
// `session.create.before` backstop — both are `databaseHooks` entries this
// package's own `enterprise-policy` plugin owns, returned from one `init()`
// call per better-auth's per-plugin `databaseHooks` merge convention (each
// plugin's own `init()`-returned hooks become their own `dbHooks` entry, not
// shallow-merged into one global object), so this can't clobber anything
// `admin()`/`sso()` register earlier in the preset.

import type { GenericEndpointContext } from "better-auth";
import { APIError } from "better-auth/api";
import { findOrgByEmailDomain } from "./home-realm";

function isSsoCallbackPath(path: string | undefined): boolean {
  if (!path) return false;
  return path.startsWith("/sso/callback/") || path.startsWith("/sso/saml2/sp/acs");
}

/**
 * `databaseHooks.user.create.before` — refuses a new user row being created
 * from an SSO callback when the org owning a verified SSO provider for the
 * user's email domain has any SCIM provider connected. Never blocks account
 * creation from any other path (email/password sign-up, magic link, social
 * sign-in, a SCIM-driven `/scim/v2/Users` POST, ...) — only the two SSO
 * callback route families above, and only once a domain match resolves an
 * org with SCIM active.
 */
export function buildScimRequiredUserCreateBeforeHook() {
  return async (
    user: { email?: unknown } & Record<string, unknown>,
    ctx: GenericEndpointContext | null,
  ): Promise<void> => {
    if (!ctx) return;
    if (!isSsoCallbackPath(ctx.path)) return;
    const email = typeof user.email === "string" ? user.email : null;
    if (!email) return;

    const match = await findOrgByEmailDomain(ctx, email);
    if (!match) return;

    const scimProvider = await ctx.context.adapter.findOne({
      model: "scimProvider",
      where: [{ field: "organizationId", value: match.orgId }],
    });
    if (!scimProvider) return;

    throw new APIError("FORBIDDEN", {
      code: "SCIM_PROVISIONING_REQUIRED",
      message: "Your account was not provisioned by your IT admin",
    });
  };
}
