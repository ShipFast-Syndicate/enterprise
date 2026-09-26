// Alpha Bros enterprise layer — "SSO only for SCIM-active users" (Task 8,
// controller ruling (e)).
//
// Once an org has provisioned any SCIM connection (a `scimManagedConnection` row
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
// the two SSO callback route families, resolves **every** org owning a
// verified SSO provider for the new user's email domain
// (`findOrgsByEmailDomain`, `./home-realm.ts` — the same upstream-parity
// lookup the home-realm endpoint and `./enforcement.ts`'s policy resolution
// both use, so a comma-list, mixed-case or subdomain provider matches here
// too, F-04), and refuses account creation when **any** of those orgs has a
// live `scimManagedConnection` row.
//
// `ctx.path` at a `databaseHooks` call site cannot be trusted to be either
// the registered route *pattern* or the concrete resolved path (see
// `./enforcement.ts`'s header comment on the identical ambiguity for
// `databaseHooks.session.create.before`, and `deriveSessionCreateMethod`'s
// handling of both forms) — `isSsoCallbackPath` below matches with
// `startsWith` so both `/sso/callback/:providerId` (pattern) /
// `/sso/callback/okta` (concrete) and `/sso/saml2/sp/acs/:providerId` /
// `/sso/saml2/sp/acs/okta` match regardless of which form this hook actually
// observes. The *shared* OIDC callback `/sso/callback` (no provider
// segment) is matched too: `@better-auth/sso` registers it unconditionally
// and `/sign-in/sso` always stores the provider reference in the OAuth
// state, so any IdP that redirects there — an attacker-controlled one
// always will — completes a JIT sign-in through it just like the per-provider
// route.
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
import { findOrgsByEmailDomain } from "./home-realm";

export function isSsoCallbackPath(path: string | undefined): boolean {
  if (!path) return false;
  return (
    path === "/sso/callback" ||
    path.startsWith("/sso/callback/") ||
    path.startsWith("/sso/saml2/sp/acs")
  );
}

/**
 * `databaseHooks.user.create.before` — refuses a new user row being created
 * from an SSO callback when any org owning a verified SSO provider for the
 * user's email domain has a SCIM provider connected. Never blocks account
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

    const orgIds = new Set((await findOrgsByEmailDomain(ctx, email)).map((m) => m.orgId));
    for (const orgId of orgIds) {
      const scimManagedConnection = await ctx.context.adapter.findOne({
        model: "scimManagedConnection",
        where: [
          { field: "provisioningDomainId", value: orgId },
          { field: "status", value: "decommissioned", operator: "ne" },
        ],
      });
      if (!scimManagedConnection) continue;

      throw new APIError("FORBIDDEN", {
        code: "SCIM_PROVISIONING_REQUIRED",
        message: "Your account was not provisioned by your IT admin",
      });
    }
  };
}
