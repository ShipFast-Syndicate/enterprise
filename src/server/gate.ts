// Alpha Bros enterprise layer — entitlement gate plugin.
//
// `enterpriseGate` adds a single global `hooks.before` that intercepts the
// upper-tier paths listed in `GATED_PATHS` and enforces the matching
// `Feature` via `requireFeature` before the real endpoint ever runs.
//
// Anonymous calls are deliberately let through to the real endpoint: the
// gate only resolves the session to find the org id; if there is no
// session, the endpoint's own `sessionMiddleware` is the one that answers
// 401, not us (see the `!session` branch below).

import { APIError, createAuthMiddleware, getSessionFromCtx } from "better-auth/api";
import type { BetterAuthPlugin, GenericEndpointContext } from "better-auth";
import type { EnterpriseOptions, Feature } from "./types";
import { requireFeature } from "./entitlements";
import { getMemberRoles } from "./policy/store";
import { withSecretEncryption } from "./secrets";

export const GATED_PATHS: Record<string, Feature> = {
  "/sso/register": "sso",
  "/sso/request-domain-verification": "sso",
  "/sso/verify-domain": "sso",
  "/scim/generate-token": "scim",
  "/scim/delete-provider-connection": "scim",
  "/organization/create-team": "teams",
  "/api-key/create": "api_keys",
  "/enterprise/audit/list": "audit_log",
  "/enterprise/audit/export": "audit_log",
  "/enterprise/audit/compact": "audit_log",
  "/enterprise/policy/set": "enforce_2fa", // any policy write needs the top tier
  // Task 7 (`./enterprise-api/plugin.ts`) portal wrappers. `/enterprise/
  // members` and `/enterprise/features` are deliberately absent — basic org
  // membership/entitlement reads, session + membership only (see that
  // plugin's own file headers).
  "/enterprise/sso/providers": "sso",
  "/enterprise/sso/register": "sso",
  "/enterprise/sso/test-login/start": "sso",
  "/enterprise/sso/test-login/finish": "sso",
  "/enterprise/scim/tokens": "scim",
  "/enterprise/scim/tokens/create": "scim",
  "/enterprise/scim/tokens/revoke": "scim",
};

// `@better-auth/scim` below 1.7 has an unpatched HIGH advisory
// (GHSA-j8v8-g9cx-5qf4): a SCIM provider created without `organizationId`
// ("personal" provider) can be taken over. This design only ever allows
// org-scoped providers, so these two paths require `organizationId`
// explicitly in the body — unlike every other gated path, they must NOT
// fall back to the session's active org (see the org-id resolution below).
const ORG_ID_REQUIRED_IN_BODY = new Set<string>([
  "/scim/generate-token",
  "/scim/delete-provider-connection",
]);

// Paths only an org **owner** may call (M-01). Minting a SCIM token is the
// second half of the admin→owner escalation the audit reproduced (write
// `groupRoleMap: {Bosses: "owner"}` as an admin, mint a token, `POST
// /scim/v2/Groups {displayName: "Bosses", members: [self]}`); the first half
// is closed in `./policy/plugin.ts`. Enforced here rather than only in
// `./enterprise-api/scim.ts` so calling the upstream endpoint directly is
// covered too — the portal wrapper forwards through this same dispatch
// pipeline, so both routes hit this check.
const OWNER_ONLY_PATHS = new Set<string>([
  "/scim/generate-token",
  "/enterprise/scim/tokens/create",
]);

// No explicit `: BetterAuthPlugin` return-type annotation (client task-9 fix
// round 1, applied here too for consistency — see `./enterprise-api/
// plugin.ts`'s identical comment on `enterpriseApi`). `enterpriseGate` has
// no `endpoints` of its own, so this doesn't unlock any new client typing
// by itself, but keeps every plugin constructor in this package following
// the same `satisfies BetterAuthPlugin` convention.
export function enterpriseGate(opts: EnterpriseOptions) {
  return {
    id: "enterprise-gate",
    // Exposed the same way built-in plugins (e.g. `jwt`) expose their
    // config on themselves — `requireFeature` reads it back off
    // `ctx.context.options.plugins` so it isn't tied to this specific
    // closure.
    options: opts,
    // Encryption at rest for IdP secrets (C-04). better-auth merges a
    // plugin's returned `context` into the live `AuthContext` and builds
    // `internalAdapter` from `context.adapter` *after* every plugin's
    // `init()` has run (`node_modules/better-auth/dist/context/helpers.mjs`),
    // so wrapping the adapter here covers both access paths — including
    // every `@better-auth/sso` read/write of `ssoProvider`. See
    // `./secrets.ts`.
    init(context) {
      return { context: { adapter: withSecretEncryption(context.adapter, opts.secretsKey) } };
    },
    hooks: {
      before: [
        {
          matcher: (ctx) => !!ctx.path && ctx.path in GATED_PATHS,
          handler: createAuthMiddleware(async (ctx) => {
            // `ctx.path` is guaranteed to be a `GATED_PATHS` key here — the
            // matcher above is the only way into this handler, and it
            // already checked `ctx.path in GATED_PATHS`. Kept as a defensive
            // fallback rather than a non-null assertion.
            const feature = GATED_PATHS[ctx.path];
            if (!feature) return;

            // The hook context (`HookEndpointContext`) is structurally the
            // same shape `getSessionFromCtx`/`requireFeature` need
            // (`{ context: AuthContext, path, body, ... }` — a
            // `GenericEndpointContext` minus a few endpoint-specific,
            // unused-here fields); this hook runs inside the same request
            // dispatch as the endpoint itself, so `ctx.context` is the real,
            // live `AuthContext` for this request either way.
            const session = await getSessionFromCtx(ctx as unknown as GenericEndpointContext);
            if (!session) return; // anonymous — let the endpoint answer 401

            const body = ctx.body as { organizationId?: string; orgId?: string } | undefined;
            // GET endpoints (e.g. `/enterprise/audit/list|export`, Task 4)
            // carry the org id in the query string, not the body.
            const query = ctx.query as { orgId?: string } | undefined;
            const orgId = ORG_ID_REQUIRED_IN_BODY.has(ctx.path)
              ? body?.organizationId
              : (body?.organizationId ??
                body?.orgId ??
                query?.orgId ??
                (session.session as { activeOrganizationId?: string }).activeOrganizationId);
            if (!orgId) {
              throw new APIError("BAD_REQUEST", {
                code: "ORG_REQUIRED",
                message: "An organization id is required.",
              });
            }

            // Membership before entitlement (M-07). `orgId` here is still
            // caller-supplied on most paths, and `resolveEntitlements` is the
            // product's own billing/plan lookup: letting a non-member reach
            // it turned `/enterprise/*?orgId=<any string>` into both a
            // cross-tenant existence/plan oracle (`FEATURE_NOT_ENTITLED` =
            // "org exists, no plan" vs. `NOT_ORG_ADMIN` = "org exists and is
            // entitled") and a free amplifier into that lookup. A non-member
            // now gets the same `NOT_ORG_MEMBER` for every org id they do not
            // belong to, whatever its plan — and never reaches the resolver.
            const roles = await getMemberRoles(
              ctx as unknown as GenericEndpointContext,
              orgId,
              session.user.id,
            );
            if (roles.length === 0) {
              throw new APIError("FORBIDDEN", {
                code: "NOT_ORG_MEMBER",
                message: "You are not a member of this organization.",
              });
            }
            if (OWNER_ONLY_PATHS.has(ctx.path) && !roles.includes("owner")) {
              throw new APIError("FORBIDDEN", {
                code: "NOT_ORG_OWNER",
                message: "Owner role required.",
              });
            }

            await requireFeature(ctx as unknown as GenericEndpointContext, orgId, feature);
          }),
        },
      ],
    },
  } satisfies BetterAuthPlugin;
}
