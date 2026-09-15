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
  "/enterprise/policy/set": "enforce_2fa", // any policy write needs the top tier
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

export function enterpriseGate(opts: EnterpriseOptions): BetterAuthPlugin {
  return {
    id: "enterprise-gate",
    // Exposed the same way built-in plugins (e.g. `jwt`) expose their
    // config on themselves — `requireFeature` reads it back off
    // `ctx.context.options.plugins` so it isn't tied to this specific
    // closure.
    options: opts,
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
            const orgId = ORG_ID_REQUIRED_IN_BODY.has(ctx.path)
              ? body?.organizationId
              : (body?.organizationId ??
                body?.orgId ??
                (session.session as { activeOrganizationId?: string }).activeOrganizationId);
            if (!orgId) {
              throw new APIError("BAD_REQUEST", {
                code: "ORG_REQUIRED",
                message: "An organization id is required.",
              });
            }

            await requireFeature(ctx as unknown as GenericEndpointContext, orgId, feature);
          }),
        },
      ],
    },
  };
}
