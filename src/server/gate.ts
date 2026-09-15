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
            const feature = GATED_PATHS[ctx.path];
            if (!feature) return;

            const session = await getSessionFromCtx(ctx as unknown as GenericEndpointContext);
            if (!session) return; // anonymous — let the endpoint answer 401

            const body = ctx.body as { organizationId?: string; orgId?: string } | undefined;
            const orgId =
              body?.organizationId ??
              body?.orgId ??
              (session.session as { activeOrganizationId?: string }).activeOrganizationId;
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
