// `POST /enterprise/entitlements/set` — the HTTP face of the staff-managed
// entitlement store (`../entitlement-store.ts`).
//
// Deliberately **not** in `GATED_PATHS` and not an org-admin endpoint: the
// caller is platform staff acting on any organization, usually one that is not
// entitled to anything yet, and a tenant's owner must get nothing from it.
// Checks, in order: a session (`sessionMiddleware`), not an impersonation
// session (staff acting as a user does not carry staff authority), a stored
// non-banned user holding a staff role, the table store being enabled. The
// route is rate limited (`ENTITLEMENT_SET_RATE_LIMIT`) and audited as
// `entitlement.changed` in the target organization's chain, in the same
// transaction as the write.

import type { GenericEndpointContext } from "better-auth";
import { APIError, createAuthEndpoint, getIP, sessionMiddleware } from "better-auth/api";
import * as z from "zod";
import {
  ENTITLEMENT_SET_PATH,
  entitlementStoreDisabledError,
  isPlatformStaff,
  notPlatformStaffError,
  usesEntitlementTable,
  writeEntitlements,
} from "../entitlement-store";
import { orgIdSchema } from "../org-id";
import { FEATURES, type EnterpriseOptions } from "../types";

const setEntitlementsBodySchema = z.object({
  orgId: orgIdSchema,
  features: z.array(z.enum(FEATURES)).max(FEATURES.length),
});

/** `BetterAuthPlugin["rateLimit"]` entry for the staff write — merged into `enterpriseApi()`. */
export const ENTITLEMENT_SET_RATE_LIMIT = {
  pathMatcher: (path: string) => path === ENTITLEMENT_SET_PATH,
  window: 60,
  max: 20,
};

export function buildSetEntitlementsEndpoint(opts: EnterpriseOptions) {
  return createAuthEndpoint(
    ENTITLEMENT_SET_PATH,
    { method: "POST", use: [sessionMiddleware], body: setEntitlementsBodySchema },
    async (ctx) => {
      const fullCtx = ctx as unknown as GenericEndpointContext;
      const { session, user } = ctx.context.session;
      if ((session as { impersonatedBy?: unknown }).impersonatedBy) {
        throw new APIError("FORBIDDEN", {
          code: "IMPERSONATION_NOT_ALLOWED",
          message: "Entitlements cannot be changed from an impersonation session.",
        });
      }
      if (!(await isPlatformStaff(fullCtx.context.adapter, opts, user.id))) {
        throw notPlatformStaffError();
      }
      if (!usesEntitlementTable(opts)) throw entitlementStoreDisabledError();

      const { orgId, features } = ctx.body;
      const result = await writeEntitlements(fullCtx.context, orgId, features, {
        actor: { actorType: "user", actorId: user.id },
        ip: ctx.request ? (getIP(ctx.request, fullCtx.context.options) ?? null) : null,
        userAgent: ctx.request?.headers.get("user-agent") ?? null,
      });
      return ctx.json({ orgId, features: result.features });
    },
  );
}
