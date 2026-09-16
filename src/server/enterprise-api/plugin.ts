// Alpha Bros enterprise layer — enterpriseApi plugin.
//
// Portal-facing wrappers the admin UI drives directly: `GET /enterprise/
// features` (entitlement read model), the SSO wizard (`./sso.ts`), SCIM
// token lifecycle (`./scim.ts`), and org membership (`./members.ts`) — plus
// the one cross-cutting precondition this task adds to `POST /enterprise/
// policy/set` (ruling (g), below).
//
// Split into `./sso.ts`/`./scim.ts`/`./members.ts`/`./forward.ts` once this
// file would otherwise pass ~300 lines (task brief's own guidance) — this
// file is purely the assembly point: `GATED_PATHS`/`AUDITED_PATHS` wiring
// notes live in `../gate.ts`/`../audit/plugin.ts` themselves (edited
// alongside this plugin, per the task brief), and `../preset.ts` appends
// `enterpriseApi(opts)` last.
//
// Registered last in the preset specifically so this plugin's own
// `hooks.before` below runs *after* `../gate.ts`'s `enterpriseGate` (feature
// entitlement) — plugin registration order only affects hook *ordering*
// within the shared before/after arrays (`node_modules/better-auth/dist/
// api/dispatch.mjs`'s `getHooks`), never whether a hook fires at all; every
// plugin's `hooks.before` still runs before the *matched endpoint's own*
// handler body regardless of which plugin declared that endpoint (verified
// against the pinned better-auth@1.6.33's `dispatchAuthEndpoint`).

import {
  APIError,
  createAuthEndpoint,
  createAuthMiddleware,
  sessionMiddleware,
} from "better-auth/api";
import type { BetterAuthPlugin, GenericEndpointContext } from "better-auth";
import * as z from "zod";
import type { EnterpriseOptions } from "../types";
import { getPolicyPreconditions } from "../policy/plugin";
import { getOrgPolicy, isOrgOwner, requireOrgMember } from "../policy/store";
import { buildSsoEndpoints } from "./sso";
import { buildScimEndpoints } from "./scim";
import { buildMembersEndpoint } from "./members";

const featuresQuerySchema = z.object({ orgId: z.string() });

function buildFeaturesEndpoint(opts: EnterpriseOptions) {
  return createAuthEndpoint(
    "/enterprise/features",
    { method: "GET", use: [sessionMiddleware], query: featuresQuerySchema },
    async (ctx) => {
      const fullCtx = ctx as unknown as GenericEndpointContext;
      const { orgId } = ctx.query;
      await requireOrgMember(fullCtx, orgId);
      const features = [...new Set(await opts.resolveEntitlements(orgId))];
      return ctx.json({ features });
    },
  );
}

// --- ruling (g): mandatory successful test login before ssoEnforced -------
//
// `../policy/plugin.ts`'s `setPolicy` handler already throws
// `SSO_ENFORCE_PRECONDITION` when `ssoEnforced:true` lacks a verified
// provider or an owner `breakGlassUserId` — this hook adds the *further*
// `testLoginPassed` requirement (spec §5.2) without pre-empting that
// existing check for a request that would have failed it anyway: it
// re-derives the exact same `verifiedProvider`/`breakGlassIsOwner` combination
// (merging `breakGlassUserId` against the stored row the same way `setPolicy`
// does) and only throws `SSO_TEST_LOGIN_REQUIRED` when both already hold —
// i.e. only for a request that would otherwise have *succeeded*. This keeps
// `test/server/policy.test.ts`'s existing "no verified provider" and
// "breakGlassUserId isn't an owner" cases asserting their original
// `SSO_ENFORCE_PRECONDITION` code untouched; only the tests that actually
// flip `ssoEnforced` on now also need to seed an `ab-sso-test-ok:<providerId>`
// row first (`./sso.ts`'s test-login/finish is what normally writes it).
function buildSsoEnforcePreconditionHook() {
  return {
    matcher: (ctx: { path?: string }) => ctx.path === "/enterprise/policy/set",
    handler: createAuthMiddleware(async (ctx) => {
      const body = ctx.body as
        { orgId?: string; ssoEnforced?: boolean; breakGlassUserId?: string | null } | undefined;
      if (!body?.ssoEnforced || !body.orgId) return;
      const fullCtx = ctx as unknown as GenericEndpointContext;
      const orgId = body.orgId;

      const { verifiedProvider, testLoginPassed } = await getPolicyPreconditions(fullCtx, orgId);
      if (!verifiedProvider) return; // setPolicy's own check reports this

      const current = await getOrgPolicy(fullCtx, orgId);
      const breakGlassUserId =
        body.breakGlassUserId !== undefined ? body.breakGlassUserId : current.breakGlassUserId;
      const breakGlassIsOwner =
        breakGlassUserId !== null && (await isOrgOwner(fullCtx, orgId, breakGlassUserId));
      if (!breakGlassIsOwner) return; // ditto

      if (!testLoginPassed) {
        throw new APIError("BAD_REQUEST", {
          code: "SSO_TEST_LOGIN_REQUIRED",
          message:
            "Enforcing SSO requires a successful admin test login for a verified SSO provider first (POST /enterprise/sso/test-login/start, then complete the flow).",
        });
      }
    }),
  };
}

// No explicit `: BetterAuthPlugin` return-type annotation (client task-9
// fix round 1): annotating it there would widen the whole returned object
// to that general interface — whose `endpoints` field is the generic
// `{ [key: string]: Endpoint }` index signature — discarding each
// endpoint's own literal `path` before `ReturnType<typeof enterpriseApi>`
// (`../client/plugin.ts`'s `$InferServerPlugin`) ever sees it. `satisfies
// BetterAuthPlugin` on the returned object literal keeps the same
// structural check (a typo here still fails `pnpm typecheck`) without that
// widening — the standard TS pattern for "validate the shape, keep the
// narrow inferred type" (in use since TS 4.9; this repo pins TS 5.9.3).
export function enterpriseApi(opts: EnterpriseOptions) {
  return {
    id: "enterprise-api",
    endpoints: {
      enterpriseFeatures: buildFeaturesEndpoint(opts),
      ...buildSsoEndpoints(),
      ...buildScimEndpoints(),
      enterpriseMembers: buildMembersEndpoint(),
    },
    hooks: {
      before: [buildSsoEnforcePreconditionHook()],
    },
  } satisfies BetterAuthPlugin;
}
