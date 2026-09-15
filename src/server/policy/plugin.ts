// Alpha Bros enterprise layer — org security policy plugin.
//
// `orgPolicy(opts)` (id `enterprise-policy`) is the last plugin appended by
// the preset (`../preset.ts`, after `auditLog`). This file is the wiring
// layer — the `org_policy` table schema, the `GET`/`POST /enterprise/
// policy*` endpoints, `getPolicyPreconditions`, and the final plugin object
// — built on three leaf modules that don't import each other or this file:
//
// - `./store.ts` — the `OrgPolicy` shape, defaults, and org-membership/role
//   reads (`getOrgPolicy`, `getMemberRoles`, `requireOrgMember`,
//   `requireOwnerOrAdmin`, `isOrgOwner`).
// - `./enforcement.ts` — sign-in `hooks.before`, the `databaseHooks.
//   session.create.before` backstop, and `resolvePolicyOrgForUser` (the
//   membership-first, domain-fallback org resolver both enforcement points
//   share).
// - `./deprovision.ts` — the SCIM deprovision `hooks.after` cascade.
// - `./home-realm.ts` — `findOrgByEmailDomain` and the public
//   `/enterprise/home-realm` endpoint.
//
// `require2fa` (the `hooks.after` on `/get-session`) lives here rather than
// in `./enforcement.ts`: it only ever decorates a response, never blocks a
// request, so it doesn't fit "enforcement" and is closely tied to this
// file's other endpoint-shaped concerns.
//
// `org_policy`'s primary key is `org_id`, not `id` — see `./store.ts`'s
// header comment for the full explanation (why the `schema` below omits an
// `id` field, and why that's safe).

import type { BetterAuthPlugin, GenericEndpointContext } from "better-auth";
import {
  APIError,
  createAuthEndpoint,
  createAuthMiddleware,
  isAPIError,
  sessionMiddleware,
} from "better-auth/api";
import * as z from "zod";
import { requireFeature } from "../entitlements";
import type { EnterpriseOptions } from "../types";
import { buildDeprovisionAfterHook } from "./deprovision";
import { buildSessionCreateBeforeHook, buildSignInBeforeHook } from "./enforcement";
import { findOrgByEmailDomain, HOME_REALM_RATE_LIMIT, homeRealmEndpoint } from "./home-realm";
import { buildScimRequiredUserCreateBeforeHook } from "./scim-required";
import {
  ALLOWED_METHOD_VALUES,
  findPolicyRow,
  getOrgPolicy,
  isOrgOwner,
  requireOwner,
  requireOwnerOrAdmin,
  toOrgPolicy,
  type OrgPolicy,
} from "./store";

export type { OrgPolicy } from "./store";
export { ALLOWED_METHOD_VALUES } from "./store";
export { deriveSessionCreateMethod } from "./enforcement";

// --- SSO-enforcement preconditions (controller ruling (b)) -----------------

/**
 * A verified SSO provider for the org, and (separately, for Task 7) whether
 * any of that org's verified providers has passed the admin test-login flow
 * — a `verification` row with identifier `ab-sso-test-ok:<providerId>`,
 * which Task 7 is what writes. v0.1's `POST /enterprise/policy/set` only
 * requires `verifiedProvider`; `testLoginPassed` is computed and exported
 * now so Task 7 can gate on it without this function's shape changing.
 */
export async function getPolicyPreconditions(
  ctx: GenericEndpointContext,
  orgId: string,
): Promise<{ verifiedProvider: boolean; testLoginPassed: boolean }> {
  const providers = await ctx.context.adapter.findMany<{
    providerId: string;
    domainVerified: boolean;
  }>({
    model: "ssoProvider",
    where: [
      { field: "organizationId", value: orgId },
      { field: "domainVerified", value: true },
    ],
  });
  let testLoginPassed = false;
  for (const provider of providers) {
    const verification = await ctx.context.adapter.findOne({
      model: "verification",
      where: [{ field: "identifier", value: `ab-sso-test-ok:${provider.providerId}` }],
    });
    if (verification) {
      testLoginPassed = true;
      break;
    }
  }
  return { verifiedProvider: providers.length > 0, testLoginPassed };
}

// --- policy endpoints --------------------------------------------------

const getPolicyQuerySchema = z.object({ orgId: z.string() });

const setPolicyBodySchema = z.object({
  orgId: z.string(),
  require2fa: z.boolean().optional(),
  ssoEnforced: z.boolean().optional(),
  breakGlassUserId: z.string().nullable().optional(),
  sessionMaxAgeS: z.number().int().positive().nullable().optional(),
  allowedMethods: z.array(z.enum(ALLOWED_METHOD_VALUES)).min(1).optional(),
  groupRoleMap: z.record(z.string(), z.enum(["owner", "admin", "member"])).optional(),
});

function buildPolicyEndpoints() {
  const getPolicy = createAuthEndpoint(
    "/enterprise/policy",
    { method: "GET", use: [sessionMiddleware], query: getPolicyQuerySchema },
    async (ctx) => {
      const fullCtx = ctx as unknown as GenericEndpointContext;
      const { orgId } = ctx.query;
      // Owner/admin, not any member (M-08): this response carries
      // `breakGlassUserId`, `groupRoleMap` and `allowedMethods` — the org's
      // security configuration, and a map of exactly which IdP group grants
      // which role. Plain members get `require2fa` surfaced on
      // `/get-session` instead (see `buildRequire2faAfterHook` below).
      await requireOwnerOrAdmin(fullCtx, orgId);
      return ctx.json(await getOrgPolicy(fullCtx, orgId));
    },
  );

  const setPolicy = createAuthEndpoint(
    "/enterprise/policy/set",
    { method: "POST", use: [sessionMiddleware], body: setPolicyBodySchema },
    async (ctx) => {
      const fullCtx = ctx as unknown as GenericEndpointContext;
      const { orgId, ...patch } = ctx.body;
      // Role before entitlement (M-07) — a non-member must never reach the
      // product's `resolveEntitlements` with an org id they invented.
      // `./gate.ts`'s `GATED_PATHS` already runs `requireFeature` for this
      // path (mapped to the top `"enforce_2fa"` tier) before this handler
      // ever executes; called again here so this endpoint is self-defending
      // the same way `../audit/plugin.ts`'s audit endpoints are, independent
      // of the gate staying wired up.
      await requireOwnerOrAdmin(fullCtx, orgId);
      await requireFeature(fullCtx, orgId, "enforce_2fa");

      // The two knobs that can mint owners are owner-only (M-01): an admin
      // who can write `groupRoleMap` can point a group at `owner`, mint
      // themselves a SCIM token and add themselves to that group — the full
      // admin→owner escalation the audit reproduced end to end. Same for
      // `breakGlassUserId`, which exempts a user from `ssoEnforced` *and*
      // from `allowedMethods`.
      if (patch.groupRoleMap !== undefined || patch.breakGlassUserId !== undefined) {
        await requireOwner(fullCtx, orgId);
      }
      // `owner` is refused as a mapping target outright in v0.1 (M-01):
      // there is no legitimate reason for an IdP group to confer org
      // ownership, and it is the escalation's payload.
      if (patch.groupRoleMap && Object.values(patch.groupRoleMap).includes("owner")) {
        throw new APIError("BAD_REQUEST", {
          code: "GROUP_ROLE_MAP_OWNER_FORBIDDEN",
          message: 'groupRoleMap may map a group to "admin" or "member" only, never "owner".',
        });
      }

      const existing = await findPolicyRow(fullCtx, orgId);
      const current = toOrgPolicy(existing, orgId);
      const next: OrgPolicy = {
        orgId,
        require2fa: patch.require2fa ?? current.require2fa,
        ssoEnforced: patch.ssoEnforced ?? current.ssoEnforced,
        breakGlassUserId:
          patch.breakGlassUserId !== undefined ? patch.breakGlassUserId : current.breakGlassUserId,
        sessionMaxAgeS:
          patch.sessionMaxAgeS !== undefined ? patch.sessionMaxAgeS : current.sessionMaxAgeS,
        allowedMethods: patch.allowedMethods ?? current.allowedMethods,
        groupRoleMap: patch.groupRoleMap ?? current.groupRoleMap,
      };

      if (next.ssoEnforced) {
        const { verifiedProvider } = await getPolicyPreconditions(fullCtx, orgId);
        const breakGlassIsOwner =
          next.breakGlassUserId !== null &&
          (await isOrgOwner(fullCtx, orgId, next.breakGlassUserId));
        if (!verifiedProvider || !breakGlassIsOwner) {
          throw new APIError("BAD_REQUEST", {
            code: "SSO_ENFORCE_PRECONDITION",
            message:
              "Enforcing SSO requires a verified SSO provider for this organization and a breakGlassUserId who holds the owner role.",
          });
        }
      }

      // Break-glass identity is validated on *every* write (M-06), not only
      // when `ssoEnforced` is being turned on — which is what the check
      // above (deliberately left first, so enabling enforcement still
      // reports `SSO_ENFORCE_PRECONDITION`) used to be the only cover for.
      // Without this, an owner could set `breakGlassUserId` to a user of
      // another org — or of no org at all — while `ssoEnforced` was false,
      // and that outsider was then permanently exempt from the org's
      // `allowedMethods` enforcement too (`./enforcement.ts` honours
      // break-glass for both rules).
      if (patch.breakGlassUserId !== undefined && patch.breakGlassUserId !== null) {
        if (!(await isOrgOwner(fullCtx, orgId, patch.breakGlassUserId))) {
          throw new APIError("BAD_REQUEST", {
            code: "BREAK_GLASS_NOT_OWNER",
            message:
              "breakGlassUserId must be a user who holds the owner role in this organization.",
          });
        }
      }

      const updatedAt = new Date();
      const data = {
        require2fa: next.require2fa,
        ssoEnforced: next.ssoEnforced,
        breakGlassUserId: next.breakGlassUserId,
        sessionMaxAgeS: next.sessionMaxAgeS,
        allowedMethods: next.allowedMethods,
        groupRoleMap: next.groupRoleMap,
        updatedAt,
      };
      if (existing) {
        await fullCtx.context.adapter.update({
          model: "orgPolicy",
          where: [{ field: "orgId", value: orgId }],
          update: data,
        });
      } else {
        await fullCtx.context.adapter.create({
          model: "orgPolicy",
          data: { orgId, ...data },
        });
      }

      // `../audit/plugin.ts`'s generic `hooks.after` on this same path
      // already writes the `policy.updated` row (ruling (g)) — its
      // `resolveTargetId` falls back to `extractId(returned)`, which only
      // ever finds an `.id` field, so the response includes one aliased to
      // `orgId` (the resource `policy.updated` actually targets) purely for
      // that resolver; it is not part of the public `OrgPolicy` shape.
      return ctx.json({ ...next, id: next.orgId });
    },
  );

  return { enterprisePolicyGet: getPolicy, enterprisePolicySet: setPolicy };
}

// --- require2fa surfaced on GET /get-session (controller ruling (e)) ---

/**
 * Re-implementation of better-auth's own `getEndpointResponse`
 * (`node_modules/better-auth/dist/utils/plugin-helper.mjs`, used internally
 * by e.g. the `admin`/`custom-session` plugins' own `hooks.after`) — not
 * re-exported from the package's public `better-auth/api` entry point
 * (verified by grep), so vendored here rather than reached into `dist/` for.
 */
async function getEndpointJson(ctx: { context: { returned?: unknown } }): Promise<unknown> {
  const returned = ctx.context.returned;
  if (!returned) return null;
  if (returned instanceof Response) {
    if (returned.status !== 200) return null;
    return await returned.clone().json();
  }
  if (isAPIError(returned)) return null;
  return returned;
}

function buildRequire2faAfterHook() {
  return {
    matcher: (ctx: { path?: string }) => ctx.path === "/get-session",
    handler: createAuthMiddleware(async (ctx) => {
      const response = (await getEndpointJson(ctx)) as {
        user: { twoFactorEnabled?: boolean };
        session: { activeOrganizationId?: string | null };
      } | null;
      if (!response?.user) return;
      const orgId = response.session?.activeOrganizationId;
      if (!orgId) return;

      const fullCtx = ctx as unknown as GenericEndpointContext;
      const policy = await getOrgPolicy(fullCtx, orgId);
      if (!policy.require2fa) return;

      return ctx.json({
        ...response,
        enterprise: { require2fa: true, twoFactorEnabled: !!response.user.twoFactorEnabled },
      });
    }),
  };
}

// No explicit `: BetterAuthPlugin` return-type annotation (client task-9
// fix round 1) — see `../enterprise-api/plugin.ts`'s identical comment on
// `enterpriseApi` for why: `satisfies BetterAuthPlugin` below keeps the
// same structural validation while letting each endpoint's literal `path`
// (and this plugin's own `id`) survive into `ReturnType<typeof orgPolicy>`
// for `../client/plugin.ts`'s `$InferServerPlugin`.
export function orgPolicy(opts: EnterpriseOptions) {
  return {
    id: "enterprise-policy",
    options: opts,
    schema: {
      orgPolicy: {
        modelName: "org_policy",
        fields: {
          orgId: { type: "string", required: true, fieldName: "org_id" },
          require2fa: { type: "boolean", required: true, fieldName: "require_2fa" },
          ssoEnforced: { type: "boolean", required: true, fieldName: "sso_enforced" },
          breakGlassUserId: {
            type: "string",
            required: false,
            fieldName: "break_glass_user_id",
          },
          sessionMaxAgeS: { type: "number", required: false, fieldName: "session_max_age_s" },
          allowedMethods: { type: "string[]", required: true, fieldName: "allowed_methods" },
          groupRoleMap: { type: "json", required: true, fieldName: "group_role_map" },
          updatedAt: { type: "date", required: true, fieldName: "updated_at" },
        },
      },
    },
    endpoints: { ...buildPolicyEndpoints(), enterpriseHomeRealm: homeRealmEndpoint },
    rateLimit: [HOME_REALM_RATE_LIMIT],
    hooks: {
      before: [buildSignInBeforeHook()],
      after: [buildRequire2faAfterHook(), buildDeprovisionAfterHook()],
    },
    // `databaseHooks` is wired via `init()` returning `{options:
    // {databaseHooks}}` — the better-auth convention every plugin that
    // needs one follows (verified against upstream's own `admin` plugin,
    // `node_modules/better-auth/dist/plugins/admin/admin.mjs`), NOT a
    // top-level `databaseHooks` key on the returned plugin object
    // (`BetterAuthPlugin` has no such field — `tsc` rejects it outright).
    // Each plugin's `init()`-returned `databaseHooks` is kept as its own
    // entry in an array (`node_modules/better-auth/dist/context/
    // helpers.mjs`'s `dbHooks.push({source: "plugin:<id>", hooks: ...})`),
    // not shallow-merged into one object, so `admin()`'s own `session.
    // create.before` (banned-user check, already in the preset ahead of
    // `orgPolicy`) and this one both run in sequence rather than one
    // clobbering the other.
    init() {
      return {
        options: {
          databaseHooks: {
            session: {
              create: {
                before: buildSessionCreateBeforeHook(),
              },
            },
            // Task 8, controller ruling (e): "SSO only for SCIM-active
            // users" — see `./scim-required.ts`'s header comment.
            user: {
              create: {
                before: buildScimRequiredUserCreateBeforeHook(),
              },
            },
          },
        },
      };
    },
  } satisfies BetterAuthPlugin;
}

export { findOrgByEmailDomain };
