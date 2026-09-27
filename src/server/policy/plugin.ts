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
// - `./enforcement.ts` — the `/magic-link/verify` `hooks.before`
//   pre-flight, the `databaseHooks.session.create.before` backstop, the
//   `databaseHooks.session.update.before` refresh clamp, and
//   `resolvePolicyOrgsForUser` (the union-of-orgs resolver every
//   enforcement point feeds into `getEffectivePolicy`).
// SCIM deactivation runs in the native identity transaction (../scim.ts).
// - `./home-realm.ts` — `findOrgByEmailDomain` and the public
//   `/enterprise/home-realm` endpoint.
// - `./sso-jit.ts` — the SSO domain binding (`databaseHooks.user.create.
//   before`, composed with `./scim-required.ts`'s guard below) and the
//   provider resolution `./enforcement.ts`'s session backstop shares.
//
// `require2fa` is enforced in `./enforcement.ts` (the session-creation rule
// and the enrolment gate, both wired below); what lives here is its
// `/get-session` face (`null` for a session that does not stand, else the
// `enterprise.{require2fa, twoFactorEnabled, enrollmentRequired}`
// annotation) and the `/enterprise/policy/set` precondition that the admin
// enabling it can still sign in afterwards.
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
import { orgIdSchema } from "../org-id";
import type { EnterpriseOptions } from "../types";
import {
  buildSessionCreateBeforeHook,
  buildSessionUpdateBeforeHook,
  buildSignInBeforeHook,
  buildTwoFactorEnrollmentGate,
  resolvePolicyOrgsForUser,
  resolveTwoFactorStanding,
  twoFactorSatisfiedBy,
} from "./enforcement";
import {
  findOrgByEmailDomain,
  findOrgsByEmailDomain,
  HOME_REALM_RATE_LIMIT,
  homeRealmEndpoint,
} from "./home-realm";
import { buildScimRequiredUserCreateBeforeHook } from "./scim-required";
import { buildDomainBindingUserCreateBeforeHook, composeUserCreateBeforeHooks } from "./sso-jit";
import {
  allowedMethodValues,
  anyOrgRequiresTwoFactor,
  findPolicyRow,
  getEffectivePolicy,
  getOrgPolicy,
  isOrgOwner,
  requireOwner,
  requireOwnerOrAdmin,
  toOrgPolicy,
  twoFactorEnrollmentState,
  type OrgPolicy,
} from "./store";

export type { OrgPolicy } from "./store";
export { ALLOWED_METHOD_VALUES } from "./store";
export { classifySessionCreate, deriveSessionCreateMethod } from "./enforcement";

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

const getPolicyQuerySchema = z.object({ orgId: orgIdSchema });

/**
 * `allowedMethods` accepts the closed `ALLOWED_METHOD_VALUES` set plus the
 * method names the product declared in `policy.signInMethods`
 * (`allowedMethodValues`, `./store.ts`) — the only way an org can list a
 * sign-in plugin this preset does not ship.
 */
function buildSetPolicyBodySchema(opts: EnterpriseOptions) {
  const methods = allowedMethodValues(opts) as [string, ...string[]];
  return z.object({
    orgId: orgIdSchema,
    require2fa: z.boolean().optional(),
    ssoEnforced: z.boolean().optional(),
    breakGlassUserId: z.string().nullable().optional(),
    sessionMaxAgeS: z.number().int().positive().nullable().optional(),
    allowedMethods: z.array(z.enum(methods)).min(1).optional(),
    groupRoleMap: z.record(z.string(), z.enum(["owner", "admin", "member"])).optional(),
  });
}

function buildPolicyEndpoints(opts: EnterpriseOptions) {
  const setPolicyBodySchema = buildSetPolicyBodySchema(opts);
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

      const existing = await findPolicyRow(fullCtx, orgId);
      const current = toOrgPolicy(existing, orgId);

      // The two knobs that can mint owners are owner-only (M-01): an admin
      // who can write `groupRoleMap` can point a group at `owner`, mint
      // themselves a SCIM token and add themselves to that group — the full
      // admin→owner escalation the audit reproduced end to end. Same for
      // `breakGlassUserId`, which exempts a user from `ssoEnforced` *and*
      // from `allowedMethods`.
      //
      // Narrowed to an actual *change* of the break-glass identity (final
      // review I-1). M-01 made the whole field owner-only, which silently
      // made the SSO wizard's last step owner-only too — the spec, the README
      // and `docs/sso.md` all describe SSO setup as an owner-**or-admin**
      // flow, and an admin walked four steps into a bare "Owner role
      // required." The risk M-01 named is in *choosing* who is exempt from
      // enforcement, not in switching enforcement on against an exemption an
      // owner already chose: so an admin may enable `ssoEnforced` while
      // leaving `breakGlassUserId` alone (omitted entirely, or repeated
      // unchanged), and setting a new one — or clearing an existing one —
      // still requires an owner. `groupRoleMap` stays owner-only on any
      // write: it has no equivalent "unchanged" use.
      const changesBreakGlass =
        patch.breakGlassUserId !== undefined && patch.breakGlassUserId !== current.breakGlassUserId;
      if (patch.groupRoleMap !== undefined || changesBreakGlass) {
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

      // Turning `require2fa` on is done by someone it will apply to, and it
      // re-judges every session of the org's members that predates the flip —
      // the caller's own included (`twoFactorStanding`): only a caller who can
      // get back in afterwards may do it, or the org is locked out with
      // nobody left to switch it off. Two ways back in: the caller has
      // enrolled a second factor (their next password sign-in is challenged;
      // their current session keeps standing), or an SSO sign-in satisfies
      // the requirement (`policy.twoFactor.satisfiedBy` includes `sso`) and
      // this org owns a verified SSO provider for the caller's e-mail domain
      // (`findOrgsByEmailDomain`, the same match the sign-in path uses) — the
      // caller signs in again through it. Anyone else — a magic-link or
      // social-only admin in particular, who could never sign in under the
      // requirement — is refused and the row is left as it was.
      if (next.require2fa && !current.require2fa) {
        const caller = fullCtx.context.session?.user;
        const state = caller ? await twoFactorEnrollmentState(fullCtx, caller.id) : null;
        const canReturnThroughSso =
          !!caller?.email &&
          twoFactorSatisfiedBy(opts).includes("sso") &&
          (await findOrgsByEmailDomain(fullCtx, caller.email)).some(
            (match) => match.orgId === orgId,
          );
        if (!state || (!state.twoFactorEnabled && !canReturnThroughSso)) {
          throw new APIError("BAD_REQUEST", {
            code: "REQUIRE_2FA_PRECONDITION",
            message:
              "Requiring two-factor authentication needs the caller to have enrolled a second factor, or to sign in through this organization's verified SSO provider.",
          });
        }
      }

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

/**
 * `/get-session` under `require2fa` — the session every product authorizes
 * its own routes with (`auth.api.getSession({ headers })` runs this same
 * endpoint and its hooks). When some org with a claim on the user requires a
 * second factor — the **effective** policy (`resolvePolicyOrgsForUser`:
 * memberships, active org and verified-domain claims), not only the session's
 * active organization, which nothing sets by default — the session is judged
 * the way the enrolment gate judges it (`resolveTwoFactorStanding`):
 *
 * - a session that does not stand and cannot be brought to stand (a
 *   no-password user's session that was never judged under the requirement)
 *   is answered with `null`, exactly as upstream answers for no session: the
 *   product sees a signed-out visitor, with no flag to read and nothing to
 *   get wrong;
 * - otherwise the response is annotated with
 *   `enterprise: { require2fa, twoFactorEnabled, enrollmentRequired }`, where
 *   `enrollmentRequired` is the enrolment-only session the gate confines (a
 *   password holder who has not enrolled) — the flag a product's enrolment
 *   redirect keys on.
 *
 * Left untouched when no policy requires 2FA. Never reached for an API key
 * under the opt-in mock session: upstream's api-key before-hook answers
 * `/get-session` itself and better-auth runs no after-hook then. A key's
 * owner is judged before that, in `enterpriseApiKeyValidator` and
 * `apiKeySessionStanding` (`../api-keys.ts`).
 */
function buildRequire2faAfterHook(opts: EnterpriseOptions) {
  return {
    matcher: (ctx: { path?: string }) => ctx.path === "/get-session",
    handler: createAuthMiddleware(async (ctx) => {
      const response = (await getEndpointJson(ctx)) as {
        user: { id: string; email: string; twoFactorEnabled?: boolean };
        session: Record<string, unknown> & { activeOrganizationId?: string | null };
      } | null;
      if (!response?.user?.id || !response.user.email) return;

      const fullCtx = ctx as unknown as GenericEndpointContext;
      // Same cheap probe as the gate: nothing to judge on a deployment where
      // no organization requires a second factor.
      if (!(await anyOrgRequiresTwoFactor(fullCtx))) return;
      const orgIds = await resolvePolicyOrgsForUser(fullCtx, {
        userId: response.user.id,
        email: response.user.email,
        activeOrganizationId: response.session?.activeOrganizationId ?? null,
      });
      if (orgIds.length === 0) return;
      const eff = await getEffectivePolicy(fullCtx, orgIds, response.user.id, opts);
      if (!eff.require2fa) return;

      const state = await twoFactorEnrollmentState(fullCtx, response.user.id);
      const standing = await resolveTwoFactorStanding(
        fullCtx,
        response.session ?? {},
        response.user.id,
        eff,
        state,
      );
      if (standing === "two-factor-required") return ctx.json(null);
      return ctx.json({
        ...response,
        enterprise: {
          require2fa: true,
          twoFactorEnabled: state.twoFactorEnabled,
          enrollmentRequired: standing === "enrollment-required",
        },
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
    endpoints: { ...buildPolicyEndpoints(opts), enterpriseHomeRealm: homeRealmEndpoint },
    rateLimit: [HOME_REALM_RATE_LIMIT],
    hooks: {
      // The enrolment gate runs on every request outside its allow-list
      // (`TWO_FACTOR_ENROLLMENT_ALLOWED_PATHS`), after `../gate.ts`'s hooks
      // (the preset mounts that plugin first): a request an API key or a
      // missing entitlement already refused never reaches it.
      before: [buildSignInBeforeHook(opts), buildTwoFactorEnrollmentGate(opts)],
      after: [buildRequire2faAfterHook(opts)],
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
                before: buildSessionCreateBeforeHook(opts),
              },
              // F-05: `/get-session`'s refresh rewrites `expiresAt` to the
              // global lifetime; the clamp keeps it within `sessionMaxAgeS`.
              update: {
                before: buildSessionUpdateBeforeHook(opts),
              },
            },
            // One `user.create.before` slot, two guards, in this order:
            // the SSO domain binding (F-01, `./sso-jit.ts` — the signing
            // provider must be verified for the new user's e-mail domain,
            // and the row is stored `emailVerified: true`), then Task 8's
            // "SSO only for SCIM-active users" (`./scim-required.ts`).
            user: {
              create: {
                before: composeUserCreateBeforeHooks(
                  buildDomainBindingUserCreateBeforeHook(opts),
                  buildScimRequiredUserCreateBeforeHook(),
                ),
              },
            },
          },
        },
      };
    },
  } satisfies BetterAuthPlugin;
}

export { findOrgByEmailDomain };
