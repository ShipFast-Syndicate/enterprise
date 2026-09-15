// Alpha Bros enterprise layer — org security policy plugin.
//
// `orgPolicy(opts)` (id `enterprise-policy`) is the last plugin appended by
// the preset (`../preset.ts`, after `auditLog`). It owns the `org_policy`
// table (declared here with the same camelCase-field -> snake_case-column
// mapping `../audit/plugin.ts` uses for `audit_event`) and does five things:
//
// 1. `GET /enterprise/policy` / `POST /enterprise/policy/set` — read/write
//    the policy row, with defaults when no row exists yet.
// 2. Sign-in enforcement (`hooks.before` on the sign-in paths) and the
//    session-creation backstop (`databaseHooks.session.create.before`) —
//    together these are what actually make `ssoEnforced`/`allowedMethods`/
//    `sessionMaxAgeS` bite.
// 3. `require2fa` surfaced to the client via a `hooks.after` on
//    `/get-session`.
// 4. The SCIM deprovision cascade (`hooks.after` on
//    `/scim/v2/Users/:userId`).
// 5. `findOrgByEmailDomain`/home-realm discovery — actually implemented in
//    `./home-realm.ts` (a leaf module with no dependency on this file) and
//    merged into the plugin object returned here, so this file can import
//    `findOrgByEmailDomain` from it without the two files importing each
//    other.
//
// `org_policy`'s primary key is `org_id`, not `id` (see the SQL migration,
// `src/schema/sql/0001_enterprise.sql`, and the production drizzle table,
// `src/schema/index.ts`'s `orgPolicy`) — unlike `audit_event`. better-auth's
// adapter factory unconditionally injects an `id` field into every model's
// write path regardless of what a plugin's `schema` declares (verified
// against the pinned better-auth@1.6.33: `createAdapterFactory`'s
// `transformInput` always does `fields.id = idField(...)` before iterating
// fields); confirmed empirically (a standalone drizzle-orm script against an
// in-memory libsql db) that `db.insert(table).values({id: "x", ...})`
// silently drops the extra `id` key when the target table has no such
// column, so this is safe to leave alone rather than declaring a `fieldName`
// override for it — there is no physical column to alias it to anyway.

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
import { writeAudit } from "../audit/chain";
import { findOrgByEmailDomain, HOME_REALM_RATE_LIMIT, homeRealmEndpoint } from "./home-realm";

export interface OrgPolicy {
  orgId: string;
  require2fa: boolean;
  ssoEnforced: boolean;
  breakGlassUserId: string | null;
  sessionMaxAgeS: number | null;
  allowedMethods: string[];
  groupRoleMap: Record<string, "owner" | "admin" | "member">;
}

// Mirrors the SQL migration's `allowed_methods` column default exactly.
const DEFAULT_ALLOWED_METHODS = [
  "sso",
  "magic_link",
  "google",
  "github",
  "linkedin",
  "microsoft",
  "password",
  "passkey",
];

function defaultPolicy(orgId: string): OrgPolicy {
  return {
    orgId,
    require2fa: false,
    ssoEnforced: false,
    breakGlassUserId: null,
    sessionMaxAgeS: null,
    allowedMethods: [...DEFAULT_ALLOWED_METHODS],
    groupRoleMap: {},
  };
}

interface OrgPolicyDbRow {
  orgId: string;
  require2fa: boolean;
  ssoEnforced: boolean;
  breakGlassUserId: string | null;
  sessionMaxAgeS: number | null;
  allowedMethods: string[];
  groupRoleMap: Record<string, "owner" | "admin" | "member">;
  updatedAt: Date;
}

async function findPolicyRow(
  ctx: GenericEndpointContext,
  orgId: string,
): Promise<OrgPolicyDbRow | null> {
  return ctx.context.adapter.findOne<OrgPolicyDbRow>({
    model: "orgPolicy",
    where: [{ field: "orgId", value: orgId }],
  });
}

function toOrgPolicy(row: OrgPolicyDbRow | null, orgId: string): OrgPolicy {
  if (!row) return defaultPolicy(orgId);
  return {
    orgId: row.orgId,
    require2fa: row.require2fa,
    ssoEnforced: row.ssoEnforced,
    breakGlassUserId: row.breakGlassUserId ?? null,
    sessionMaxAgeS: row.sessionMaxAgeS ?? null,
    allowedMethods: row.allowedMethods,
    groupRoleMap: row.groupRoleMap,
  };
}

async function getOrgPolicy(ctx: GenericEndpointContext, orgId: string): Promise<OrgPolicy> {
  return toOrgPolicy(await findPolicyRow(ctx, orgId), orgId);
}

// --- org membership/role helpers -------------------------------------------
// Same shape as `../audit/plugin.ts`'s `requireOwnerOrAdmin` (member table,
// comma-separated `role` column) but factored around a shared
// `getMemberRoles` since this file also needs a plain-membership check (GET
// /enterprise/policy) and an arbitrary-user owner check (the break-glass
// precondition in POST /enterprise/policy/set), not just "is the caller
// owner/admin".

async function getMemberRoles(
  ctx: GenericEndpointContext,
  orgId: string,
  userId: string,
): Promise<string[]> {
  const member = await ctx.context.adapter.findOne<{ role: string }>({
    model: "member",
    where: [
      { field: "organizationId", value: orgId },
      { field: "userId", value: userId },
    ],
  });
  return member?.role.split(",").map((r) => r.trim()) ?? [];
}

async function requireOrgMember(ctx: GenericEndpointContext, orgId: string): Promise<void> {
  const userId = ctx.context.session?.user.id;
  if (!userId) throw new APIError("UNAUTHORIZED");
  const roles = await getMemberRoles(ctx, orgId, userId);
  if (roles.length === 0) {
    throw new APIError("FORBIDDEN", {
      code: "NOT_ORG_MEMBER",
      message: "You are not a member of this organization.",
    });
  }
}

async function requireOwnerOrAdmin(ctx: GenericEndpointContext, orgId: string): Promise<void> {
  const userId = ctx.context.session?.user.id;
  if (!userId) throw new APIError("UNAUTHORIZED");
  const roles = await getMemberRoles(ctx, orgId, userId);
  if (!roles.includes("owner") && !roles.includes("admin")) {
    throw new APIError("FORBIDDEN", {
      code: "NOT_ORG_ADMIN",
      message: "Owner or admin role required.",
    });
  }
}

async function isOrgOwner(
  ctx: GenericEndpointContext,
  orgId: string,
  userId: string,
): Promise<boolean> {
  const roles = await getMemberRoles(ctx, orgId, userId);
  return roles.includes("owner");
}

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
  allowedMethods: z.array(z.string()).min(1).optional(),
  groupRoleMap: z.record(z.string(), z.enum(["owner", "admin", "member"])).optional(),
});

function buildPolicyEndpoints() {
  const getPolicy = createAuthEndpoint(
    "/enterprise/policy",
    { method: "GET", use: [sessionMiddleware], query: getPolicyQuerySchema },
    async (ctx) => {
      const fullCtx = ctx as unknown as GenericEndpointContext;
      const { orgId } = ctx.query;
      await requireOrgMember(fullCtx, orgId);
      return ctx.json(await getOrgPolicy(fullCtx, orgId));
    },
  );

  const setPolicy = createAuthEndpoint(
    "/enterprise/policy/set",
    { method: "POST", use: [sessionMiddleware], body: setPolicyBodySchema },
    async (ctx) => {
      const fullCtx = ctx as unknown as GenericEndpointContext;
      const { orgId, ...patch } = ctx.body;
      // `./gate.ts`'s `GATED_PATHS` already runs `requireFeature` for this
      // path (mapped to the top `"enforce_2fa"` tier) before this handler
      // ever executes; called again here so this endpoint is self-defending
      // the same way `../audit/plugin.ts`'s audit endpoints are, independent
      // of the gate staying wired up.
      await requireFeature(fullCtx, orgId, "enforce_2fa");
      await requireOwnerOrAdmin(fullCtx, orgId);

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

// --- sign-in enforcement (controller ruling (d)) ----------------------

const SIGNIN_ENFORCEMENT_PATHS = new Set<string>([
  "/sign-in/email",
  "/sign-in/social",
  "/sign-in/magic-link",
  "/sign-in/passkey",
  "/magic-link/verify",
]);

function deriveMethod(path: string, body: { provider?: unknown } | undefined): string | null {
  switch (path) {
    case "/sign-in/email":
      return "password";
    case "/sign-in/magic-link":
    case "/magic-link/verify":
      return "magic_link";
    case "/sign-in/passkey":
      return "passkey";
    case "/sign-in/social":
      return typeof body?.provider === "string" ? body.provider : null;
    default:
      return null;
  }
}

/**
 * Resolves the email a sign-in request is *for* — straightforward for
 * `/sign-in/email`/`/sign-in/magic-link` (`body.email`); for
 * `/magic-link/verify` (a GET with a `?token=`, no email in the request)
 * best-effort via a non-destructive `findVerificationValue` read of the
 * still-pending token (never `consumeVerificationValue` — that's the real
 * endpoint's job, and consuming it here would burn the token before the
 * user's actual verification request). Returns `null` for `/sign-in/social`
 * and `/sign-in/passkey` (no email available pre-authentication) and for an
 * unresolvable/already-consumed magic-link token; per the controller ruling,
 * those cases are left to the `databaseHooks.session.create.before` backstop
 * below rather than enforced here.
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
    const verification = await ctx.context.internalAdapter
      .findVerificationValue(token)
      .catch(() => null);
    if (!verification) return null;
    try {
      const parsed = JSON.parse(verification.value) as { email?: unknown };
      return typeof parsed.email === "string" ? parsed.email : null;
    } catch {
      return null;
    }
  }
  return null;
}

async function enforceForEmail(
  ctx: GenericEndpointContext,
  email: string,
  method: string | null,
): Promise<void> {
  if (!method) return;
  const match = await findOrgByEmailDomain(ctx, email);
  if (!match) return;
  const policy = await getOrgPolicy(ctx, match.orgId);

  const targetUser = await ctx.context.internalAdapter.findUserByEmail(email);
  const isBreakGlass = !!policy.breakGlassUserId && targetUser?.user.id === policy.breakGlassUserId;

  if (policy.ssoEnforced && !isBreakGlass) {
    throw new APIError("FORBIDDEN", {
      code: "SSO_REQUIRED",
      message: "Your organization requires SSO",
    });
  }
  if (!policy.allowedMethods.includes(method)) {
    throw new APIError("FORBIDDEN", {
      code: "METHOD_NOT_ALLOWED",
      message: `Sign-in method "${method}" is not allowed for this organization.`,
    });
  }
}

function buildSignInBeforeHook() {
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
      if (!email) return; // social/passkey pre-flight, or an unresolvable magic-link token
      await enforceForEmail(fullCtx, email, deriveMethod(path, ctx.body as { provider?: unknown }));
    }),
  };
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

// --- SCIM deprovision cascade (controller ruling (f)) -------------------

const DEPROVISION_PATH = "/scim/v2/Users/:userId";
const DEPROVISION_METHODS = new Set(["PATCH", "PUT", "DELETE"]);

interface ScimPatchOperation {
  op?: unknown;
  path?: unknown;
  value?: unknown;
}

/**
 * Mirrors `@better-auth/scim`'s own PATCH `active` handling
 * (`userPatchMappings["/active"]`/`active()` in
 * `node_modules/@better-auth/scim/dist/index.mjs`): a PatchOp whose
 * (dot-or-slash, leading-slash-optional) normalized `path` is `/active`,
 * `op` is `add` or `replace` (the only ops SCIM patch application honors —
 * `remove` is a no-op for a boolean field upstream), and `value` is `false`
 * or the string `"false"`.
 */
function isScimDeactivatePatch(body: unknown): boolean {
  const operations = (body as { Operations?: ScimPatchOperation[] } | undefined)?.Operations;
  if (!Array.isArray(operations)) return false;
  return operations.some((operation) => {
    const op = typeof operation.op === "string" ? operation.op.toLowerCase() : "replace";
    if (op !== "replace" && op !== "add") return false;
    if (typeof operation.path !== "string") return false;
    const normalized =
      `/${operation.path.startsWith("/") ? operation.path.slice(1) : operation.path}`.replaceAll(
        ".",
        "/",
      );
    return normalized === "/active" && (operation.value === false || operation.value === "false");
  });
}

function buildDeprovisionAfterHook() {
  return {
    matcher: (ctx: { path?: string; request?: { method?: string } }) =>
      ctx.path === DEPROVISION_PATH &&
      !!ctx.request?.method &&
      DEPROVISION_METHODS.has(ctx.request.method),
    handler: createAuthMiddleware(async (ctx) => {
      if (isAPIError(ctx.context.returned)) return; // only cascade on a successful SCIM call

      const method = ctx.request?.method;
      const userId = (ctx.params as { userId?: string } | undefined)?.userId;
      if (!userId) return;

      const deactivated =
        method === "DELETE"
          ? true
          : method === "PUT"
            ? (ctx.body as { active?: unknown } | undefined)?.active === false
            : isScimDeactivatePatch(ctx.body);
      if (!deactivated) return;

      const fullCtx = ctx as unknown as GenericEndpointContext;
      // `@better-auth/api-key`'s `apikey` model's owner field is literally
      // named `referenceId` (`node_modules/@better-auth/api-key/dist/
      // index.mjs`'s `apiKeySchema` — "The ID of the entity that owns this
      // key (userId or organizationId based on config's `references`
      // setting)"), not `userId` as the task brief's shorthand says; no
      // `fieldName` override remaps it, so `referenceId` is also the
      // physical column name. This preset never configures `references:
      // "organization"`, so it always holds a user id.
      await fullCtx.context.adapter.deleteMany({
        model: "apikey",
        where: [{ field: "referenceId", value: userId }],
      });

      // A DELETE on this path already gets a `scim.user_deleted` audit row
      // from `../audit/plugin.ts`'s generic `hooks.after`
      // (`METHOD_ACTION_OVERRIDES`) — that's the same action this hook would
      // otherwise write, so DELETE only runs the cascade above and skips a
      // second, redundant row. PATCH/PUT deactivation has no equivalent: the
      // generic hook writes `scim.user_updated` for *any* PATCH/PUT on this
      // path (deactivating or not), which doesn't capture deactivation
      // specifically, so `scim.user_deactivated` here is additional
      // information, not a duplicate.
      if (method === "DELETE") return;

      const scimProvider = (
        fullCtx.context as unknown as {
          scimProvider?: { providerId?: string; organizationId?: string };
        }
      ).scimProvider;
      if (!scimProvider?.organizationId) return;

      await writeAudit(fullCtx, {
        orgId: scimProvider.organizationId,
        actorType: "scim",
        actorId: scimProvider.providerId ?? null,
        action: "scim.user_deactivated",
        targetType: "user",
        targetId: userId,
      });
    }),
  };
}

// --- session-creation backstop (controller ruling (d)) ------------------
//
// Set via `init()` returning `{ options: { databaseHooks } }` — the better-
// auth convention every plugin that needs a `databaseHooks` entry follows
// (verified against upstream's own `admin` plugin,
// `node_modules/better-auth/dist/plugins/admin/admin.mjs`), NOT a top-level
// `databaseHooks` key on the returned plugin object (`BetterAuthPlugin` has
// no such field). Each plugin's `init()`-returned `databaseHooks` is kept as
// its own entry in an array (`node_modules/better-auth/dist/context/
// helpers.mjs`'s `dbHooks.push({source: "plugin:<id>", hooks: ...})`), not
// shallow-merged into one object, so `admin()`'s own `session.create.before`
// (banned-user check, already in the preset ahead of `orgPolicy`) and this
// one both run in sequence rather than one clobbering the other.

function buildSessionCreateBeforeHook() {
  return async (
    session: { userId: string; expiresAt?: unknown } & Record<string, unknown>,
    ctx: GenericEndpointContext | null,
  ) => {
    if (!ctx) return;
    const user = await ctx.context.internalAdapter.findUserById(session.userId);
    if (!user?.email) return;

    const match = await findOrgByEmailDomain(ctx, user.email);
    if (!match) return;
    const policy = await getOrgPolicy(ctx, match.orgId);

    const isSsoPath = typeof ctx.path === "string" && ctx.path.startsWith("/sso/");
    const isBreakGlass = !!policy.breakGlassUserId && session.userId === policy.breakGlassUserId;
    if (policy.ssoEnforced && !isSsoPath && !isBreakGlass) {
      throw new APIError("FORBIDDEN", {
        code: "SSO_REQUIRED",
        message: "Your organization requires SSO",
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

export function orgPolicy(opts: EnterpriseOptions): BetterAuthPlugin {
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
    init() {
      return {
        options: {
          databaseHooks: {
            session: {
              create: {
                before: buildSessionCreateBeforeHook(),
              },
            },
          },
        },
      };
    },
  };
}

export { findOrgByEmailDomain };
