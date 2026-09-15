// Alpha Bros enterprise layer — org policy data layer.
//
// A leaf module (imports nothing from `./enforcement`/`./deprovision`/
// `./plugin`, so nothing in this package can form an import cycle through
// it): the `org_policy` row shape, defaults, read/write-adjacent helpers,
// and the org-membership/role checks both `./plugin.ts`'s endpoints and
// `./enforcement.ts`'s hooks need.
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
// override for it — there is no physical column to alias it to anyway. The
// plugin's own `schema.orgPolicy` declaration (which is what makes the
// table's field list — and hence this file's `id`-less contract — real)
// lives in `./plugin.ts`, next to where it's registered.

import type { GenericEndpointContext } from "better-auth";
import { APIError } from "better-auth/api";

export interface OrgPolicy {
  orgId: string;
  require2fa: boolean;
  ssoEnforced: boolean;
  breakGlassUserId: string | null;
  sessionMaxAgeS: number | null;
  allowedMethods: string[];
  groupRoleMap: Record<string, "owner" | "admin" | "member">;
}

// The closed set of sign-in methods `allowedMethods` may name: the 4
// mechanisms this preset's plugins expose (`password` via core
// `emailAndPassword`, `magic_link`/`sso`/`passkey` via their respective
// plugins) plus the 4 social provider ids `../preset.ts`'s header comment
// and `DEFAULT_ALLOWED_METHODS` below already assumed — validated at
// `POST /enterprise/policy/set` (`./plugin.ts`) so a typo can't silently
// lock an org out of every sign-in method. Order matches the SQL
// migration's `allowed_methods` column default exactly (`defaultPolicy`
// below returns this literal array), not the order the controller ruling
// happened to list the set in.
export const ALLOWED_METHOD_VALUES = [
  "sso",
  "magic_link",
  "google",
  "github",
  "linkedin",
  "microsoft",
  "password",
  "passkey",
] as const;

function defaultPolicy(orgId: string): OrgPolicy {
  return {
    orgId,
    require2fa: false,
    ssoEnforced: false,
    breakGlassUserId: null,
    sessionMaxAgeS: null,
    allowedMethods: [...ALLOWED_METHOD_VALUES],
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

export async function findPolicyRow(
  ctx: GenericEndpointContext,
  orgId: string,
): Promise<OrgPolicyDbRow | null> {
  return ctx.context.adapter.findOne<OrgPolicyDbRow>({
    model: "orgPolicy",
    where: [{ field: "orgId", value: orgId }],
  });
}

export function toOrgPolicy(row: OrgPolicyDbRow | null, orgId: string): OrgPolicy {
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

export async function getOrgPolicy(ctx: GenericEndpointContext, orgId: string): Promise<OrgPolicy> {
  return toOrgPolicy(await findPolicyRow(ctx, orgId), orgId);
}

// --- org membership/role helpers -----------------------------------------

export async function getMemberRoles(
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

export async function requireOrgMember(ctx: GenericEndpointContext, orgId: string): Promise<void> {
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

export async function requireOwnerOrAdmin(
  ctx: GenericEndpointContext,
  orgId: string,
): Promise<void> {
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

export async function isOrgOwner(
  ctx: GenericEndpointContext,
  orgId: string,
  userId: string,
): Promise<boolean> {
  const roles = await getMemberRoles(ctx, orgId, userId);
  return roles.includes("owner");
}

/**
 * All `organizationId`s a user belongs to, via a raw `member` scan — used by
 * `./enforcement.ts`'s `resolvePolicyOrgForUser` to find "the user's single
 * org" without assuming a particular adapter's `distinct`/`groupBy` support.
 */
export async function memberOrgIds(ctx: GenericEndpointContext, userId: string): Promise<string[]> {
  const rows = await ctx.context.adapter.findMany<{ organizationId: string }>({
    model: "member",
    where: [{ field: "userId", value: userId }],
  });
  return rows.map((r) => r.organizationId);
}
