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

/** The slice of `EnterpriseOptions` (`../types.ts`) the method vocabulary is derived from. */
export interface MethodVocabularyOptions {
  policy?: { signInMethods?: Record<string, string> };
}

/**
 * The **full method vocabulary**: the closed set above plus every method
 * name the product declared through `policy.signInMethods` (`../types.ts`)
 * — so an org can list `email_otp` once the product maps
 * `/sign-in/email-otp` to it. De-duplicated, closed set first.
 *
 * Both the write side (`POST /enterprise/policy/set` accepts exactly these
 * values, `./plugin.ts`) and the read side (`getEffectivePolicy` decides
 * whether an org's stored list *narrows* sign-in by comparing it against
 * this vocabulary, not against the 8 built-ins alone) use it, so an org can
 * exclude a declared method without also dropping a built-in. Validation of
 * the option itself lives in `../options.ts`.
 */
export function allowedMethodValues(opts?: MethodVocabularyOptions): string[] {
  const declared = Object.values(opts?.policy?.signInMethods ?? {});
  return [...new Set<string>([...ALLOWED_METHOD_VALUES, ...declared])];
}

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

// --- effective (union-of-orgs) policy ---------------------------------------

/**
 * The policy that applies to one user across **every** org that has a claim
 * on them (`resolvePolicyOrgsForUser`, `./enforcement.ts`): the strictest
 * combination, never a single "chosen" org. Resolving to one org — and to
 * *no* org when the choice was ambiguous — is what let any member escape
 * `ssoEnforced`/`allowedMethods` by creating a second organization (F-03).
 *
 * Per field:
 * - `ssoEnforced` — OR over the orgs where the user is **not** that org's
 *   break-glass user (`sources.ssoEnforcedBy` lists them).
 * - `allowedMethods` — intersection over the same non-break-glass orgs
 *   (break-glass is the emergency password login for an SSO-only org, so an
 *   org's own `allowedMethods` never binds its own break-glass user — the
 *   same per-org exemption the single-org hook always had). An empty
 *   intersection locks the user out of every method; that is the two orgs'
 *   configuration, not a bug here.
 * - `sessionMaxAgeS` — minimum over **all** orgs (break-glass included; a
 *   session cap is a compliance control, not a sign-in gate).
 * - `require2fa` — OR over **all** orgs.
 * - `restricted` — whether any contributing org narrows sign-in at all
 *   (`ssoEnforced`, or an `allowedMethods` row that omits any value of the
 *   full method vocabulary — `allowedMethodValues(opts)`, the 8 built-ins
 *   plus every product-declared `policy.signInMethods` name); the
 *   fail-closed switch for sign-in paths that can't be classified. An org
 *   with **no** `org_policy` row never narrows anything; an org whose row
 *   lists exactly the 8 built-ins while the product declared `email_otp`
 *   *does* narrow (it excludes `email_otp`) — the allow-list is what the
 *   row says, so a row written before the product declared a method keeps
 *   excluding it until an admin lists the name.
 * - `sources` — which org contributed each constraint, for error messages
 *   and audit rows.
 *
 * `orgIds = []` yields the permissive default (no policy applies), matching
 * "free agents unchanged".
 */
export interface EffectivePolicy {
  /** The orgs considered, in the order given (de-duplicated). */
  orgIds: string[];
  ssoEnforced: boolean;
  allowedMethods: string[];
  sessionMaxAgeS: number | null;
  require2fa: boolean;
  restricted: boolean;
  /** `true` when the user is some contributing org's break-glass user. */
  breakGlass: boolean;
  sources: {
    ssoEnforcedBy: string[];
    allowedMethodsBy: string[];
    sessionMaxAgeBy: string | null;
    require2faBy: string[];
    breakGlassIn: string[];
  };
}

export async function getEffectivePolicy(
  ctx: GenericEndpointContext,
  orgIds: readonly string[],
  userId: string | null,
  opts?: MethodVocabularyOptions,
): Promise<EffectivePolicy> {
  const ids = [...new Set(orgIds)];
  const vocabulary = allowedMethodValues(opts);
  const rows = await Promise.all(ids.map((orgId) => findPolicyRow(ctx, orgId)));
  // An org with no row has never narrowed anything: it allows the *whole*
  // vocabulary (declared methods included), not merely the built-in default
  // `toOrgPolicy(null, …)` reports for the read endpoint.
  const policies = rows.map((row, i) => {
    const orgId = ids[i] as string;
    const policy = toOrgPolicy(row, orgId);
    return row ? policy : { ...policy, allowedMethods: [...vocabulary] };
  });

  const sources: EffectivePolicy["sources"] = {
    ssoEnforcedBy: [],
    allowedMethodsBy: [],
    sessionMaxAgeBy: null,
    require2faBy: [],
    breakGlassIn: [],
  };
  const methodSets: Array<Set<string>> = [];
  let sessionMaxAgeS: number | null = null;
  let require2fa = false;

  for (const policy of policies) {
    const isBreakGlass = !!userId && policy.breakGlassUserId === userId;
    if (isBreakGlass) sources.breakGlassIn.push(policy.orgId);

    if (!isBreakGlass) {
      if (policy.ssoEnforced) sources.ssoEnforcedBy.push(policy.orgId);
      const methods = new Set(policy.allowedMethods);
      if (!vocabulary.every((m) => methods.has(m))) {
        sources.allowedMethodsBy.push(policy.orgId);
      }
      methodSets.push(methods);
    }

    if (
      policy.sessionMaxAgeS != null &&
      (sessionMaxAgeS === null || policy.sessionMaxAgeS < sessionMaxAgeS)
    ) {
      sessionMaxAgeS = policy.sessionMaxAgeS;
      sources.sessionMaxAgeBy = policy.orgId;
    }
    if (policy.require2fa) {
      require2fa = true;
      sources.require2faBy.push(policy.orgId);
    }
  }

  const ssoEnforced = sources.ssoEnforcedBy.length > 0;
  // Intersection over the non-break-glass orgs, in the first org's order;
  // no contributing org at all (empty `orgIds`, or break-glass everywhere)
  // means the permissive default.
  const first = methodSets[0];
  const allowedMethods =
    first === undefined
      ? [...vocabulary]
      : [...first].filter((m) => methodSets.every((set) => set.has(m)));
  return {
    orgIds: ids,
    ssoEnforced,
    allowedMethods,
    sessionMaxAgeS,
    require2fa,
    restricted: ssoEnforced || sources.allowedMethodsBy.length > 0,
    breakGlass: sources.breakGlassIn.length > 0,
    sources,
  };
}

// --- two-factor enrolment state ----------------------------------------------

/**
 * Whether **some** organization on the deployment requires two-factor
 * authentication at all — the cheap probe the enrolment gate
 * (`./enforcement.ts`) runs before it resolves a session or a policy, so a
 * deployment with no such organization pays one small `org_policy` read per
 * request (the table holds one row per configured org) and nothing else.
 */
export async function anyOrgRequiresTwoFactor(ctx: GenericEndpointContext): Promise<boolean> {
  const row = await ctx.context.adapter.findOne<{ orgId: string }>({
    model: "orgPolicy",
    where: [{ field: "require2fa", value: true }],
  });
  return row !== null;
}

/**
 * Whether the user can enrol a second factor through upstream's
 * `/two-factor/enable`: that endpoint re-authenticates with the user's
 * password (`shouldRequirePassword`, `better-auth/dist/utils/password.mjs`),
 * so the answer is exactly what upstream's own check reads — a `credential`
 * account (`internalAdapter.findCredentialAccount`) that holds a password. A
 * user without one (an SSO- or magic-link-only account) cannot enrol here;
 * their second factor, when `require2fa` applies, is the sign-in method that
 * satisfied it (`policy.twoFactor.satisfiedBy`).
 */
export async function canEnrollTwoFactor(
  ctx: GenericEndpointContext,
  userId: string,
): Promise<boolean> {
  const account = await ctx.context.internalAdapter.findCredentialAccount(userId);
  return Boolean(account?.password);
}

export interface TwoFactorEnrollmentState {
  twoFactorEnabled: boolean;
  /**
   * `true` when the user holds a password account and could therefore enrol
   * a second factor through upstream's `/two-factor/enable` — independent of
   * whether they already have. A user without one (SSO-, magic-link-,
   * social- or passkey-only) is `false`: they cannot enrol here, and their
   * standing towards `require2fa` rests on whether their session was judged
   * under the requirement when it was created, not on enrolment.
   */
  canEnroll: boolean;
  /** `true` when the user holds a password and is not yet enrolled — the one state a `require2fa` org confines to the enrolment allow-list. */
  enrollmentPending: boolean;
}

/**
 * The user's standing towards a `require2fa` policy, read from the live
 * user row (never from a cached copy): enrolled, or able to enrol and not
 * yet enrolled (`enrollmentPending`), or unable to enrol at all (`!canEnroll`).
 * Shared by the enrolment gate, the `/get-session` annotation and the
 * `/enterprise/policy/set` precondition so the three never disagree.
 */
export async function twoFactorEnrollmentState(
  ctx: GenericEndpointContext,
  userId: string,
): Promise<TwoFactorEnrollmentState> {
  const user = (await ctx.context.internalAdapter.findUserById(userId)) as {
    twoFactorEnabled?: boolean | null;
  } | null;
  const twoFactorEnabled = user?.twoFactorEnabled === true;
  if (twoFactorEnabled) return { twoFactorEnabled, canEnroll: false, enrollmentPending: false };
  const canEnroll = await canEnrollTwoFactor(ctx, userId);
  return { twoFactorEnabled, canEnroll, enrollmentPending: canEnroll };
}

// --- two-factor requirement onset ---------------------------------------------

/**
 * Epoch milliseconds from a stored timestamp, whatever unit and type the
 * adapter hands back, or `null` when it cannot be read. Products keep these
 * columns in different units — klar's and dispatch's `session.created_at` is
 * Drizzle `mode: "timestamp"` (whole **seconds**, read back as a `Date`
 * whose milliseconds are 0), their `member.createdAt` and `org_policy.
 * updated_at` are milliseconds — so:
 *
 * - a `Date` is taken as is;
 * - a number (or numeric string) below `1e11` is seconds (`1e11` s is the
 *   year 5138; `1e11` ms is 1973), anything larger milliseconds;
 * - any other string is parsed as a date.
 */
export function timestampMs(value: unknown): number | null {
  if (value instanceof Date) {
    const ms = value.getTime();
    return Number.isFinite(ms) ? ms : null;
  }
  let numeric: number | null = null;
  if (typeof value === "number") numeric = value;
  else if (typeof value === "bigint") numeric = Number(value);
  else if (typeof value === "string" && /^\s*\d+(\.\d+)?\s*$/.test(value)) numeric = Number(value);
  if (numeric !== null) {
    if (!Number.isFinite(numeric)) return null;
    return Math.abs(numeric) < 1e11 ? numeric * 1000 : numeric;
  }
  if (typeof value === "string") {
    const parsed = Date.parse(value);
    return Number.isFinite(parsed) ? parsed : null;
  }
  return null;
}

/**
 * The latest instant a stored timestamp can stand for. A value that falls on a
 * whole second may have been truncated from anywhere inside that second (a
 * seconds column, or a `Date` read back from one), so it is widened to the
 * second's last millisecond: when the *onset* of a requirement is compared
 * against a session's creation, the doubt goes against the session.
 */
function latestInstantMs(ms: number): number {
  return ms % 1000 === 0 ? ms + 999 : ms;
}

/**
 * When `require2fa` came to apply to this user, as epoch milliseconds: the
 * latest, over the given orgs (the effective policy's `sources.require2faBy`),
 * of the org's `org_policy.updated_at` and — where the user is a member — the
 * membership's `createdAt`. A session created strictly after this instant was
 * judged under the requirement by the session-creation hook; one created at
 * or before it was not (the policy was flipped on, or edited, after it; or the
 * user joined the org after it) and is re-judged by the caller.
 *
 * Every stamp is widened to the latest instant it can stand for
 * (`latestInstantMs`), and a stamp that cannot be read at all makes the onset
 * `Infinity` — nothing predates an unknown onset's end, so no session is
 * taken to have been judged (fail closed). An org that claims the user only
 * through a verified e-mail domain, without a membership, contributes its
 * `updated_at` alone: `ssoProvider` records no timestamp for when a domain was
 * verified.
 */
export async function twoFactorRequirementOnsetMs(
  ctx: GenericEndpointContext,
  userId: string,
  orgIds: readonly string[],
): Promise<number> {
  let onset = -Infinity;
  for (const orgId of new Set(orgIds)) {
    const row = await findPolicyRow(ctx, orgId);
    const updatedAt = timestampMs(row?.updatedAt);
    if (updatedAt === null) return Infinity;
    onset = Math.max(onset, latestInstantMs(updatedAt));

    const member = await ctx.context.adapter.findOne<{ createdAt?: unknown }>({
      model: "member",
      where: [
        { field: "organizationId", value: orgId },
        { field: "userId", value: userId },
      ],
    });
    if (member) {
      const joinedAt = timestampMs(member.createdAt);
      if (joinedAt === null) return Infinity;
      onset = Math.max(onset, latestInstantMs(joinedAt));
    }
  }
  return onset;
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

/**
 * A caller who holds no `member` row at all always gets `NOT_ORG_MEMBER`,
 * never `NOT_ORG_ADMIN` — one answer for "this org is none of your business",
 * whatever role the endpoint wanted (M-07: the codes must not let an
 * outsider tell orgs apart). Role-based refusals for *actual* members keep
 * their specific code, which is what the portal renders.
 */
function notAMemberOr(roles: string[], code: string, message: string): APIError {
  return roles.length === 0
    ? new APIError("FORBIDDEN", {
        code: "NOT_ORG_MEMBER",
        message: "You are not a member of this organization.",
      })
    : new APIError("FORBIDDEN", { code, message });
}

export async function requireOwnerOrAdmin(
  ctx: GenericEndpointContext,
  orgId: string,
): Promise<void> {
  const userId = ctx.context.session?.user.id;
  if (!userId) throw new APIError("UNAUTHORIZED");
  const roles = await getMemberRoles(ctx, orgId, userId);
  if (!roles.includes("owner") && !roles.includes("admin")) {
    throw notAMemberOr(roles, "NOT_ORG_ADMIN", "Owner or admin role required.");
  }
}

/**
 * Owner-only gate, for the two knobs that can mint owners (M-01):
 * `groupRoleMap`/`breakGlassUserId` writes and SCIM token creation.
 * `requireOwnerOrAdmin` is too weak for those — an admin who can point a
 * group at `owner` and then mint a SCIM token can promote themselves.
 */
export async function requireOwner(ctx: GenericEndpointContext, orgId: string): Promise<void> {
  const userId = ctx.context.session?.user.id;
  if (!userId) throw new APIError("UNAUTHORIZED");
  const roles = await getMemberRoles(ctx, orgId, userId);
  if (!roles.includes("owner")) {
    throw notAMemberOr(roles, "NOT_ORG_OWNER", "Owner role required.");
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
 * Upstream caps one `findMany` page at
 * `advanced.database.defaultFindManyLimit ?? 100` rows — an *implicit* cap
 * when the call passes no `limit` — so the membership scan pages in that
 * unit (`offset` stepping), sorted by `id` for a stable walk.
 */
const MEMBER_PAGE_SIZE = 100;

/**
 * Default `max` for `memberOrgIds`. The preset leaves upstream's
 * `organizationLimit` unset (unlimited self-serve orgs — a product decision,
 * see `docs/security.md`), so a user's membership count is attacker-chosen;
 * 5000 is far past any legitimate count and not a number worth reaching.
 */
export const MEMBERSHIP_SCAN_MAX = 5000;

/**
 * All `organizationId`s a user belongs to, via a raw `member` scan — used by
 * `./enforcement.ts`'s `resolvePolicyOrgsForUser` to collect every org with
 * a claim on the user, without assuming a particular adapter's
 * `distinct`/`groupBy` support.
 *
 * Paginated, and failing **closed** past `max`: an unpaginated `findMany`
 * silently returned only the first 100 rows, so a member who first joined
 * (or self-created) 100+ other orgs had their restricted org's `member` row
 * dropped from the scan and escaped its `ssoEnforced`/`allowedMethods`/
 * `sessionMaxAgeS` (F-03, second cut). More than `max` memberships is a
 * 500 `POLICY_MEMBERSHIP_SCAN_OVERFLOW` (and a `logger.error`) rather than a
 * truncated set that could hide an org with a claim on the user.
 */
export async function memberOrgIds(
  ctx: GenericEndpointContext,
  userId: string,
  options: { max?: number } = {},
): Promise<string[]> {
  const max = options.max ?? MEMBERSHIP_SCAN_MAX;
  const orgIds: string[] = [];
  let offset = 0;
  for (;;) {
    const page = await ctx.context.adapter.findMany<{ organizationId: string }>({
      model: "member",
      where: [{ field: "userId", value: userId }],
      limit: MEMBER_PAGE_SIZE,
      offset,
      sortBy: { field: "id", direction: "asc" },
    });
    for (const row of page) orgIds.push(row.organizationId);
    if (orgIds.length > max) {
      ctx.context.logger.error(
        `enterprise-policy: user ${userId} holds more than ${max} memberships — refusing the policy resolution rather than truncating it (POLICY_MEMBERSHIP_SCAN_OVERFLOW)`,
      );
      throw new APIError("INTERNAL_SERVER_ERROR", {
        code: "POLICY_MEMBERSHIP_SCAN_OVERFLOW",
        message: "Too many organization memberships to resolve the sign-in policy safely.",
      });
    }
    if (page.length < MEMBER_PAGE_SIZE) return orgIds;
    offset += page.length;
  }
}
