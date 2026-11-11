// Alpha Bros enterprise layer — the staff-managed entitlement store.
//
// `entitlements: { store: "table" }` (`./types.ts`) resolves an organization's
// features from the `org_entitlement` table instead of a product callback.
// The table exists because the obvious alternative — a flag in
// `organization.metadata` — is writable by the organization's own owner
// through better-auth's `/organization/update`, so an owner could grant itself
// SSO or SCIM. Nothing a tenant can call writes this table: the only writers
// are `setEntitlements()` (server code) and `POST /enterprise/entitlements/set`
// (`./enterprise-api/entitlements.ts`), and both require a platform staff
// user (`user.role` in `entitlements.staffRoles`, default `["admin"]`, the
// `admin()` plugin's own mechanism) — never an impersonation session.
//
// This module is the leaf: table reads and writes, the staff test, and the
// audited write both entry points share. It imports no endpoint code, so
// `./entitlements.ts` (the resolver) can depend on it.

import type { AuthContext } from "better-auth";
import { APIError } from "better-auth/api";
import { runWithTransaction } from "@better-auth/core/context";
import { writeAudit, type AuditActorType } from "./audit/chain";
import { isOrgId } from "./org-id";
import { FEATURES, type EnterpriseOptions, type Feature } from "./types";

const ENTERPRISE_GATE_PLUGIN_ID = "enterprise-gate";

export const ENTITLEMENT_CHANGED_ACTION = "entitlement.changed";
export const ENTITLEMENT_SET_PATH = "/enterprise/entitlements/set";

const DEFAULT_STAFF_ROLES = ["admin"];

/** The `EnterpriseOptions` the `enterprise-gate` plugin carries, read off an auth context. */
export function enterpriseOptionsOfContext(context: {
  options: { plugins?: Array<{ id: string }> };
}): EnterpriseOptions {
  const plugin = context.options.plugins?.find((p) => p.id === ENTERPRISE_GATE_PLUGIN_ID) as
    { options?: EnterpriseOptions } | undefined;
  if (!plugin?.options) {
    throw new Error(
      "requireFeature() requires the enterpriseGate() plugin to be registered on this auth instance.",
    );
  }
  return plugin.options;
}

export function usesEntitlementTable(opts: EnterpriseOptions): boolean {
  return opts.entitlements?.store === "table";
}

/** The features of `raw` that are in the closed vocabulary, deduplicated, in `FEATURES` order. */
export function normalizeFeatures(raw: unknown): Feature[] {
  let list: unknown = raw;
  if (typeof list === "string") {
    try {
      list = JSON.parse(list);
    } catch {
      return [];
    }
  }
  if (!Array.isArray(list)) return [];
  const present = new Set<unknown>(list);
  return FEATURES.filter((feature) => present.has(feature));
}

type Adapter = AuthContext["adapter"];

interface EntitlementRow {
  id: string;
  orgId: string;
  features: unknown;
}

/**
 * The features the `org_entitlement` row of `orgId` grants — none without a
 * row, and values outside `FEATURES` are dropped. A query error propagates
 * (the request fails; nothing is granted), wrapped with the likeliest cause —
 * the optional migration was never applied — so the 500 is actionable.
 */
export async function readEntitlementRow(adapter: Adapter, orgId: string): Promise<Feature[]> {
  let row: EntitlementRow | null;
  try {
    row = await adapter.findOne<EntitlementRow>({
      model: "orgEntitlement",
      where: [{ field: "orgId", value: orgId }],
    });
  } catch (cause) {
    throw new Error(
      'Could not read the org_entitlement table (`entitlements: { store: "table" }`). ' +
        "If it does not exist yet, apply the optional migration: `ab-enterprise migrate --entitlements` " +
        "(SQLite/libSQL, drizzle folder) or `applyMigrationPg(client, { entitlements: true })` (Postgres). " +
        "Nothing is granted while it cannot be read.",
      { cause },
    );
  }
  return row ? normalizeFeatures(row.features) : [];
}

interface StaffUserRow {
  id: string;
  role?: string | null;
  banned?: boolean | null;
  banExpires?: Date | number | string | null;
}

function isBanned(user: StaffUserRow): boolean {
  if (!user.banned) return false;
  if (user.banExpires === null || user.banExpires === undefined) return true;
  return new Date(user.banExpires).getTime() > Date.now();
}

/**
 * Whether `userId` is platform staff: a stored user whose `role` — a
 * comma-separated list, as the `admin()` plugin writes it — holds one of the
 * configured staff roles, and who is not banned. Read from the database, not
 * from a session snapshot, so a demoted or banned staff user loses the
 * ability at once.
 */
export async function isPlatformStaff(
  adapter: Adapter,
  opts: EnterpriseOptions,
  userId: string,
): Promise<boolean> {
  const user = await adapter.findOne<StaffUserRow>({
    model: "user",
    where: [{ field: "id", value: userId }],
  });
  if (!user || isBanned(user)) return false;
  const staffRoles = opts.entitlements?.staffRoles ?? DEFAULT_STAFF_ROLES;
  return (user.role ?? "")
    .split(",")
    .map((role) => role.trim())
    .some((role) => staffRoles.includes(role));
}

export function notPlatformStaffError(): APIError {
  return new APIError("FORBIDDEN", {
    code: "NOT_PLATFORM_STAFF",
    message: "Only platform staff can change an organization's entitlements.",
  });
}

export function entitlementStoreDisabledError(): APIError {
  return new APIError("NOT_FOUND", {
    code: "ENTITLEMENT_STORE_DISABLED",
    message: 'The entitlement table is not enabled (set `entitlements: { store: "table" }`).',
  });
}

export interface EntitlementChange {
  /** The audit actor: the staff user (never an impersonation). */
  actor: { actorType: AuditActorType; actorId: string; metadata?: Record<string, unknown> };
  ip?: string | null;
  userAgent?: string | null;
}

/**
 * Writes `features` as the organization's whole entitlement set and appends
 * `entitlement.changed` to the organization's audit chain, in one transaction
 * — a change with no audit row does not commit. The caller has already
 * authorized the actor.
 */
export async function writeEntitlements(
  context: AuthContext,
  orgId: string,
  features: readonly Feature[],
  change: EntitlementChange,
): Promise<{ features: Feature[]; previousFeatures: Feature[] }> {
  const next = normalizeFeatures(features);
  const adapter = context.adapter;
  const organization = await adapter.findOne<{ id: string }>({
    model: "organization",
    where: [{ field: "id", value: orgId }],
  });
  if (!organization) {
    throw new APIError("NOT_FOUND", {
      code: "ORG_NOT_FOUND",
      message: "No such organization.",
    });
  }
  return runWithTransaction(adapter, async () => {
    const existing = await adapter.findOne<EntitlementRow>({
      model: "orgEntitlement",
      where: [{ field: "orgId", value: orgId }],
    });
    const previousFeatures = existing ? normalizeFeatures(existing.features) : [];
    const data = { features: next, updatedAt: new Date(), updatedBy: change.actor.actorId };
    if (existing) {
      await adapter.update({
        model: "orgEntitlement",
        where: [{ field: "orgId", value: orgId }],
        update: data,
      });
    } else {
      await adapter.create({ model: "orgEntitlement", data: { orgId, ...data } });
    }
    await writeAudit(
      { context },
      {
        orgId,
        actorType: change.actor.actorType,
        actorId: change.actor.actorId,
        action: ENTITLEMENT_CHANGED_ACTION,
        targetType: "org_entitlement",
        targetId: orgId,
        ip: change.ip ?? null,
        userAgent: change.userAgent ?? null,
        metadata: { ...change.actor.metadata, features: next, previousFeatures },
      },
    );
    return { features: next, previousFeatures };
  });
}

/** The identity `setEntitlements` acts for: a platform staff user's id. */
export interface EntitlementActor {
  userId: string;
}

/**
 * Server API: sets the organization's entitlements, audited as
 * `entitlement.changed`.
 *
 * `auth` is the better-auth instance built with `entitlements: { store:
 * "table" }`. `actor.userId` must be a stored, non-banned platform staff user
 * (`entitlements.staffRoles`); anything else is refused — a billing webhook
 * that syncs plans uses a dedicated staff service user. `features` replaces
 * the whole set (`[]` revokes everything) and must come from `FEATURES`.
 * Resolves with the stored set and the one it replaced.
 */
export async function setEntitlements(
  auth: { $context: PromiseLike<unknown> },
  orgId: string,
  features: readonly Feature[],
  actor: EntitlementActor,
): Promise<{ features: Feature[]; previousFeatures: Feature[] }> {
  // `$context` is typed per auth instance (its own option set); the layer
  // only relies on the surface every instance shares.
  const context = (await auth.$context) as AuthContext;
  const opts = enterpriseOptionsOfContext(context);
  if (!usesEntitlementTable(opts)) throw entitlementStoreDisabledError();
  if (!isOrgId(orgId)) {
    throw new APIError("BAD_REQUEST", {
      code: "ORG_ID_INVALID",
      message: "An organization id must be a non-empty string.",
    });
  }
  const unknown = features.filter((feature) => !FEATURES.includes(feature));
  if (unknown.length > 0) {
    throw new APIError("BAD_REQUEST", {
      code: "UNKNOWN_FEATURE",
      message: `Unknown feature(s): ${unknown.map(String).join(", ")}.`,
    });
  }
  if (
    !actor ||
    !isOrgId(actor.userId) ||
    !(await isPlatformStaff(context.adapter, opts, actor.userId))
  ) {
    throw notPlatformStaffError();
  }
  return writeEntitlements(context, orgId, features, {
    actor: { actorType: "user", actorId: actor.userId },
  });
}
