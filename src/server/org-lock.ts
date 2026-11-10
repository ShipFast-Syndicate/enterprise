// Alpha Bros enterprise layer — staff-only organization creation and metadata
// write lock (spike security finding 1, second half).
//
// The entitlement table (`./entitlement-store.ts`) keeps entitlements out of
// reach of a tenant. This plugin closes the other half of the finding: with
// `organization.metadata` open, the organization's own owner can write any
// JSON into it through `/organization/update` (and at creation through
// `/organization/create`), which a product that reads plans, quotas or flags
// from `metadata` then trusts. Two options, both off by default:
//
// - `organization.creation: "staff-only" | (ctx) => boolean` — who may create
//   an organization at all;
// - `organization.metadata: "staff-only"` — who may send a `metadata` field to
//   `/organization/create` or `/organization/update`.
//
// Both are `hooks.before` on the two routes, in a plugin of their own
// (`enterprise-org-lock`) rather than options of the preset's `organization()`
// entry: a product that replaces that entry with its own `organization()`
// (nomi, klar) keeps the lock, and upstream's `allowUserToCreateOrganization`
// cannot express either rule (it refuses staff too, and knows nothing of
// metadata). Mounted by `enterprisePreset` only when an option departs from
// its default, so a deployment that sets neither has the same plugin list as
// before.
//
// Who passes: platform staff — the staff test of `setEntitlements`
// (`isPlatformStaff`: a stored, non-banned user whose `role` holds one of
// `entitlements.staffRoles`), and never from an impersonation session — and
// any server-only call (`auth.api.*` with neither a `Request` nor headers: the
// code that calls it is the product's own). Everyone else is refused `403`
// and the refusal is audited (`organization.write_refused`), except a refusal
// for a caller with no organization chain to record it in (logged at `warn`).
// A `creation` function that throws is a refusal too (fail closed).
//
// Covered routes: exactly `/organization/create` (body `metadata`) and
// `/organization/update` (body `data.metadata`), matched by exact path as the
// gate does. A metadata-writing route or alias added by a future better-auth
// is NOT covered: re-check `crud-org` on every upgrade of better-auth.

import type { BetterAuthPlugin, GenericEndpointContext } from "better-auth";
import { APIError, createAuthMiddleware, getIP, getSessionFromCtx } from "better-auth/api";
import { writeAudit } from "./audit/chain";
import { auditUserAgent } from "./audit/bounds";
import { sessionActor } from "./audit/plugin";
import { isPlatformStaff } from "./entitlement-store";
import { isOrgId } from "./org-id";
import { getMemberRoles } from "./policy/store";
import type { EnterpriseOptions } from "./types";

export const ORG_LOCK_PLUGIN_ID = "enterprise-org-lock";

export const ORG_CREATION_STAFF_ONLY = "ORG_CREATION_STAFF_ONLY";
export const ORG_METADATA_STAFF_ONLY = "ORG_METADATA_STAFF_ONLY";

/** Audit action of a refused write (`organization.write_refused`). */
export const ORG_WRITE_REFUSED_ACTION = "organization.write_refused";

const CREATE_PATH = "/organization/create";
const UPDATE_PATH = "/organization/update";

/** How many of a caller's organizations a refused creation is recorded in. */
const MAX_AUDITED_ORGS = 20;

/** Whether either option departs from its default — whether the preset mounts the plugin. */
export function orgLockConfigured(opts: EnterpriseOptions): boolean {
  const { creation, metadata } = opts.organization ?? {};
  return (creation !== undefined && creation !== "self-service") || metadata === "staff-only";
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

/** Whether the request carries a `metadata` field to write (`undefined` is absent; `null` is a write). */
function writesMetadata(path: string, body: unknown): boolean {
  const record = asRecord(body);
  if (!record) return false;
  if (path === CREATE_PATH) return record.metadata !== undefined;
  return asRecord(record.data)?.metadata !== undefined;
}

function refusal(code: string, message: string): APIError {
  return new APIError("FORBIDDEN", { code, message });
}

interface RefusalFacts {
  path: string;
  code: string;
  /** The organization the request names (update only), when it is an id. */
  targetOrgId: string | null;
}

/**
 * Appends `organization.write_refused` to the chain of every organization the
 * refusal concerns *and* the caller belongs to: the one an update names, or
 * (for a creation, which has no organization yet) the caller's own
 * organizations. An organization id taken from the request body is never
 * written to without a membership row, so a caller cannot append rows to a
 * chain they are not part of. Never throws: a failure to audit must not turn
 * a refusal into a success.
 */
async function auditWriteRefused(
  ctx: GenericEndpointContext,
  session: NonNullable<Awaited<ReturnType<typeof getSessionFromCtx>>>,
  facts: RefusalFacts,
): Promise<void> {
  try {
    const userId = session.user.id;
    let orgIds: string[];
    if (facts.targetOrgId) {
      const roles = await getMemberRoles(ctx, facts.targetOrgId, userId);
      orgIds = roles.length > 0 ? [facts.targetOrgId] : [];
    } else {
      const rows = await ctx.context.adapter.findMany<{ organizationId: string }>({
        model: "member",
        where: [{ field: "userId", value: userId }],
        limit: MAX_AUDITED_ORGS,
      });
      orgIds = [...new Set(rows.map((row) => row.organizationId).filter(isOrgId))];
    }
    if (orgIds.length === 0) {
      ctx.context.logger.warn(
        `enterprise-org-lock: ${facts.code} on ${facts.path} for user ${userId}: no organization chain to record it in`,
      );
      return;
    }
    const actor = sessionActor(session);
    const request = ctx.request;
    const ip = request ? (getIP(request, ctx.context.options) ?? null) : null;
    const userAgent = auditUserAgent(request?.headers.get("user-agent"));
    for (const orgId of orgIds) {
      await writeAudit(ctx, {
        orgId,
        actorType: actor.actorType,
        actorId: actor.actorId,
        action: ORG_WRITE_REFUSED_ACTION,
        targetType: "organization",
        targetId: facts.targetOrgId ?? null,
        ip,
        userAgent,
        metadata: { ...actor.metadata, code: facts.code, path: facts.path },
      });
    }
  } catch (err) {
    ctx.context.logger.error(
      `enterprise-org-lock: failed to write ${ORG_WRITE_REFUSED_ACTION} (${facts.code}) on ${facts.path}`,
      err,
    );
  }
}

export function orgWriteLock(opts: EnterpriseOptions) {
  const creation = opts.organization?.creation ?? "self-service";
  const metadataLocked = opts.organization?.metadata === "staff-only";

  return {
    id: ORG_LOCK_PLUGIN_ID,
    options: opts,
    hooks: {
      before: [
        {
          matcher: (ctx) =>
            (ctx.path === CREATE_PATH && (creation !== "self-service" || metadataLocked)) ||
            (ctx.path === UPDATE_PATH && metadataLocked),
          handler: createAuthMiddleware(async (ctx) => {
            const path = ctx.path as string;
            // A server-only call (`auth.api.*` with neither a `Request` nor
            // headers) is the product's own code acting — never refused.
            if (!ctx.request && !ctx.headers) return;

            const fullCtx = ctx as unknown as GenericEndpointContext;
            const session = await getSessionFromCtx(fullCtx);
            // Anonymous: upstream answers 401 on both routes.
            if (!session) return;

            const impersonated = Boolean(
              (session.session as { impersonatedBy?: unknown }).impersonatedBy,
            );
            const staff =
              !impersonated && (await isPlatformStaff(ctx.context.adapter, opts, session.user.id));
            if (staff) return;

            let code: string | null = null;
            let message = "";
            if (path === CREATE_PATH && creation !== "self-service") {
              let allowed = false;
              if (typeof creation === "function") {
                try {
                  allowed = (await creation({ user: session.user, body: ctx.body })) === true;
                } catch (err) {
                  // Fail closed: a predicate that throws is a refusal (audited,
                  // 403), not an unaudited 500.
                  ctx.context.logger.error(
                    "enterprise-org-lock: organization.creation predicate threw; refusing",
                    err,
                  );
                }
              }
              if (!allowed) {
                code = ORG_CREATION_STAFF_ONLY;
                message = "Only platform staff can create an organization.";
              }
            }
            if (code === null && metadataLocked && writesMetadata(path, ctx.body)) {
              code = ORG_METADATA_STAFF_ONLY;
              message = "Only platform staff can write an organization's metadata.";
            }
            if (code === null) return;

            const body = asRecord(ctx.body);
            const named = path === UPDATE_PATH ? body?.organizationId : undefined;
            const active = (session.session as { activeOrganizationId?: unknown })
              .activeOrganizationId;
            const targetOrgId =
              path === UPDATE_PATH
                ? isOrgId(named)
                  ? named
                  : isOrgId(active)
                    ? active
                    : null
                : null;
            await auditWriteRefused(fullCtx, session, { path, code, targetOrgId });
            throw refusal(code, message);
          }),
        },
      ],
    },
  } satisfies BetterAuthPlugin;
}
