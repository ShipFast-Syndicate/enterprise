// Alpha Bros enterprise layer — audit log plugin.
//
// `auditLog(opts)` (id `enterprise-audit`) does three things:
//
// 1. Declares the `auditEvent` model (`audit_event` table) with the same
//    camelCase-field -> snake_case-column mapping the SQL migration
//    (`src/schema/sql/0001_enterprise.sql`) and drizzle table
//    (`src/schema/index.ts`) use, so `ctx.context.adapter` works against it
//    on any better-auth adapter, not just drizzle.
// 2. A `hooks.after` on `AUDITED_PATHS` that turns select upstream/
//    enterprise-gate endpoint calls into `writeAudit` (`./chain.ts`) calls,
//    filling actor/target from `ctx.context.returned` and the caller's
//    session (re-resolved via `getSessionFromCtx` — see the note on
//    `resolveActorId` below for why).
// 3. Three endpoints — `/enterprise/audit/list`, `/enterprise/audit/export`,
//    `/enterprise/audit/verify` — gated by `sessionMiddleware` + an
//    owner/admin membership check + `requireFeature(ctx, orgId, "audit_log")`.
//
// Path matching for (2): `ctx.path` inside a hook handler is the *route
// pattern* an endpoint was registered with (`internalContext.path =
// endpoint.path` in better-auth's `dispatchAuthEndpoint`; verified against
// the pinned better-auth@1.6.33/@better-auth/sso@1.6.33/@better-auth/
// scim@1.6.33 sources), e.g. `"/sso/callback/:providerId"` — never the
// concrete resolved path with real param values substituted in. `AUDITED_PATHS`
// is therefore keyed by those exact patterns and matched with a plain `in`
// check; no pattern-to-regex matching is needed. One correction from the
// task brief's illustrative sketch: `@better-auth/scim`'s SCIM Users
// update/get/delete endpoints are registered at `/scim/v2/Users/:userId`
// (not `/scim/v2/Users/:id` as the brief's shorthand wrote) — confirmed by
// grepping `node_modules/@better-auth/scim/dist/index.mjs` — so that's the
// literal key used here; using the brief's literal string would silently
// never match. `test/server/audit-plugin.test.ts`'s "parameterised path
// matching" describe block proves both `ctx.path` being the pattern and
// this corrected key.

import type { BetterAuthPlugin, GenericEndpointContext } from "better-auth";
import type { Where } from "@better-auth/core/db/adapter";
import {
  APIError,
  createAuthEndpoint,
  createAuthMiddleware,
  getIp,
  getSessionFromCtx,
  isAPIError,
  sessionMiddleware,
} from "better-auth/api";
import * as z from "zod";
import { requireFeature } from "../entitlements";
import type { EnterpriseOptions } from "../types";
import { verifyChain, writeAudit, type AuditInput, type AuditRow } from "./chain";

export const AUDITED_PATHS: Record<string, { action: string; targetType: string }> = {
  "/sign-in/email": { action: "auth.sign_in", targetType: "user" },
  "/sign-in/social": { action: "auth.sign_in", targetType: "user" },
  "/sign-in/magic-link": { action: "auth.magic_link_requested", targetType: "user" },
  "/magic-link/verify": { action: "auth.sign_in", targetType: "user" },
  "/sso/callback/:providerId": { action: "auth.sso_sign_in", targetType: "user" },
  "/sso/saml2/sp/acs/:providerId": { action: "auth.sso_sign_in", targetType: "user" },
  "/sign-out": { action: "auth.sign_out", targetType: "user" },
  "/organization/invite-member": { action: "member.invited", targetType: "member" },
  "/organization/remove-member": { action: "member.removed", targetType: "member" },
  "/organization/update-member-role": { action: "member.role_changed", targetType: "member" },
  "/organization/accept-invitation": { action: "member.joined", targetType: "member" },
  "/sso/register": { action: "sso.provider_registered", targetType: "sso_provider" },
  "/sso/verify-domain": { action: "sso.domain_verified", targetType: "sso_provider" },
  "/scim/generate-token": { action: "scim.token_created", targetType: "scim_provider" },
  "/scim/delete-provider-connection": { action: "scim.token_revoked", targetType: "scim_provider" },
  "/scim/v2/Users": { action: "scim.user_created", targetType: "user" },
  // Real upstream pattern (`:userId`), not the brief's illustrative `:id` — see header comment.
  "/scim/v2/Users/:userId": { action: "scim.user_updated", targetType: "user" },
  "/api-key/create": { action: "api_key.created", targetType: "api_key" },
  "/api-key/delete": { action: "api_key.revoked", targetType: "api_key" },
  "/enterprise/policy/set": { action: "policy.updated", targetType: "org_policy" },
};

// Endpoints an unauthenticated caller can hit (no session yet at hook time,
// or the session existed only to be torn down): writeAudit failures here are
// logged and swallowed rather than turned into a 500, per ruling (e) — an
// audit-log hiccup must never block sign-in/out.
const SIGN_IN_PATHS = new Set<string>([
  "/sign-in/email",
  "/sign-in/social",
  "/sign-in/magic-link",
  "/magic-link/verify",
  "/sso/callback/:providerId",
  "/sso/saml2/sp/acs/:providerId",
  "/sign-out",
]);

function extractId(value: unknown): string | null {
  if (value && typeof value === "object" && "id" in value) {
    const id = (value as { id?: unknown }).id;
    return typeof id === "string" ? id : null;
  }
  return null;
}

// Best-effort, generic actor/target resolution shared by every audited
// path: most better-auth endpoints (`invite-member`, `remove-member`,
// `api-key/create`, SCIM user create/update, ...) return the
// created/mutated resource directly with a top-level `id`, so `extractId`
// on `ctx.context.returned` covers them. Sign-in endpoints are the
// exception (they return `{ user, token, ... }`, no top-level `id`), so a
// `.user`/`.inviterId`/`.userId` fallback and — for sign-out, which returns
// `{ success: true }` and has no resource id at all — `session` round out
// the fallback chain. The one path this is exhaustively verified against
// (`test/server/audit-plugin.test.ts`) is `/organization/invite-member`,
// per the brief's test list; the rest follow the same shape by convention
// but aren't individually asserted in v0.1.
//
// `session` is passed in already resolved (via `getSessionFromCtx`, same as
// `./gate.ts`'s before-hook) rather than read off `ctx.context.session`:
// that field is populated by an endpoint's own `use: [sessionMiddleware]`
// chain, which — verified empirically against the pinned better-auth@1.6.33
// (`test/server/audit-plugin.test.ts`'s invite-member test failed
// `actorId`/session assertions until this was made explicit) — does not
// reliably survive into a plugin-level `hooks.after` handler the way
// `ctx.context.returned`/`ctx.context.scimProvider` do.
function resolveActorId(
  returned: unknown,
  session: { user: { id: string } } | null,
): string | null {
  const asRecord = returned as
    { user?: unknown; inviterId?: unknown; userId?: unknown } | undefined;
  const inviterId = typeof asRecord?.inviterId === "string" ? asRecord.inviterId : null;
  const userId = typeof asRecord?.userId === "string" ? asRecord.userId : null;
  return extractId(asRecord?.user) ?? inviterId ?? userId ?? session?.user.id ?? null;
}

function resolveTargetId(returned: unknown, actorId: string | null): string | null {
  const asRecord = returned as
    { user?: unknown; member?: unknown; invitation?: unknown } | undefined;
  return (
    extractId(returned) ??
    extractId(asRecord?.user) ??
    extractId(asRecord?.member) ??
    extractId(asRecord?.invitation) ??
    actorId
  );
}

function resolveOrgId(
  ctx: GenericEndpointContext,
  session: { session: object } | null,
): string | null {
  const body = ctx.body as { organizationId?: string; orgId?: string } | undefined;
  const query = ctx.query as { orgId?: string } | undefined;
  const activeOrganizationId = (session?.session as { activeOrganizationId?: string } | undefined)
    ?.activeOrganizationId;
  const scimProvider = (ctx.context as unknown as { scimProvider?: { organizationId?: string } })
    .scimProvider;
  return (
    body?.organizationId ??
    body?.orgId ??
    query?.orgId ??
    activeOrganizationId ??
    scimProvider?.organizationId ??
    null
  );
}

async function requireOwnerOrAdmin(ctx: GenericEndpointContext, orgId: string): Promise<void> {
  const userId = ctx.context.session?.user.id;
  if (!userId) {
    throw new APIError("UNAUTHORIZED");
  }
  const member = await ctx.context.adapter.findOne<{ role: string }>({
    model: "member",
    where: [
      { field: "organizationId", value: orgId },
      { field: "userId", value: userId },
    ],
  });
  const roles = member?.role.split(",").map((r) => r.trim()) ?? [];
  if (!roles.includes("owner") && !roles.includes("admin")) {
    throw new APIError("FORBIDDEN", {
      code: "NOT_ORG_ADMIN",
      message: "Owner or admin role required.",
    });
  }
}

async function purgeExpired(
  ctx: GenericEndpointContext,
  orgId: string,
  opts: EnterpriseOptions,
): Promise<void> {
  const retentionDays = opts.audit?.retentionDays ?? 365;
  const cutoff = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000);
  await ctx.context.adapter.deleteMany({
    model: "auditEvent",
    where: [
      { field: "orgId", value: orgId },
      { field: "createdAt", value: cutoff, operator: "lt" },
    ],
  });
}

interface AuditEventRow {
  id: string;
  orgId: string;
  seq: number;
  actorType: string;
  actorId: string | null;
  action: string;
  targetType: string;
  targetId: string | null;
  ip: string | null;
  userAgent: string | null;
  metadata: Record<string, unknown>;
  createdAt: Date;
  prevHash: string;
  hash: string;
}

function toEpochMs(value: Date | number): number {
  return value instanceof Date ? value.getTime() : value;
}

function toAuditRow(row: AuditEventRow): AuditRow {
  return { ...row, createdAt: toEpochMs(row.createdAt) };
}

function serializeRow(row: AuditEventRow) {
  return { ...row, createdAt: new Date(row.createdAt).toISOString() };
}

const CSV_HEADER =
  "id,seq,created_at,actor_type,actor_id,action,target_type,target_id,ip,user_agent,metadata,prev_hash,hash";

function csvField(value: unknown): string {
  const s = value === null || value === undefined ? "" : String(value);
  return /["\n\r,]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function toCsvRow(row: AuditEventRow): string {
  return [
    row.id,
    row.seq,
    new Date(row.createdAt).toISOString(),
    row.actorType,
    row.actorId ?? "",
    row.action,
    row.targetType,
    row.targetId ?? "",
    row.ip ?? "",
    row.userAgent ?? "",
    JSON.stringify(row.metadata ?? {}),
    row.prevHash,
    row.hash,
  ]
    .map(csvField)
    .join(",");
}

const listQuerySchema = z.object({
  orgId: z.string(),
  action: z.string().optional(),
  actorId: z.string().optional(),
  from: z.coerce.number().optional(),
  to: z.coerce.number().optional(),
  cursor: z.string().optional(),
  limit: z.coerce.number().int().min(1).max(200).optional(),
});

const exportQuerySchema = z.object({
  orgId: z.string(),
  from: z.coerce.number().optional(),
  to: z.coerce.number().optional(),
});

const verifyQuerySchema = z.object({
  orgId: z.string(),
});

function buildWhere(
  orgId: string,
  filters: { action?: string; actorId?: string; from?: number; to?: number },
): Where[] {
  const where: Where[] = [{ field: "orgId", value: orgId }];
  if (filters.action) where.push({ field: "action", value: filters.action });
  if (filters.actorId) where.push({ field: "actorId", value: filters.actorId });
  if (filters.from !== undefined)
    where.push({ field: "createdAt", value: new Date(filters.from), operator: "gte" });
  if (filters.to !== undefined)
    where.push({ field: "createdAt", value: new Date(filters.to), operator: "lte" });
  return where;
}

export function auditLog(opts: EnterpriseOptions): BetterAuthPlugin {
  const listEndpoint = createAuthEndpoint(
    "/enterprise/audit/list",
    { method: "GET", use: [sessionMiddleware], query: listQuerySchema },
    async (ctx) => {
      const { orgId, action, actorId, from, to, cursor } = ctx.query;
      const limit = ctx.query.limit ?? 50;
      await requireFeature(ctx as unknown as GenericEndpointContext, orgId, "audit_log");
      await requireOwnerOrAdmin(ctx as unknown as GenericEndpointContext, orgId);
      await purgeExpired(ctx as unknown as GenericEndpointContext, orgId, opts);

      const where = buildWhere(orgId, { action, actorId, from, to });
      if (cursor) where.push({ field: "seq", value: Number(cursor), operator: "lt" });

      const rows = await ctx.context.adapter.findMany<AuditEventRow>({
        model: "auditEvent",
        where,
        sortBy: { field: "seq", direction: "desc" },
        limit: limit + 1,
      });
      const hasMore = rows.length > limit;
      const items = hasMore ? rows.slice(0, limit) : rows;
      const nextCursor = hasMore ? String(items[items.length - 1]!.seq) : null;

      return ctx.json({ items: items.map(serializeRow), nextCursor });
    },
  );

  const exportEndpoint = createAuthEndpoint(
    "/enterprise/audit/export",
    { method: "GET", use: [sessionMiddleware], query: exportQuerySchema },
    async (ctx) => {
      const { orgId, from, to } = ctx.query;
      await requireFeature(ctx as unknown as GenericEndpointContext, orgId, "audit_log");
      await requireOwnerOrAdmin(ctx as unknown as GenericEndpointContext, orgId);

      const rows = await ctx.context.adapter.findMany<AuditEventRow>({
        model: "auditEvent",
        where: buildWhere(orgId, { from, to }),
        sortBy: { field: "seq", direction: "asc" },
      });

      const csv = [CSV_HEADER, ...rows.map(toCsvRow)].join("\r\n");
      const filename = `audit-${orgId}-${from ?? ""}-${to ?? ""}.csv`;
      return new Response(csv, {
        headers: {
          "content-type": "text/csv",
          "content-disposition": `attachment; filename="${filename}"`,
        },
      });
    },
  );

  const verifyEndpoint = createAuthEndpoint(
    "/enterprise/audit/verify",
    { method: "GET", use: [sessionMiddleware], query: verifyQuerySchema },
    async (ctx) => {
      const { orgId } = ctx.query;
      await requireFeature(ctx as unknown as GenericEndpointContext, orgId, "audit_log");
      await requireOwnerOrAdmin(ctx as unknown as GenericEndpointContext, orgId);

      const rows = await ctx.context.adapter.findMany<AuditEventRow>({
        model: "auditEvent",
        where: [{ field: "orgId", value: orgId }],
        sortBy: { field: "seq", direction: "asc" },
      });

      const result = await verifyChain(rows.map(toAuditRow));
      return ctx.json(result);
    },
  );

  return {
    id: "enterprise-audit",
    schema: {
      auditEvent: {
        modelName: "audit_event",
        fields: {
          orgId: { type: "string", required: true, fieldName: "org_id" },
          seq: { type: "number", required: true, fieldName: "seq" },
          actorType: { type: "string", required: true, fieldName: "actor_type" },
          actorId: { type: "string", required: false, fieldName: "actor_id" },
          action: { type: "string", required: true, fieldName: "action" },
          targetType: { type: "string", required: true, fieldName: "target_type" },
          targetId: { type: "string", required: false, fieldName: "target_id" },
          ip: { type: "string", required: false, fieldName: "ip" },
          userAgent: { type: "string", required: false, fieldName: "user_agent" },
          metadata: { type: "json", required: true, fieldName: "metadata" },
          createdAt: { type: "date", required: true, fieldName: "created_at" },
          prevHash: { type: "string", required: true, fieldName: "prev_hash" },
          hash: { type: "string", required: true, fieldName: "hash" },
        },
      },
    },
    endpoints: {
      enterpriseAuditList: listEndpoint,
      enterpriseAuditExport: exportEndpoint,
      enterpriseAuditVerify: verifyEndpoint,
    },
    hooks: {
      after: [
        {
          matcher: (ctx) => !!ctx.path && ctx.path in AUDITED_PATHS,
          handler: createAuthMiddleware(async (ctx) => {
            const entry = AUDITED_PATHS[ctx.path as string];
            if (!entry) return;

            const returned = ctx.context.returned;
            if (isAPIError(returned)) return; // only audit successful calls

            const fullCtx = ctx as unknown as GenericEndpointContext;
            const session = await getSessionFromCtx(fullCtx).catch(() => null);
            const orgId = resolveOrgId(fullCtx, session);
            if (!orgId) {
              ctx.context.logger.warn(
                `enterprise-audit: no organization id resolvable for ${ctx.path}; skipping audit write`,
              );
              return;
            }

            const scimProvider = (ctx.context as unknown as { scimProvider?: unknown })
              .scimProvider;
            const actorId = resolveActorId(returned, session);
            const input: AuditInput = {
              orgId,
              actorType: scimProvider ? "scim" : "user",
              actorId,
              action: entry.action,
              targetType: entry.targetType,
              targetId: resolveTargetId(returned, actorId),
              ip: ctx.request ? (getIp(ctx.request, ctx.context.options) ?? null) : null,
              userAgent: ctx.request?.headers.get("user-agent") ?? null,
              metadata: {},
            };

            try {
              await writeAudit(fullCtx, input);
            } catch (err) {
              if (SIGN_IN_PATHS.has(ctx.path as string)) {
                ctx.context.logger.error("enterprise-audit: failed to write audit row", err);
                return;
              }
              throw new APIError("INTERNAL_SERVER_ERROR", { code: "AUDIT_WRITE_FAILED" });
            }
          }),
        },
      ],
    },
  };
}
