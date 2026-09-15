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

export const AUDITED_PATHS: Record<
  string,
  { action: string; targetType: string; methods?: string[] }
> = {
  "/sign-in/email": { action: "auth.sign_in", targetType: "user" },
  "/sign-in/social": { action: "auth.sign_in", targetType: "user" },
  "/sign-in/magic-link": { action: "auth.magic_link_requested", targetType: "user" },
  "/magic-link/verify": { action: "auth.sign_in", targetType: "user" },
  // The action recorded here is the *successful*-sign-in one; the
  // `hooks.after` handler below overrides both `action`/`targetType` at
  // write time to `auth.sso_sign_in_failed`/`sso_provider` when the request
  // didn't actually create a session (see `isSsoSignInSuccess` and its call
  // site) — both paths redirect on *every* outcome (success and failure
  // alike), so the static entry here can't distinguish them on its own.
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
  // "/scim/v2/Users" and "/scim/v2/Users/:userId" are each shared by several
  // SCIM endpoints at different HTTP methods (list vs. create; get/put/patch
  // vs. delete) — `methods` restricts a path entry to only the mutating ones
  // (list/get are reads, never audited); DELETE on the `:userId` path needs
  // a *different* action than its PUT/PATCH default, so it's handled via
  // `METHOD_ACTION_OVERRIDES` below rather than `methods` alone.
  "/scim/v2/Users": { action: "scim.user_created", targetType: "user", methods: ["POST"] },
  // Real upstream pattern (`:userId`), not the brief's illustrative `:id` — see header comment.
  "/scim/v2/Users/:userId": {
    action: "scim.user_updated",
    targetType: "user",
    methods: ["PUT", "PATCH"],
  },
  "/api-key/create": { action: "api_key.created", targetType: "api_key" },
  "/api-key/delete": { action: "api_key.revoked", targetType: "api_key" },
  "/enterprise/policy/set": { action: "policy.updated", targetType: "org_policy" },
};

// `../enterprise-api/plugin.ts` (Task 7) deliberately has NO entries here
// for its own `/enterprise/sso/register`, `/enterprise/scim/tokens/create`,
// `/enterprise/scim/tokens/revoke` paths, even though each one performs
// exactly the mutating action the matching upstream entry above already
// describes (`sso.provider_registered`/`sso_provider`,
// `scim.token_created`/`scim_provider`, `scim.token_revoked`/
// `scim_provider`). Those wrapper endpoints forward the *real* request
// through this same auth instance's own dispatch pipeline (`../enterprise-
// api/forward.ts`'s `forwardToAuth`, via `better-auth/api`'s `router` — not
// a plain internal function call) to `/sso/register`/`/scim/generate-token`/
// `/scim/delete-provider-connection`, which already run through this exact
// `hooks.after` and get audited by the entries above. Adding a second entry
// for the wrapper's own path would audit the same action twice (confirmed
// empirically: a wrapper-path entry plus the upstream entry both firing,
// vs. only the upstream one firing once forwarding is the *only* audit
// trigger — see `forward.ts`'s header comment for the full trace).

// Per-method action overrides for a path already in `AUDITED_PATHS`, for the
// rare case where the action genuinely depends on the HTTP method rather
// than just whether the path is audited at all (`methods` above covers
// that). Currently only SCIM user deletion, which shares
// `/scim/v2/Users/:userId` with the PUT/PATCH update endpoints.
const METHOD_ACTION_OVERRIDES: Record<
  string,
  Record<string, { action: string; targetType: string }>
> = {
  "/scim/v2/Users/:userId": {
    DELETE: { action: "scim.user_deleted", targetType: "user" },
  },
};

// Resolves the `{action, targetType}` to audit for a request, or `null` if
// it shouldn't be audited at all — either the path isn't in `AUDITED_PATHS`,
// or it is but `methods` excludes this request's HTTP method (e.g. a GET
// read on a path whose mutating siblings share the same route pattern).
function auditEntryFor(
  path: string,
  method: string | undefined,
): { action: string; targetType: string } | null {
  const override = method ? METHOD_ACTION_OVERRIDES[path]?.[method] : undefined;
  if (override) return override;
  const entry = AUDITED_PATHS[path];
  if (!entry) return null;
  if (entry.methods && (!method || !entry.methods.includes(method))) return null;
  return { action: entry.action, targetType: entry.targetType };
}

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

function resolveTargetId(
  returned: unknown,
  routeParamId: string | null,
  actorId: string | null,
): string | null {
  const asRecord = returned as
    { user?: unknown; member?: unknown; invitation?: unknown } | undefined;
  return (
    extractId(returned) ??
    extractId(asRecord?.user) ??
    extractId(asRecord?.member) ??
    extractId(asRecord?.invitation) ??
    routeParamId ??
    actorId
  );
}

// A route param naming the resource a parameterised AUDITED_PATHS entry
// acts on — e.g. SCIM user delete (`/scim/v2/Users/:userId`) returns no
// body (204, no content) to extract an id from, so its target id has to
// come from the URL instead.
function resolveRouteParamId(ctx: GenericEndpointContext): string | null {
  const params = ctx.params as Record<string, string | undefined> | undefined;
  return params?.userId ?? params?.providerId ?? null;
}

// `/sso/callback/:providerId`/`/sso/saml2/sp/acs/:providerId` (Task 8) share
// this path-prefix test for two unrelated reasons: (1) `resolveOrgId` below
// needs it because these callbacks carry no `organizationId` of their own in
// body/query, and (2) the `hooks.after` handler needs it to know when to
// apply the success/failure action split (see `isSsoSignInSuccess`). Both
// patterns are matched with `startsWith` rather than an exact `in` check —
// unlike `AUDITED_PATHS`'s own lookup — because `resolveRouteParamId`/this
// prefix test also has to work against a *concrete* resolved path
// (`/sso/callback/okta`), not only the registered pattern; see
// `./enforcement.ts`'s header comment for the identical ambiguity.
const SSO_CALLBACK_PATH_PREFIXES = ["/sso/callback/", "/sso/saml2/sp/acs"];

function isSsoCallbackPath(path: string): boolean {
  return SSO_CALLBACK_PATH_PREFIXES.some((prefix) => path.startsWith(prefix));
}

// The org this audit entry belongs to is the one the *provider itself* is
// bound to (`ssoProvider.organizationId`, set at `/sso/register` time),
// resolved via the `providerId` route param both patterns share with the
// generic `resolveRouteParamId` helper below — the caller isn't
// authenticated yet when the request starts, and a freshly created session
// has no `activeOrganizationId` set on creation either (only
// `/organization/set-active`/`/organization/create` do that), so neither of
// `resolveOrgId`'s other signals can find it.
async function resolveSsoProviderOrgId(
  ctx: GenericEndpointContext,
  path: string,
): Promise<string | null> {
  if (!isSsoCallbackPath(path)) return null;
  const providerId = resolveRouteParamId(ctx);
  if (!providerId) return null;
  const provider = await ctx.context.adapter.findOne<{ organizationId: string | null }>({
    model: "ssoProvider",
    where: [{ field: "providerId", value: providerId }],
  });
  return provider?.organizationId ?? null;
}

async function resolveOrgId(
  ctx: GenericEndpointContext,
  session: { session: object } | null,
): Promise<string | null> {
  const body = ctx.body as { organizationId?: string; orgId?: string } | undefined;
  const query = ctx.query as { orgId?: string } | undefined;
  const activeOrganizationId = (session?.session as { activeOrganizationId?: string } | undefined)
    ?.activeOrganizationId;
  const scimProvider = (ctx.context as unknown as { scimProvider?: { organizationId?: string } })
    .scimProvider;
  const direct =
    body?.organizationId ??
    body?.orgId ??
    query?.orgId ??
    activeOrganizationId ??
    scimProvider?.organizationId ??
    null;
  if (direct) return direct;
  return resolveSsoProviderOrgId(ctx, ctx.path ?? "");
}

// Whether an SSO callback actually created a session — the one reliable
// success/failure signal for these two paths, since both `processSAMLResponse`
// and `handleOIDCCallback` (`@better-auth/sso@1.6.33`) finish via
// `throw ctx.redirect(...)` on *every* outcome, success included
// (`ctx.redirect` is itself `new APIError("FOUND", ...)`,
// `node_modules/better-call/dist/error.mjs` — see the header comment on the
// `newSession` fallback below for the full trace). A session is only ever
// created just before that final redirect, via `setSessionCookie(ctx,
// {session, user})`, which synchronously sets `ctx.context.newSession`
// (`context.setNewSession`, `node_modules/better-auth/dist/cookies/
// index.mjs`) — so its presence is a stronger signal than trying to parse
// the redirect target itself (a successful redirect's target is caller
// -supplied `callbackURL`/`idpInitiatedCallbackUrl`, which is free-form and
// not guaranteed to omit an `error` key of its own).
function isSsoSignInSuccess(ctx: { context: unknown }): boolean {
  return !!(ctx.context as { newSession?: unknown }).newSession;
}

// The `error` query param off a failed callback's redirect `Location`
// header, for `auth.sso_sign_in_failed`'s `metadata.error`. Only
// `ctx.redirect(url)` populates `.headers` with a real `Headers` instance
// (`headers.set("location", url)`, then `new APIError("FOUND", void 0,
// headers)`) — a plain `new APIError("BAD_REQUEST", {...})` thrown directly
// (no `redirect`) defaults `headers` to a plain `{}` object with no `.get`,
// hence the `instanceof Headers` guard.
function extractRedirectError(returned: unknown): string | null {
  if (!isAPIError(returned)) return null;
  const headers = (returned as { headers?: unknown }).headers;
  if (!(headers instanceof Headers)) return null;
  const location = headers.get("location");
  if (!location) return null;
  try {
    return new URL(location, "http://localhost").searchParams.get("error");
  } catch {
    return null;
  }
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

// No explicit `: BetterAuthPlugin` return-type annotation (client task-9 fix
// round 1) — see `../enterprise-api/plugin.ts`'s identical comment on
// `enterpriseApi` for why. `satisfies BetterAuthPlugin` below still
// contextually types every nested closure here (`matcher`/`handler`, same
// as an annotation would — the whole reason `satisfies` exists) while
// keeping literal endpoint `path`s intact in `ReturnType<typeof auditLog>`.
export function auditLog(opts: EnterpriseOptions) {
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
      const range = from === undefined && to === undefined ? "" : `-${from ?? ""}-${to ?? ""}`;
      const filename = `audit-${orgId}${range}.csv`;
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
          matcher: (ctx) => !!ctx.path && auditEntryFor(ctx.path, ctx.request?.method) !== null,
          handler: createAuthMiddleware(async (ctx) => {
            const path = ctx.path as string;
            const entry = auditEntryFor(path, ctx.request?.method);
            if (!entry) return;

            const returned = ctx.context.returned;
            const ssoCallback = isSsoCallbackPath(path);
            // Every other audited path returns its normal JSON/Response
            // shape on success and only ever produces an `APIError` on a
            // genuine failure — `isAPIError` alone is the right "did this
            // fail" test for them, same as before Task 8. The two SSO
            // callback paths are the sole exception (see
            // `isSsoSignInSuccess`'s header comment): they route success
            // *and* failure through `ctx.redirect(...)`, itself an
            // `APIError`, so they're excluded from this check and handled
            // by the success/failure branch below instead.
            if (!ssoCallback && isAPIError(returned)) return;

            const fullCtx = ctx as unknown as GenericEndpointContext;
            // `getSessionFromCtx` re-derives the session from the *inbound*
            // request's cookies (`getSession()` reads `ctx.headers`) — it
            // never sees a session this same request just created. Both SSO
            // callback paths (Task 8) sign the caller in and redirect within
            // one request, so for them `ctx.context.session` is still
            // whatever it was on the way in (typically `null`, anonymous)
            // while the fresh session lives only in `ctx.context.newSession`
            // (set synchronously by `setSessionCookie` -> `context.
            // setNewSession`, `node_modules/better-auth/dist/cookies/
            // index.mjs`). Falling back to it covers exactly that case
            // without changing behavior for every other audited path (whose
            // endpoints don't create a session mid-request).
            const session =
              (await getSessionFromCtx(fullCtx).catch(() => null)) ??
              (
                ctx.context as unknown as {
                  newSession: { session: object; user: { id: string } } | null;
                }
              ).newSession;
            const orgId = await resolveOrgId(fullCtx, session);
            if (!orgId) {
              ctx.context.logger.warn(
                `enterprise-audit: no organization id resolvable for ${path}; skipping audit write`,
              );
              return;
            }

            // A failed SSO sign-in (tampered/wrong-key SAML response, the
            // SCIM-required JIT gate, an unknown provider, ...) is audited
            // as its own `auth.sso_sign_in_failed` action rather than either
            // silently dropped or mis-recorded as `auth.sso_sign_in` with a
            // fabricated actor — a null-actor "successful" sign-in row would
            // both under-report real attacks in the log and be
            // indistinguishable from a data-integrity bug.
            const ssoFailed = ssoCallback && !isSsoSignInSuccess(ctx);
            const action = ssoFailed ? "auth.sso_sign_in_failed" : entry.action;
            const targetType = ssoFailed ? "sso_provider" : entry.targetType;

            const scimProvider = (ctx.context as unknown as { scimProvider?: unknown })
              .scimProvider;
            const actorId = ssoFailed ? null : resolveActorId(returned, session);
            const input: AuditInput = {
              orgId,
              actorType: ssoFailed ? "system" : scimProvider ? "scim" : "user",
              actorId,
              action,
              targetType,
              targetId: ssoFailed
                ? resolveRouteParamId(fullCtx)
                : resolveTargetId(returned, resolveRouteParamId(fullCtx), actorId),
              ip: ctx.request ? (getIp(ctx.request, ctx.context.options) ?? null) : null,
              userAgent: ctx.request?.headers.get("user-agent") ?? null,
              metadata: ssoFailed ? { error: extractRedirectError(returned) } : {},
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
  } satisfies BetterAuthPlugin;
}
