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
// One shared implementation of the owner/admin check (it used to be
// duplicated here), so the `NOT_ORG_MEMBER` vs `NOT_ORG_ADMIN` distinction
// M-07 depends on is made in exactly one place.
import { requireOwnerOrAdmin } from "../policy/store";
import type { EnterpriseOptions } from "../types";
import {
  compactChain,
  verifyChain,
  writeAudit,
  type AuditInput,
  type AuditRow,
  type CompactionResult,
} from "./chain";

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

// Where the `hooks.before` below stashes the caller's pre-request session for
// the matching `hooks.after` to read (see that hook's comment). Kept on the
// per-request `ctx.context` object (better-auth builds a fresh one per
// dispatch — `node_modules/better-auth/dist/api/dispatch.mjs`'s
// `internalContext`), never on anything shared between requests.
const AUDIT_ACTOR_KEY = "enterpriseAuditActor";

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

async function isOrgMember(
  ctx: GenericEndpointContext,
  orgId: string,
  userId: string,
): Promise<boolean> {
  const member = await ctx.context.adapter.findOne<{ id: string }>({
    model: "member",
    where: [
      { field: "organizationId", value: orgId },
      { field: "userId", value: userId },
    ],
  });
  return !!member;
}

/**
 * Which org's chain this request appends to — **never** a caller-supplied id
 * on trust (C-01). Before the fix, `body.organizationId`/`body.orgId`/
 * `query.orgId` were taken verbatim, so any signed-up user could append rows
 * to any other tenant's chain with `POST /sign-out?orgId=<victim>` (and
 * attacker-controlled `ip`/`user_agent`), with `verify` still reporting
 * `ok:true` — the forgeries being cryptographically indistinguishable from
 * genuine entries.
 *
 * The resolution order is now strictly "most trustworthy source first", and
 * every remaining caller-supplied value has to be *proved*:
 *
 * 1. **SCIM bearer** — `ctx.context.scimProvider` is set by SCIM bearer
 *    authentication from the token row itself; a SCIM request may only ever
 *    write to its own token's org, whatever its body says.
 * 2. **SSO callbacks** — the org comes from the `ssoProvider` row named by
 *    the `:providerId` route param (server-side state, set at registration).
 * 3. **Session** — the session's own `activeOrganizationId` is trusted as-is
 *    (better-auth only ever sets it through `/organization/set-active` /
 *    `/organization/create`, both of which check membership). Any *other*
 *    org id in the body/query is honoured only if the resolved actor holds a
 *    `member` row in it.
 *
 * Anything else resolves to `null`, and the caller (`hooks.after` below)
 * skips the write with a warning rather than guessing.
 */
async function resolveOrgId(
  ctx: GenericEndpointContext,
  session: { session: object; user?: { id?: string } } | null,
): Promise<string | null> {
  const scimProvider = (ctx.context as unknown as { scimProvider?: { organizationId?: string } })
    .scimProvider;
  if (scimProvider?.organizationId) return scimProvider.organizationId;

  const providerOrgId = await resolveSsoProviderOrgId(ctx, ctx.path ?? "");
  if (providerOrgId) return providerOrgId;

  const body = ctx.body as { organizationId?: string; orgId?: string } | undefined;
  const query = ctx.query as { orgId?: string } | undefined;
  const activeOrganizationId =
    (session?.session as { activeOrganizationId?: string } | undefined)?.activeOrganizationId ??
    null;
  const claimed = body?.organizationId ?? body?.orgId ?? query?.orgId ?? null;

  if (!claimed) return activeOrganizationId;
  if (claimed === activeOrganizationId) return claimed;

  const actorId = session?.user?.id;
  if (!actorId) return null;
  return (await isOrgMember(ctx, claimed, actorId)) ? claimed : null;
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

/**
 * Applies `audit.retentionDays` to one org's chain as archival compaction
 * (C-02) — `compactChain` deletes the expired prefix *and* leaves the signed
 * anchor row `verifyChain` re-anchors on, so retention no longer flips the
 * compliance verdict to "tampered" during normal operation.
 *
 * Still invoked from `GET /enterprise/audit/list` (which is already
 * owner/admin-only and feature-gated), deliberately and explicitly: on a
 * deployment with no scheduler, the admin opening the log is the only
 * reliable trigger. `POST /enterprise/audit/compact` exposes the same
 * operation to operators who want to run it on purpose.
 */
async function compactExpired(
  ctx: GenericEndpointContext,
  orgId: string,
  opts: EnterpriseOptions,
): Promise<CompactionResult | null> {
  const retentionDays = opts.audit?.retentionDays ?? 365;
  const cutoff = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000);
  return compactChain(ctx, orgId, cutoff);
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

// Cells whose first character makes Excel/Sheets/LibreOffice treat the value
// as a formula rather than text (M-02). An attacker only needs a field that
// lands in the export verbatim — `user_agent` is the obvious one — to get
// `=cmd|'/C calc'!A0` executed on the machine of the admin who opens the
// CSV they just handed their auditor.
const CSV_FORMULA_PREFIX = /^[=+\-@\t\r]/;

/**
 * RFC 4180 quoting *plus* formula-injection neutralisation (M-02): a leading
 * `= + - @ TAB CR` is prefixed with a single quote, which every spreadsheet
 * treats as "the rest of this cell is literal text". Applied to every cell,
 * `metadata` JSON included.
 */
function csvField(value: unknown): string {
  const raw = value === null || value === undefined ? "" : String(value);
  const s = CSV_FORMULA_PREFIX.test(raw) ? `'${raw}` : raw;
  return /["\n\r,]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

/** `csvField` under test (`test/security/m02-csv-injection.test.ts`) — not part of the public API. */
export const toCsvRowForTest = csvField;

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

const compactBodySchema = z.object({
  orgId: z.string(),
});

/** Default ceiling on one `/enterprise/audit/export` call (M-05); override with `audit.exportMaxRows`. */
export const DEFAULT_EXPORT_ROW_CAP = 100_000;

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
  const exportCap = opts.audit?.exportMaxRows ?? DEFAULT_EXPORT_ROW_CAP;

  const listEndpoint = createAuthEndpoint(
    "/enterprise/audit/list",
    { method: "GET", use: [sessionMiddleware], query: listQuerySchema },
    async (ctx) => {
      const { orgId, action, actorId, from, to, cursor } = ctx.query;
      const limit = ctx.query.limit ?? 50;
      // Membership/role first, entitlement second (M-07): a non-member must
      // never reach `resolveEntitlements` with an org id they made up, since
      // the two distinct 403s would otherwise be a tenant/plan oracle.
      await requireOwnerOrAdmin(ctx as unknown as GenericEndpointContext, orgId);
      await requireFeature(ctx as unknown as GenericEndpointContext, orgId, "audit_log");
      await compactExpired(ctx as unknown as GenericEndpointContext, orgId, opts);

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
      await requireOwnerOrAdmin(ctx as unknown as GenericEndpointContext, orgId);
      await requireFeature(ctx as unknown as GenericEndpointContext, orgId, "audit_log");

      const rows = await ctx.context.adapter.findMany<AuditEventRow>({
        model: "auditEvent",
        where: buildWhere(orgId, { from, to }),
        sortBy: { field: "seq", direction: "asc" },
        // Bounded (M-05): the whole result set is joined into one in-memory
        // string, so an org with millions of rows would otherwise materialise
        // the table twice per click. One row over the cap is fetched purely
        // to detect "there is more" without a second count query.
        limit: exportCap + 1,
      });
      if (rows.length > exportCap) {
        throw new APIError("PAYLOAD_TOO_LARGE", {
          code: "AUDIT_EXPORT_TOO_LARGE",
          message: `This export exceeds ${exportCap} rows. Narrow it with the "from"/"to" query parameters and export in ranges.`,
          limit: exportCap,
        });
      }

      const csv = [CSV_HEADER, ...rows.map(toCsvRow)].join("\r\n");
      const range = from === undefined && to === undefined ? "" : `-${from ?? ""}-${to ?? ""}`;
      // `orgId` is caller-supplied (any org they admin), so it is sanitised
      // before it is interpolated into a header value (L-05) rather than
      // trusted to be free of `"`/CR/LF.
      const filename = `audit-${orgId.replace(/[^A-Za-z0-9_-]/g, "_")}${range}.csv`;
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
      await requireOwnerOrAdmin(ctx as unknown as GenericEndpointContext, orgId);
      await requireFeature(ctx as unknown as GenericEndpointContext, orgId, "audit_log");

      const rows = await ctx.context.adapter.findMany<AuditEventRow>({
        model: "auditEvent",
        where: [{ field: "orgId", value: orgId }],
        sortBy: { field: "seq", direction: "asc" },
      });

      const result = await verifyChain(rows.map(toAuditRow));
      return ctx.json(result);
    },
  );

  // Retention on purpose rather than as a side effect of a read (C-02):
  // owner/admin only, feature-gated like every other audit endpoint, and
  // reporting exactly what it removed.
  const compactEndpoint = createAuthEndpoint(
    "/enterprise/audit/compact",
    { method: "POST", use: [sessionMiddleware], body: compactBodySchema },
    async (ctx) => {
      const { orgId } = ctx.body;
      await requireOwnerOrAdmin(ctx as unknown as GenericEndpointContext, orgId);
      await requireFeature(ctx as unknown as GenericEndpointContext, orgId, "audit_log");

      const result = await compactExpired(ctx as unknown as GenericEndpointContext, orgId, opts);
      return ctx.json({
        compacted: result !== null,
        compactedThroughSeq: result?.compactedThroughSeq ?? null,
        compactedCount: result?.compactedCount ?? 0,
      });
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
      enterpriseAuditCompact: compactEndpoint,
    },
    hooks: {
      // The actor is resolved *before* the endpoint runs as well as after
      // (C-01). `getSessionFromCtx` re-reads the inbound cookie against the
      // database, so on `/sign-out` — which has just deleted that session
      // row — the after-hook can no longer tell who the caller was, and
      // without a proven actor the org check below can only skip the write.
      // Capturing the session on the way in keeps sign-out audited *and*
      // keeps the proof requirement: this value comes from the caller's own
      // cookie, never from their body or query string.
      before: [
        {
          matcher: (ctx) => !!ctx.path && auditEntryFor(ctx.path, ctx.request?.method) !== null,
          handler: createAuthMiddleware(async (ctx) => {
            const session = await getSessionFromCtx(ctx as unknown as GenericEndpointContext).catch(
              () => null,
            );
            if (session) {
              (ctx.context as unknown as Record<string, unknown>)[AUDIT_ACTOR_KEY] = session;
            }
          }),
        },
      ],
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
              ((ctx.context as unknown as Record<string, unknown>)[AUDIT_ACTOR_KEY] as {
                session: object;
                user: { id: string };
              } | null) ??
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
