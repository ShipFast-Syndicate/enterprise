// Alpha Bros enterprise layer — audit log plugin.
//
// `auditLog(opts)` (id `enterprise-audit`) does four things:
//
// 1. Declares the `auditEvent` model (`audit_event` table) with the same
//    camelCase-field -> snake_case-column mapping the SQL migration
//    (`src/schema/sql/0001_enterprise.sql`) and drizzle table
//    (`src/schema/index.ts`) use, so `ctx.context.adapter` works against it
//    on any better-auth adapter, not just drizzle.
// 2. `hooks.before`/`hooks.after` on the route table in `./routes.ts`
//    (`AUDITED_PATHS`): the before-hook captures what the endpoint is about
//    to destroy or change (the caller's session, the provider's org, the
//    target user's orgs, the acted-on team's/invitation's org); the after-hook writes one
//    row per organization in the entry's `scope`, with the actor taken from
//    the session first (never from the response), impersonation made
//    explicit (`actorType: "impersonated"`, `metadata.impersonatedBy`).
//    A second after-hook covers every *other* path: a request that minted a
//    session is audited as `auth.sign_in`, one that ended in a policy
//    refusal as `auth.sign_in_refused`, whatever plugin serves it.
// 3. `databaseHooks` (via `init`) that note, on the request's audit stash,
//    whom a session or user creation was *for* — so a refusal thrown by a
//    later hook (`../policy/*`) is attributed to that user and their orgs.
// 4. Endpoints — `/enterprise/audit/list|export|verify|head` and
//    `POST /enterprise/audit/compact` — gated by `sessionMiddleware` + an
//    owner/admin membership check + `requireFeature(ctx, orgId,
//    "audit_log")`.
//
// Path matching: `ctx.path` inside a hook handler is the *route pattern* an
// endpoint was registered with (`internalContext.path = endpoint.path` in
// better-auth's `dispatchAuthEndpoint`), e.g. `"/sso/callback/:providerId"`
// — never the concrete resolved path. `AUDITED_PATHS` is keyed by those
// exact patterns and matched with a plain lookup. `@better-auth/scim`'s SCIM
// Users update/get/delete endpoints are registered at
// `/scim/v2/Users/:userId` (not `:id`); `test/server/audit-plugin.test.ts`
// pins both facts.
//
// Organization resolution never takes a caller-supplied id on trust (C-01):
// see `AuditScope` in `./routes.ts`. A `?orgId=` on the request is ignored
// everywhere except the two endpoints that themselves require the caller to
// be an owner/admin of exactly that org (`/enterprise/policy/set`, and the
// export, which audits itself). An organization endpoint's row goes to the
// org of the resource it acted on, read from that resource
// (`RESOURCE_ORG_SOURCES`) — never from an org id the caller named.

import type { BetterAuthPlugin, GenericEndpointContext } from "better-auth";
import type { Where } from "@better-auth/core/db/adapter";
import {
  APIError,
  createAuthEndpoint,
  createAuthMiddleware,
  getIP,
  getSessionFromCtx,
  isAPIError,
  sessionMiddleware,
} from "better-auth/api";
import * as z from "zod";
import { requireFeature } from "../entitlements";
import { isOrgId, orgIdSchema } from "../org-id";
// One shared implementation of the owner/admin check (it used to be
// duplicated here), so the `NOT_ORG_MEMBER` vs `NOT_ORG_ADMIN` distinction
// M-07 depends on is made in exactly one place.
import { requireOwnerOrAdmin } from "../policy/store";
import {
  classifySessionCreate,
  resolveMagicLinkEmail,
  resolvePolicyOrgsForUser,
} from "../policy/enforcement";
import { resolveSsoCallbackProviderId } from "../policy/sso-jit";
import type { EnterpriseOptions } from "../types";
import {
  compactChain,
  isKeyedHash,
  readChainHead,
  signChainHead,
  verifyChainPage,
  writeAudit,
  type AuditActorType,
  type AuditInput,
  type AuditRow,
  type CompactionResult,
} from "./chain";
import { auditInBackground } from "./background";
import {
  AUDIT_TIME_MAX,
  auditChangedKeys,
  auditCode,
  auditEmail,
  auditId,
  auditRoles,
  auditToken,
  auditUserAgent,
} from "./bounds";
import {
  auditStashOf,
  isNotedPolicyRefusal,
  SIGN_IN_REFUSED_ACTION,
  type EnterpriseAuditStash,
} from "./refusal";
import {
  auditEntryFor,
  POLICY_REFUSAL_CODES,
  SELF_AUDITED_PATHS,
  type AuditedPath,
} from "./routes";

export {
  AUDITED_PATHS,
  METHOD_ACTION_OVERRIDES,
  POLICY_REFUSAL_CODES,
  SELF_AUDITED_PATHS,
  UNAUDITED_PATHS,
  UNAUDITED_SERVER_ONLY_ENDPOINTS,
  auditEntryFor,
  type AuditedPath,
  type AuditScope,
} from "./routes";

// ---------------------------------------------------------------------------
// Actors
// ---------------------------------------------------------------------------

/** The session shape the audit code reads (a subset of better-auth's). */
interface SessionLike {
  session: {
    id?: string;
    token?: string;
    userId?: string;
    activeOrganizationId?: string | null;
    impersonatedBy?: string | null;
  };
  user: { id: string; email?: string | null };
}

export interface AuditActor {
  actorType: AuditActorType;
  actorId: string | null;
  /** `{ impersonatedBy }` for an impersonation session, else empty. */
  metadata: Record<string, unknown>;
}

const SYSTEM_ACTOR: AuditActor = { actorType: "system", actorId: null, metadata: {} };

/**
 * The actor for a request made with `session`: the session's user — or,
 * when the session is an impersonation (`admin` plugin sets
 * `session.impersonatedBy` to the staff member's id), the impersonated user
 * with `actorType: "impersonated"` and the staff member in
 * `metadata.impersonatedBy` (F-12), so no row ever reads as the user's own
 * act. `null` session → `system`.
 */
export function sessionActor(session: SessionLike | null | undefined): AuditActor {
  const userId = session?.user?.id;
  if (typeof userId !== "string") return SYSTEM_ACTOR;
  const impersonatedBy = session?.session?.impersonatedBy;
  if (typeof impersonatedBy === "string" && impersonatedBy) {
    return { actorType: "impersonated", actorId: userId, metadata: { impersonatedBy } };
  }
  return { actorType: "user", actorId: userId, metadata: {} };
}

// ---------------------------------------------------------------------------
// Organizations
// ---------------------------------------------------------------------------

/**
 * Every org with a claim on a user — memberships ∪ orgs owning a verified
 * SSO domain for the user's e-mail — through the same resolver the policy
 * layer uses (`resolvePolicyOrgsForUser`, no active org). An unknown user
 * with a known address gets the domain orgs only.
 */
export async function auditOrgIdsForUser(
  ctx: GenericEndpointContext,
  user: { userId?: string | null; email?: string | null },
): Promise<string[]> {
  const userId = user.userId ?? null;
  let email = user.email ?? null;
  if (!userId && !email) return [];
  if (!email && userId) {
    const row = await ctx.context.internalAdapter.findUserById(userId).catch(() => null);
    email = row?.email ?? null;
  }
  return resolvePolicyOrgsForUser(ctx, { userId, email: email ?? "" });
}

function str(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function record(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" ? (value as Record<string, unknown>) : null;
}

function extractId(value: unknown): string | null {
  return str(record(value)?.id);
}

/**
 * The organization id carried by the resource an organization endpoint
 * returned — the member, invitation, team or organization it acted on
 * (F-10: the org *joined*, never the acceptor's previously active org).
 */
function returnedOrgId(path: string, returned: unknown): string | null {
  const body = record(returned);
  if (!body) return null;
  if (path === "/organization/update" || path === "/organization/delete") return str(body.id);
  return (
    str(body.organizationId) ??
    str(record(body.member)?.organizationId) ??
    str(record(body.invitation)?.organizationId) ??
    str(record(body.team)?.organizationId) ??
    null
  );
}

// ---------------------------------------------------------------------------
// Request facts captured by the before-hook
// ---------------------------------------------------------------------------

interface AuditStash extends EnterpriseAuditStash {
  captured?: boolean;
  session?: SessionLike | null;
  /** Who a sign-in step / unauthenticated account request is about, from the request itself. */
  subjectHint?: { userId?: string | null; email?: string | null } | null;
  /** The subject's orgs, resolved before the endpoint deleted them. */
  preOrgIds?: string[];
  /** The org of the team/invitation a `resource`-scope endpoint is about to act on, read from that row (`RESOURCE_ORG_SOURCES`). */
  resourceOrgId?: string | null;
  provider?: { providerId: string; orgId: string | null; linkedAccounts?: number } | null;
  targetUser?: { userId: string; orgIds: string[] } | null;
  /** Noted by the `databaseHooks` below: whose session / user a create was for. */
  dbSessionUserId?: string;
  dbUserEmail?: string;
}

function stashOf(ctx: { context: unknown }): AuditStash {
  return auditStashOf(ctx) as AuditStash;
}

/** `{ email }` from the (still unverified) payload of a `/verify-email` JWT — trusted only once the endpoint succeeded, which means it verified that very token. */
function emailFromVerificationJwt(token: unknown): string | null {
  if (typeof token !== "string") return null;
  const payload = token.split(".")[1];
  if (!payload) return null;
  try {
    const json = JSON.parse(
      new TextDecoder().decode(
        Uint8Array.from(atob(payload.replace(/-/g, "+").replace(/_/g, "/")), (c) =>
          c.charCodeAt(0),
        ),
      ),
    ) as { email?: unknown };
    return str(json.email);
  } catch {
    return null;
  }
}

/** Upstream `twoFactor()`'s challenge cookie name (`TWO_FACTOR_COOKIE_NAME`, not exported). */
const TWO_FACTOR_COOKIE = "two_factor";

/**
 * Who an unauthenticated request is about, read the way the endpoint itself
 * will read it: the body's `email`, the magic link's pending verification
 * value, the 2FA challenge cookie's verification value, the password-reset
 * token's verification value, the e-mail-verification token's address.
 * Read-only — nothing is consumed. An address is taken only when it is a
 * valid e-mail address (`auditEmail`): anything else names no subject, so
 * no organization is resolved from it and no row records it.
 */
async function subjectHintOf(
  ctx: GenericEndpointContext,
  path: string,
): Promise<{ userId?: string | null; email?: string | null } | null> {
  const body = record(ctx.body);
  const query = record(ctx.query);
  if (path === "/magic-link/verify") {
    const email = auditEmail(
      await resolveMagicLinkEmail(ctx, query as { token?: unknown } | undefined),
    );
    return email ? { email } : null;
  }
  if (path.startsWith("/two-factor/verify-")) {
    const cookie = ctx.context.createAuthCookie(TWO_FACTOR_COOKIE);
    const identifier = await ctx.getSignedCookie(cookie.name, ctx.context.secret);
    if (!identifier) return null;
    const value = await ctx.context.internalAdapter.findVerificationValue(identifier);
    return str(value?.value) ? { userId: value!.value } : null;
  }
  if (path === "/reset-password") {
    const token = str(body?.token) ?? str(query?.token);
    if (!token) return null;
    const value = await ctx.context.internalAdapter.findVerificationValue(
      `reset-password:${token}`,
    );
    return str(value?.value) ? { userId: value!.value } : null;
  }
  if (path === "/verify-email") {
    const email = auditEmail(emailFromVerificationJwt(query?.token));
    return email ? { email } : null;
  }
  const email = auditEmail(body?.email);
  return email ? { email } : null;
}

/**
 * The provider a provider-scoped endpoint acts on: a route with a
 * `:providerId` parameter (`/sso/saml2/sp/slo/:providerId`) acts on the
 * parameter and ignores any body field (`const { providerId } = ctx.params`,
 * `node_modules/@better-auth/sso/dist/index.mjs:4285`); every other provider
 * route acts on `body.providerId` (`checkProviderAccess(ctx,
 * body.providerId)`, the `/sso/*` entries of `GATE_ORG_SOURCES` in
 * `../gate.ts`). Reading the body first let
 * a request that named another org's provider in its body file the row in
 * that org's chain.
 */
export function actedOnProviderId(
  ctx: { body?: unknown; params?: unknown },
  path: string,
): string | null {
  return path.includes(":providerId")
    ? str(record(ctx.params)?.providerId)
    : str(record(ctx.body)?.providerId);
}

async function providerOf(
  ctx: GenericEndpointContext,
  path: string,
): Promise<AuditStash["provider"]> {
  const providerId = actedOnProviderId(ctx, path);
  if (!providerId) return null;
  const row = await ctx.context.adapter.findOne<{ organizationId?: string | null }>({
    model: "ssoProvider",
    where: [{ field: "providerId", value: providerId }],
  });
  const provider: NonNullable<AuditStash["provider"]> = {
    providerId,
    orgId: row?.organizationId ?? null,
  };
  if (path === "/sso/delete-provider" && row) {
    // Upstream deletes every `account` row linked to the provider with it;
    // the count is the blast radius the row records.
    provider.linkedAccounts = await ctx.context.adapter.count({
      model: "account",
      where: [{ field: "providerId", value: providerId }],
    });
  }
  return provider;
}

async function targetUserOf(
  ctx: GenericEndpointContext,
  path: string,
  session: SessionLike | null,
): Promise<AuditStash["targetUser"]> {
  let userId: string | null = null;
  if (path === "/admin/stop-impersonating") {
    userId = session?.user?.id ?? null;
  } else if (path === "/admin/revoke-user-session") {
    const token = str(record(ctx.body)?.sessionToken);
    const found = token
      ? await ctx.context.internalAdapter.findSession(token).catch(() => null)
      : null;
    userId = found?.user?.id ?? null;
  } else {
    userId = str(record(ctx.body)?.userId);
  }
  if (!userId) return null;
  return { userId, orgIds: await auditOrgIdsForUser(ctx, { userId }) };
}

/**
 * Where the org of a `resource`-scope row comes from — always the resource
 * the endpoint acted on, never an org id the caller named (a body
 * `organizationId`, a `?organizationId=`, the session's active org):
 *
 * - `"team"` / `"invitation"`: the `organizationId` of the team / invitation
 *   row the request names (`body.teamId` / `body.invitationId`), read before
 *   the endpoint runs (it may delete the row). Upstream only acts on a team
 *   it found *in* the org it resolved (`findTeamById({ teamId,
 *   organizationId })`), and on an invitation of that invitation's own org,
 *   so this is the org the endpoint changed.
 * - `"returned"`: the organization id on the member, invitation, team or
 *   organization the endpoint returned (`returnedOrgId`).
 *
 * A path in `scope: "resource"` without an entry here resolves no org and
 * writes no row (logged) — `test/security/audit-cluster-resource-org.test.ts`
 * pins that every such path has one.
 */
export const RESOURCE_ORG_SOURCES: Readonly<Record<string, "team" | "invitation" | "returned">> = {
  "/organization/update": "returned",
  "/organization/delete": "returned",
  "/organization/leave": "returned",
  "/organization/invite-member": "returned",
  "/organization/cancel-invitation": "invitation",
  "/organization/reject-invitation": "invitation",
  "/organization/accept-invitation": "invitation",
  "/organization/remove-member": "returned",
  "/organization/update-member-role": "returned",
  "/organization/create-team": "returned",
  "/organization/update-team": "team",
  "/organization/remove-team": "team",
  "/organization/add-team-member": "team",
  "/organization/remove-team-member": "team",
};

/** The org of the team / invitation a `resource`-scope request names, from that row; `null` for the other sources. */
async function resourceOrgBefore(
  ctx: GenericEndpointContext,
  path: string,
): Promise<string | null> {
  const source = RESOURCE_ORG_SOURCES[path];
  const body = record(ctx.body);
  const lookup =
    source === "team"
      ? { model: "team", id: str(body?.teamId) }
      : source === "invitation"
        ? { model: "invitation", id: str(body?.invitationId) }
        : null;
  if (!lookup?.id) return null;
  const row = await ctx.context.adapter.findOne<{ organizationId?: string | null }>({
    model: lookup.model,
    where: [{ field: "id", value: lookup.id }],
  });
  return str(row?.organizationId);
}

/** The org a `resource`-scope row goes to: the acted-on resource's own org, or `null` (no row). */
function resourceOrgId(path: string, stash: AuditStash, returned: unknown): string | null {
  const source = RESOURCE_ORG_SOURCES[path];
  if (source === "returned") return returnedOrgId(path, returned);
  if (source === "team" || source === "invitation") return stash.resourceOrgId ?? null;
  return null;
}

async function captureBefore(
  ctx: GenericEndpointContext,
  path: string,
  entry: AuditedPath,
): Promise<void> {
  const stash = stashOf(ctx);
  stash.captured = true;
  const session = (await getSessionFromCtx(ctx).catch(() => null)) as SessionLike | null;
  stash.session = session;
  if (entry.scope === "subject") {
    stash.subjectHint = await subjectHintOf(ctx, path);
    if (entry.resolveBefore && session) {
      stash.preOrgIds = await auditOrgIdsForUser(ctx, {
        userId: session.user.id,
        email: session.user.email ?? null,
      });
    }
  } else if (entry.scope === "target-user") {
    stash.targetUser = await targetUserOf(ctx, path, session);
  } else if (entry.scope === "resource") {
    stash.resourceOrgId = await resourceOrgBefore(ctx, path);
  } else if (entry.scope === "provider") {
    stash.provider = await providerOf(ctx, path);
  }
}

// ---------------------------------------------------------------------------
// Outcome of the request
// ---------------------------------------------------------------------------

interface MintedSession {
  session: { id?: string; token?: string; impersonatedBy?: string | null; userId?: string };
  user: { id: string; email?: string | null };
}

/**
 * The session this request **minted**, or `null`. `ctx.context.newSession`
 * is set by every `setSessionCookie` call — including the refresh of the
 * caller's own session on `/get-session` and the cookie re-issue after
 * `/update-user` or `/organization/set-active` — so a session only counts
 * as minted when its token differs from the one the request came in with
 * (signed session cookie, or the session captured before the endpoint ran).
 * `twoFactor()` resets `newSession` to `null` when a sign-in turns into a
 * 2FA challenge.
 */
async function mintedSession(
  ctx: GenericEndpointContext,
  stash: AuditStash,
): Promise<MintedSession | null> {
  const minted = (ctx.context as unknown as { newSession?: MintedSession | null }).newSession;
  if (!minted?.session || !minted.user?.id) return null;
  const token = minted.session.token;
  if (!token) return minted;
  if (stash.session?.session?.token === token) return null;
  try {
    const inbound = await ctx.getSignedCookie(
      ctx.context.authCookies.sessionToken.name,
      ctx.context.secret,
    );
    if (inbound === token) return null;
  } catch {
    // no readable inbound cookie — the session is new
  }
  return minted;
}

interface Failure {
  code: string;
  /** Whether the failure came as a redirect `?error=` (the SSO/social callbacks, magic links with a callback URL). */
  redirect: boolean;
}

/**
 * Whether the endpoint failed, and with which code. The redirecting flows
 * finish via `throw ctx.redirect(url)` — itself an `APIError` (302) — on
 * success *and* failure alike, so a redirect is a failure only when its
 * target carries an `error` parameter; any other `APIError` is a failure
 * with its body `code` (or its status).
 *
 * A redirect's target starts with a URL the caller supplied
 * (`errorCallbackURL`/`callbackURL`), which may already carry `error=`
 * parameters of its own; upstream *appends* its error to it
 * (`appendQueryParams`, the SSO plugin's `errorRedirectUrl`), so the code
 * is the **last** `error` value. Whatever it is, it is only a label
 * (bounded by `auditCode`): whether a failure is a policy refusal is never
 * read from it (`isPolicyRefusal`).
 */
function failureOf(returned: unknown): Failure | null {
  if (!isAPIError(returned)) return null;
  const headers = (returned as { headers?: unknown }).headers;
  const location = headers instanceof Headers ? headers.get("location") : null;
  if (location) {
    let error: string | undefined;
    try {
      error = new URL(location, "http://localhost").searchParams.getAll("error").at(-1);
    } catch {
      error = undefined;
    }
    return error ? { code: auditCode(error), redirect: true } : null;
  }
  const body = (returned as { body?: { code?: unknown } }).body;
  const code =
    str(body?.code) ??
    String(
      (returned as { status?: unknown }).status ??
        (returned as { statusCode?: unknown }).statusCode ??
        "ERROR",
    );
  return { code: auditCode(code), redirect: false };
}

/**
 * A failure is a policy refusal only when this package's own code refused
 * the request with that code (`policyRefusal`, `../audit/refusal.ts`) —
 * never because the code appears in a redirect URL or an error body, which
 * a caller can shape (a callback URL carrying `?error=SSO_REQUIRED`, an IdP
 * error response naming a policy code).
 */
function isPolicyRefusal(ctx: GenericEndpointContext, failure: Failure): boolean {
  return POLICY_REFUSAL_CODES.has(failure.code) && isNotedPolicyRefusal(ctx, failure.code);
}

/**
 * Account requests about the address or token they carry, whoever sends
 * them: the subject is read from the request (`subjectHintOf`), not from a
 * session that may belong to someone else.
 */
const REQUEST_NAMES_SUBJECT = new Set([
  "/sign-in/magic-link",
  "/request-password-reset",
  "/reset-password",
]);

const SSO_CALLBACK_PATHS = new Set([
  "/sso/callback",
  "/sso/callback/:providerId",
  "/sso/saml2/sp/acs/:providerId",
]);

/**
 * Paths where an audit-write failure is logged and swallowed rather than
 * failing the request (ruling e): the sign-in family and the other
 * unauthenticated account flows — an audit hiccup must never block
 * sign-in/out. Everything else answers 500 `AUDIT_WRITE_FAILED` — after the
 * endpoint's change is already committed (the after-hook runs once it has
 * returned), so the 500 reports a missing row, it does not undo the change.
 * docs/security.md ("Audit log coverage") lists both sets.
 */
export function writeFailureIsSoft(path: string, entry: AuditedPath | null): boolean {
  if (!entry || entry.kind === "session") return true;
  return (
    path === "/sign-out" ||
    path === "/sign-in/magic-link" ||
    path === "/request-password-reset" ||
    path === "/reset-password" ||
    path === "/sso/saml2/logout/:providerId" ||
    path === "/sso/saml2/sp/slo/:providerId"
  );
}

/** Keys (never values) a write request changed: top-level body keys, and one level into nested objects. */
function changedKeyPaths(body: unknown, exclude: readonly string[]): string[] {
  const source = record(body);
  if (!source) return [];
  const keys: string[] = [];
  for (const [key, value] of Object.entries(source)) {
    if (exclude.includes(key) || value === undefined) continue;
    const nested = record(value);
    if (nested && !Array.isArray(value)) {
      const inner = Object.keys(nested).filter((k) => nested[k] !== undefined);
      if (inner.length > 0) {
        for (const k of inner) keys.push(`${key}.${k}`);
        continue;
      }
    }
    keys.push(key);
  }
  return keys.sort();
}

/** `{ changed, changedCount? }` for the keys a write request changed, bounded (`auditChangedKeys`). */
function changedKeys(
  body: unknown,
  exclude: readonly string[],
): { changed: string[]; changedCount?: number } {
  return auditChangedKeys(changedKeyPaths(body, exclude));
}

function requestMeta(ctx: GenericEndpointContext): { ip: string | null; userAgent: string | null } {
  return {
    ip: ctx.request ? (getIP(ctx.request, ctx.context.options) ?? null) : null,
    userAgent: auditUserAgent(ctx.request?.headers.get("user-agent")),
  };
}

/** The error a non-soft path answers when its audit row could not be written. */
function auditWriteFailed(): APIError {
  return new APIError("INTERNAL_SERVER_ERROR", { code: "AUDIT_WRITE_FAILED" });
}

function isAuditWriteFailed(error: unknown): error is APIError {
  return (
    isAPIError(error) &&
    (error.body as { code?: unknown } | undefined)?.code === "AUDIT_WRITE_FAILED"
  );
}

/**
 * The HTTP answer for `AUDIT_WRITE_FAILED`: a `Response` rather than a thrown
 * `APIError`. better-auth answers a thrown after-hook error with the status
 * the endpoint set (`dispatch.mjs` passes the endpoint's `status` to
 * `toResponse`, which prefers it over the error's own), so an endpoint that
 * calls `ctx.setStatus` — SCIM `POST /scim/v2/Users` answers 201 — reported
 * success for a change whose row was never written, with
 * `{"code":"AUDIT_WRITE_FAILED"}` as its body. A returned `Response` is
 * answered as-is. A server-side call (no `Request`) still gets the thrown
 * error, which better-auth rethrows to the caller.
 */
function auditWriteFailedResponse(error: APIError): Response {
  return new Response(JSON.stringify(error.body ?? { code: "AUDIT_WRITE_FAILED" }), {
    status: error.statusCode,
    headers: { "content-type": "application/json" },
  });
}

/**
 * One row per org. A write failure is logged and swallowed on soft paths
 * (`writeFailureIsSoft`), else `500 AUDIT_WRITE_FAILED`. No org at all is
 * logged (warn when the scope promised one, debug for a user who belongs
 * to none) and nothing is written — never a guessed org.
 */
async function writeRows(
  ctx: GenericEndpointContext,
  orgIds: Iterable<string | null | undefined>,
  row: Omit<AuditInput, "orgId">,
  opts: { soft: boolean; expectOrg: boolean; path: string },
): Promise<void> {
  const targets = [...new Set([...orgIds].filter((id): id is string => !!id))];
  if (targets.length === 0) {
    const message = `enterprise-audit: no organization resolvable for ${row.action} on ${opts.path}; nothing written`;
    if (opts.expectOrg) ctx.context.logger.warn(message);
    else ctx.context.logger.debug(message);
    return;
  }
  for (const orgId of targets) {
    try {
      // `writeAudit` applies the row backstop (`./bounds.ts`) itself.
      await writeAudit(ctx, { ...row, orgId });
    } catch (err) {
      // Logged on both kinds of path: the error is what the adapter let
      // through, which never carries a statement or its values
      // (`../db-errors.ts`).
      ctx.context.logger.error(
        `enterprise-audit: failed to write the ${row.action} row on ${opts.path}`,
        err,
      );
      if (opts.soft) continue;
      throw auditWriteFailed();
    }
  }
}

async function safeOrgIds(
  ctx: GenericEndpointContext,
  user: { userId?: string | null; email?: string | null },
): Promise<string[]> {
  try {
    return await auditOrgIdsForUser(ctx, user);
  } catch (err) {
    ctx.context.logger.error("enterprise-audit: could not resolve the user's organizations", err);
    return [];
  }
}

async function providerOrgId(ctx: GenericEndpointContext, providerId: string | null) {
  if (!providerId) return null;
  const row = await ctx.context.adapter
    .findOne<{ organizationId?: string | null }>({
      model: "ssoProvider",
      where: [{ field: "providerId", value: providerId }],
    })
    .catch(() => null);
  return row?.organizationId ?? null;
}

/** Who a failed/refused sign-in step was for: the user a create hook saw, else what the request named. */
async function failedSubject(
  ctx: GenericEndpointContext,
  stash: AuditStash,
): Promise<{ userId: string | null; email: string | null }> {
  if (stash.dbSessionUserId) return { userId: stash.dbSessionUserId, email: null };
  const hint = stash.subjectHint;
  if (hint?.userId) return { userId: hint.userId, email: hint.email ?? null };
  const email = stash.dbUserEmail ?? hint?.email ?? null;
  if (email) {
    const found = await ctx.context.internalAdapter.findUserByEmail(email).catch(() => null);
    return { userId: found?.user?.id ?? null, email };
  }
  return { userId: null, email: null };
}

// ---------------------------------------------------------------------------
// The after-hook
// ---------------------------------------------------------------------------

interface AuditCtx {
  ctx: GenericEndpointContext;
  path: string;
  entry: AuditedPath | null;
  stash: AuditStash;
  returned: unknown;
  opts: EnterpriseOptions;
}

function methodOf(a: AuditCtx, userId: string | null): string | null {
  const classified = classifySessionCreate(a.ctx, a.opts, { userId: userId ?? undefined });
  return classified.kind === "method"
    ? classified.method
    : classified.kind === "continuation"
      ? "continuation"
      : null;
}

/** The provider an SSO callback names, as recorded (a short token, else `null`). */
async function callbackProviderId(ctx: GenericEndpointContext): Promise<string | null> {
  return auditToken(await resolveSsoCallbackProviderId(ctx).catch(() => null));
}

async function auditSessionMinted(a: AuditCtx, minted: MintedSession): Promise<void> {
  const { ctx, path, entry, stash } = a;
  const userId = minted.user.id;
  let action = entry?.action ?? "auth.sign_in";
  // With a session already in hand, these re-issue it rather than sign in.
  if (stash.session && path.startsWith("/two-factor/verify-")) action = "two_factor.enabled";
  if (stash.session?.user?.id === userId && path === "/verify-email") {
    action = "user.email_verified";
  }
  const sso = SSO_CALLBACK_PATHS.has(path);
  const providerId = sso ? await callbackProviderId(ctx) : null;
  const orgIds = await safeOrgIds(ctx, { userId, email: minted.user.email ?? null });
  if (sso) orgIds.push(...[await providerOrgId(ctx, providerId)].filter((x): x is string => !!x));
  const actor = sessionActor({ session: minted.session, user: minted.user });
  const method = methodOf(a, userId);
  await writeRows(
    ctx,
    orgIds,
    {
      actorType: actor.actorType,
      actorId: actor.actorId,
      action,
      targetType: "user",
      targetId: userId,
      ...requestMeta(ctx),
      metadata: {
        ...actor.metadata,
        ...(method ? { method } : {}),
        ...(providerId ? { providerId } : {}),
        ...(entry ? {} : { path }),
      },
    },
    { soft: true, expectOrg: false, path },
  );
}

/**
 * Failed, refused and 2FA-pending sign-ins are about an address the caller
 * chose; the lookups and writes behind them always run off the response
 * path (`auditInBackground` — better-auth's `runInBackground`: the product's
 * `advanced.backgroundTasks.handler`, else a detached promise), so the
 * response takes the same time whether or not the address has an account or
 * organizations.
 */
function auditSignInFailure(a: AuditCtx, failure: Failure): void {
  const { ctx, stash } = a;
  if (stash.refusalWritten) return; // a `hooks.before` handler already recorded this refusal
  const refused = isPolicyRefusal(ctx, failure);
  auditInBackground(ctx, () => writeSignInFailure(a, failure, refused));
}

async function writeSignInFailure(a: AuditCtx, failure: Failure, refused: boolean): Promise<void> {
  const { ctx, path, stash } = a;
  const sso = SSO_CALLBACK_PATHS.has(path);
  const providerId = sso ? await callbackProviderId(ctx) : null;
  const subject = await failedSubject(ctx, stash);
  const orgIds = await safeOrgIds(ctx, subject);
  if (sso) orgIds.push(...[await providerOrgId(ctx, providerId)].filter((x): x is string => !!x));
  const meta = requestMeta(ctx);
  if (sso && !refused) {
    // Historical shape of a failed SSO sign-in (no user was signed in).
    await writeRows(
      ctx,
      orgIds,
      {
        actorType: "system",
        actorId: null,
        action: "auth.sso_sign_in_failed",
        targetType: "sso_provider",
        targetId: providerId,
        ...meta,
        metadata: { error: failure.code },
      },
      { soft: true, expectOrg: true, path },
    );
    return;
  }
  const method = methodOf(a, subject.userId);
  await writeRows(
    ctx,
    orgIds,
    {
      actorType: "system",
      actorId: null,
      action: refused ? SIGN_IN_REFUSED_ACTION : "auth.sign_in_failed",
      targetType: "user",
      targetId: subject.userId,
      ...meta,
      metadata: {
        code: failure.code,
        path,
        ...(method ? { method } : {}),
        ...(providerId ? { providerId } : {}),
        ...(subject.userId === null && subject.email ? { email: subject.email } : {}),
      },
    },
    { soft: true, expectOrg: false, path },
  );
}

function auditTwoFactorPending(a: AuditCtx): void {
  auditInBackground(a.ctx, () => writeTwoFactorPending(a));
}

async function writeTwoFactorPending(a: AuditCtx): Promise<void> {
  const { ctx, path, stash } = a;
  const subject = await failedSubject(ctx, stash);
  if (!subject.userId) return;
  await writeRows(
    ctx,
    await safeOrgIds(ctx, subject),
    {
      // The password was right; the second factor is still owed — not a
      // sign-in yet, and no session exists to attribute one to.
      actorType: "system",
      actorId: null,
      action: "auth.sign_in_2fa_pending",
      targetType: "user",
      targetId: subject.userId,
      ...requestMeta(ctx),
      metadata: { method: methodOf(a, subject.userId) },
    },
    { soft: true, expectOrg: false, path },
  );
}

async function auditSignInStep(a: AuditCtx): Promise<void> {
  const { ctx, path, stash, returned } = a;
  const minted = await mintedSession(ctx, stash);
  if (minted) return auditSessionMinted(a, minted);
  if (record(returned)?.twoFactorRedirect === true) return auditTwoFactorPending(a);
  const failure = failureOf(returned);
  if (failure) return auditSignInFailure(a, failure);
  // Succeeded without minting a session — a sign-up that answers the same
  // way for a taken address (upstream's generic duplicate response), or a
  // verification link: off the response path like the failures.
  if (path === "/sign-up/email" || path === "/verify-email") {
    auditInBackground(ctx, () => writeSignUpOrVerification(a));
  }
}

async function writeSignUpOrVerification(a: AuditCtx): Promise<void> {
  const { ctx, path, stash, returned, entry } = a;
  const userId =
    extractId(record(returned)?.user) ?? (await failedSubject(ctx, stash)).userId ?? null;
  if (!userId) return;
  await writeRows(
    ctx,
    await safeOrgIds(ctx, { userId }),
    {
      actorType: "system",
      actorId: null,
      action: path === "/sign-up/email" ? (entry?.action ?? "auth.sign_up") : "user.email_verified",
      targetType: "user",
      targetId: userId,
      ...requestMeta(ctx),
      metadata: {},
    },
    { soft: true, expectOrg: false, path },
  );
}

function routeParamId(ctx: GenericEndpointContext): string | null {
  const params = record(ctx.params);
  return str(params?.userId) ?? str(params?.groupId) ?? str(params?.providerId);
}

// Every value below that comes from the request (a body field, a route
// parameter) goes through `./bounds.ts` before it reaches the row: ids via
// `auditId`, roles via `auditRoles`, key lists via `changedKeys`; values read
// back from the database or the response are the stored ones. `writeRows`
// hands the result to `writeAudit`, which applies `auditRowBounds` as a
// backstop to every row.

async function auditEvent(a: AuditCtx, entry: AuditedPath): Promise<void> {
  const { ctx, path, stash, returned } = a;
  const failure = failureOf(returned);
  if (failure) {
    if (isPolicyRefusal(ctx, failure)) auditSignInFailure(a, failure);
    return;
  }
  const body = record(ctx.body);
  const meta = requestMeta(ctx);
  const soft = writeFailureIsSoft(path, entry);
  const scimConnection = (
    ctx.context as unknown as { scimConnection?: { id?: string; provisioningDomainId?: string } }
  ).scimConnection;

  let actor: AuditActor = scimConnection?.id
    ? { actorType: "scim", actorId: scimConnection.id, metadata: {} }
    : sessionActor(stash.session);
  let orgIds: Array<string | null> = [];
  let targetId: string | null = null;
  let action = entry.action;
  let targetType = entry.targetType;
  const metadata: Record<string, unknown> = {};

  switch (entry.scope) {
    case "scim":
      orgIds = [scimConnection?.provisioningDomainId ?? null];
      targetId = auditId(extractId(returned) ?? routeParamId(ctx));
      break;
    case "request-org":
      // The one field the endpoint acts on (`/enterprise/policy/set` reads
      // `body.orgId`, the gate's `GATE_ORG_SOURCES` entry too) — never
      // another org-id field of the same body. The endpoint's own schema
      // already refused anything but an id (`../org-id.ts`); checked again
      // so this row can never be filed under a value that is not one.
      orgIds = [isOrgId(body?.orgId) ? body.orgId : null];
      targetId = auditId(orgIds[0]);
      Object.assign(metadata, changedKeys(body, ["orgId", "organizationId"]));
      break;
    case "provider": {
      const providerId = stash.provider?.providerId ?? actedOnProviderId(ctx, path);
      const orgId =
        stash.provider?.orgId ??
        (await providerOrgId(ctx, providerId)) ??
        str(record(returned)?.organizationId);
      orgIds = [orgId];
      targetId = auditId(providerId);
      if (path === "/sso/update-provider") {
        Object.assign(metadata, changedKeys(body, ["providerId"]));
      }
      if (path === "/sso/delete-provider") {
        metadata.linkedAccounts = stash.provider?.linkedAccounts ?? 0;
      }
      break;
    }
    case "target-user": {
      let target = stash.targetUser ?? null;
      if (!target && path === "/admin/create-user") {
        const userId = extractId(record(returned)?.user);
        target = userId ? { userId, orgIds: await safeOrgIds(ctx, { userId }) } : null;
      }
      orgIds = target?.orgIds ?? [];
      targetId = auditId(target?.userId);
      if (path === "/admin/stop-impersonating") {
        // The session being ended was the staff member's impersonation of
        // the target: the staff member is the actor.
        const staff = str(stash.session?.session?.impersonatedBy);
        actor = staff
          ? { actorType: "user", actorId: staff, metadata: {} }
          : sessionActor(stash.session);
      }
      if (path === "/admin/set-role") Object.assign(metadata, auditRoles(body?.role));
      if (path === "/admin/update-user") Object.assign(metadata, changedKeys(body?.data, []));
      break;
    }
    case "resource": {
      orgIds = [resourceOrgId(path, stash, returned)];
      const returnedBody = record(returned);
      if (path === "/organization/update" || path === "/organization/delete") {
        targetId = auditId(orgIds[0]);
        if (path === "/organization/update") Object.assign(metadata, changedKeys(body?.data, []));
      } else if (path === "/organization/update-member-role") {
        // F-09: the target is the member whose role changed, the actor the
        // caller — never the `userId` on the returned member row.
        targetId = auditId(str(returnedBody?.id) ?? str(body?.memberId));
        metadata.targetUserId = auditId(str(returnedBody?.userId));
        Object.assign(metadata, auditRoles(body?.role));
      } else if (path === "/organization/remove-member") {
        const member = record(returnedBody?.member);
        targetId = auditId(str(member?.id) ?? str(body?.memberIdOrEmail));
        metadata.targetUserId = auditId(str(member?.userId));
      } else if (path === "/organization/accept-invitation") {
        const member = record(returnedBody?.member);
        targetId = auditId(str(member?.id));
        metadata.invitationId = auditId(
          str(record(returnedBody?.invitation)?.id) ?? str(body?.invitationId),
        );
      } else if (path === "/organization/leave") {
        targetId = auditId(str(returnedBody?.id));
      } else {
        targetId = auditId(
          extractId(returned) ??
            extractId(returnedBody?.invitation) ??
            extractId(returnedBody?.team) ??
            extractId(returnedBody?.member) ??
            str(body?.invitationId) ??
            str(body?.teamId),
        );
      }
      break;
    }
    case "subject": {
      if (REQUEST_NAMES_SUBJECT.has(path)) {
        // The address/token in the request is who this is about — never the
        // session of whoever sent it. An outcome for an arbitrary address:
        // looked up and written off the response path (`auditInBackground`),
        // so the response time does not depend on whether the address has
        // an account or organizations.
        const requestActor = actor;
        auditInBackground(ctx, async () => {
          const subject = await failedSubject(ctx, stash);
          await writeRows(
            ctx,
            await safeOrgIds(ctx, subject),
            {
              actorType: requestActor.actorType,
              actorId: requestActor.actorId,
              action,
              targetType,
              targetId: subject.userId,
              ...meta,
              metadata: {
                ...requestActor.metadata,
                ...(subject.userId === null && subject.email ? { email: subject.email } : {}),
              },
            },
            { soft: true, expectOrg: false, path },
          );
        });
        return;
      }
      const subject = stash.session
        ? { userId: stash.session.user.id, email: stash.session.user.email ?? null }
        : await failedSubject(ctx, stash);
      orgIds = stash.preOrgIds ?? (await safeOrgIds(ctx, subject));
      targetId = subject.userId;
      if (path === "/delete-user" && record(returned)?.message === "Verification email sent") {
        action = "user.deletion_requested";
      }
      if (path === "/update-user") Object.assign(metadata, changedKeys(body, []));
      if (path === "/unlink-account") metadata.providerId = auditId(body?.providerId);
      if (path.startsWith("/api-key/")) {
        targetType = "api_key";
        targetId = auditId(extractId(returned) ?? str(body?.keyId));
        if (path === "/api-key/update") Object.assign(metadata, changedKeys(body, ["keyId"]));
      }
      if (path.startsWith("/passkey/")) {
        targetId = auditId(extractId(returned) ?? str(body?.id));
      }
      if (targetType === "session") targetId = null; // never record a session token
      break;
    }
  }

  await writeRows(
    ctx,
    orgIds,
    {
      actorType: actor.actorType,
      actorId: actor.actorId,
      action,
      targetType,
      targetId,
      ...meta,
      metadata: { ...actor.metadata, ...metadata },
    },
    { soft, expectOrg: entry.scope !== "subject" && entry.scope !== "target-user", path },
  );
}

async function auditUnlistedPath(a: AuditCtx): Promise<void> {
  const { ctx, stash, returned } = a;
  const minted = await mintedSession(ctx, stash);
  if (minted) return auditSessionMinted(a, minted);
  const failure = failureOf(returned);
  if (failure && isPolicyRefusal(ctx, failure)) auditSignInFailure(a, failure);
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
  // The anchor that replaces the deleted rows names who deleted them (F-13)
  // — under impersonation, the staff member too (`metadata.impersonatedBy`).
  const actor = sessionActor(ctx.context.session as SessionLike | null);
  return compactChain(ctx, orgId, cutoff, {
    chainKey: opts.audit?.chainKey,
    actor: { actorType: actor.actorType, actorId: actor.actorId, metadata: actor.metadata },
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

/**
 * A `from`/`to` filter: whole milliseconds since the epoch within what a
 * `Date` can hold (`[0, AUDIT_TIME_MAX]`). Anything else is a 400 at
 * validation, before a query is built — an out-of-range value used to reach
 * the adapter as an Invalid Date and answer 500.
 */
const timeBound = z.coerce.number().int().min(0).max(AUDIT_TIME_MAX).optional();

const listQuerySchema = z.object({
  orgId: orgIdSchema,
  action: z.string().optional(),
  actorId: z.string().optional(),
  from: timeBound,
  to: timeBound,
  cursor: z.coerce.number().int().optional(),
  limit: z.coerce.number().int().min(1).max(200).optional(),
});

const exportQuerySchema = z.object({
  orgId: orgIdSchema,
  from: timeBound,
  to: timeBound,
});

const verifyQuerySchema = z.object({
  orgId: orgIdSchema,
});

const headQuerySchema = z.object({
  orgId: orgIdSchema,
});

const compactBodySchema = z.object({
  orgId: orgIdSchema,
});

/** Default ceiling on one `/enterprise/audit/export` call (M-05); override with `audit.exportMaxRows`. */
export const DEFAULT_EXPORT_ROW_CAP = 100_000;

/**
 * Rows `/enterprise/audit/verify` reads and hashes per batch (I-3). Not
 * configurable: it is an implementation detail of how the endpoint walks the
 * chain, not a limit on what it verifies — every row is still checked, and
 * the answer is identical whatever the batch size. 1000 keeps one page's
 * `AuditEventRow[]` comfortably small while keeping the number of round trips
 * to the adapter low.
 */
export const VERIFY_PAGE_SIZE = 1000;

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
  const chainKey = opts.audit?.chainKey;

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
      if (cursor !== undefined) where.push({ field: "seq", value: cursor, operator: "lt" });

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
      const fullCtx = ctx as unknown as GenericEndpointContext;
      await requireOwnerOrAdmin(fullCtx, orgId);
      await requireFeature(fullCtx, orgId, "audit_log");

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
      // Who took the log out, and how much of it (F-13) — written after the
      // CSV is built, so an export never contains its own row. An export
      // that cannot be recorded is not handed out.
      const actor = sessionActor(ctx.context.session as SessionLike | null);
      try {
        await writeAudit(
          fullCtx,
          {
            orgId,
            actorType: actor.actorType,
            actorId: actor.actorId,
            action: "audit.exported",
            targetType: "organization",
            targetId: orgId,
            ...requestMeta(fullCtx),
            metadata: {
              ...actor.metadata,
              rows: rows.length,
              from: from ?? null,
              to: to ?? null,
            },
          },
          { chainKey },
        );
      } catch {
        throw new APIError("INTERNAL_SERVER_ERROR", { code: "AUDIT_WRITE_FAILED" });
      }
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

      // Paged (I-3). This used to be one unbounded `findMany` that
      // materialised the org's whole chain and then SHA-256'd every row of
      // it — worse per row than the export endpoint M-05 capped, and it is
      // the endpoint `<ab-audit-log>`'s "Verify chain" badge calls, so a
      // single click on a large org blocked on all of it. Memory is bounded
      // to one page now; the chain is still verified in full, because
      // `verifyChainPage` carries the running `prevHash` across pages.
      // Verified under the deployment's `audit.chainKey`, if any: keyed
      // rows are HMAC links only the key can check.
      let cursor: number | null = null;
      let prevHash: string | null = null;
      let keyed = false;
      for (;;) {
        const where: Where[] = [{ field: "orgId", value: orgId }];
        if (cursor !== null) where.push({ field: "seq", value: cursor, operator: "gt" });
        const page = await ctx.context.adapter.findMany<AuditEventRow>({
          model: "auditEvent",
          where,
          sortBy: { field: "seq", direction: "asc" },
          limit: VERIFY_PAGE_SIZE,
        });
        if (page.length === 0) break;

        const result = await verifyChainPage(page.map(toAuditRow), prevHash, chainKey);
        if (!result.ok) return ctx.json(result);
        prevHash = result.prevHash;
        cursor = page[page.length - 1]!.seq;
        keyed = isKeyedHash(page[page.length - 1]!.hash);
        if (page.length < VERIFY_PAGE_SIZE) break;
      }
      // `keyed`: whether the newest row is an HMAC link (`audit.chainKey`) —
      // the same flag `/enterprise/audit/head` reports. An unkeyed chain
      // that verifies proves consistency, not authenticity.
      return ctx.json({ ok: true, keyed });
    },
  );

  // The chain's newest row, for an operator to store off-box (gap 6): a
  // later truncation or consistent rewrite of the chain no longer matches
  // the exported head (`ab-enterprise audit-verify --expect-head`). With
  // `audit.chainKey` the head is signed (`signChainHead`), so the stored
  // value also proves it came from this deployment; unkeyed, `signature` is
  // `null`.
  const headEndpoint = createAuthEndpoint(
    "/enterprise/audit/head",
    { method: "GET", use: [sessionMiddleware], query: headQuerySchema },
    async (ctx) => {
      const { orgId } = ctx.query;
      await requireOwnerOrAdmin(ctx as unknown as GenericEndpointContext, orgId);
      await requireFeature(ctx as unknown as GenericEndpointContext, orgId, "audit_log");
      const head = await readChainHead(ctx as unknown as GenericEndpointContext, orgId);
      if (!head) return ctx.json({ head: null, keyed: false, signature: null });
      return ctx.json({
        head: {
          orgId: head.orgId,
          seq: head.seq,
          hash: head.hash,
          createdAt: new Date(head.createdAt).toISOString(),
        },
        keyed: isKeyedHash(head.hash),
        signature: chainKey ? await signChainHead(chainKey, head) : null,
      });
    },
  );

  // Retention on purpose rather than as a side effect of a read (C-02):
  // owner/admin only, feature-gated like every other audit endpoint, and
  // reporting exactly what it removed. The anchor row names the caller.
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
    // Exposed like `enterpriseGate` exposes it, so the chain writers can
    // read `audit.chainKey` back off the running auth instance
    // (`auditChainKeyOf`, `./chain.ts`) — no writer can forget the key.
    options: opts,
    // Notes whom a session / user creation is *for*, on the request's
    // audit stash, before any later hook (`../policy/*`, which this plugin
    // precedes in the preset) can refuse it — the after-hook attributes the
    // refusal to that user and their orgs (the victim org of a refused JIT
    // squat included). Never changes the row, never throws.
    init() {
      return {
        options: {
          databaseHooks: {
            session: {
              create: {
                before: async (
                  session: { userId?: unknown },
                  ctx: GenericEndpointContext | null | undefined,
                ) => {
                  if (ctx?.context && typeof session.userId === "string") {
                    stashOf(ctx).dbSessionUserId = session.userId;
                  }
                },
              },
            },
            user: {
              create: {
                before: async (
                  user: { email?: unknown },
                  ctx: GenericEndpointContext | null | undefined,
                ) => {
                  const email = auditEmail(user.email);
                  if (ctx?.context && email) stashOf(ctx).dbUserEmail = email;
                },
              },
            },
          },
        },
      };
    },
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
      enterpriseAuditHead: headEndpoint,
      enterpriseAuditCompact: compactEndpoint,
    },
    hooks: {
      // Captured *before* the endpoint runs (C-01 and F-13): the caller's
      // session (`/sign-out` deletes it; its value comes from the caller's
      // own cookie, never their body), the provider's org and linked-account
      // count (`/sso/delete-provider` deletes both), the target user's orgs
      // (`/admin/remove-user` deletes the memberships), the org of the team
      // or invitation an organization endpoint is about to act on
      // (`/organization/remove-team` deletes it). A capture failure is
      // logged and never blocks the request.
      before: [
        {
          matcher: (ctx) => !!ctx.path && auditEntryFor(ctx.path, ctx.request?.method) !== null,
          handler: createAuthMiddleware(async (ctx) => {
            const path = ctx.path as string;
            const entry = auditEntryFor(path, ctx.request?.method);
            if (!entry) return;
            try {
              await captureBefore(ctx as unknown as GenericEndpointContext, path, entry);
            } catch (err) {
              ctx.context.logger.error(
                `enterprise-audit: could not capture request facts for ${path}`,
                err,
              );
            }
          }),
        },
      ],
      after: [
        {
          // The route table (`./routes.ts`).
          matcher: (ctx) => !!ctx.path && auditEntryFor(ctx.path, ctx.request?.method) !== null,
          handler: createAuthMiddleware(async (ctx) => {
            const path = ctx.path as string;
            const entry = auditEntryFor(path, ctx.request?.method);
            if (!entry) return;
            const fullCtx = ctx as unknown as GenericEndpointContext;
            const stash = stashOf(fullCtx);
            if (!stash.captured) {
              stash.session = (await getSessionFromCtx(fullCtx).catch(
                () => null,
              )) as SessionLike | null;
            }
            const a: AuditCtx = {
              ctx: fullCtx,
              path,
              entry,
              stash,
              returned: ctx.context.returned,
              opts,
            };
            try {
              if (entry.kind === "session") await auditSignInStep(a);
              else await auditEvent(a, entry);
            } catch (err) {
              // The change is committed and its row is missing: never a 2xx.
              if (isAuditWriteFailed(err) && ctx.request) return auditWriteFailedResponse(err);
              throw err;
            }
          }),
        },
        {
          // Every other path: a session minted by any plugin is a sign-in,
          // a policy refusal on any path is a refused sign-in — fail closed
          // for sign-in methods this package does not know by name.
          matcher: (ctx) =>
            !!ctx.path &&
            auditEntryFor(ctx.path, ctx.request?.method) === null &&
            !(ctx.path in SELF_AUDITED_PATHS),
          handler: createAuthMiddleware(async (ctx) => {
            const fullCtx = ctx as unknown as GenericEndpointContext;
            const newSession = (ctx.context as unknown as { newSession?: unknown }).newSession;
            const returned = ctx.context.returned;
            if (!newSession && !isAPIError(returned)) return; // the common case: nothing to look at
            await auditUnlistedPath({
              ctx: fullCtx,
              path: ctx.path as string,
              entry: null,
              stash: stashOf(fullCtx),
              returned,
              opts,
            });
          }),
        },
      ],
    },
  } satisfies BetterAuthPlugin;
}
