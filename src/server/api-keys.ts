// Alpha Bros enterprise layer — API-key lifecycle binding (audit 3, gap 1;
// F-21 inverse).
//
// Upstream `@better-auth/api-key` keys are user-global bearer credentials
// (`apikey.referenceId` = user id) that re-check nothing about the *user* at
// key-use time: `validateApiKey` never loads the user, and the opt-in
// mock-session hook (`enableSessionForAPIKeys`) loads it but ignores
// `banned`. Neither path ever creates a session row, so none of the
// session-time controls (`admin()`'s ban check, `org_policy`) ever run for a
// key — and no deprovisioning path other than a SCIM deactivation deleted
// keys at all. A key therefore outlived `/admin/ban-user`,
// `/admin/remove-user` and every session revocation, and (with the mock
// session on) could mint further keys or drive the `/enterprise/*`
// management surface on the user's behalf.
//
// This module binds every key use to the same identity checks a session
// gets, revokes keys on every deprovisioning path (audited into every org the
// user belonged to — captured *before* the rows go, see `revokeUserApiKeys`),
// and confines a key to an explicit allow-list of endpoints
// (`API_KEY_ALLOWED_PATHS`: the owner's own session lookup; plus the api-key
// plugin's own server-only verify call, `isApiKeyVerifyCall`) — every other
// better-auth endpoint, including those of plugins a product adds later,
// answers `403 API_KEY_NOT_ALLOWED_HERE`.
// Enforced twice: in the validator (`enterpriseApiKeyValidator`, whatever
// carries the key) and on the `x-api-key` header alone
// (`assertNotApiKeyRequest`, via the gate). Policy (`org_policy`) still
// governs sessions only: keys are bound to the user at use time and bounded
// by expiry (`apiKeys.*` in `./types.ts`).

import type { AuthContext, BetterAuthPlugin, GenericEndpointContext } from "better-auth";
import { APIError, createAuthMiddleware, getSessionFromCtx, isAPIError } from "better-auth/api";
import { writeAudit, type ChainWriteOptions } from "./audit/chain";
import { memberOrgIds } from "./policy/store";

export const API_KEY_ERROR = {
  USER_BANNED: "USER_BANNED",
  USER_NOT_FOUND: "USER_NOT_FOUND",
  API_KEY_NOT_ALLOWED_HERE: "API_KEY_NOT_ALLOWED_HERE",
  API_KEY_EXPIRY_REQUIRED: "API_KEY_EXPIRY_REQUIRED",
} as const;

const API_KEY_NOT_ALLOWED_HERE_MESSAGE =
  "API keys authenticate a product's own API only: they can reach /get-session (and be verified server-side), no other endpoint.";

/**
 * Request headers that carry an API key. Passed to upstream `apiKey({
 * apiKeyHeaders })` by the preset (so the two agree by construction) and
 * checked by `assertNotApiKeyRequest`. A hand-composed `apiKey()` that reads
 * the key from elsewhere (`apiKeyHeaders: ["authorization"]`, a
 * `customAPIKeyGetter`) is still confined to `API_KEY_ALLOWED_PATHS` by
 * `enterpriseApiKeyValidator` — the header check is the second layer, not
 * the only one.
 */
export const API_KEY_HEADERS: readonly string[] = ["x-api-key"];

/**
 * Plugin id of `apiKeyLifecycle()`. The preset registers it directly after
 * upstream `api-key`, before `sso` (`./preset.ts`).
 */
export const API_KEY_LIFECYCLE_PLUGIN_ID = "enterprise-api-keys";

/** Same hash upstream stores (`defaultKeyHasher`): SHA-256, base64url, unpadded. */
export async function hashApiKey(key: string): Promise<string> {
  // Web Crypto, like `policy/enforcement.ts`'s magic-link token hash — no new dependency.
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(key));
  let binary = "";
  for (const byte of new Uint8Array(digest)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

interface UserRow {
  id: string;
  banned: boolean | null;
  banExpires: Date | number | string | null;
}

/** Mirrors `admin()`'s session hook: an expired temporary ban is not a ban. */
function isBanned(user: UserRow): boolean {
  if (!user.banned) return false;
  if (user.banExpires === null || user.banExpires === undefined) return true;
  const expires = new Date(user.banExpires).getTime();
  return Number.isNaN(expires) ? true : expires >= Date.now();
}

/**
 * `customAPIKeyValidator` for `apiKey({...})`. Upstream runs it on BOTH
 * key-use paths: the mock-session hook (only when an integrator enables
 * `enableSessionForAPIKeys`; the validator runs before the key row is even
 * loaded there) and `/api-key/verify` (`auth.api.verifyApiKey`, the
 * server-only path products use; the validator runs after the row lookup, so
 * an unknown key is already `INVALID_API_KEY` by then).
 *
 * Two checks, in order:
 *
 * 1. **Where** the key is being used. On the mock-session path `ctx.path` is
 *    the endpoint the key is trying to authenticate to; anything outside
 *    `API_KEY_ALLOWED_PATHS` (`isApiKeyRefusedPath`) is `403
 *    API_KEY_NOT_ALLOWED_HERE` before the key is even looked up — so a
 *    refused request never consumes the key's rate limit either. This is
 *    the layer that holds however the key is carried — a hand-composed
 *    `apiKey()` with `apiKeyHeaders: ["authorization"]` or a
 *    `customAPIKeyGetter` reading a query parameter never presents an
 *    `x-api-key` header to the gate's header check
 *    (`assertNotApiKeyRequest`), but it cannot mint a session without
 *    running this validator. Upstream's own verify call (`auth.api.
 *    verifyApiKey`, path-less) is let through by `isApiKeyVerifyCall`, so
 *    the verify path is never refused by this check.
 * 2. **Who** the key belongs to: the user row is re-read on every use and a
 *    banned (`USER_BANNED`; an expired temporary ban is not a ban) or missing
 *    (`USER_NOT_FOUND`) user is refused.
 *
 * Throws a typed `APIError` rather than returning `false` so both paths
 * surface a code: `/api-key/verify` answers `{ valid: false, error: { code }
 * }` and the mock-session hook a 401/403 — instead of upstream's generic
 * `KEY_NOT_FOUND`/`INVALID_API_KEY`. An unknown key returns `true` so
 * upstream keeps answering `INVALID_API_KEY` exactly as before.
 */
export async function enterpriseApiKeyValidator({
  ctx,
  key,
}: {
  ctx: GenericEndpointContext;
  key: string;
}): Promise<boolean> {
  if (
    typeof ctx.path === "string" &&
    isApiKeyRefusedPath(ctx.path) &&
    !isApiKeyVerifyCall(ctx, key)
  ) {
    throw new APIError("FORBIDDEN", {
      code: API_KEY_ERROR.API_KEY_NOT_ALLOWED_HERE,
      message: API_KEY_NOT_ALLOWED_HERE_MESSAGE,
    });
  }
  const row = await ctx.context.adapter.findOne<{ referenceId: string }>({
    model: "apikey",
    where: [{ field: "key", value: await hashApiKey(key) }],
  });
  if (!row) return true;
  const user = await ctx.context.adapter.findOne<UserRow>({
    model: "user",
    where: [{ field: "id", value: row.referenceId }],
  });
  if (!user) {
    throw new APIError("UNAUTHORIZED", {
      code: API_KEY_ERROR.USER_NOT_FOUND,
      message: "The user this API key belongs to no longer exists.",
    });
  }
  if (isBanned(user)) {
    throw new APIError("UNAUTHORIZED", {
      code: API_KEY_ERROR.USER_BANNED,
      message: "The user this API key belongs to is banned.",
    });
  }
  return true;
}

export interface ApiKeyRevocationActor {
  actorType: "user" | "scim" | "system";
  actorId: string | null;
}

/**
 * The minimal context `revokeUserApiKeys` needs — an endpoint context, or a
 * SCIM transaction's `{ context: { adapter } }` (a `DBTransactionAdapter`,
 * which has everything but `transaction`).
 */
export interface ApiKeyRevocationContext {
  context: {
    adapter: Pick<AuthContext["adapter"], "findOne" | "findMany" | "deleteMany">;
    logger?: AuthContext["logger"];
  };
}

const API_KEY_PAGE_SIZE = 100;

async function listUserApiKeyIds(ctx: ApiKeyRevocationContext, userId: string): Promise<string[]> {
  const ids: string[] = [];
  let offset = 0;
  for (;;) {
    // Explicit `limit`: the adapter caps an unbounded `findMany` at 100.
    const page = await ctx.context.adapter.findMany<{ id: string }>({
      model: "apikey",
      where: [{ field: "referenceId", value: userId }],
      limit: API_KEY_PAGE_SIZE,
      offset,
      sortBy: { field: "id", direction: "asc" },
    });
    for (const row of page) ids.push(row.id);
    if (page.length < API_KEY_PAGE_SIZE) return ids;
    offset += page.length;
  }
}

const silentLogger = {
  error: () => {},
  warn: () => {},
  info: () => {},
  debug: () => {},
  success: () => {},
} as unknown as AuthContext["logger"];

/**
 * Deletes every API key of `userId` and audits one `api_key.revoked` row per
 * key into every organization the user belongs to.
 *
 * The org set is captured **before** the rows are deleted and is the union
 * of the user's `member` rows and `options.orgIds` — the caller passes the
 * latter where the memberships are already gone by the time it runs
 * (`/admin/remove-user` stashes them on the way in; the SCIM identity hook
 * runs after the projector removed the SCIM-owned membership, so it passes
 * the provisioning orgs). `memberOrgIds` fails closed past 5000 memberships
 * (`POLICY_MEMBERSHIP_SCAN_OVERFLOW`), same as policy resolution.
 *
 * Returns the number of keys revoked (0 = nothing to do, nothing written).
 */
export async function revokeUserApiKeys(
  ctx: ApiKeyRevocationContext,
  userId: string,
  actor: ApiKeyRevocationActor,
  reason: string,
  options: ChainWriteOptions & { orgIds?: readonly string[] } = {},
): Promise<number> {
  const keyIds = await listUserApiKeyIds(ctx, userId);
  if (keyIds.length === 0) return 0;
  const policyCtx = {
    context: { adapter: ctx.context.adapter, logger: ctx.context.logger ?? silentLogger },
  } as unknown as GenericEndpointContext;
  const orgIds = new Set<string>(options.orgIds ?? []);
  for (const orgId of await memberOrgIds(policyCtx, userId)) orgIds.add(orgId);
  await ctx.context.adapter.deleteMany({
    model: "apikey",
    where: [{ field: "referenceId", value: userId }],
  });
  for (const orgId of orgIds) {
    for (const keyId of keyIds) {
      await writeAudit(
        ctx as { context: Pick<AuthContext, "adapter"> },
        {
          orgId,
          actorType: actor.actorType,
          actorId: actor.actorId,
          action: "api_key.revoked",
          targetType: "api_key",
          targetId: keyId,
          metadata: { reason, userId },
        },
        { chainKey: options.chainKey },
      );
    }
  }
  return keyIds.length;
}

const DEPROVISION_REASONS: Record<string, string> = {
  "/admin/ban-user": "admin.ban",
  "/admin/remove-user": "admin.remove",
};

// Where the `hooks.before` on `/admin/remove-user` stashes the target's org
// ids for the matching `hooks.after` (upstream's `deleteUser` takes the
// `member` rows with it before the after-hook runs). Kept on the per-request
// `ctx.context`, like the audit plugin's actor stash — never on anything
// shared between requests.
const ORGS_STASH_KEY = "enterpriseApiKeyOrgs";

function targetUserId(body: unknown): string | null {
  const userId = (body as { userId?: unknown } | undefined)?.userId;
  return typeof userId === "string" && userId ? userId : null;
}

/**
 * Revokes a user's API keys when an admin bans or removes them
 * (`/admin/ban-user`, `/admin/remove-user`) — upstream kills the sessions on
 * both and nothing else. Runs only on a 200 (an `APIError` or a non-200
 * `Response` means nothing was deprovisioned). SCIM deactivation revokes
 * through `./scim.ts`; session revocation alone (`/admin/revoke-user-
 * sessions`, `/revoke-sessions`) is deliberately *not* a key revocation —
 * the identity is unchanged and `enterpriseApiKeyValidator` keeps binding
 * each use to the live user row.
 *
 * Also keeps the expiry bound honest on `/api-key/update`: upstream's
 * `updateApiKey` accepts `expiresIn: null`, skips the min/max check for it
 * and writes `expiresAt = null` — so any key owner could turn a 90-day key
 * into a perpetual one, past both `apiKeys.defaultExpiresInS` and the
 * `apiKeys.maxExpiresInDays` ceiling. Refused with `400
 * API_KEY_EXPIRY_REQUIRED` unless the operator chose `defaultExpiresInS:
 * null` ("never expire") — their explicit opt-out, applied consistently to
 * create and update. A finite `expiresIn` still goes through upstream's
 * ceiling check (`EXPIRES_IN_IS_TOO_LARGE`).
 */
export function apiKeyLifecycle(
  opts: {
    audit?: { chainKey?: string };
    apiKeys?: { defaultExpiresInS?: number | null };
  } = {},
) {
  const chainKey = opts.audit?.chainKey;
  const perpetualKeysAllowed = opts.apiKeys?.defaultExpiresInS === null;
  return {
    id: API_KEY_LIFECYCLE_PLUGIN_ID,
    hooks: {
      before: [
        {
          matcher: (ctx) => ctx.path === "/api-key/update",
          handler: createAuthMiddleware(async (ctx) => {
            // A key never re-issues its own lifetime: the gate refuses the
            // header on this path too, but this plugin's hooks run first
            // (preset order), so the refusal has to be here as well for a
            // key-carrying request to get the 403, not a 400.
            assertNotApiKeyRequest(ctx);
            if (perpetualKeysAllowed) return;
            const body = ctx.body as { expiresIn?: unknown } | undefined;
            if (body && "expiresIn" in body && body.expiresIn === null) {
              throw new APIError("BAD_REQUEST", {
                code: API_KEY_ERROR.API_KEY_EXPIRY_REQUIRED,
                message:
                  "An API key's expiry cannot be removed; pass a lifetime within apiKeys.maxExpiresInDays or omit expiresIn.",
              });
            }
          }),
        },
        {
          matcher: (ctx) => ctx.path === "/admin/remove-user",
          handler: createAuthMiddleware(async (ctx) => {
            const userId = targetUserId(ctx.body);
            if (!userId) return;
            // Only for a signed-in caller: an anonymous request is answered
            // 401 by the endpoint itself and must not trigger the scan.
            const full = ctx as unknown as GenericEndpointContext;
            if (!(await getSessionFromCtx(full).catch(() => null))) return;
            (ctx.context as unknown as Record<string, unknown>)[ORGS_STASH_KEY] =
              await memberOrgIds(full, userId);
          }),
        },
      ],
      after: [
        {
          matcher: (ctx) => !!ctx.path && Object.hasOwn(DEPROVISION_REASONS, ctx.path),
          handler: createAuthMiddleware(async (ctx) => {
            const reason = DEPROVISION_REASONS[ctx.path];
            if (!reason) return;
            const returned = ctx.context.returned;
            if (isAPIError(returned)) return;
            if (returned instanceof Response && returned.status !== 200) return;
            const userId = targetUserId(ctx.body);
            if (!userId) return;
            const full = ctx as unknown as GenericEndpointContext;
            const stashed = (ctx.context as unknown as Record<string, unknown>)[ORGS_STASH_KEY];
            await revokeUserApiKeys(
              full,
              userId,
              { actorType: "user", actorId: full.context.session?.user.id ?? null },
              reason,
              { chainKey, orgIds: Array.isArray(stashed) ? (stashed as string[]) : [] },
            );
          }),
        },
      ],
    },
  } satisfies BetterAuthPlugin;
}

/**
 * The only better-auth endpoint a request carrying an API key may reach
 * over HTTP — an allow-list, not a deny-list (verifier round 3, F6/F7: a
 * deny-list is fail-open for every endpoint it does not know, and
 * `/list-sessions` handed a key the owner's raw session tokens while a
 * `jwt()` or `oneTimeToken()` plugin a product adds minted a fresh
 * credential from a key). Built from what the fleet products actually do
 * with a key (2026-09-26, read-only survey of the seven `enterprisePreset`
 * integrators — evidence table in the fork PR and plan §6): every one of
 * them calls `auth.api.getSession({ headers })` with the incoming request's
 * headers (which is where an `x-api-key` header reaches this package) and
 * none opts into the mock session. Nothing else: not the organization,
 * provider, account or key *reads* rounds 2–3 allow-listed (no product
 * reads them with a key; a key's owner resolves through `/get-session`),
 * not sign-in flows (no key is ever sent to them), not any endpoint of a
 * plugin added later. Widening this set is a reviewed change to this
 * package, on evidence, never a per-product option — that is the point.
 *
 * The api-key plugin's own verify path (`auth.api.verifyApiKey`, the
 * server-only call products use) is the one other place the validator runs;
 * it has no HTTP route and no path (`ctx.path` is one of
 * `SERVER_ONLY_PATHS`), so it is not in this set — see
 * `isApiKeyVerifyCall`.
 *
 * Paths are matched exactly against the endpoint's declared path
 * (`ctx.path`), never normalised: better-call answers 404 for a trailing
 * slash or case mismatch, so there is nothing to normalise here.
 */
export const API_KEY_ALLOWED_PATHS: ReadonlySet<string> = new Set(["/get-session"]);

/**
 * The two `ctx.path` values an endpoint that declares no path — a
 * `createAuthEndpoint.serverOnly({ method, body })` endpoint, which has no
 * HTTP route and is reachable only from the product's own server code
 * (`auth.api.*`) — shows to this module: `virtual:` inside the endpoint
 * itself (better-call fills it in for a path-less endpoint,
 * `node_modules/better-call/dist/context.mjs`) and `/` inside a plugin
 * `hooks.before` handler (better-auth's dispatcher passes the endpoint's
 * undefined path into the hook, `node_modules/better-auth/dist/api/
 * dispatch.mjs`, so the `createAuthMiddleware` context falls back to the
 * middleware's own `/`, `node_modules/better-call/dist/middleware.mjs`). An
 * HTTP request never produces either: the router sets the matched route's
 * path, and no route is declared as `/`.
 */
export const SERVER_ONLY_PATHS: ReadonlySet<string> = new Set(["virtual:", "/"]);

/** Whether `path` is one of `SERVER_ONLY_PATHS`. */
export function isServerOnlyPath(path: string): boolean {
  return SERVER_ONLY_PATHS.has(path);
}

/** Whether `path` is one of `API_KEY_ALLOWED_PATHS` (exact match). */
export function isApiKeyAllowedPath(path: string): boolean {
  return API_KEY_ALLOWED_PATHS.has(path);
}

/**
 * Whether a request carrying an API key is refused on `path` (`403
 * API_KEY_NOT_ALLOWED_HERE`): every better-auth endpoint that is not in
 * `API_KEY_ALLOWED_PATHS` — the management surface, credential minting,
 * every write, every read other than the owner's own session, every
 * path-less server-only endpoint and every endpoint of a plugin this
 * package does not know (fail-closed by construction). Enforced twice: by
 * `enterpriseApiKeyValidator` (whatever carries the key, before the key is
 * looked up; it additionally lets upstream's own verify call through, see
 * `isApiKeyVerifyCall`) and by the gate's first hook on the `x-api-key`
 * header alone (`assertNotApiKeyRequest`, on every HTTP-routable path, so
 * it also holds under the preset default). `GATED_PATHS` is a subset by
 * construction (pinned by `test/security/gap1-api-keys.test.ts`).
 */
export function isApiKeyRefusedPath(path: string): boolean {
  return !isApiKeyAllowedPath(path);
}

/**
 * Whether the validator is being run for upstream's own `verifyApiKey`
 * endpoint (`auth.api.verifyApiKey({ body: { key } })`): a path-less
 * server-only call (`SERVER_ONLY_PATHS` — the validator runs twice for it
 * when a product forwards headers that carry the key: from the mock-session
 * hook, path `/`, and from the endpoint's own `validateApiKey`, path
 * `virtual:`) whose body carries the very key being validated — which is
 * how that endpoint hands the key to `validateApiKey` and on to the
 * validator. Recognised structurally rather than by path because the
 * endpoint declares none, and deliberately *not* as "any server-only call":
 * the other path-less endpoints upstream mounts (`viewBackupCodes`,
 * `generateTOTP`, SCIM token minting, JWT signing, …) stay refused for a
 * key even when a product forwards the request headers into them. Over HTTP
 * `ctx.path` is always the route's path, so this never matches an HTTP
 * request.
 */
export function isApiKeyVerifyCall(ctx: { path?: string; body?: unknown }, key: string): boolean {
  if (typeof ctx.path !== "string" || !isServerOnlyPath(ctx.path)) return false;
  const body = ctx.body as { key?: unknown } | null | undefined;
  return typeof body?.key === "string" && body.key === key;
}

/**
 * Gate helper: refuses a request that carries an API key on every path
 * outside `API_KEY_ALLOWED_PATHS` (the gate's first hook matches on
 * `isApiKeyRefusedPath`) — the management surface (`/enterprise/*`), every
 * credential-minting path (`GATED_PATHS`, incl. `/api-key/create`), every
 * key, account, credential, organization and SSO-provider write, every read
 * other than the owner's own session, and every endpoint of a plugin this
 * package does not know. Keys are for a product's own API; with the opt-in
 * mock session on they would otherwise authenticate the key's owner to
 * everything that owner can do, including minting further keys or another
 * credential, re-issuing their own lifetime, reconfiguring the org or
 * rewriting its IdP — a leaked key must never be able to do any of that.
 * Judged on the header alone (so it also holds under the preset default,
 * where upstream ignores the header): a browser session never sends one.
 * The validator-level refusal in `enterpriseApiKeyValidator` is the layer
 * that covers keys carried some other way.
 */
export function assertNotApiKeyRequest(ctx: { headers?: Headers | null }): void {
  const headers = ctx.headers;
  if (!headers) return;
  for (const name of API_KEY_HEADERS) {
    if (headers.get(name)) {
      throw new APIError("FORBIDDEN", {
        code: API_KEY_ERROR.API_KEY_NOT_ALLOWED_HERE,
        message: API_KEY_NOT_ALLOWED_HERE_MESSAGE,
      });
    }
  }
}
