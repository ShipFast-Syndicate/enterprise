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
// and keeps keys off the management/credential-minting surface. Policy
// (`org_policy`) still governs sessions only: keys are bound to the user at
// use time and bounded by expiry (`apiKeys.*` in `./types.ts`).

import type { AuthContext, BetterAuthPlugin, GenericEndpointContext } from "better-auth";
import { APIError, createAuthMiddleware, getSessionFromCtx, isAPIError } from "better-auth/api";
import { writeAudit, type ChainWriteOptions } from "./audit/chain";
import { memberOrgIds } from "./policy/store";

export const API_KEY_ERROR = {
  USER_BANNED: "USER_BANNED",
  USER_NOT_FOUND: "USER_NOT_FOUND",
  API_KEY_NOT_ALLOWED_HERE: "API_KEY_NOT_ALLOWED_HERE",
} as const;

/**
 * Request headers that carry an API key. Passed to upstream `apiKey({
 * apiKeyHeaders })` by the preset (so the two agree by construction) and
 * checked by `assertNotApiKeyRequest`.
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
 * key-use paths: the `x-api-key` mock-session hook (only when an integrator
 * enables `enableSessionForAPIKeys`; the validator runs before the key row is
 * even loaded there) and `/api-key/verify` (`auth.api.verifyApiKey`, the
 * server-only path products use; the validator runs after the row lookup, so
 * an unknown key is already `INVALID_API_KEY` by then).
 *
 * Throws a typed `APIError` rather than returning `false` so both paths
 * surface a code: `/api-key/verify` answers `{ valid: false, error: { code }
 * }` and the mock-session hook a 401 — instead of upstream's generic
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
 */
export function apiKeyLifecycle(opts: { audit?: { chainKey?: string } } = {}) {
  const chainKey = opts.audit?.chainKey;
  return {
    id: API_KEY_LIFECYCLE_PLUGIN_ID,
    hooks: {
      before: [
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
 * Gate helper: refuses a request that carries an API key on the management
 * surface (`/enterprise/*`) or a credential-minting path (`GATED_PATHS`,
 * incl. `/api-key/create`). Keys are for a product's own API; with the
 * opt-in mock session on they would otherwise authenticate the key's owner
 * to everything that owner can do, including minting further keys — a
 * leaked key must never be able to re-mint itself or reconfigure the org.
 * Judged on the header alone (so it also holds under the preset default,
 * where upstream ignores the header): a browser session never sends one.
 */
export function assertNotApiKeyRequest(ctx: { headers?: Headers | null }): void {
  const headers = ctx.headers;
  if (!headers) return;
  for (const name of API_KEY_HEADERS) {
    if (headers.get(name)) {
      throw new APIError("FORBIDDEN", {
        code: API_KEY_ERROR.API_KEY_NOT_ALLOWED_HERE,
        message: "API keys cannot be used to manage the organization or to mint credentials.",
      });
    }
  }
}
