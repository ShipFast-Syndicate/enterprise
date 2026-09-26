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
// and keeps keys off the management/credential-minting surface — twice: in
// the validator (`enterpriseApiKeyValidator`, whatever carries the key) and
// on the `x-api-key` header alone (`assertNotApiKeyRequest`, via the gate).
// Policy (`org_policy`) still governs sessions only: keys are bound to the
// user at use time and bounded by expiry (`apiKeys.*` in `./types.ts`).

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
  "API keys cannot be used to manage the organization, its SSO providers, the account or its credentials, or to mint credentials.";

/**
 * Request headers that carry an API key. Passed to upstream `apiKey({
 * apiKeyHeaders })` by the preset (so the two agree by construction) and
 * checked by `assertNotApiKeyRequest`. A hand-composed `apiKey()` that reads
 * the key from elsewhere (`apiKeyHeaders: ["authorization"]`, a
 * `customAPIKeyGetter`) is still refused on every `isApiKeyRefusedPath` by
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
 *    the endpoint the key is trying to authenticate to; a refused path
 *    (`isApiKeyRefusedPath`) is `403 API_KEY_NOT_ALLOWED_HERE` before the
 *    key is even looked up. This is the layer that holds however the key is
 *    carried — a hand-composed `apiKey()` with `apiKeyHeaders:
 *    ["authorization"]` or a `customAPIKeyGetter` reading a query parameter
 *    never presents an `x-api-key` header to the gate's header check
 *    (`assertNotApiKeyRequest`), but it cannot mint a session without
 *    running this validator. `/api-key/verify`'s own path is never refused.
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
  if (typeof ctx.path === "string" && isApiKeyRefusedPath(ctx.path)) {
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

// `/organization/*` is refused wholesale except these reads — the paths an
// integrator's API handler legitimately resolves for a key's owner (which
// orgs, which members, which role). Fail-closed on purpose: a write endpoint
// upstream adds later is refused until it is reviewed here, a read one
// merely needs adding to this list (upstream is pinned exactly, `README.md`).
const API_KEY_ALLOWED_ORG_READS: ReadonlySet<string> = new Set([
  "/organization/list",
  "/organization/get-full-organization",
  "/organization/get-organization",
  "/organization/list-members",
  "/organization/get-active-member",
  "/organization/get-active-member-role",
  "/organization/has-permission",
  "/organization/check-slug",
  "/organization/get-invitation",
  "/organization/list-invitations",
  "/organization/list-user-invitations",
  "/organization/list-teams",
  "/organization/list-user-teams",
  "/organization/list-team-members",
  "/organization/list-roles",
  "/organization/get-role",
]);

// `/sso/*` is refused wholesale except the sign-in/callback paths (no
// session — the browser and the IdP drive them) and the two provider reads
// (upstream sanitizes them: `clientIdLastFour`, never a secret). Everything
// else under `/sso/` is a provider write — `register`, `update-provider`,
// `delete-provider` (which also deletes every `account` row of that
// provider), `request-domain-verification`, `verify-domain` — i.e. the
// org's identity boundary that the domain binding (`./sso-domain.ts`) hangs
// on. `/sso/saml2/logout/:providerId` is deliberately *not* allow-listed: it
// is a session-scoped write (it deletes the caller's session and sends the
// IdP a LogoutRequest for the owner), not a sign-in or a read. Paths are
// compared as upstream declares them (`ctx.path` is the endpoint's pattern,
// e.g. `/sso/callback/:providerId`), so the parameterised ones match by
// prefix. Fail-closed on purpose, like `/organization/*`: a new upstream
// `/sso/*` endpoint is refused until it is reviewed here
// (`test/security/gap1-api-keys.test.ts` enumerates upstream's route table).
const API_KEY_ALLOWED_SSO_PATHS: ReadonlySet<string> = new Set([
  "/sso/callback",
  "/sso/saml2/sp/metadata",
  "/sso/providers",
  "/sso/get-provider",
]);
const API_KEY_ALLOWED_SSO_PREFIXES: readonly string[] = [
  "/sso/callback/",
  "/sso/saml2/sp/acs/",
  "/sso/saml2/sp/slo/",
];

// Exact paths refused to a key-carrying request, on top of the prefix rules
// below. `GATED_PATHS` (the gate's own table) is a subset of what this module
// refuses — pinned by `test/security/gap1-api-keys.test.ts` — so the
// validator-level check (`enterpriseApiKeyValidator`) needs nothing else.
const API_KEY_REFUSED_PATHS: ReadonlySet<string> = new Set([
  // Key writes: a key must never mint, extend, un-expire, re-enable or
  // delete a key — including itself. `/api-key/verify`, `/api-key/get` and
  // `/api-key/list` stay reachable (the verify path is what products call,
  // often forwarding the incoming request's headers).
  "/api-key/create",
  "/api-key/update",
  "/api-key/delete",
  // Account and credential writes: a leaked key must not rewrite the
  // profile, move the e-mail, set a password, register a new long-lived
  // credential (passkey), link a social identity to its owner (a persistent
  // credential — upstream's `freshSessionMiddleware` is satisfied by the
  // mock session, whose `createdAt` is "now") or unlink one.
  "/update-user",
  "/change-email",
  "/change-password",
  "/set-password",
  "/delete-user",
  "/link-social",
  "/unlink-account",
  "/passkey/generate-register-options",
  "/passkey/verify-registration",
  "/passkey/update-passkey",
  "/passkey/delete-passkey",
  // Credential *reads*: these return (and refresh) the owner's stored OAuth
  // provider tokens — a stronger credential than the key itself. Metadata
  // reads (`/list-accounts`, `/account-info`) expose no token and stay
  // reachable.
  "/get-access-token",
  "/refresh-token",
]);

// Whole surfaces refused to a key: the enterprise management API, the admin
// plugin, and two-factor enrolment/verification (a key never satisfies or
// disables a second factor).
const API_KEY_REFUSED_PREFIXES: readonly string[] = ["/enterprise/", "/admin/", "/two-factor/"];

/**
 * Whether a request carrying an API key is refused on `path` (`403
 * API_KEY_NOT_ALLOWED_HERE`) — the management surface, credential minting,
 * account/credential writes, credential-yielding reads, every organization
 * write and every SSO provider write. Enforced twice: by
 * `enterpriseApiKeyValidator` (whatever carries the key, before the key is
 * looked up) and by the gate's first hook on the `x-api-key` header alone
 * (`assertNotApiKeyRequest`, so it also holds under the preset default). The
 * gate ORs this with its own `GATED_PATHS` table, a subset. Reads, sign-in
 * flows and `/api-key/verify` are never refused: a key is for a product's
 * own API, and with the opt-in mock session the product's handler still
 * needs `/get-session` and the owner's org reads.
 */
export function isApiKeyRefusedPath(path: string): boolean {
  if (API_KEY_REFUSED_PATHS.has(path)) return true;
  if (API_KEY_REFUSED_PREFIXES.some((prefix) => path.startsWith(prefix))) return true;
  if (path.startsWith("/organization/")) return !API_KEY_ALLOWED_ORG_READS.has(path);
  if (path.startsWith("/sso/")) {
    return (
      !API_KEY_ALLOWED_SSO_PATHS.has(path) &&
      !API_KEY_ALLOWED_SSO_PREFIXES.some((prefix) => path.startsWith(prefix))
    );
  }
  return false;
}

/**
 * Gate helper: refuses a request that carries an API key on the management
 * surface (`/enterprise/*`), a credential-minting path (`GATED_PATHS`,
 * incl. `/api-key/create`) and every path `isApiKeyRefusedPath` names (key,
 * account, credential, organization and SSO-provider writes). Keys are for a
 * product's own API; with the opt-in mock session on they would otherwise
 * authenticate the key's owner to everything that owner can do, including
 * minting further keys, re-issuing their own lifetime, reconfiguring the org
 * or rewriting its IdP — a leaked key must never be able to do any of that.
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
