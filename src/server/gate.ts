// Alpha Bros enterprise layer — entitlement gate plugin.
//
// `enterpriseGate` adds a single global `hooks.before` that intercepts the
// upper-tier paths listed in `GATED_PATHS` and enforces the matching
// `Feature` via `requireFeature` before the real endpoint ever runs.
//
// Anonymous calls are deliberately let through to the real endpoint: the
// gate only resolves the session to find the org id; if there is no
// session, the endpoint's own `sessionMiddleware` is the one that answers
// 401, not us (see the `!session` branch below).

import { APIError, createAuthMiddleware, getSessionFromCtx } from "better-auth/api";
import type { BetterAuthPlugin, GenericEndpointContext } from "better-auth";
import type { EnterpriseOptions, Feature } from "./types";
import { requireFeature } from "./entitlements";
import { getMemberRoles } from "./policy/store";
import { withSecretEncryption } from "./secrets";
import { buildSsoDomainGuardHook } from "./sso-domain";
import { assertEnterpriseOptions, takeDomainBindingOffUnlistedWarning } from "./options";
import { assertNotApiKeyRequest } from "./api-keys";

export const GATED_PATHS: Record<string, Feature> = {
  "/sso/register": "sso",
  "/sso/request-domain-verification": "sso",
  "/sso/verify-domain": "sso",
  "/organization/create-team": "teams",
  "/api-key/create": "api_keys",
  "/enterprise/audit/list": "audit_log",
  "/enterprise/audit/export": "audit_log",
  "/enterprise/audit/compact": "audit_log",
  "/enterprise/policy/set": "enforce_2fa", // any policy write needs the top tier
  // Task 7 (`./enterprise-api/plugin.ts`) portal wrappers. `/enterprise/
  // members` and `/enterprise/features` are deliberately absent — basic org
  // membership/entitlement reads, session + membership only (see that
  // plugin's own file headers).
  "/enterprise/sso/providers": "sso",
  "/enterprise/sso/register": "sso",
  "/enterprise/sso/test-login/start": "sso",
  // `/enterprise/sso/test-login/finish` is deliberately **absent** (C-1).
  // It is the one `/enterprise/*` path a browser reaches immediately after
  // an SSO sign-in, and the session that sign-in mints never carries an
  // `activeOrganizationId` (only `/organization/set-active` ever writes one
  // — `node_modules/better-auth/dist/plugins/organization/adapter.mjs:295`;
  // `@better-auth/sso` never does). It is also a GET with no body and no
  // `orgId` query parameter, so the org-id resolution below had *no* source
  // for it and answered `400 ORG_REQUIRED` on the default path — which made
  // the mandatory test login, and therefore `ssoEnforced`, unreachable for
  // every org. The org for that request comes from the provider row
  // (`ssoProvider.organizationId`), which is the trustworthy source anyway,
  // so the `sso` entitlement check lives in the handler itself
  // (`./enterprise-api/sso.ts`) where the provider is already resolved — and
  // fails through that endpoint's redirect rather than a JSON error page the
  // wizard cannot read.
  "/enterprise/scim/tokens": "scim",
  "/enterprise/scim/tokens/create": "scim",
  "/enterprise/scim/tokens/rotate": "scim",
  "/enterprise/scim/tokens/revoke": "scim",
};

// These upstream endpoints accept only a providerId. Their organization must
// come from the stored provider, independent of the caller's active organization.
const PROVIDER_DOMAIN_PATHS = new Set(["/sso/request-domain-verification", "/sso/verify-domain"]);

// Credential management is tenant-authorized; only owners may mint, rotate or
// revoke. Revoke joined the set for F-07: since 1.7 it is a *decommission*
// that replays every user the connection provisioned as inactive — a global
// ban, session wipe and API-key wipe — so an admin could lock a manually
// promoted owner out of the whole platform.
const OWNER_ONLY_PATHS = new Set([
  "/enterprise/scim/tokens/create",
  "/enterprise/scim/tokens/rotate",
  "/enterprise/scim/tokens/revoke",
]);

// Paths whose org must come from the request **body**, never from the
// session's active organization (audit gap 5). Upstream `/sso/register`
// runs its owner/admin check only when `body.organizationId` is present;
// without it, any signed-in user — a plain member, with the org's `sso`
// entitlement resolved from their *active* org by the fallback chain below —
// registered a "personal" (`organizationId: null`, `userId`-bound) provider
// claiming any domain. Such a row can never be domain-verified through this
// gate (`PROVIDER_DOMAIN_PATHS` answers `NOT_ORG_MEMBER` for it), but it
// still poisoned upstream's e-mail `/sign-in/sso` lookup (F-30) and was
// invisible to every org-scoped read. `400 ORG_REQUIRED` before the
// fallback chain closes it.
export const BODY_ORG_REQUIRED_PATHS = new Set(["/sso/register"]);

// No explicit `: BetterAuthPlugin` return-type annotation (client task-9 fix
// round 1, applied here too for consistency — see `./enterprise-api/
// plugin.ts`'s identical comment on `enterpriseApi`). `enterpriseGate` has
// no `endpoints` of its own, so this doesn't unlock any new client typing
// by itself, but keeps every plugin constructor in this package following
// the same `satisfies BetterAuthPlugin` convention.
export function enterpriseGate(opts: EnterpriseOptions) {
  // Validated here, not only in `./preset.ts`: this plugin is the one the
  // rest of the layer cannot work without (it carries `options` for
  // `requireFeature`, and installs the at-rest encryption wrapper below), so
  // a product that hand-composes its plugin list still gets the checks.
  assertEnterpriseOptions(opts);
  return {
    id: "enterprise-gate",
    // Exposed the same way built-in plugins (e.g. `jwt`) expose their
    // config on themselves — `requireFeature` reads it back off
    // `ctx.context.options.plugins` so it isn't tied to this specific
    // closure.
    options: opts,
    // Encryption at rest for IdP secrets (C-04). better-auth merges a
    // plugin's returned `context` into the live `AuthContext` and builds
    // `internalAdapter` from `context.adapter` *after* every plugin's
    // `init()` has run (`node_modules/better-auth/dist/context/helpers.mjs`),
    // so wrapping the adapter here covers both access paths — including
    // every `@better-auth/sso` read/write of `ssoProvider`. See
    // `./secrets.ts`.
    init(context) {
      // One line, once per process, through the auth logger: the binding is
      // off and nothing restricts which IdPs may sign users in (`./options.ts`).
      const warning = takeDomainBindingOffUnlistedWarning(opts);
      if (warning) context.logger.warn(warning);
      return {
        context: {
          adapter: withSecretEncryption(context.adapter, opts.secretsKey, {
            // F-06: an undecryptable secret is an operator problem (rotated
            // key, corrupted row), reported through the product's logger —
            // never a request failure for every tenant.
            onUndecryptable: ({ providerId, field }) =>
              context.logger.error(
                `ssoProvider "${providerId}" field "${field}" could not be decrypted (wrong or rotated secretsKey, or a corrupted/transplanted ciphertext); the value is left sealed and this provider's IdP exchange will fail until the secret is re-entered.`,
              ),
          }),
        },
      };
    },
    hooks: {
      before: [
        {
          // First, before any session/org resolution: the management surface
          // and credential minting are never key-authenticated (gap 1 —
          // `./api-keys.ts`). `403 API_KEY_NOT_ALLOWED_HERE` on the header
          // alone, whatever else the request carries.
          matcher: (ctx) =>
            !!ctx.path && (ctx.path in GATED_PATHS || ctx.path.startsWith("/enterprise/")),
          handler: createAuthMiddleware(async (ctx) => {
            assertNotApiKeyRequest(ctx);
          }),
        },
        {
          matcher: (ctx) => !!ctx.path && ctx.path in GATED_PATHS,
          handler: createAuthMiddleware(async (ctx) => {
            // `ctx.path` is guaranteed to be a `GATED_PATHS` key here — the
            // matcher above is the only way into this handler, and it
            // already checked `ctx.path in GATED_PATHS`. Kept as a defensive
            // fallback rather than a non-null assertion.
            const feature = GATED_PATHS[ctx.path];
            if (!feature) return;

            // The hook context (`HookEndpointContext`) is structurally the
            // same shape `getSessionFromCtx`/`requireFeature` need
            // (`{ context: AuthContext, path, body, ... }` — a
            // `GenericEndpointContext` minus a few endpoint-specific,
            // unused-here fields); this hook runs inside the same request
            // dispatch as the endpoint itself, so `ctx.context` is the real,
            // live `AuthContext` for this request either way.
            const session = await getSessionFromCtx(ctx as unknown as GenericEndpointContext);
            if (!session) return; // anonymous — let the endpoint answer 401

            const body = ctx.body as
              { organizationId?: string; orgId?: string; providerId?: string } | undefined;
            if (
              BODY_ORG_REQUIRED_PATHS.has(ctx.path) &&
              !(typeof body?.organizationId === "string" && body.organizationId)
            ) {
              throw new APIError("BAD_REQUEST", {
                code: "ORG_REQUIRED",
                message: "organizationId is required.",
              });
            }
            // GET endpoints (e.g. `/enterprise/audit/list|export`, Task 4)
            // carry the org id in the query string, not the body.
            const query = ctx.query as { orgId?: string } | undefined;
            let orgId =
              body?.organizationId ??
              body?.orgId ??
              query?.orgId ??
              (session.session as { activeOrganizationId?: string }).activeOrganizationId;
            if (PROVIDER_DOMAIN_PATHS.has(ctx.path)) {
              const provider =
                typeof body?.providerId === "string"
                  ? await ctx.context.adapter.findOne<{ organizationId?: string | null }>({
                      model: "ssoProvider",
                      where: [{ field: "providerId", value: body.providerId }],
                    })
                  : null;
              // Never let an entitled session/caller org authorize verification
              // for another provider, including a legacy unbound provider.
              orgId = provider?.organizationId ?? undefined;
              if (!orgId) {
                throw new APIError("FORBIDDEN", {
                  code: "NOT_ORG_MEMBER",
                  message: "You are not a member of this organization.",
                });
              }
            }
            if (!orgId) {
              throw new APIError("BAD_REQUEST", {
                code: "ORG_REQUIRED",
                message: "An organization id is required.",
              });
            }

            // Membership before entitlement (M-07). `orgId` here is still
            // caller-supplied on most paths, and `resolveEntitlements` is the
            // product's own billing/plan lookup: letting a non-member reach
            // it turned `/enterprise/*?orgId=<any string>` into both a
            // cross-tenant existence/plan oracle (`FEATURE_NOT_ENTITLED` =
            // "org exists, no plan" vs. `NOT_ORG_ADMIN` = "org exists and is
            // entitled") and a free amplifier into that lookup. A non-member
            // now gets the same `NOT_ORG_MEMBER` for every org id they do not
            // belong to, whatever its plan — and never reaches the resolver.
            const roles = await getMemberRoles(
              ctx as unknown as GenericEndpointContext,
              orgId,
              session.user.id,
            );
            if (roles.length === 0) {
              throw new APIError("FORBIDDEN", {
                code: "NOT_ORG_MEMBER",
                message: "You are not a member of this organization.",
              });
            }
            if (OWNER_ONLY_PATHS.has(ctx.path) && !roles.includes("owner")) {
              throw new APIError("FORBIDDEN", {
                code: "NOT_ORG_OWNER",
                message: "Owner role required.",
              });
            }

            await requireFeature(ctx as unknown as GenericEndpointContext, orgId, feature);
          }),
        },
        // SSO domain ownership/uniqueness, issuer allow-list and the e-mail
        // sign-in pin (F-30, F-28 — `./sso-domain.ts`). Runs *after* the
        // entitlement gate above: a caller who is not an entitled member of
        // the org named in the body never reaches the domain scan.
        buildSsoDomainGuardHook(opts),
      ],
    },
  } satisfies BetterAuthPlugin;
}
