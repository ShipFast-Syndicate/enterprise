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
import { assertNotApiKeyRequest, isApiKeyRefusedPath, isServerOnlyCall } from "./api-keys";
import { isOrgId, ORG_ID_FIELDS, requestOrgIds } from "./org-id";
import { withDatabaseErrorRedaction } from "./db-errors";

export const GATED_PATHS: Record<string, Feature> = {
  "/sso/register": "sso",
  "/sso/request-domain-verification": "sso",
  "/sso/verify-domain": "sso",
  // F-17: changing or deleting a provider needs the `sso` entitlement of the
  // org that owns it, like registering one. An org-less (legacy, personal)
  // provider has no org to be entitled, so it is refused here — operators
  // manage one server-side (docs/security.md, "SSO providers without an
  // organization").
  "/sso/update-provider": "sso",
  "/sso/delete-provider": "sso",
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

/** A request field that can name the organization an endpoint acts on. */
export interface GateOrgField {
  from: "body" | "query";
  field: (typeof ORG_ID_FIELDS)[number];
}

/**
 * Where a gated endpoint takes the organization it acts on — the one org
 * the gate checks membership and entitlement for.
 *
 * - `request`: the first of `fields` that holds an id (an empty string counts
 *   as absent, as upstream's `||` does), else — only when `activeOrganization`
 *   is set — the session's active organization, a stored value. Every other
 *   org-id carrier of the request is ignored, because the endpoint ignores it.
 * - `provider`: the organization of the stored SSO provider that
 *   `body.providerId` names — never the session's or the request's org. A
 *   provider without an org (legacy, personal) is refused.
 *
 * `refs` are the `file:line`s where the endpoint reads that source;
 * `test/security/gate-org-source.test.ts` checks that each line still names
 * every declared field.
 */
export type GateOrgSource =
  | {
      kind: "request";
      fields: readonly GateOrgField[];
      activeOrganization: boolean;
      refs: readonly string[];
    }
  | { kind: "provider"; refs: readonly string[] };

const body = (field: GateOrgField["field"]): GateOrgField => ({ from: "body", field });
const query = (field: GateOrgField["field"]): GateOrgField => ({ from: "query", field });
const SSO = "node_modules/@better-auth/sso/dist/index.mjs";

/**
 * The org source of every `GATED_PATHS` entry, read off the handler that
 * serves it. The gate used to check the first org id the request carried in
 * any field (`body.organizationId`, `body.orgId`, `?orgId`, then the active
 * org), whatever the endpoint itself read: `/organization/create-team` acts
 * on `body.organizationId || activeOrganizationId` only, so a caller who
 * named an entitled org in `?orgId` or `body.orgId` created teams in their
 * unentitled active org. A gated path without an entry here is refused
 * (`GATE_ORG_SOURCE_UNDECLARED`) — fail closed.
 */
export const GATE_ORG_SOURCES: Record<string, GateOrgSource> = {
  // `if (ctx.body.organizationId)` … `organizationId: body.organizationId`;
  // required here (`BODY_ORG_REQUIRED_PATHS`), no active-org fallback.
  "/sso/register": {
    kind: "request",
    fields: [body("organizationId")],
    activeOrganization: false,
    refs: [`${SSO}:3357`, `${SSO}:3506`],
  },
  // `checkProviderAccess(ctx, body.providerId)` / `ctx.body.providerId`.
  "/sso/request-domain-verification": { kind: "provider", refs: [`${SSO}:2540`] },
  "/sso/verify-domain": { kind: "provider", refs: [`${SSO}:2578`] },
  "/sso/update-provider": { kind: "provider", refs: [`${SSO}:2367`] },
  "/sso/delete-provider": { kind: "provider", refs: [`${SSO}:2467`] },
  // `ctx.body.organizationId || session?.session.activeOrganizationId`.
  "/organization/create-team": {
    kind: "request",
    fields: [body("organizationId")],
    activeOrganization: true,
    refs: ["node_modules/better-auth/dist/plugins/organization/routes/crud-team.mjs:75"],
  },
  // Upstream reads `ctx.body.organizationId` (an organization-owned key,
  // `references: "organization"`). A user-owned key — the preset's default —
  // belongs to no org, and upstream reads none: the entitlement is then the
  // session's active organization's, a stored value (`/organization/set-active`
  // checks membership), never a caller-named one.
  "/api-key/create": {
    kind: "request",
    fields: [body("organizationId")],
    activeOrganization: true,
    refs: ["node_modules/@better-auth/api-key/dist/index.mjs:739"],
  },
  // This package's own endpoints: exactly the field each handler reads.
  "/enterprise/audit/list": {
    kind: "request",
    fields: [query("orgId")],
    activeOrganization: false,
    refs: ["src/server/audit/plugin.ts:1303"],
  },
  "/enterprise/audit/export": {
    kind: "request",
    fields: [query("orgId")],
    activeOrganization: false,
    refs: ["src/server/audit/plugin.ts:1333"],
  },
  "/enterprise/audit/compact": {
    kind: "request",
    fields: [body("orgId")],
    activeOrganization: false,
    refs: ["src/server/audit/plugin.ts:1478"],
  },
  "/enterprise/policy/set": {
    kind: "request",
    fields: [body("orgId")],
    activeOrganization: false,
    refs: ["src/server/policy/plugin.ts:166"],
  },
  "/enterprise/sso/providers": {
    kind: "request",
    fields: [query("orgId")],
    activeOrganization: false,
    refs: ["src/server/enterprise-api/sso.ts:140"],
  },
  "/enterprise/sso/register": {
    kind: "request",
    fields: [body("organizationId")],
    activeOrganization: false,
    refs: ["src/server/enterprise-api/sso.ts:231"],
  },
  "/enterprise/sso/test-login/start": {
    kind: "request",
    fields: [body("orgId")],
    activeOrganization: false,
    refs: ["src/server/enterprise-api/sso.ts:274"],
  },
  "/enterprise/scim/tokens": {
    kind: "request",
    fields: [query("orgId")],
    activeOrganization: false,
    refs: ["src/server/enterprise-api/scim.ts:135"],
  },
  "/enterprise/scim/tokens/create": {
    kind: "request",
    fields: [body("orgId")],
    activeOrganization: false,
    refs: ["src/server/enterprise-api/scim.ts:50"],
  },
  "/enterprise/scim/tokens/rotate": {
    kind: "request",
    fields: [body("orgId")],
    activeOrganization: false,
    refs: ["src/server/enterprise-api/scim.ts:50"],
  },
  "/enterprise/scim/tokens/revoke": {
    kind: "request",
    fields: [body("orgId")],
    activeOrganization: false,
    refs: ["src/server/enterprise-api/scim.ts:160"],
  },
};

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
// gate (a `provider` source answers `NOT_ORG_MEMBER` for it), but it
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
          // Innermost, directly around the product's adapter: a query that
          // fails anywhere reaches the logs without its SQL or parameter
          // values (`./db-errors.ts`). Inside the encryption wrapper, not
          // around it: that wrapper routes each call to the adapter the
          // request's async-local store holds, which is the one returned
          // here, so it must stay the outermost layer.
          adapter: withSecretEncryption(
            withDatabaseErrorRedaction(context.adapter),
            opts.secretsKey,
            {
              // F-06: an undecryptable secret is an operator problem (rotated
              // key, corrupted row), reported through the product's logger —
              // never a request failure for every tenant.
              onUndecryptable: ({ providerId, field }) =>
                context.logger.error(
                  `ssoProvider "${providerId}" field "${field}" could not be decrypted (wrong or rotated secretsKey, or a corrupted/transplanted ciphertext); the value is left sealed and this provider's IdP exchange will fail until the secret is re-entered.`,
                ),
            },
          ),
        },
      };
    },
    hooks: {
      before: [
        {
          // First, before any session/org resolution: a request carrying an
          // API key reaches only `API_KEY_ALLOWED_PATHS` (gap 1 —
          // `./api-keys.ts`; `GATED_PATHS` and `/enterprise/*` are outside
          // that allow-list by construction, pinned by
          // `test/security/gap1-api-keys.test.ts`). `403
          // API_KEY_NOT_ALLOWED_HERE` on the header alone, whatever else the
          // request carries. Every HTTP-routable path; a path-less
          // server-only call (`SERVER_ONLY_PATHS`, e.g. `auth.api.
          // verifyApiKey({ headers })` — its hook context has no path at
          // all) has no HTTP route, and with the mock session on it is the
          // validator layer that decides (`isApiKeyVerifyCall`) — without
          // it the header is inert there.
          // A literal `/` product route is an HTTP request, not the
          // server-only sentinel (`isServerOnlyCall` checks the `Request`).
          matcher: (ctx) => !!ctx.path && !isServerOnlyCall(ctx) && isApiKeyRefusedPath(ctx.path),
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

            // Every org-id field of the body and the query string is checked
            // first, before the session lookup or any other query: a value
            // that is not a short string (an array — which is what a
            // duplicated query parameter parses to —, an object, a number)
            // answers `400 ORG_ID_INVALID` (`./org-id.ts`). It used to reach
            // `getMemberRoles` below as a query value; the driver refused to
            // bind it, the request answered 500 and the failed query with its
            // parameters went to the error log.
            const ids = requestOrgIds(ctx.body, ctx.query);

            // The org the endpoint acts on comes from its declared source
            // only (`GATE_ORG_SOURCES`). A gated path without one is refused,
            // with or without a session.
            const source = GATE_ORG_SOURCES[ctx.path];
            if (!source) {
              throw new APIError("FORBIDDEN", {
                code: "GATE_ORG_SOURCE_UNDECLARED",
                message: "This endpoint has no declared organization source.",
              });
            }

            // The hook context (`HookEndpointContext`) is structurally the
            // same shape `getSessionFromCtx`/`requireFeature` need
            // (`{ context: AuthContext, path, body, ... }` — a
            // `GenericEndpointContext` minus a few endpoint-specific,
            // unused-here fields); this hook runs inside the same request
            // dispatch as the endpoint itself, so `ctx.context` is the real,
            // live `AuthContext` for this request either way.
            const session = await getSessionFromCtx(ctx as unknown as GenericEndpointContext);
            if (!session) return; // anonymous — let the endpoint answer 401

            let orgId: string | undefined;
            if (source.kind === "provider") {
              const providerId = (ctx.body as { providerId?: unknown } | undefined)?.providerId;
              const provider =
                typeof providerId === "string"
                  ? await ctx.context.adapter.findOne<{ organizationId?: string | null }>({
                      model: "ssoProvider",
                      where: [{ field: "providerId", value: providerId }],
                    })
                  : null;
              // Never let an entitled session/caller org authorize a change
              // to another provider, including a legacy unbound provider.
              orgId = isOrgId(provider?.organizationId) ? provider.organizationId : undefined;
              if (!orgId) {
                throw new APIError("FORBIDDEN", {
                  code: "NOT_ORG_MEMBER",
                  message: "You are not a member of this organization.",
                });
              }
            } else {
              for (const { from, field } of source.fields) {
                const value = ids[from][field];
                if (value) {
                  orgId = value;
                  break;
                }
              }
              if (BODY_ORG_REQUIRED_PATHS.has(ctx.path) && !orgId) {
                throw new APIError("BAD_REQUEST", {
                  code: "ORG_REQUIRED",
                  message: "organizationId is required.",
                });
              }
              // The session's active organization is a stored value; it is
              // used only where the endpoint itself falls back to it, and
              // only when it is an id.
              const active = (session.session as { activeOrganizationId?: unknown })
                .activeOrganizationId;
              if (!orgId && source.activeOrganization && isOrgId(active)) orgId = active;
            }
            if (!orgId) {
              throw new APIError("BAD_REQUEST", {
                code: "ORG_REQUIRED",
                message: "An organization id is required.",
              });
            }

            // Membership before entitlement (M-07). `orgId` here is still
            // caller-supplied on most paths (in the one field the endpoint
            // reads), and `resolveEntitlements` is the product's own
            // billing/plan lookup: letting a non-member reach
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
