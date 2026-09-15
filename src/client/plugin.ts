// Alpha Bros enterprise layer — better-auth client plugin.
//
// `enterpriseClient()` types `authClient.enterprise.*` / the inferred
// `/enterprise/*` endpoint methods against the enterprise layer's own
// server plugins, the same way upstream's own client plugins do for their
// server counterpart (`organizationClient` <-> `organization()`,
// `ssoClient` <-> `sso()`: both set `$InferServerPlugin: {} as <return type
// of the server constructor>` in their real TS source — verified against
// `node_modules/@better-auth/sso/dist/client.d.mts`; the emitted `.mjs`
// only ever has the erased `$InferServerPlugin: {}`, since it's a type-only
// field).
//
// `EnterpriseServerPlugins` intersects the three server plugins
// `enterprisePreset` (`../server/preset.ts`) registers under `/enterprise/*`
// — `enterpriseApi`, `orgPolicy`, `auditLog`. `scimGroups` is deliberately
// excluded: it only extends the *upstream* SCIM Groups surface
// (`@better-auth/scim`'s own `/scim/v2/Groups*`), adding no `/enterprise/*`
// endpoint of its own for this client to type.
//
// Client task-9 fix round 1: `enterpriseApi`/`orgPolicy`/`auditLog` no
// longer declare an explicit `: BetterAuthPlugin` return type (see each
// file's own header comment) — `ReturnType<typeof X>` now carries every
// endpoint's real literal `path`/body/query types, which `PathToObject`
// (`better-auth/dist/client/path-to-object.d.mts`) needs to synthesize
// `authClient.enterprise.*`'s nested method names (verified: `client.
// enterprise.features` and `client.enterprise.policy.set` are both typed
// functions — `test/client/client.test.ts`'s `expectTypeOf` block).
//
// One wrinkle intersecting three *specific* return types (rather than the
// general `BetterAuthPlugin` interface) surfaces: each plugin's own `id`
// literal differs (`"enterprise-api"`/`"enterprise-policy"`/
// `"enterprise-audit"`) and — empirically, intersecting two object types
// that share a property whose literal types are disjoint collapses the
// *entire* intersection to `never` here (not just that one property to
// `never`, which is what a minimal repro of the same pattern with plain
// object-literal types does instead — verified both ways against this
// pinned TypeScript 5.9.3; a compiler quirk on these specific
// deeply-generic `ReturnType<>`s, not something to fully explain here).
// `Omit<_, "id">` on each plugin before intersecting, with a single
// `enterprise-*` id union reattached, sidesteps it entirely — an `as const`
// on each plugin's own `id` field (the fallback the controller ruling
// suggested) would not have helped, since the ids were never widened
// non-literal to begin with; the problem was three *different* literals
// colliding, not one losing its literal-ness.
import type { BetterAuthClientPlugin } from "@better-auth/core";
import type { auditLog } from "../server/audit/plugin";
import type { enterpriseApi } from "../server/enterprise-api/plugin";
import type { orgPolicy } from "../server/policy/plugin";

type NoId<T> = Omit<T, "id">;

type EnterpriseServerPlugins = NoId<ReturnType<typeof enterpriseApi>> &
  NoId<ReturnType<typeof orgPolicy>> &
  NoId<ReturnType<typeof auditLog>> & {
    id: "enterprise-api" | "enterprise-policy" | "enterprise-audit";
  };

/**
 * better-auth client plugin for `@alphabros/enterprise`. Add it to
 * `createAuthClient({ plugins: [enterpriseClient(), ssoClient(), ...] })`
 * alongside whichever upstream client plugins (re-exported from this
 * package's `./index.ts` for convenience) the product also needs.
 */
export function enterpriseClient() {
  return {
    id: "enterprise",
    $InferServerPlugin: {} as EnterpriseServerPlugins,
    // Every `/enterprise/*` GET endpoint, forced explicitly: an inferred
    // endpoint the client has no other signal for otherwise defaults to
    // POST (the same reason `organizationClient`/`ssoClient` list their own
    // GET-only routes here too, even though the server side already
    // declares `method: "GET"` on each).
    pathMethods: {
      "/enterprise/features": "GET",
      "/enterprise/sso/providers": "GET",
      "/enterprise/scim/tokens": "GET",
      "/enterprise/members": "GET",
      "/enterprise/policy": "GET",
      "/enterprise/audit/list": "GET",
      "/enterprise/audit/export": "GET",
      "/enterprise/audit/verify": "GET",
      "/enterprise/sso/test-login/finish": "GET",
    },
  } satisfies BetterAuthClientPlugin;
}
