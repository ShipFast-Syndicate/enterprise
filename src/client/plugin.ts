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
// Known limitation (not a Task 9 regression — pre-existing on the server
// side): `enterpriseApi`/`orgPolicy`/`auditLog` each declare an explicit
// `: BetterAuthPlugin` return type (`../server/enterprise-api/plugin.ts` et
// al.), so `ReturnType<typeof X>` is exactly that interface — whose
// `endpoints` field is the generic `{ [key: string]: Endpoint }` index
// signature (`@better-auth/core`'s `dist/types/plugin.d.mts`), not each
// endpoint's own literal `path`/body/query types. `PathToObject`
// (`better-auth/dist/client/path-to-object.d.mts`) needs those literal
// `path` strings to synthesize `authClient.enterprise.*`'s nested method
// names, so this intersection alone can't produce full per-endpoint
// autocomplete; changing the server plugins' return-type annotations to
// unlock that is out of scope here. `pathMethods` below is unaffected by
// this — it's a plain runtime lookup keyed by literal path strings supplied
// directly in this file, not derived from `$InferServerPlugin`.
import type { BetterAuthClientPlugin } from "@better-auth/core";
import type { auditLog } from "../server/audit/plugin";
import type { enterpriseApi } from "../server/enterprise-api/plugin";
import type { orgPolicy } from "../server/policy/plugin";

type EnterpriseServerPlugins = ReturnType<typeof enterpriseApi> &
  ReturnType<typeof orgPolicy> &
  ReturnType<typeof auditLog>;

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
