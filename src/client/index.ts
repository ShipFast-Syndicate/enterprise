// Alpha Bros enterprise layer — client entry point.
//
// Re-exports this package's own `enterpriseClient()` plugin and the
// home-realm helpers (`./plugin.ts`/`./home-realm.ts`), plus the upstream
// better-auth client plugins a product wiring up the full enterprise layer
// needs alongside it — one import for `ssoClient`, `organizationClient`,
// `twoFactorClient`, `passkeyClient`, `apiKeyClient` rather than each
// product reaching into `better-auth/client/plugins`, `@better-auth/sso/
// client`, `@better-auth/passkey/client`, `@better-auth/api-key/client`
// individually. `@better-auth/scim` has no client plugin at all (verified:
// `node_modules/@better-auth/scim/package.json`'s `exports` has no
// `"./client"` entry) — SCIM provisioning is server/IdP-to-server, nothing
// a browser client calls.

export { enterpriseClient } from "./plugin";
export {
  discoverHomeRealm,
  EnterpriseClientError,
  homeRealmLogin,
  startSsoLogin,
  type EnterpriseClientErrorShape,
  type HomeRealmLoginResult,
  type HomeRealmOptions,
  type HomeRealmResult,
  type StartSsoLoginOptions,
} from "./home-realm";

export { ssoClient } from "@better-auth/sso/client";
export { organizationClient, twoFactorClient } from "better-auth/client/plugins";
export { passkeyClient } from "@better-auth/passkey/client";
export { apiKeyClient } from "@better-auth/api-key/client";
