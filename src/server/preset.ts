import type { BetterAuthPlugin } from "better-auth";
import { admin, organization, twoFactor } from "better-auth/plugins";
import { passkey } from "@better-auth/passkey";
import { apiKey } from "@better-auth/api-key";
import { sso } from "@better-auth/sso";
import { resolveScimSsoUser, guardScimSsoProviderMutation } from "./scim-sso";
import { composeSsoResolvers } from "./sso-resolve";
import { enterpriseScim, scimMembershipSchema } from "./scim";
import type { EnterpriseOptions } from "./types";
import { enterpriseGate } from "./gate";
import { auditLog } from "./audit/plugin";
import { orgPolicy } from "./policy/plugin";
import { enterpriseApi } from "./enterprise-api/plugin";
import { assertEnterpriseOptions } from "./options";
import { orgLockConfigured, orgWriteLock } from "./org-lock";
import {
  API_KEY_HEADERS,
  API_KEY_LIFECYCLE_PLUGIN_ID,
  API_KEY_STANDING_PLUGIN_ID,
  apiKeyLifecycle,
  apiKeySessionStanding,
  enterpriseApiKeyValidator,
} from "./api-keys";

export { API_KEY_LIFECYCLE_PLUGIN_ID, API_KEY_STANDING_PLUGIN_ID };

/** 90 days, in seconds — the default lifetime of a key created without `expiresIn`. */
const DEFAULT_API_KEY_EXPIRES_IN_S = 90 * 24 * 3600;

export function enterprisePreset(opts: EnterpriseOptions): BetterAuthPlugin[] {
  // `secretsKey` is load-bearing as of the pre-publish security pass (C-04):
  // it encrypts `ssoProvider` secret material at rest, so the documented
  // ">= 32 characters" rule is enforced (L-08) instead of being a comment on
  // a dead option — along with the retention/export bounds. `enterpriseGate`
  // re-runs the same validation for hand-composed plugin lists that skip
  // this preset; calling it here too keeps the failure at the outermost
  // call site a product actually wrote.
  assertEnterpriseOptions(opts);
  return [
    admin(),
    organization({
      teams: { enabled: true },
      // Both set explicitly rather than inherited from upstream defaults —
      // see `EnterpriseOptions.organization` (`./types.ts`) for why each
      // default is what it is. `requireEmailVerificationOnInvitation` is
      // the invitation half of the cross-tenant squat fix: an account
      // minted for someone else's address must not be able to accept an
      // invitation meant for that address's real owner.
      requireEmailVerificationOnInvitation:
        opts.organization?.requireEmailVerificationOnInvitation ?? true,
      allowUserToCreateOrganization: opts.organization?.allowUserToCreateOrganization ?? true,
    }),
    twoFactor(),
    passkey(),
    // With the opt-in mock session on, a key whose owner does not stand under
    // `require2fa` answers `/get-session` as "no session" (`null`): this
    // plugin's before-hook has to run ahead of upstream's, which answers
    // `/get-session` itself (`./api-keys.ts`).
    ...(opts.apiKeys?.enableSessionForAPIKeys ? [apiKeySessionStanding()] : []),
    apiKey({
      // The header list is shared with `assertNotApiKeyRequest` (`./api-keys.ts`).
      apiKeyHeaders: [...API_KEY_HEADERS],
      // Every key use is bound to the live user row (banned / removed) and
      // confined to `API_KEY_ALLOWED_PATHS` (`isApiKeyRefusedPath`), on both
      // upstream paths (`/api-key/verify` and the opt-in mock session below).
      customAPIKeyValidator: enterpriseApiKeyValidator,
      // The documented opt-in (`apiKeys.enableSessionForAPIKeys`): built
      // here rather than by hand so the validator, header list and expiry
      // bound cannot be left out of the recipe.
      enableSessionForAPIKeys: opts.apiKeys?.enableSessionForAPIKeys ?? false,
      // Upstream's per-key rate limit, forwarded as-is (validated in
      // `./options.ts`); left out, upstream keeps its own default of 10
      // requests per key per 24 h — see `EnterpriseOptions.apiKeys.rateLimit`.
      ...(opts.apiKeys?.rateLimit ? { rateLimit: opts.apiKeys.rateLimit } : {}),
      // Bounded by expiry (gap 1): 90 days unless the product says otherwise,
      // never longer than `maxExpiresInDays`. `defaultExpiresIn` is in
      // **seconds** — upstream's `.d.mts` says milliseconds, but `create`
      // feeds it to `getDate(…, "sec")` (pinned by
      // `test/security/gap1-api-keys.test.ts`); `maxExpiresIn` is in days.
      keyExpiration: {
        defaultExpiresIn:
          opts.apiKeys?.defaultExpiresInS === undefined
            ? DEFAULT_API_KEY_EXPIRES_IN_S
            : opts.apiKeys.defaultExpiresInS,
        maxExpiresIn: opts.apiKeys?.maxExpiresInDays ?? 365,
      },
    }),
    apiKeyLifecycle(opts),
    sso({
      domainVerification: { enabled: true },
      // `sso.organizationProvisioning: "off"` (1.3, opt-in) stops both of
      // upstream's automatic org joins; absent, it is the 1.2 value.
      organizationProvisioning: {
        disabled: opts.sso?.organizationProvisioning === "off",
        defaultRole: "member",
      },
      // `sso.existingUsersOnly` (1.3, opt-in) — upstream's own switch for the
      // sign-up half; the resolver and the create hook are the rest of it.
      disableImplicitSignUp: opts.sso?.existingUsersOnly === true,
      provisionUser: opts.provisionUser,
      // The base resolver itself unless a 1.3 option needs the composed one
      // (`./sso-resolve.ts`'s identity rule).
      resolveUser: composeSsoResolvers(opts, resolveScimSsoUser),
      guardProviderMutation: guardScimSsoProviderMutation,
      saml: { allowIdpInitiated: true },
    }),
    enterpriseScim(opts),
    enterpriseGate(opts),
    // Only when `organization.creation` / `organization.metadata` depart from
    // their defaults: right after the gate (whose API-key refusal runs first),
    // and absent otherwise so the plugin list of an existing consumer is
    // unchanged. See `./org-lock.ts`.
    ...(orgLockConfigured(opts) ? [orgWriteLock(opts)] : []),
    auditLog(opts),
    orgPolicy(opts),
    scimMembershipSchema(),
    enterpriseApi(opts),
  ];
}
