import type { BetterAuthPlugin } from "better-auth";
import { admin, organization, twoFactor } from "better-auth/plugins";
import { passkey } from "@better-auth/passkey";
import { apiKey } from "@better-auth/api-key";
import { sso } from "@better-auth/sso";
import { resolveScimSsoUser, guardScimSsoProviderMutation } from "./scim-sso";
import { enterpriseScim, scimMembershipSchema } from "./scim";
import type { EnterpriseOptions } from "./types";
import { enterpriseGate } from "./gate";
import { auditLog } from "./audit/plugin";
import { orgPolicy } from "./policy/plugin";
import { enterpriseApi } from "./enterprise-api/plugin";
import { assertEnterpriseOptions } from "./options";
import {
  API_KEY_HEADERS,
  API_KEY_LIFECYCLE_PLUGIN_ID,
  apiKeyLifecycle,
  enterpriseApiKeyValidator,
} from "./api-keys";

export { API_KEY_LIFECYCLE_PLUGIN_ID };

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
    apiKey({
      // The header list is shared with `assertNotApiKeyRequest` (`./api-keys.ts`).
      apiKeyHeaders: [...API_KEY_HEADERS],
      // Every key use is bound to the live user row (banned / removed), on
      // both upstream paths (`/api-key/verify` and the opt-in mock session).
      customAPIKeyValidator: enterpriseApiKeyValidator,
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
      organizationProvisioning: { disabled: false, defaultRole: "member" },
      disableImplicitSignUp: false,
      provisionUser: opts.provisionUser,
      resolveUser: resolveScimSsoUser,
      guardProviderMutation: guardScimSsoProviderMutation,
      saml: { allowIdpInitiated: true },
    }),
    enterpriseScim(opts),
    enterpriseGate(opts),
    auditLog(opts),
    orgPolicy(opts),
    scimMembershipSchema(),
    enterpriseApi(opts),
  ];
}
