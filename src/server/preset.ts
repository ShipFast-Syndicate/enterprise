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

/**
 * Plugin id of the API-key lifecycle plugin (use-time user checks and
 * revocation on ban/removal). The preset reserves its slot — directly after
 * upstream `api-key`, before `sso` — so the plugin order is fixed once; this
 * build registers the id with no hooks, and the lifecycle hooks land in the
 * same slot.
 */
export const API_KEY_LIFECYCLE_PLUGIN_ID = "enterprise-api-keys";

function apiKeyLifecycleSlot(): BetterAuthPlugin {
  return { id: API_KEY_LIFECYCLE_PLUGIN_ID, hooks: { before: [], after: [] } };
}

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
    apiKey(),
    apiKeyLifecycleSlot(),
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
