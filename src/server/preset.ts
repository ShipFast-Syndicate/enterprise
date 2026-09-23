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
    organization({ teams: { enabled: true } }),
    twoFactor(),
    passkey(),
    apiKey(),
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
