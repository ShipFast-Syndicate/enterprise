// Alpha Bros enterprise layer — better-auth plugin preset.
//
// v0.1 (this task): the upstream plugins the enterprise layer always needs
// plus `enterpriseGate`. Later tasks append `auditLog`, `orgPolicy`, and our
// own `scimGroups` (better-auth 1.6 has no SCIM Groups) to this list.
//
// `EnterpriseOptions.provisionUser` is plumbed onto the type in this task
// (see `./types.ts`) for a later task to wire into the `sso()` call below;
// per the controller ruling for this task, the `sso()` options here are
// exactly `domainVerification` + `organizationProvisioning`, nothing more.

import type { BetterAuthPlugin } from "better-auth";
import { admin, organization, twoFactor } from "better-auth/plugins";
import { passkey } from "@better-auth/passkey";
import { apiKey } from "@better-auth/api-key";
import { sso } from "@better-auth/sso";
import { scim } from "@better-auth/scim";
import type { EnterpriseOptions } from "./types";
import { enterpriseGate } from "./gate";

export function enterprisePreset(opts: EnterpriseOptions): BetterAuthPlugin[] {
  return [
    admin(),
    organization({ teams: { enabled: true } }),
    twoFactor(),
    passkey(),
    apiKey(),
    sso({
      domainVerification: { enabled: true },
      organizationProvisioning: { disabled: false, defaultRole: "member" },
    }),
    scim({ storeSCIMToken: "hashed" }),
    enterpriseGate(opts),
  ];
}
