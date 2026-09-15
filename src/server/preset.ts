// Alpha Bros enterprise layer — better-auth plugin preset.
//
// v0.1: the upstream plugins the enterprise layer always needs, plus
// `enterpriseGate` and (Task 4) `auditLog`. Later tasks append `orgPolicy`
// and our own `scimGroups` (better-auth 1.6 has no SCIM Groups) to this
// list.
//
// `EnterpriseOptions.provisionUser` is plumbed onto the type in this task
// (see `./types.ts`) for a later task to wire into the `sso()` call below;
// per the controller ruling for this task, the `sso()` options here are
// exactly `domainVerification` + `organizationProvisioning`, nothing more.
//
// `scim({ providerOwnership: { enabled: true } })`: `@better-auth/scim`
// below 1.7 has an unpatched HIGH advisory (GHSA-j8v8-g9cx-5qf4) — a SCIM
// provider created without `organizationId` ("personal" provider) can be
// taken over. This design only ever allows org-scoped providers (enforced
// in `./gate.ts`, which requires `organizationId` explicitly for
// `/scim/generate-token` and `/scim/delete-provider-connection` rather than
// falling back to the session's active org), and `providerOwnership`
// additionally binds each provider connection to the user who generated its
// token as defense in depth.

import type { BetterAuthPlugin } from "better-auth";
import { admin, organization, twoFactor } from "better-auth/plugins";
import { passkey } from "@better-auth/passkey";
import { apiKey } from "@better-auth/api-key";
import { sso } from "@better-auth/sso";
import { scim } from "@better-auth/scim";
import type { EnterpriseOptions } from "./types";
import { enterpriseGate } from "./gate";
import { auditLog } from "./audit/plugin";

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
    scim({ storeSCIMToken: "hashed", providerOwnership: { enabled: true } }),
    enterpriseGate(opts),
    auditLog(opts),
  ];
}
