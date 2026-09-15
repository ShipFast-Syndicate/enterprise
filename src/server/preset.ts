// Alpha Bros enterprise layer — better-auth plugin preset.
//
// v0.1: the upstream plugins the enterprise layer always needs, plus
// `enterpriseGate`, (Task 4) `auditLog`, (Task 5) `orgPolicy`, (Task 6) our
// own `scimGroups` — better-auth 1.6's `@better-auth/scim` has no SCIM
// Groups support, so this preset replaces just that gap in-house
// (FDR-enterprise-0001) rather than waiting on 1.7 — and (Task 7)
// `enterpriseApi`, the portal-facing wrapper endpoints. `enterpriseApi` is
// appended *last*: its own `hooks.before` (the mandatory-test-login
// precondition on `/enterprise/policy/set`, ruling (g)) only needs to run
// before that path's endpoint handler, which every plugin's `hooks.before`
// already does regardless of registration order — appended last purely by
// convention, matching how each task's plugin lands after the ones before
// it.
//
// `orgPolicy` deliberately does NOT bring its own `magicLink()` plugin —
// `/sign-in/magic-link`/`/magic-link/verify` sign-in enforcement is generic
// (it matches on `ctx.path` and simply never fires if no plugin registers
// those paths); a product wires up `magicLink()` itself alongside this
// preset the same way it wires up its own email delivery, the same as
// `emailAndPassword` is a core `betterAuth()` option rather than something
// this preset turns on.
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
import { orgPolicy } from "./policy/plugin";
import { scimGroups } from "./scim-groups/plugin";
import { enterpriseApi } from "./enterprise-api/plugin";

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
    orgPolicy(opts),
    scimGroups(opts),
    enterpriseApi(opts),
  ];
}
