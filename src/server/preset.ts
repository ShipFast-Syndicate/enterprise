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
// Task 8 finalises the `sso()` call: `disableImplicitSignUp: false` (JIT
// account creation is on — paired with `organizationProvisioning` below, a
// user signing in through a verified SSO provider both gets an account *and*
// joins the provider's org in one step) and `provisionUser: opts.provisionUser`
// (forwarded verbatim so a product's own provisioning hook — CRM sync,
// welcome email, whatever — runs on every SSO-driven signup, per `./types.ts`'s
// header comment on why this field is plumbed through `EnterpriseOptions`
// rather than configured directly). `saml: { allowIdpInitiated: true }` is
// upstream's *default* already (`options?.saml?.allowIdpInitiated !== false`,
// verified against the pinned `@better-auth/sso@1.6.33`) — set explicitly so
// the intent (this preset accepts unsolicited, IdP-initiated SAML responses,
// not only SP-initiated ones) is visible here rather than relying on a
// default that could change upstream, and so the SAML e2e test
// (`test/e2e/saml.test.ts`) that exercises exactly that flow doesn't depend
// on an implicit default.
//
// `opts.samlSpKeys` is deliberately NOT threaded into this `sso()` call:
// `SSOOptions.saml` (`@better-auth/sso@1.6.33`) has no `spMetadata` (or any
// other SP-identity) field at all — verified directly against
// `node_modules/@better-auth/sso/dist/index-CMcY1z4e.d.mts`'s `SSOOptions`
// interface — only a *per-provider* `samlConfig.spMetadata` exists, set at
// `/sso/register` time for that one org's connection, not at the plugin
// level for every org at once. `samlSpKeys` therefore stays exactly where an
// earlier task left it: a value on `EnterpriseOptions` (`./types.ts`) a
// product can read when it builds its own `/sso/register` (or
// `/enterprise/sso/register`, `./enterprise-api/sso.ts`) request body, to
// reuse one shared SP signing identity across every org's SAML connection
// instead of generating a fresh key pair per org.
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
      saml: { allowIdpInitiated: true },
    }),
    scim({ storeSCIMToken: "hashed", providerOwnership: { enabled: true } }),
    enterpriseGate(opts),
    auditLog(opts),
    orgPolicy(opts),
    scimGroups(opts),
    enterpriseApi(opts),
  ];
}
