// Alpha Bros enterprise layer — the audit route table.
//
// Every endpoint the preset mounts is in exactly one of three tables:
//
// - `AUDITED_PATHS` — the audit plugin's after-hook writes a row for it (one
//   per organization in the entry's `scope`);
// - `SELF_AUDITED_PATHS` — the endpoint writes its own row(s), because only
//   it knows the outcome (export row count, compaction anchor, SCIM token
//   ids, the forwarded upstream call);
// - `UNAUDITED_PATHS` / `UNAUDITED_SERVER_ONLY_ENDPOINTS` — deliberately not
//   audited, each with the reason.
//
// `test/security/audit-cluster-routes.test.ts` enumerates the endpoints of a
// preset instance and fails for any endpoint (path and method) that is in
// none of them, so a new upstream endpoint is a failing test until someone
// decides whether it is auditable — the same fail-closed-by-construction
// rule the API-key allow-list follows. Independently of the table, the
// plugin audits every request that mints a session (`auth.sign_in`) or ends
// in a policy refusal (`auth.sign_in_refused`), whatever its path — so a
// product's own sign-in plugin (email OTP, generic OAuth, …) is never a
// silent way in.
//
// `ctx.path` inside a hook is the endpoint's registered *pattern*
// (`/sso/callback/:providerId`, never the concrete URL), which is what these
// tables are keyed by.

/**
 * Which organizations a row goes to — one row per organization, each in its
 * own chain:
 *
 * - `subject` — every org with a claim on the user the event is about: the
 *   user signing in / out / failing / refused, or changing their own
 *   credentials, sessions, keys — memberships ∪ orgs owning a verified SSO
 *   domain for the user's e-mail (the same union the policy resolver uses).
 *   A caller-supplied `?orgId` is never consulted.
 * - `target-user` — every org of the user an `/admin/*` action targets,
 *   resolved *before* the endpoint runs (removal deletes the memberships).
 * - `resource` — the org of the resource the endpoint acted on, read from
 *   that resource: the team / invitation row the request names (read
 *   before the endpoint runs), or the organization id on the member,
 *   invitation, team or organization it returned (`RESOURCE_ORG_SOURCES`
 *   in `./plugin.ts`). Never an org id the caller named — not the body's,
 *   not a `?organizationId=`, not the session's active org.
 * - `provider` — the org owning the SSO provider named by the request
 *   (`ssoProvider.organizationId`, read before the endpoint runs, so a
 *   deletion is still attributed).
 * - `scim` — the SCIM bearer's own provisioning org.
 * - `request-org` — the org id in the request body, for endpoints that
 *   themselves require the caller to be an owner/admin of exactly that org
 *   (`/enterprise/policy/set`); written only when the endpoint succeeded.
 */
export type AuditScope =
  "subject" | "target-user" | "resource" | "provider" | "scim" | "request-org";

export interface AuditedPath {
  action: string;
  targetType: string;
  scope: AuditScope;
  /**
   * `"session"`: the endpoint is a sign-in step. Success is "a new session
   * was minted" (`ctx.context.newSession` with a token other than the one
   * the request came in with); a 2FA challenge instead of a session is
   * `auth.sign_in_2fa_pending`; an error is `auth.sign_in_failed`, or
   * `auth.sign_in_refused` when it carries a `POLICY_REFUSAL_CODES` code.
   * `"event"` (default): success is "no `APIError`" (a redirect without an
   * `error` parameter counts as success).
   */
  kind?: "session" | "event";
  /** HTTP methods this entry covers (the path's other methods are reads). */
  methods?: readonly string[];
  /** Resolve the subject's organizations before the endpoint runs (it deletes the memberships). */
  resolveBefore?: boolean;
}

const session = (action: string, extra: Partial<AuditedPath> = {}): AuditedPath => ({
  action,
  targetType: "user",
  scope: "subject",
  kind: "session",
  ...extra,
});
const self = (action: string, extra: Partial<AuditedPath> = {}): AuditedPath => ({
  action,
  targetType: "user",
  scope: "subject",
  ...extra,
});
const org = (action: string, targetType: string): AuditedPath => ({
  action,
  targetType,
  scope: "resource",
});
const admin = (action: string): AuditedPath => ({
  action,
  targetType: "user",
  scope: "target-user",
});
const provider = (action: string): AuditedPath => ({
  action,
  targetType: "sso_provider",
  scope: "provider",
});

export const AUDITED_PATHS: Record<string, AuditedPath> = {
  // --- sign-in steps (kind "session") -------------------------------------
  "/sign-in/email": session("auth.sign_in"),
  "/sign-up/email": session("auth.sign_up"),
  // Social sign-in with an `idToken` mints a session here; the redirect
  // flow does not (it answers a URL) and is audited at `/callback/:id`.
  "/sign-in/social": session("auth.sign_in"),
  "/callback/:id": session("auth.sign_in"),
  "/magic-link/verify": session("auth.sign_in"),
  // A session only when auto-sign-in after verification is on; otherwise
  // the verification itself (`user.email_verified`).
  "/verify-email": session("auth.sign_in"),
  "/passkey/verify-authentication": session("auth.sign_in"),
  // Without a session: the 2FA challenge answered → `auth.sign_in`. With
  // one: enrolment completed (a fresh session is re-issued) →
  // `two_factor.enabled`; a step-up check that mints nothing → no row.
  "/two-factor/verify-totp": session("auth.sign_in"),
  "/two-factor/verify-otp": session("auth.sign_in"),
  "/two-factor/verify-backup-code": session("auth.sign_in"),
  // SSO callbacks: rows also go to the provider's own org; a non-policy
  // failure keeps its historical name, `auth.sso_sign_in_failed`.
  "/sso/callback": session("auth.sso_sign_in"),
  "/sso/callback/:providerId": session("auth.sso_sign_in"),
  "/sso/saml2/sp/acs/:providerId": session("auth.sso_sign_in"),

  // --- the user's own account (scope "subject") ---------------------------
  "/sign-in/magic-link": self("auth.magic_link_requested"),
  "/request-password-reset": self("user.password_reset_requested"),
  "/reset-password": self("user.password_reset"),
  "/sign-out": self("auth.sign_out"),
  "/sso/saml2/logout/:providerId": self("auth.sign_out"),
  "/change-password": self("user.password_changed"),
  "/change-email": self("user.email_change_requested"),
  "/update-user": self("user.updated"),
  "/delete-user": self("user.deleted", { resolveBefore: true }),
  "/delete-user/callback": self("user.deleted", { resolveBefore: true }),
  "/revoke-session": self("session.revoked", { targetType: "session" }),
  "/revoke-sessions": self("session.revoked_all", { targetType: "session" }),
  "/revoke-other-sessions": self("session.revoked_others", { targetType: "session" }),
  "/link-social": self("account.link_requested", { targetType: "account" }),
  "/unlink-account": self("account.unlinked", { targetType: "account" }),
  "/two-factor/enable": self("two_factor.enrollment_started"),
  "/two-factor/disable": self("two_factor.disabled"),
  "/two-factor/generate-backup-codes": self("two_factor.backup_codes_generated"),
  "/passkey/verify-registration": self("passkey.registered", { targetType: "passkey" }),
  "/passkey/update-passkey": self("passkey.updated", { targetType: "passkey" }),
  "/passkey/delete-passkey": self("passkey.deleted", { targetType: "passkey" }),
  "/api-key/create": self("api_key.created", { targetType: "api_key" }),
  "/api-key/update": self("api_key.updated", { targetType: "api_key" }),
  "/api-key/delete": self("api_key.revoked", { targetType: "api_key" }),

  // --- organizations (scope "resource") -----------------------------------
  "/organization/update": org("org.updated", "organization"),
  // The terminal row of the org's chain (rows outlive the organization).
  "/organization/delete": org("org.deleted", "organization"),
  "/organization/leave": org("member.left", "member"),
  "/organization/invite-member": org("member.invited", "member"),
  "/organization/cancel-invitation": org("member.invitation_canceled", "invitation"),
  "/organization/reject-invitation": org("member.invitation_rejected", "invitation"),
  "/organization/accept-invitation": org("member.joined", "member"),
  "/organization/remove-member": org("member.removed", "member"),
  "/organization/update-member-role": org("member.role_changed", "member"),
  "/organization/create-team": org("team.created", "team"),
  "/organization/update-team": org("team.updated", "team"),
  "/organization/remove-team": org("team.removed", "team"),
  "/organization/add-team-member": org("team.member_added", "team"),
  "/organization/remove-team-member": org("team.member_removed", "team"),

  // --- platform staff (`admin` plugin, scope "target-user") ---------------
  "/admin/create-user": admin("admin.user_created"),
  "/admin/update-user": admin("admin.user_updated"),
  "/admin/set-role": admin("admin.user_role_changed"),
  "/admin/set-user-password": admin("admin.user_password_set"),
  "/admin/ban-user": admin("admin.user_banned"),
  "/admin/unban-user": admin("admin.user_unbanned"),
  "/admin/remove-user": admin("admin.user_removed"),
  "/admin/revoke-user-session": admin("admin.user_session_revoked"),
  "/admin/revoke-user-sessions": admin("admin.user_sessions_revoked"),
  "/admin/impersonate-user": admin("admin.impersonation_started"),
  // The only trace of an impersonation once it ends (upstream deletes the
  // impersonation session): actor = the staff member, target = the user.
  "/admin/stop-impersonating": admin("admin.impersonation_stopped"),

  // --- SSO providers (scope "provider") -----------------------------------
  "/sso/register": provider("sso.provider_registered"),
  "/sso/update-provider": provider("sso.provider_updated"),
  "/sso/delete-provider": provider("sso.provider_deleted"),
  "/sso/request-domain-verification": provider("sso.domain_verification_requested"),
  "/sso/verify-domain": provider("sso.domain_verified"),
  // IdP-initiated single logout: the IdP ends the user's sessions.
  "/sso/saml2/sp/slo/:providerId": provider("auth.sso_logout"),

  // --- SCIM provisioning (scope "scim") -----------------------------------
  // `/scim/v2/Users` and `/scim/v2/Users/:userId` are each shared by several
  // SCIM endpoints at different HTTP methods; `methods` restricts an entry
  // to the mutating ones (list/get are reads). DELETE needs a different
  // action than its PUT/PATCH siblings — `METHOD_ACTION_OVERRIDES` below.
  "/scim/v2/Users": {
    action: "scim.user_created",
    targetType: "scim_user",
    scope: "scim",
    methods: ["POST"],
  },
  "/scim/v2/Users/:userId": {
    action: "scim.user_updated",
    targetType: "scim_user",
    scope: "scim",
    methods: ["PUT", "PATCH"],
  },
  "/scim/v2/Groups": {
    action: "scim.group_created",
    targetType: "scim_group",
    scope: "scim",
    methods: ["POST"],
  },
  "/scim/v2/Groups/:groupId": {
    action: "scim.group_updated",
    targetType: "scim_group",
    scope: "scim",
    methods: ["PUT", "PATCH"],
  },

  // --- policy -------------------------------------------------------------
  "/enterprise/policy/set": {
    action: "policy.updated",
    targetType: "org_policy",
    scope: "request-org",
  },
};

/** Per-method action overrides for a path already in `AUDITED_PATHS` (SCIM deletes). */
export const METHOD_ACTION_OVERRIDES: Record<
  string,
  Record<string, { action: string; targetType: string }>
> = {
  "/scim/v2/Users/:userId": {
    DELETE: { action: "scim.user_deleted", targetType: "scim_user" },
  },
  "/scim/v2/Groups/:groupId": {
    DELETE: { action: "scim.group_deleted", targetType: "scim_group" },
  },
};

/**
 * The `AuditedPath` for a request, or `null` when it is not audited by the
 * after-hook (not in the table, or a read method of a shared path).
 */
export function auditEntryFor(path: string, method: string | undefined): AuditedPath | null {
  const entry = AUDITED_PATHS[path];
  const override = method ? METHOD_ACTION_OVERRIDES[path]?.[method] : undefined;
  if (override && entry) return { ...entry, ...override, methods: undefined };
  if (!entry) return null;
  if (entry.methods && (!method || !entry.methods.includes(method))) return null;
  return entry;
}

/** Endpoints that write their own audit row(s) — the after-hook leaves them alone. */
export const SELF_AUDITED_PATHS: Record<string, string> = {
  "/enterprise/audit/export":
    "`audit.exported` (row count, range), written after the CSV is built so the export never contains its own row",
  "/enterprise/audit/compact":
    "the retention anchor row it leaves carries the caller as its actor; nothing is written when nothing expired",
  "/enterprise/audit/list":
    "a read, except that it runs retention compaction first — whose anchor row carries the caller",
  "/enterprise/scim/tokens/create": "`scim.token_created` / `scim.token_rotated`, in the handler",
  "/enterprise/scim/tokens/rotate": "`scim.token_rotated`, in the handler",
  "/enterprise/scim/tokens/revoke": "`scim.token_revoked`, in the handler",
  "/enterprise/sso/register":
    "forwards to `/sso/register` through the same dispatch, which is audited (`sso.provider_registered`)",
  "/enterprise/sso/test-login/finish": "`sso.test_login_passed`, in the handler",
};

const READ = "read-only: returns data and changes nothing an organization governs";
const FLOW_START =
  "starts a flow and changes nothing by itself; the step that does (callback, verification) is audited";
const SESSION_PREFERENCE =
  "switches the caller's own active organization/team or the session's own fields; no identity, permission or credential changes";

/**
 * Deliberately unaudited HTTP endpoints, with the reason. `methods` limits
 * an entry to those methods (the others must be audited).
 */
export const UNAUDITED_PATHS: Record<string, { reason: string; methods?: readonly string[] }> = {
  "/ok": { reason: "health check" },
  "/error": { reason: "static error page" },
  "/get-session": {
    reason:
      "a read; refreshing a session's expiry is not a new session (one minted anywhere is audited as auth.sign_in by the universal rule)",
  },
  "/list-sessions": { reason: READ },
  "/list-accounts": { reason: READ },
  "/account-info": { reason: READ },
  "/verify-password": {
    reason: "checks the caller's own password and answers yes/no; nothing changes",
  },
  "/get-access-token": {
    reason:
      "returns (refreshing it upstream when due) the caller's own linked-provider token; no organization-governed state changes, and API keys are refused here",
  },
  "/refresh-token": {
    reason:
      "refreshes the caller's own linked-provider token; no organization-governed state changes, and API keys are refused here",
  },
  "/update-session": { reason: SESSION_PREFERENCE },
  "/send-verification-email": { reason: FLOW_START },
  "/reset-password/:token": {
    reason: "redirects the browser to the product's reset page; the reset itself is audited",
  },
  "/sign-in/sso": { reason: FLOW_START },
  "/sso/providers": { reason: READ },
  "/sso/get-provider": { reason: READ },
  "/sso/saml2/sp/metadata": { reason: READ },
  "/passkey/generate-authenticate-options": { reason: FLOW_START },
  "/passkey/generate-register-options": { reason: FLOW_START },
  "/passkey/list-user-passkeys": { reason: READ },
  "/two-factor/get-totp-uri": {
    reason: "re-displays the caller's own TOTP URI after a password check; nothing changes",
  },
  "/two-factor/send-otp": { reason: FLOW_START },
  "/api-key/get": { reason: READ },
  "/api-key/list": { reason: READ },
  "/admin/get-user": { reason: READ },
  "/admin/list-users": { reason: READ },
  "/admin/list-user-sessions": { reason: READ },
  "/admin/has-permission": { reason: READ },
  "/organization/create": {
    reason:
      "creates a new tenant: no existing organization's state changes, and the new org's chain starts empty — its first governed change (invite, policy, provider, …) is its first row",
  },
  "/organization/set-active": { reason: SESSION_PREFERENCE },
  "/organization/set-active-team": { reason: SESSION_PREFERENCE },
  "/organization/check-slug": { reason: READ },
  "/organization/has-permission": { reason: READ },
  "/organization/get-active-member": { reason: READ },
  "/organization/get-active-member-role": { reason: READ },
  "/organization/get-full-organization": { reason: READ },
  "/organization/get-invitation": { reason: READ },
  "/organization/get-organization": { reason: READ },
  "/organization/list": { reason: READ },
  "/organization/list-invitations": { reason: READ },
  "/organization/list-members": { reason: READ },
  "/organization/list-team-members": { reason: READ },
  "/organization/list-teams": { reason: READ },
  "/organization/list-user-invitations": { reason: READ },
  "/organization/list-user-teams": { reason: READ },
  "/scim/v2/Users": { reason: READ, methods: ["GET"] },
  "/scim/v2/Users/:userId": { reason: READ, methods: ["GET"] },
  "/scim/v2/Groups": { reason: READ, methods: ["GET"] },
  "/scim/v2/Groups/:groupId": { reason: READ, methods: ["GET"] },
  "/scim/v2/ResourceTypes": { reason: READ },
  "/scim/v2/ResourceTypes/:resourceTypeId": { reason: READ },
  "/scim/v2/Schemas": { reason: READ },
  "/scim/v2/Schemas/:schemaId": { reason: READ },
  "/scim/v2/ServiceProviderConfig": { reason: READ },
  "/enterprise/audit/verify": { reason: READ },
  "/enterprise/audit/head": { reason: READ },
  "/enterprise/features": { reason: READ },
  "/enterprise/home-realm": { reason: "public pre-sign-in probe; " + READ },
  "/enterprise/members": { reason: READ },
  "/enterprise/policy": { reason: READ },
  "/enterprise/scim/tokens": { reason: READ },
  "/enterprise/sso/providers": { reason: READ },
  "/enterprise/sso/test-login/start": { reason: FLOW_START },
};

const SERVER_ONLY =
  "server-only (no HTTP route, no path for a hook to match): only the product's own server code can call it, and that code is where it is audited";

/**
 * Path-less, server-only endpoints (`auth.api.<name>`), by API name. A hook
 * cannot tell them apart (their `ctx.path` is not theirs), so none is
 * audited by the plugin.
 */
export const UNAUDITED_SERVER_ONLY_ENDPOINTS: Record<string, string> = {
  setPassword: SERVER_ONLY,
  addMember: SERVER_ONLY,
  generateTOTP: SERVER_ONLY,
  viewBackupCodes: SERVER_ONLY,
  verifyApiKey: "server-only read: answers whether a key is valid",
  deleteAllExpiredApiKeys: "server-only maintenance: removes keys that have already expired",
  createSCIMManagedConnection:
    "server-only: called by `/enterprise/scim/tokens/create|rotate`, which audit it",
  rotateSCIMManagedCredential:
    "server-only: called by `/enterprise/scim/tokens/rotate`, audited there",
  revokeSCIMManagedCredential: SERVER_ONLY,
  decommissionSCIMManagedConnection:
    "server-only: called by `/enterprise/scim/tokens/revoke`, audited there",
  decommissionSCIMConnection: SERVER_ONLY,
  listSCIMManagedConnections: "server-only read",
  getSCIMManagedConnection: "server-only read",
  listSCIMManagedConnectionEvents: "server-only read",
  reconcileSCIMProjection:
    "server-only maintenance; each identity change it applies is audited by the SCIM projector (`scim.user_deactivated`, `api_key.revoked`, …)",
};

/**
 * Error codes that mean "a policy refused this sign-in" (as opposed to a
 * wrong password, an expired link, a bad signature …): an error carrying
 * one of them — in the `APIError` body or, on the redirecting SSO/social
 * callbacks, in the redirect's `error` parameter — is audited as
 * `auth.sign_in_refused` on any path; every other sign-in-step error is
 * `auth.sign_in_failed` (`auth.sso_sign_in_failed` on the SSO callbacks).
 */
export const POLICY_REFUSAL_CODES: ReadonlySet<string> = new Set([
  "SSO_REQUIRED",
  "METHOD_NOT_ALLOWED",
  "TWO_FACTOR_REQUIRED",
  "TWO_FACTOR_ENROLLMENT_REQUIRED",
  "SSO_DOMAIN_NOT_ALLOWED",
  "SSO_PROVIDER_UNRESOLVED",
  "SSO_ISSUER_NOT_ALLOWED",
  "SCIM_PROVISIONING_REQUIRED",
  "SCIM_USER_NOT_ACTIVE",
]);
