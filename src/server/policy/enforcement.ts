// Alpha Bros enterprise layer — sign-in enforcement, session-creation
// backstop, session-refresh clamp, and policy-org resolution.
//
// Depends only on `./home-realm` (a leaf), `./store` (a leaf) and
// `../audit/refusal` (a leaf) — not on `./plugin.ts` — so `./plugin.ts` can
// import everything here without a cycle.
//
// Where each policy field is enforced:
//
// - `ssoEnforced` / `allowedMethods` — `buildSessionCreateBeforeHook`
//   (`databaseHooks.session.create.before`), the one place every sign-in
//   path funnels through *after* the credential has been checked. The only
//   pre-authentication hook left is the `/magic-link/verify` pre-flight
//   (`buildSignInBeforeHook`), whose "credential" — the pending token — is
//   what resolves the e-mail, so refusing there reveals nothing a stranger
//   could not already learn. `/sign-in/email` and `/sign-in/magic-link` are
//   deliberately *not* pre-flighted any more: answering `SSO_REQUIRED` before
//   the password was checked told anyone "this address is a member of an
//   SSO-enforced org" (audit gap 3).
// - `sessionMaxAgeS` — the same create hook (cap at creation) plus
//   `buildSessionUpdateBeforeHook` (`databaseHooks.session.update.before`),
//   which clamps the refresh `/get-session` writes back (F-05).
// - SSO domain binding (F-01, `./sso-jit.ts`) — the create hook again, for
//   every session an SSO callback mints: the signing provider must be
//   domain-verified for the user's e-mail domain, *before* any policy logic
//   and independent of it (a legacy `account` row linked to a foreign IdP
//   stays in the database but can no longer sign in — R4 of the fix plan).
//   `ssoEnforced` is then satisfied only by the enforcing org's **own**
//   IdP (R3), never by another tenant flipping their own org to enforce.
// - `require2fa` — two places. The create hook refuses a session whose
//   sign-in method carries no second factor and will not be challenged for
//   one (`TWO_FACTOR_REQUIRED`), and stamps the ones it admits as judged;
//   `buildTwoFactorEnrollmentGate` (`hooks.before` on every request outside a
//   small allow-list) confines a signed-in user who holds a password but has
//   not enrolled to the enrolment endpoints (`TWO_FACTOR_ENROLLMENT_REQUIRED`)
//   and refuses a no-password user's session that was never judged under the
//   requirement (`TWO_FACTOR_REQUIRED`, `twoFactorStanding`).

import type { BetterAuthPlugin, GenericEndpointContext } from "better-auth";
import { APIError, createAuthMiddleware, getSessionFromCtx } from "better-auth/api";
import { auditRefusal, policyRefusal } from "../audit/refusal";
import type { EnterpriseOptions } from "../types";
import { findOrgsByEmailDomain } from "./home-realm";
import { isSsoCallbackPath } from "./scim-required";
import {
  assertStoredProviderAllowed,
  domainBindingEnabled,
  issuerAllowListEnabled,
  providerAuthorizesEmail,
  resolveSsoCallbackProvider,
  ssoDomainNotAllowedError,
  ssoProviderUnresolvedError,
  type SsoCallbackProvider,
} from "./sso-jit";
import {
  anyOrgRequiresTwoFactor,
  getEffectivePolicy,
  memberOrgIds,
  timestampMs,
  twoFactorEnrollmentState,
  twoFactorRequirementOnsetMs,
  type EffectivePolicy,
  type TwoFactorEnrollmentState,
} from "./store";

// --- policy-org resolution -------------------------------------------------

/**
 * Every org that has a claim on a user's sign-in policy — the **union** of
 * the request's active organization, every org the user is a member of, and
 * every org owning a verified SSO provider for the user's e-mail domain
 * (`findOrgsByEmailDomain`, upstream-parity matching). De-duplicated, in that
 * order. Feed the result to `getEffectivePolicy` (`./store.ts`).
 *
 * This replaced the single-org, priority-ordered `resolvePolicyOrgForUser`,
 * which returned `null` — no policy at all — for a user in two or more orgs
 * and let any member escape `ssoEnforced`/`allowedMethods` by creating a
 * second organization (F-03). An empty result still means "no policy
 * applies" (free agents unchanged); a non-empty one is never narrowed by
 * ambiguity.
 */
export async function resolvePolicyOrgsForUser(
  ctx: GenericEndpointContext,
  params: { userId: string | null; email: string; activeOrganizationId?: string | null },
): Promise<string[]> {
  return (await resolvePolicyClaims(ctx, params)).orgIds;
}

/**
 * `resolvePolicyOrgsForUser` plus the *identity* orgs on their own — the
 * orgs owning a verified provider for the user's e-mail domain — which the
 * `ssoEnforced` rule needs separately (R3): one domain scan serves both.
 */
async function resolvePolicyClaims(
  ctx: GenericEndpointContext,
  params: { userId: string | null; email: string; activeOrganizationId?: string | null },
): Promise<{ orgIds: string[]; identityOrgIds: string[] }> {
  const orgIds = new Set<string>();
  if (params.activeOrganizationId) orgIds.add(params.activeOrganizationId);
  if (params.userId) {
    for (const orgId of await memberOrgIds(ctx, params.userId)) orgIds.add(orgId);
  }
  const identityOrgIds = new Set<string>();
  for (const match of await findOrgsByEmailDomain(ctx, params.email)) {
    orgIds.add(match.orgId);
    identityOrgIds.add(match.orgId);
  }
  return { orgIds: [...orgIds], identityOrgIds: [...identityOrgIds] };
}

// --- sign-in method classification ---------------------------------------

export type SessionCreateClassification =
  /** A sign-in method this layer knows by name; subject to `allowedMethods`. */
  | { kind: "method"; method: string }
  /**
   * A session (re)issued inside a flow the user already authenticated for —
   * a 2FA challenge answered, an already-signed-in user's e-mail verified,
   * password changed, 2FA toggled, an admin impersonating. The sign-in
   * method was classified and enforced when the flow started; the
   * continuation itself is not a method and is never refused as one.
   */
  | { kind: "continuation"; path: string }
  /**
   * A session-creating path this layer cannot name. Refused for a user under
   * a restricted policy (fail closed, audit gap 4); a product that ships such
   * a plugin declares it in `policy.signInMethods`.
   */
  | { kind: "unknown"; path: string | null };

/**
 * Session-creating paths that are not a sign-in method of their own (see
 * `SessionCreateClassification["kind"] === "continuation"`). Every entry was
 * traced to an `internalAdapter.createSession` call in the pinned
 * better-auth 1.7.7 or one of the preset's plugins. The `/two-factor/verify-*`
 * endpoints run without a session (the challenge cookie stands in for it);
 * the rest sit behind `sessionMiddleware`.
 *
 * `/verify-email` is deliberately **not** here: it is a continuation only
 * for an already-signed-in user (`isVerifyEmailContinuation`).
 */
const CONTINUATION_PATHS = new Set<string>([
  "/two-factor/verify-totp",
  "/two-factor/verify-otp",
  "/two-factor/verify-backup-code",
  "/two-factor/enable",
  "/two-factor/disable",
  "/change-password",
  "/admin/impersonate-user",
]);

/**
 * Upstream `/verify-email` is reachable **unauthenticated** — the emailed
 * token is the whole credential — and mints a brand-new session for a user
 * with no current one under `emailVerification.autoSignInAfterVerification`
 * (the deferred sign-in of a `requireEmailVerification` sign-up, whose
 * `/sign-up/email` created no session for the backstop to classify) and in
 * the two change-e-mail branches. Treating every `/verify-email` session as
 * a continuation let a member of an `allowedMethods`-narrowed org sign in
 * through the verification link (audit gap 4, second cut). Every upstream
 * branch calls `getSessionFromCtx(ctx)` — which sets `ctx.context.session`
 * to the result or `null` — before `createSession`, so the field is reliably
 * populated at the hook call site: the call is a continuation only when the
 * request already carries a session **for the same user** (upstream still
 * mints a new session when the current one belongs to someone else).
 * Otherwise it is a first sign-in whose credential is e-mail possession —
 * classified as `magic_link`, the closed-set name for exactly that.
 */
function isVerifyEmailContinuation(
  ctx: { context?: { session?: unknown } | null },
  subject: { userId?: unknown } | undefined,
): boolean {
  const current = ctx.context?.session as { user?: { id?: unknown } } | null | undefined;
  const currentUserId = current?.user?.id;
  if (typeof currentUserId !== "string") return false;
  return subject?.userId === undefined || subject.userId === currentUserId;
}

function classifyFromOptions(path: string, opts: EnterpriseOptions | undefined): string | null {
  const map = opts?.policy?.signInMethods;
  if (!map) return null;
  const exact = map[path];
  if (typeof exact === "string") return exact;
  for (const [key, method] of Object.entries(map)) {
    if (!key.endsWith("/*")) continue;
    const prefix = key.slice(0, -1); // keep the trailing slash: "/phone/*" -> "/phone/"
    if (path.startsWith(prefix)) return method;
  }
  return null;
}

/**
 * Classifies the endpoint whose call is creating a session. `ctx.path`
 * inside a request handler can be either the endpoint's registered
 * *pattern* (`/callback/:id`, with the provider in `ctx.params.id`) or a
 * *concrete* resolved path (`/callback/google`) — `../audit/plugin.ts`'s
 * header comment documents this ambiguity across better-auth dispatch
 * layers — so both forms are handled here rather than assuming one.
 *
 * Order: the product's `policy.signInMethods` first (so a product can
 * re-name or add a path), then the built-in map for the methods this
 * preset's own plugins expose, then continuations, then `unknown`.
 *
 * `session` is the row being created (its `userId`), which `/verify-email`
 * needs to tell a continuation from a first sign-in — see
 * `isVerifyEmailContinuation`.
 */
export function classifySessionCreate(
  ctx: {
    path?: string;
    params?: Record<string, string | undefined>;
    body?: unknown;
    context?: { session?: unknown } | null;
  },
  opts?: EnterpriseOptions,
  session?: { userId?: unknown },
): SessionCreateClassification {
  const path = ctx.path;
  if (!path) return { kind: "unknown", path: null };

  const configured = classifyFromOptions(path, opts);
  if (configured) return { kind: "method", method: configured };

  if (path === "/sign-in/email" || path === "/sign-up/email") {
    return { kind: "method", method: "password" };
  }
  if (path === "/magic-link/verify") return { kind: "method", method: "magic_link" };
  if (path === "/verify-email") {
    return isVerifyEmailContinuation(ctx, session)
      ? { kind: "continuation", path }
      : { kind: "method", method: "magic_link" };
  }
  if (path === "/passkey/verify-authentication" || path === "/passkey/verify-registration") {
    return { kind: "method", method: "passkey" };
  }
  if (path.startsWith("/sso/")) return { kind: "method", method: "sso" };
  if (path === "/sign-in/social") {
    const body = ctx.body as { provider?: unknown } | undefined;
    return typeof body?.provider === "string"
      ? { kind: "method", method: body.provider }
      : { kind: "unknown", path };
  }
  const callbackMatch = /^\/callback\/(.+)$/.exec(path);
  if (callbackMatch) {
    const segment = callbackMatch[1];
    if (segment && segment !== ":id") return { kind: "method", method: segment }; // concrete: /callback/google
    const id = ctx.params?.id;
    return typeof id === "string" ? { kind: "method", method: id } : { kind: "unknown", path }; // pattern: /callback/:id
  }
  if (CONTINUATION_PATHS.has(path)) return { kind: "continuation", path };
  return { kind: "unknown", path };
}

/**
 * The sign-in *method* a session-creating call carries, or `null` when the
 * path is a continuation or unknown — a thin wrapper over
 * `classifySessionCreate` kept for callers (and tests) that only need the
 * name. `null` no longer means "never blocked": see the hook below.
 */
export function deriveSessionCreateMethod(
  ctx: {
    path?: string;
    params?: Record<string, string | undefined>;
    body?: unknown;
    context?: { session?: unknown } | null;
  },
  opts?: EnterpriseOptions,
  session?: { userId?: unknown },
): string | null {
  const classified = classifySessionCreate(ctx, opts, session);
  return classified.kind === "method" ? classified.method : null;
}

// --- shared refusal helpers ------------------------------------------------

function ssoRequiredError(): APIError {
  return policyRefusal(
    new APIError("FORBIDDEN", {
      code: "SSO_REQUIRED",
      message: "Your organization requires SSO through its own identity provider",
    }),
  );
}

function methodNotAllowedError(method: string): APIError {
  return policyRefusal(
    new APIError("FORBIDDEN", {
      code: "METHOD_NOT_ALLOWED",
      message: `Sign-in method "${method}" is not allowed for this organization.`,
    }),
  );
}

/**
 * `allowedMethods` binds only once some contributing org actually narrowed
 * the list (`sources.allowedMethodsBy`, computed by `getEffectivePolicy`
 * against the **full** method vocabulary — the 8 built-ins plus every
 * `policy.signInMethods` name the product declared, `allowedMethodValues`).
 * The rule per org: a declared method is allowed only if the org's stored
 * list contains it, or the org has no `org_policy` row at all, or its row
 * lists the full vocabulary. A row that stores exactly the 8 built-ins while
 * the product declares `email_otp` therefore *excludes* `email_otp` — an org
 * must be able to exclude a declared method without also dropping a
 * built-in — and declaring a new `signInMethods` entry means orgs with an
 * existing row must add the name before their members can use it. Only a
 * method name outside the vocabulary altogether (a social provider id the
 * product never declared) is left alone for an un-narrowed org.
 */
function methodRefusedBy(eff: EffectivePolicy, method: string): boolean {
  return eff.sources.allowedMethodsBy.length > 0 && !eff.allowedMethods.includes(method);
}

// --- require2fa: sign-in methods ------------------------------------------

/** `policy.twoFactor.satisfiedBy` default: the IdP did the second factor. */
export const DEFAULT_TWO_FACTOR_SATISFIED_BY: readonly string[] = ["sso"];

/** The sign-in methods that count as having satisfied `require2fa` on their own. */
export function twoFactorSatisfiedBy(opts?: EnterpriseOptions): readonly string[] {
  return opts?.policy?.twoFactor?.satisfiedBy ?? DEFAULT_TWO_FACTOR_SATISFIED_BY;
}

function twoFactorRequiredError(method: string): APIError {
  return policyRefusal(
    new APIError("FORBIDDEN", {
      code: "TWO_FACTOR_REQUIRED",
      message: `Your organization requires two-factor authentication; sign-in method "${method}" does not provide one.`,
    }),
  );
}

/**
 * Whether upstream's `twoFactor()` plugin will challenge the session this
 * path is creating: its `hooks.after` withdraws the session of an enrolled
 * user and issues the challenge cookie instead, so the session that finally
 * stands is minted by `/two-factor/verify-*` (a continuation). The decision
 * is read from the **mounted** plugin's own matcher — the same code path
 * upstream runs after the endpoint — rather than from a list kept here:
 * without the plugin, or for a path its matcher does not name, no challenge
 * follows and the answer is `false`. `/sign-up/email` is the one addition:
 * it creates the user in the same request, so there is nothing to
 * challenge yet, and the session it mints is confined to enrolment by
 * `buildTwoFactorEnrollmentGate` until the user has enrolled.
 *
 * An un-enrolled user on a challenged path gets no challenge either; their
 * session is the enrolment-only one the gate confines. That is why the
 * gate exists: this hook cannot tell a user who will enrol from one who
 * never will.
 */
export function twoFactorChallengeFollows(ctx: {
  path?: string;
  context?: { options?: { plugins?: BetterAuthPlugin[] } } | null;
}): boolean {
  const path = ctx.path;
  if (!path) return false;
  if (path === "/sign-up/email") return true;
  const plugin = ctx.context?.options?.plugins?.find((p) => p.id === "two-factor");
  const afterHooks = plugin?.hooks?.after ?? [];
  for (const hook of afterHooks) {
    try {
      if (hook.matcher({ path } as never)) return true;
    } catch {
      // a matcher that needs more than the path cannot be consulted here:
      // no challenge is assumed (fail closed)
    }
  }
  return false;
}

/**
 * The `require2fa` rule for a session being created, given its
 * classification: a continuation stands (the method that started the flow
 * was judged when it started); a named method stands when it is in
 * `satisfiedBy` or when upstream's challenge follows it; an unclassifiable
 * path never stands. Returns the refusal to throw, or `null`.
 */
export function twoFactorRefusal(
  ctx: { path?: string; context?: { options?: { plugins?: BetterAuthPlugin[] } } | null },
  classified: SessionCreateClassification,
  opts?: EnterpriseOptions,
): APIError | null {
  if (classified.kind === "continuation") return null;
  if (classified.kind === "unknown") return methodNotAllowedError(classified.path ?? "unknown");
  if (twoFactorSatisfiedBy(opts).includes(classified.method)) return null;
  if (twoFactorChallengeFollows(ctx)) return null;
  return twoFactorRequiredError(classified.method);
}

/**
 * How an **already standing** session fares against a `require2fa` policy —
 * the continuous counterpart of `twoFactorRefusal` (which judges a session
 * only at creation). Evaluated on every request by the enrolment gate, by the
 * `/get-session` hook and by the refresh clamp, so a policy that came to
 * apply after the session was minted is enforced on the existing session
 * rather than only on the next sign-in:
 *
 * - `"ok"` — the user has enrolled a second factor; or the user holds no
 *   password and the session was **judged under the requirement when it was
 *   created**: it was created strictly after the requirement's onset for this
 *   user (`onsetMs`, `twoFactorRequirementOnsetMs` — the latest of each
 *   requiring org's `org_policy.updated_at` and the user's membership in it).
 *   Every session minted after that instant went through the create hook's
 *   rule 4 (`twoFactorRefusal`), which admits a no-password user only through
 *   a `satisfiedBy` method — so it stands, and no per-session record is needed.
 * - `"enrollment-required"` — the user holds a password account and has not
 *   enrolled: confined to the enrolment allow-list until they do
 *   (`TWO_FACTOR_ENROLLMENT_REQUIRED`), whenever the session was minted.
 * - `"two-factor-required"` — the user cannot enrol here (no password account:
 *   SSO-, magic-link-, social- or passkey-only) and the session was never
 *   judged under the requirement: minted at or before the onset (before the
 *   org flipped `require2fa` on or last edited its policy, before the user
 *   joined it, or before an upgrade whose data migration moved the onset —
 *   `sql/0003_require2fa.sql`), or an impersonation session (upstream's
 *   `impersonatedBy`), which the create hook admits as a continuation of the
 *   *admin's* sign-in and therefore never judged for the impersonated user.
 *   The session is refused (`TWO_FACTOR_REQUIRED`; `/get-session` answers
 *   `null`) and the user signs in again — through a method that satisfies the
 *   policy, or not at all.
 *
 * Timestamps are compared in epoch milliseconds whatever unit the columns
 * hold (`timestampMs`); a creation time that cannot be read never stands.
 */
export type TwoFactorStanding = "ok" | "enrollment-required" | "two-factor-required";

export function twoFactorStanding(
  sessionRow: Record<string, unknown>,
  state: TwoFactorEnrollmentState,
  onsetMs: number,
): TwoFactorStanding {
  if (state.twoFactorEnabled) return "ok";
  if (state.canEnroll) return "enrollment-required";
  if (sessionRow.impersonatedBy) return "two-factor-required";
  const createdAt = timestampMs(sessionRow.createdAt);
  if (createdAt !== null && createdAt > onsetMs) return "ok";
  return "two-factor-required";
}

/**
 * `twoFactorStanding` for a session whose user is under `require2fa`
 * (`eff.require2fa`), reading only what the answer needs: the user row first
 * (enrolled, or a password holder, settles it; `known` when the caller has
 * already read it), then the requirement's onset for this user over the orgs
 * that impose it.
 */
export async function resolveTwoFactorStanding(
  ctx: GenericEndpointContext,
  sessionRow: Record<string, unknown>,
  userId: string,
  eff: EffectivePolicy,
  known?: TwoFactorEnrollmentState,
): Promise<TwoFactorStanding> {
  const state = known ?? (await twoFactorEnrollmentState(ctx, userId));
  if (state.twoFactorEnabled || state.canEnroll) return twoFactorStanding(sessionRow, state, 0);
  const onsetMs = await twoFactorRequirementOnsetMs(ctx, userId, eff.sources.require2faBy);
  return twoFactorStanding(sessionRow, state, onsetMs);
}

/**
 * The `createdAt` the create hook stamps on a session it has just judged under
 * `require2fa` (rule 4 passed for a named method): the start of the second
 * after next, measured from the later of now and the requirement's onset for
 * this user. Two reasons it is not simply "now":
 *
 * - a product's `session.created_at` may keep whole seconds, which would read
 *   back as *at or before* an onset stamped in the same second — the judged
 *   session would then look unjudged;
 * - an SSO or social callback provisions the organization membership
 *   (`@better-auth/sso`'s just-in-time assignment) **after** it creates the
 *   session, in the same request, so the membership would post-date the very
 *   session that was judged with that organization's claim in view.
 *
 * Starting the stamp one whole second past the current one keeps both on the
 * right side of the comparison in any unit. It is sound for every other
 * requiring org too: rule 4 does not depend on which org imposes the
 * requirement, so a session it admitted stands under all of them. Returns
 * `null` when the onset cannot be read (the session is then left to fail
 * closed at its first request).
 */
function judgedSessionCreatedAt(session: { createdAt?: unknown }, onsetMs: number): Date | null {
  if (onsetMs === Infinity) return null;
  const minted = timestampMs(session.createdAt) ?? Date.now();
  const from = Math.max(minted, Date.now(), onsetMs);
  return new Date((Math.floor(from / 1000) + 2) * 1000);
}

// --- sign-in pre-flight (hooks.before on /magic-link/verify) --------------

/**
 * The only sign-in path still pre-flighted. Password sign-in is enforced by
 * the session-creation backstop after the credential check; the magic-link
 * *request* is left alone (it must not reveal whether the address belongs
 * to a policy-bound member — gap 3). The *verify* step is safe to pre-flight
 * because the pending token, not a guessable e-mail, is what identifies the
 * user — and refusing before the real handler runs keeps the single-use
 * token unconsumed, which the audit row and the user's next attempt both
 * want. It also keeps upstream's handler from touching the account: for a
 * user whose e-mail is not yet verified, the handler deletes their linked
 * accounts and sessions (`revokeUnprovenAccountAccess`) before it mints the
 * session the backstop would then refuse.
 */
const SIGNIN_ENFORCEMENT_PATHS = new Set<string>(["/magic-link/verify"]);

/** Web-Crypto reimplementation of `magicLink`'s default `storeToken: "hashed"` hasher (see `resolveMagicLinkEmail` below for why). */
async function hashMagicLinkToken(token: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
  let binary = "";
  for (const byte of new Uint8Array(digest)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * The verification identifier better-auth >= 1.7.7 keys a pending magic
 * link under: `magic-link:<stored token>` (`magicLinkIdentifier` in
 * `node_modules/better-auth/dist/plugins/magic-link/index.mjs`). 1.7.7 gave
 * every verification purpose its own prefix (GHSA-965c-763c-88jm: an OAuth
 * state row, then keyed by the bare state, could be redeemed as a magic
 * link; state rows are now `auth-state:<state>`).
 */
export function magicLinkVerificationIdentifier(storedToken: string): string {
  return `magic-link:${storedToken}`;
}

/**
 * The e-mail of a magic-link verification value, or `null`. 1.7.7 stores
 * `{"type":"magic-link","email":…,"name"?:…}` and its verify handler redeems
 * only a value tagged with that type, so a row of any other shape is never
 * resolved here either.
 */
export function magicLinkRecordEmail(value: unknown): string | null {
  if (typeof value !== "string") return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    return null; // malformed verification value — fall through to the backstop
  }
  if (typeof parsed !== "object" || parsed === null) return null;
  const record = parsed as { type?: unknown; email?: unknown };
  return record.type === "magic-link" && typeof record.email === "string" ? record.email : null;
}

/**
 * Resolves the email a `/magic-link/verify` request (a GET with a
 * `?token=`, no email in the request) is *for*, best-effort via a
 * non-destructive `findVerificationValue` read of the still-pending token
 * (never `consumeVerificationValue` — that's the real endpoint's job, and
 * consuming it here would burn the token before the user's actual
 * verification request).
 *
 * It reads exactly the row the real handler will redeem: the identifier
 * `magicLinkVerificationIdentifier(storedToken)` and a value
 * `magicLinkRecordEmail` accepts. `magicLink`'s `storeToken` option controls
 * the stored token: `"plain"` (the default) stores the raw token; `"hashed"`
 * stores `defaultKeyHasher(token)` — SHA-256, base64url, unpadded
 * (`./utils.mjs`'s `defaultKeyHasher`), reimplemented here via Web Crypto
 * since this plugin has no access to the `magicLink` plugin instance's
 * options (it's configured by the product, not by `orgPolicy`) to call the
 * real one. A custom `{type: "custom-hasher", hash}` function can't be
 * replicated at all. So this tries the raw token first, then the default
 * hash — covering `"plain"` and `"hashed"` — and returns `null` (deferring
 * to the `databaseHooks.session.create.before` backstop) for a custom
 * hasher or an already-consumed/unknown token. A bare (unprefixed)
 * identifier is never looked up: since 1.7.7 the handler never redeems one,
 * and it may belong to another verification purpose.
 */
export async function resolveMagicLinkEmail(
  ctx: GenericEndpointContext,
  query: { token?: unknown } | undefined,
): Promise<string | null> {
  const token = typeof query?.token === "string" ? query.token : null;
  if (!token) return null;
  const storedTokens = [token, await hashMagicLinkToken(token)];
  for (const storedToken of storedTokens) {
    const verification = await ctx.context.internalAdapter
      .findVerificationValue(magicLinkVerificationIdentifier(storedToken))
      .catch(() => null);
    if (!verification) continue;
    const email = magicLinkRecordEmail(verification.value);
    if (email) return email;
  }
  return null;
}

async function enforceForEmail(
  ctx: GenericEndpointContext,
  path: string,
  email: string,
  method: string,
  opts: EnterpriseOptions | undefined,
): Promise<void> {
  const targetUser = await ctx.context.internalAdapter.findUserByEmail(email);
  const userId = targetUser?.user.id ?? null;
  const orgIds = await resolvePolicyOrgsForUser(ctx, { userId, email });
  if (orgIds.length === 0) return;
  const eff = await getEffectivePolicy(ctx, orgIds, userId, opts);

  const refuse = async (error: APIError): Promise<never> => {
    await auditRefusal(ctx, {
      path,
      code: String(error.body?.code ?? ""),
      orgIds: eff.orgIds,
      userId,
      email,
      method,
    });
    throw error;
  };

  if (eff.ssoEnforced) await refuse(ssoRequiredError());
  if (methodRefusedBy(eff, method)) await refuse(methodNotAllowedError(method));
}

export function buildSignInBeforeHook(opts?: EnterpriseOptions) {
  return {
    matcher: (ctx: { path?: string }) => !!ctx.path && SIGNIN_ENFORCEMENT_PATHS.has(ctx.path),
    handler: createAuthMiddleware(async (ctx) => {
      const path = ctx.path as string;
      const fullCtx = ctx as unknown as GenericEndpointContext;
      const email = await resolveMagicLinkEmail(
        fullCtx,
        ctx.query as { token?: unknown } | undefined,
      );
      if (!email) return; // custom hasher or an already-consumed/unknown token: the backstop still applies
      await enforceForEmail(fullCtx, path, email, "magic_link", opts);
    }),
  };
}

// --- session-creation backstop ---------------------------------------------

function sessionExpiryMs(session: { expiresAt?: unknown }, ctx: GenericEndpointContext): number {
  const requested = session.expiresAt;
  if (requested instanceof Date && Number.isFinite(requested.getTime())) return requested.getTime();
  if (typeof requested === "number" && Number.isFinite(requested)) return requested;
  return Date.now() + ctx.context.sessionConfig.expiresIn * 1000;
}

/**
 * `databaseHooks.session.create.before` — the backstop every sign-in path
 * (including the ones no pre-flight hook can cover: password, social,
 * passkey, and the SSO callback itself) ultimately funnels through, *after*
 * upstream has checked the credential. Wired via `init()` in `./plugin.ts`
 * (see that file's header comment for why — `BetterAuthPlugin` has no
 * top-level `databaseHooks` field).
 *
 * Rules, in order:
 * 0. **SSO provider trust** (before any policy and independent of it): on
 *    an SSO callback the signing provider is resolved once
 *    (`resolveSsoCallbackProvider`, fail-closed `SSO_PROVIDER_UNRESOLVED`);
 *    with `sso.allowedIssuers` configured its stored row must still pass
 *    the allow-list — issuer, endpoints and, for SAML, the pinned signing
 *    certificates (F-28, `SSO_ISSUER_NOT_ALLOWED`); and, unless
 *    `sso.domainBinding: "off"`, it must be domain-verified for the user's
 *    e-mail domain (F-01) → otherwise `SSO_DOMAIN_NOT_ALLOWED`. This is what
 *    makes a legacy squat — an `account` row already linked to a foreign
 *    tenant's IdP — inert: the row stays, the session is never minted.
 * Then, against the **effective** policy of every org with a claim on the
 * user (`resolvePolicyOrgsForUser` + `getEffectivePolicy`):
 * 1. `ssoEnforced` and this is not an SSO callback → `SSO_REQUIRED`. On an
 *    SSO callback the provider's org must be one of the orgs enforcing SSO
 *    on this user **and**, when the e-mail domain is claimed by verified
 *    providers at all, one of the orgs claiming it (R3) — so a tenant who
 *    flips *their own* org to `ssoEnforced` cannot satisfy another org's
 *    rule for a user they linked to their IdP. Otherwise `SSO_REQUIRED`
 *    ("through its own identity provider").
 * 2. a named method some org excluded → `METHOD_NOT_ALLOWED` (`methodRefusedBy`;
 *    narrowing is judged against the full method vocabulary, `opts` threaded
 *    into `getEffectivePolicy`).
 * 3. a path this layer cannot classify, for a user under any restriction →
 *    `METHOD_NOT_ALLOWED` (fail closed; declare it in
 *    `policy.signInMethods`). Continuations are never refused here — and a
 *    `/verify-email` session for a user with no current session is not one
 *    (`isVerifyEmailContinuation`): it is enforced as `magic_link`.
 * 4. `require2fa` (`twoFactorRefusal`): a continuation stands; a method in
 *    `policy.twoFactor.satisfiedBy` (default `sso`) stands; a path the
 *    mounted `twoFactor()` plugin challenges (`/sign-in/email`, …) stands —
 *    an enrolled user's session is withdrawn for the challenge and re-minted
 *    by `/two-factor/verify-*`, an un-enrolled user's is confined to
 *    enrolment by `buildTwoFactorEnrollmentGate`; `/sign-up/email` stands
 *    for the same reason; anything else — magic link, passkey, a social
 *    provider, an unclassified path — carries no second factor and gets
 *    none → `TWO_FACTOR_REQUIRED` (`METHOD_NOT_ALLOWED` for the
 *    unclassified path). A named method that stands is stamped as judged:
 *    its `createdAt` is set just past the requirement's onset for this user
 *    (`judgedSessionCreatedAt`), which is what lets the gate tell it, later,
 *    from a session minted before the requirement applied
 *    (`twoFactorStanding`) — without any column beyond upstream's own.
 * 5. `sessionMaxAgeS` → `expiresAt = min(requested, now + cap)`; never
 *    extends a session past the global lifetime.
 * Break-glass is honoured per org inside `getEffectivePolicy` (it exempts
 * from `ssoEnforced` and `allowedMethods`, not from `require2fa`).
 */
export function buildSessionCreateBeforeHook(opts?: EnterpriseOptions) {
  return async (
    session: { userId: string; expiresAt?: unknown; createdAt?: unknown } & Record<string, unknown>,
    ctx: GenericEndpointContext | null,
  ) => {
    if (!ctx) return;
    const user = await ctx.context.internalAdapter.findUserById(session.userId);
    if (!user?.email) return;

    const classified = classifySessionCreate(ctx, opts, session);
    // The hook's answer: upstream's row, with at most `expiresAt` (rule 5)
    // and `createdAt` (rule 4's stamp) changed — both core `session` fields
    // every product table has. Nothing is ever added to the row.
    const patched = (patch: { expiresAt?: Date; createdAt?: Date }) => {
      if (Object.keys(patch).length === 0) return undefined;
      // `expiresAt`/`createdAt` on the incoming `session` are typed
      // `unknown`; the merge keeps them `Date`s at runtime (upstream's
      // `createSession` set them), and the cast re-asserts that for the
      // hook's stricter return type.
      return {
        data: { ...session, ...patch } as typeof session & { expiresAt?: Date; createdAt?: Date },
      };
    };

    // Rule 0 — the provider is looked up once and reused by rule 1. With the
    // binding and the allow-list both off it is still needed by rule 1 (and
    // only refused as unresolved there, when a decision actually depends on
    // it). With an allow-list configured the stored row is re-judged first
    // (`assertStoredProviderAllowed`, `SSO_ISSUER_NOT_ALLOWED`): a provider
    // the operator no longer trusts is refused before its domain claim is
    // even considered.
    const ssoCallback = isSsoCallbackPath(ctx.path);
    let provider: SsoCallbackProvider | null = null;
    if (ssoCallback) {
      provider = await resolveSsoCallbackProvider(ctx);
      const bindingOn = domainBindingEnabled(opts);
      if (bindingOn || issuerAllowListEnabled(opts)) {
        if (!provider) {
          ctx.context.logger.error(
            `enterprise-policy: refusing an SSO session from ${JSON.stringify(ctx.path)} — the signing provider could not be resolved (SSO_PROVIDER_UNRESOLVED)`,
          );
          throw ssoProviderUnresolvedError();
        }
        await assertStoredProviderAllowed(ctx, opts, provider);
        if (bindingOn && !providerAuthorizesEmail(provider, user.email)) {
          throw ssoDomainNotAllowedError();
        }
      }
    }

    const activeOrganizationId =
      typeof session.activeOrganizationId === "string" ? session.activeOrganizationId : null;
    const { orgIds, identityOrgIds } = await resolvePolicyClaims(ctx, {
      userId: session.userId,
      email: user.email,
      activeOrganizationId,
    });
    if (orgIds.length === 0) return;
    const eff = await getEffectivePolicy(ctx, orgIds, session.userId, opts);

    if (eff.ssoEnforced) {
      if (!ssoCallback) throw ssoRequiredError();
      if (!provider) throw ssoProviderUnresolvedError();
      const providerOrgId = provider.organizationId;
      if (!providerOrgId || !eff.sources.ssoEnforcedBy.includes(providerOrgId)) {
        throw ssoRequiredError();
      }
      if (identityOrgIds.length > 0 && !identityOrgIds.includes(providerOrgId)) {
        throw ssoRequiredError();
      }
    }

    if (classified.kind === "method" && methodRefusedBy(eff, classified.method)) {
      throw methodNotAllowedError(classified.method);
    }
    if (classified.kind === "unknown" && (eff.restricted || eff.require2fa)) {
      ctx.context.logger.warn(
        `enterprise-policy: refusing a session from unclassified path ${JSON.stringify(classified.path)} for a user under a restricted policy — declare it in policy.signInMethods (METHOD_NOT_ALLOWED)`,
      );
      throw methodNotAllowedError(classified.path ?? "unknown");
    }

    const patch: { expiresAt?: Date; createdAt?: Date } = {};
    if (eff.require2fa) {
      const refusal = twoFactorRefusal(ctx, classified, opts);
      if (refusal) throw refusal;
      // Judged under the requirement: stamp it so it reads as such later
      // (`twoFactorStanding`, `judgedSessionCreatedAt`). A continuation is
      // not stamped — it was admitted without a judgement of its own.
      if (classified.kind === "method") {
        const onsetMs = await twoFactorRequirementOnsetMs(
          ctx,
          session.userId,
          eff.sources.require2faBy,
        );
        const createdAt = judgedSessionCreatedAt(session, onsetMs);
        if (createdAt) patch.createdAt = createdAt;
      }
    }

    if (eff.sessionMaxAgeS != null) {
      const cap = Date.now() + eff.sessionMaxAgeS * 1000;
      patch.expiresAt = new Date(Math.min(sessionExpiryMs(session, ctx), cap));
    }
    return patched(patch);
  };
}

// --- session-refresh clamp -------------------------------------------------

/**
 * `databaseHooks.session.update.before` — F-05. Upstream `/get-session`
 * refreshes a session by writing `expiresAt = now + expiresIn` (the global
 * 7-day lifetime) whenever `updateAge` has elapsed, which silently undid the
 * cap the create hook applied on the first authenticated request. This hook
 * sees that write (`data.expiresAt`) and clamps it to
 * `createdAt + sessionMaxAgeS` for the session being refreshed — the one
 * `/get-session` has already loaded into `ctx.context.session` — so a
 * capped session can be refreshed within its window but never past it.
 * Writes that do not touch `expiresAt` (`/organization/set-active`, …) and
 * writes outside a request context pass through untouched.
 */
export function buildSessionUpdateBeforeHook(opts?: EnterpriseOptions) {
  return async (
    data: { expiresAt?: unknown } & Record<string, unknown>,
    ctx: GenericEndpointContext | null,
  ) => {
    if (!ctx) return;
    const requested = data.expiresAt;
    if (!(requested instanceof Date) || !Number.isFinite(requested.getTime())) return;
    const current = ctx.context.session;
    if (!current?.session || !current.user?.email) return;

    const orgIds = await resolvePolicyOrgsForUser(ctx, {
      userId: current.session.userId,
      email: current.user.email,
      activeOrganizationId: current.session.activeOrganizationId ?? null,
    });
    if (orgIds.length === 0) return;
    const eff = await getEffectivePolicy(ctx, orgIds, current.session.userId, opts);

    // A session the enrolment gate would refuse under `require2fa` must not
    // have its lifetime extended by `/get-session`'s refresh (which is on the
    // gate's allow-list, so the gate never runs there). Keep the current
    // expiry — the session runs down and is not renewed — matching the gate's
    // refusal on every other path.
    if (eff.require2fa) {
      const standing = await resolveTwoFactorStanding(
        ctx,
        current.session as unknown as Record<string, unknown>,
        current.session.userId,
        eff,
      );
      if (standing !== "ok") {
        const currentExpiry = new Date(current.session.expiresAt).getTime();
        if (Number.isFinite(currentExpiry) && requested.getTime() > currentExpiry) {
          return { data: { ...data, expiresAt: new Date(currentExpiry) } };
        }
        return;
      }
    }

    if (eff.sessionMaxAgeS == null) return;

    const createdAt = new Date(current.session.createdAt).getTime();
    if (!Number.isFinite(createdAt)) return;
    const cap = createdAt + eff.sessionMaxAgeS * 1000;
    if (requested.getTime() <= cap) return;
    return { data: { ...data, expiresAt: new Date(cap) } };
  };
}

// --- require2fa: enrolment gate (hooks.before, every request) --------------

/**
 * What a signed-in user who still has to enrol may call: read their own
 * session (the `enterprise.enrollmentRequired` annotation is what the
 * product's redirect keys on), sign out, and upstream's enrolment endpoints
 * — `/two-factor/enable` (password re-auth, returns the TOTP URI),
 * `/two-factor/get-totp-uri`, `/two-factor/verify-totp` (the first
 * successful code is what flips `twoFactorEnabled` and re-issues the
 * session), and the OTP pair for a product that configured `sendOTP`.
 * `/enterprise/home-realm` is a public pre-sign-in probe with no session
 * semantics, kept reachable so a sign-in page still renders next to a
 * stale cookie. Everything else — every organization, enterprise, account,
 * key and sign-in endpoint, and every endpoint of a plugin this package has
 * never heard of — is refused until the user has enrolled. A product adds
 * its own enrolment UI backend with `policy.twoFactor.enrollmentPaths`.
 */
export const TWO_FACTOR_ENROLLMENT_ALLOWED_PATHS: ReadonlySet<string> = new Set([
  "/get-session",
  "/sign-out",
  "/enterprise/home-realm",
  "/two-factor/enable",
  "/two-factor/get-totp-uri",
  "/two-factor/verify-totp",
  "/two-factor/send-otp",
  "/two-factor/verify-otp",
]);

/** The built-in allow-list plus the product's `policy.twoFactor.enrollmentPaths`. */
export function twoFactorEnrollmentAllowedPaths(opts?: EnterpriseOptions): ReadonlySet<string> {
  const extra = opts?.policy?.twoFactor?.enrollmentPaths ?? [];
  if (extra.length === 0) return TWO_FACTOR_ENROLLMENT_ALLOWED_PATHS;
  return new Set([...TWO_FACTOR_ENROLLMENT_ALLOWED_PATHS, ...extra]);
}

function twoFactorEnrollmentRequiredError(allowed: ReadonlySet<string>): APIError {
  return policyRefusal(
    new APIError("FORBIDDEN", {
      code: "TWO_FACTOR_ENROLLMENT_REQUIRED",
      message:
        "Your organization requires two-factor authentication. Enrol a second factor to continue.",
      enrollmentPaths: [...allowed],
    }),
  );
}

/**
 * A `require2fa`-gated session that was never judged under the requirement,
 * for a user who cannot enrol, is refused outright rather than confined to
 * enrolment (`twoFactorStanding` → `"two-factor-required"`).
 * `TWO_FACTOR_REQUIRED`, the same code the create hook uses.
 */
export function sessionTwoFactorRequiredError(): APIError {
  return policyRefusal(
    new APIError("FORBIDDEN", {
      code: "TWO_FACTOR_REQUIRED",
      message:
        "Your organization requires two-factor authentication, which this session was not signed in with. Sign in again.",
    }),
  );
}

/**
 * The rewritten request headers a mounted header→cookie carrier would produce
 * for this request, or `null`. The one carrier in scope is upstream's
 * `bearer()` plugin, which converts an `Authorization: Bearer <token>` into
 * the session cookie its own `hooks.before` sets — but that rewrite is merged
 * into the request only *after* the whole before-hook pass, so a sibling
 * before-hook (this gate) never sees it, whatever the plugin order. The gate
 * therefore re-runs the mounted `bearer` plugin's own before-hook — the exact
 * code path the request will take — and reads the cookie it sets, so a
 * bearer-carried session is judged like a cookie one. A carrier that throws,
 * or a token it will not accept, yields `null` (no session — fail closed,
 * left to the endpoint to reject).
 */
async function bearerRewrittenHeaders(ctx: GenericEndpointContext): Promise<Headers | null> {
  const carrier = ctx.request?.headers.get("authorization") ?? ctx.headers?.get("authorization");
  if (!carrier) return null;
  const plugin = ctx.context.options?.plugins?.find((p) => p.id === "bearer");
  const beforeHooks = plugin?.hooks?.before ?? [];
  for (const hook of beforeHooks) {
    let matched = false;
    try {
      matched = hook.matcher(ctx as never);
    } catch {
      matched = false;
    }
    if (!matched) continue;
    let result: unknown;
    try {
      result = await hook.handler(ctx as never);
    } catch {
      return null;
    }
    const direct = (result as { context?: { headers?: unknown } } | null)?.context?.headers;
    if (direct instanceof Headers) return direct;
    const wrapped = (result as { response?: { context?: { headers?: unknown } } } | null)?.response
      ?.context?.headers;
    if (wrapped instanceof Headers) return wrapped;
  }
  return null;
}

/**
 * The session this request will resolve to at the endpoint, derived through
 * the same code path the endpoint's `sessionMiddleware` uses — including the
 * `bearer()` carrier a plain before-hook read would miss (see
 * `bearerRewrittenHeaders`). Returns `null` when the request carries no
 * session by any means the endpoint would accept.
 */
async function resolveGateSession(
  ctx: GenericEndpointContext,
): Promise<Awaited<ReturnType<typeof getSessionFromCtx>>> {
  const session = await getSessionFromCtx(ctx);
  if (session?.user) return session;
  const rewritten = await bearerRewrittenHeaders(ctx);
  if (!rewritten) return session;
  if (!ctx.headers) ctx.headers = new Headers();
  rewritten.forEach((value, key) => ctx.headers!.set(key, value));
  ctx.context.session = null; // clear the negative cache so the re-read runs against the rewritten cookie
  return await getSessionFromCtx(ctx);
}

/**
 * `hooks.before` on every request outside `twoFactorEnrollmentAllowedPaths`:
 * a signed-in user on whom some org's `require2fa` applies (effective policy —
 * memberships, active org and verified-domain claims alike) is confined unless
 * their session already stands under the policy (`twoFactorStanding`):
 *
 * - a password holder who has not enrolled → `403 TWO_FACTOR_ENROLLMENT_REQUIRED`
 *   with the allow-list in the body (they can enrol and continue);
 * - a no-credential user whose session was never judged under the
 *   requirement (minted at or before its onset for this user — a flip, a
 *   policy edit, a later membership, an upgrade — or an impersonation of such
 *   a user) → `403 TWO_FACTOR_REQUIRED` (nothing to enrol; sign in again).
 *   This is the case a create-time-only check missed: the create hook never
 *   judged such a session. `/get-session` answers `null` for it
 *   (`./plugin.ts`), so the products' own routes see no session either.
 *
 * Order of the reads, cheapest first, each one ending the hook when it
 * settles the answer: does any org on the deployment require 2FA at all
 * (one small `org_policy` read; a deployment without such an org pays
 * nothing else)
 * → is there a session (via `resolveGateSession`, the same resolution the
 * endpoint's `sessionMiddleware` performs, `bearer()` included; an anonymous
 * request, a SCIM bearer or an API key — which never reaches a gated path —
 * has none and is left to the endpoint) → does `require2fa` actually reach
 * this user → its standing. The refusal is audited through `auditRefusal`
 * before it is thrown, the way every `hooks.before` refusal is.
 */
export function buildTwoFactorEnrollmentGate(opts?: EnterpriseOptions) {
  const allowed = twoFactorEnrollmentAllowedPaths(opts);
  return {
    matcher: (ctx: { path?: string }) => !!ctx.path && !allowed.has(ctx.path),
    handler: createAuthMiddleware(async (ctx) => {
      const fullCtx = ctx as unknown as GenericEndpointContext;
      if (!(await anyOrgRequiresTwoFactor(fullCtx))) return;
      const session = await resolveGateSession(fullCtx);
      const userId = session?.user?.id;
      const email = session?.user?.email;
      if (!userId || !email) return;
      const state = await twoFactorEnrollmentState(fullCtx, userId);
      if (state.twoFactorEnabled) return; // enrolled — nothing to gate, whatever the policy

      const orgIds = await resolvePolicyOrgsForUser(fullCtx, {
        userId,
        email,
        activeOrganizationId: session.session.activeOrganizationId ?? null,
      });
      if (orgIds.length === 0) return;
      const eff = await getEffectivePolicy(fullCtx, orgIds, userId, opts);
      if (!eff.require2fa) return;

      const standing = await resolveTwoFactorStanding(
        fullCtx,
        session.session as unknown as Record<string, unknown>,
        userId,
        eff,
        state,
      );
      if (standing === "ok") return;

      const code =
        standing === "enrollment-required"
          ? "TWO_FACTOR_ENROLLMENT_REQUIRED"
          : "TWO_FACTOR_REQUIRED";
      await auditRefusal(fullCtx, {
        path: ctx.path as string,
        code,
        orgIds: eff.sources.require2faBy,
        userId,
        email,
        kind: "session",
      });
      throw standing === "enrollment-required"
        ? twoFactorEnrollmentRequiredError(allowed)
        : sessionTwoFactorRequiredError();
    }),
  };
}
