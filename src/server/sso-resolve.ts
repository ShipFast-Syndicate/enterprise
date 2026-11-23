// Alpha Bros enterprise layer — the composed SSO `resolveUser` (1.3 options).
//
// `@better-auth/sso` calls `resolveUser` on **every** SSO sign-in — OIDC and
// SAML, first logins and returning ones — inside the transaction that links
// the account, creates the user and mints the session (`resolveSSOUser`,
// `node_modules/@better-auth/sso/dist/index.mjs`). It is the only layer that
// sees `verifiedIdTokenClaims` (the claims of the signature-verified ID
// token), so it is where the opt-in `sso.existingUsersOnly`,
// `sso.requireMembership` and `sso.oidcClaims` options are enforced; the
// `user.create.before` backstop (`./policy/sso-jit.ts`) and the registration
// guards (`./sso-domain.ts`) only cover what the resolver cannot.
//
// Identity rule: with none of those options on, `composeSsoResolvers` returns
// the base resolver itself (`resolveScimSsoUser`, `./scim-sso.ts`), the same
// function reference, so the `sso({...})` configuration a consumer that opts
// into nothing gets is the 1.2 one (`test/server/preset.test.ts`).
//
// A refusal does two things, the same two the SCIM resolver does: it marks
// the audit stash (`notePolicyRefusal`, so the callback's failure is written
// as `auth.sign_in_refused` with the code and the provider) and it returns a
// `reject` decision carrying the code, which upstream throws as a 403 and
// redirects as `?error=<code>`. When `existingUsersOnly` is on, an OIDC sign-in
// never gets `continue` from this function: every outcome is a link or a reject,
// and a throw (a database error) becomes upstream's `SSO_USER_RESOLUTION_FAILED`,
// which also fails closed. A SAML sign-in under `existingUsersOnly` is judged
// the same way (`resolveSaml`, 1.4) minus the ID-token claims; with neither
// `existingUsersOnly` nor a SAML policy the function delegates to the base
// resolver, which returns `continue` for a non-SCIM organization. That cannot
// create a user: `disableImplicitSignUp` and the `user.create.before` backstop
// refuse the creation (`SSO_SIGNUP_DISABLED`).
//
// What was read in upstream before writing this (`@better-auth/sso` and
// `better-auth` 1.7.19), because the design depends on it:
//
// - PEER FLOOR NOT VERIFIED: only 1.7.19 is installed and read here. Whether
//   `@better-auth/sso` 1.7.10 (the `^1.7.10` peer floor) passes
//   `verifiedIdTokenClaims`, honours `{ action: "link", profile: "preserve" }`,
//   skips the account-linking refusal for a resolver-selected user, and has
//   `organizationProvisioning.disabled` has not been checked. 1.2.0 already
//   hardwires `resolveUser` at that floor, but nothing else here is proven.
//   When the claims are missing the resolver refuses (`checkClaims`) instead
//   of throwing. Consumers who turn a 1.3 option on should run 1.7.19 or newer
//   (`docs/upgrading-to-1.3.md`).
// - The `account` row an SSO sign-in stores is keyed by
//   `(providerId = the SSO provider's own providerId, accountId = the ID
//   token `sub`)`. `accountKey.issuer` is not stored anywhere, so the
//   conflict checks below key on those two columns only
//   (`handleOAuthUserInfo`, `better-auth/dist/oauth2/link-account.mjs`).
// - `{ action: "link" }` becomes `selectedUser` in `handleOAuthUserInfo`,
//   which skips the `accountLinking.enabled === false` refusal for it
//   (`!opts.selectedUser && (… || accountLinking?.enabled === false …)`), so
//   linking by resolver works with the product's global account linking off,
//   and `profile: "preserve"` leaves the local user's name, image, e-mail and
//   `emailVerified` untouched.
// - Upstream reads the e-mail from the userinfo response when the provider
//   has a `userInfoEndpoint`, and only from the ID token otherwise; the
//   `subject` of the two is compared, the e-mail is not. Hence the explicit
//   ID-token e-mail check here (`SSO_EMAIL_CLAIM_MISMATCH`).
// - `config.pkce` is read as a truthy flag (`codeVerifier: config.pkce ? … :
//   undefined`): a stored provider whose `pkce` is absent sends no verifier,
//   exactly like `false`. `requirePkce` therefore refuses anything that is not
//   truthy, not only an explicit `false`.

import type { PersistedSsoProvider, SsoResolver } from "./scim-sso";
import { findPersistedSsoProvider } from "./scim-sso";
import { notePolicyRefusal } from "./audit/refusal";
import { emailDomain, normalizeProviderDomains } from "./policy/domains";
import { providerAuthorizesEmail } from "./policy/sso-jit";
import {
  effectiveSamlPolicy,
  samlOptedOut,
  samlPolicyRefusal,
  type SamlPolicy,
} from "./sso-domain";
import type { EnterpriseOptions } from "./types";

type SsoOptions = NonNullable<EnterpriseOptions["sso"]>;
type ResolverInput = Parameters<SsoResolver>[0];
type ResolverContext = Parameters<SsoResolver>[1];
type OidcInput = Extract<ResolverInput, { protocol: "oidc" }>;
type Database = ResolverContext["database"];

type SsoPolicyRefusal =
  | "SSO_EMAIL_NOT_VERIFIED"
  | "SSO_EMAIL_CLAIM_MISMATCH"
  | "SSO_HOSTED_DOMAIN_MISMATCH"
  | "SSO_USER_NOT_PROVISIONED"
  | "SSO_USER_BANNED"
  | "SSO_NOT_MEMBER"
  | "SSO_ACCOUNT_CONFLICT"
  | "SSO_PKCE_REQUIRED"
  | "SSO_POLICY_UNSUPPORTED_PROTOCOL"
  | "SSO_SAML_UNSIGNED_ASSERTIONS"
  | "SSO_SAML_CERT_NOT_PINNED"
  | "SSO_PROVIDER_UNRESOLVED"
  | "SSO_DOMAIN_NOT_ALLOWED";

/** A refusal this package raises on upstream's behalf, marked for the audit log (`notePolicyRefusal`). */
function refuse(refusal: SsoPolicyRefusal) {
  notePolicyRefusal(refusal);
  return { action: "reject", code: refusal } as const;
}

interface UserRow {
  id: string;
  email?: string;
  banned?: unknown;
  banExpires?: unknown;
}

/** Whether any claim option (as opposed to `existingUsersOnly`) is on. */
function claimOptions(sso: SsoOptions | undefined) {
  const claims = sso?.oidcClaims;
  const hosted = claims?.requireHostedDomain;
  return {
    requireEmailVerified: claims?.requireEmailVerified === true,
    requirePkce: claims?.requirePkce === true,
    hostedDomain:
      hosted === true ? true : Array.isArray(hosted) && hosted.length > 0 ? hosted : null,
  } as const;
}

function parseOidcConfig(raw: unknown): Record<string, unknown> | null {
  if (typeof raw === "object" && raw !== null && !Array.isArray(raw)) {
    return raw as Record<string, unknown>;
  }
  if (typeof raw !== "string" || raw.length === 0) return null;
  try {
    const parsed: unknown = JSON.parse(raw);
    return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

/** Upstream's `readEmailClaim`: the claim named by `mapping.email` (default `email`), a string or the first string of an array. */
function readEmailClaim(claims: Record<string, unknown>, mapping: unknown): string | null {
  const name =
    typeof mapping === "object" &&
    mapping !== null &&
    typeof (mapping as { email?: unknown }).email === "string"
      ? (mapping as { email: string }).email
      : "email";
  const found = [claims[name]].flat().find((v) => typeof v === "string" && v.length > 0);
  return typeof found === "string" ? found : null;
}

function readEmailVerifiedClaim(claims: Record<string, unknown>, mapping: unknown): unknown {
  const name =
    typeof mapping === "object" &&
    mapping !== null &&
    typeof (mapping as { emailVerified?: unknown }).emailVerified === "string"
      ? (mapping as { emailVerified: string }).emailVerified
      : "email_verified";
  return claims[name];
}

/** The `hd` rule: a string equal (lower-cased) to a provider domain or an allow-list entry, with the e-mail on exactly that domain. */
function hostedDomainHolds(
  claim: unknown,
  email: string,
  allowed: readonly string[] | null,
): boolean {
  if (typeof claim !== "string" || claim.length === 0 || allowed === null) return false;
  const hd = claim.toLowerCase();
  return allowed.includes(hd) && emailDomain(email) === hd;
}

function isBanned(user: UserRow, now: number): boolean {
  if (user.banned !== true && user.banned !== 1) return false;
  const expires = user.banExpires;
  if (expires === null || expires === undefined) return true;
  const at =
    expires instanceof Date
      ? expires.getTime()
      : typeof expires === "number"
        ? expires
        : Date.parse(String(expires));
  // An expiry that cannot be read keeps the ban: fail closed.
  return Number.isNaN(at) || at > now;
}

/** The checks that need the claims and the stored provider (everything but the user). Returns the refusal, or `null`. */
function checkClaims(
  input: OidcInput,
  provider: PersistedSsoProvider,
  sso: SsoOptions,
): { refusal: SsoPolicyRefusal } | { email: string } {
  const config = parseOidcConfig(provider.oidcConfig);
  const wanted = claimOptions(sso);

  // `verifiedIdTokenClaims` is an upstream field this package has only read in
  // 1.7.19; it is NOT VERIFIED at the `^1.7.10` peer floor (see the header).
  // If a resolver call arrives without it, refuse with a named code instead of
  // throwing a TypeError that upstream would report as the misleading
  // `SSO_USER_RESOLUTION_FAILED`. The e-mail cannot be matched to anything
  // signed, so it is the e-mail-claim refusal.
  const rawClaims: unknown = input.verifiedIdTokenClaims;
  if (typeof rawClaims !== "object" || rawClaims === null || Array.isArray(rawClaims)) {
    return { refusal: "SSO_EMAIL_CLAIM_MISMATCH" };
  }
  const claims = rawClaims as Record<string, unknown>;

  // The ID-token e-mail must be the e-mail upstream is about to sign in:
  // with a userinfo endpoint upstream takes the profile (and so the e-mail)
  // from the userinfo response, which the ID-token signature does not cover.
  const email = readEmailClaim(claims, config?.mapping);
  if (email === null || email.toLowerCase() !== input.providerUser.email.toLowerCase()) {
    return { refusal: "SSO_EMAIL_CLAIM_MISMATCH" };
  }
  if (
    (wanted.requireEmailVerified || sso.existingUsersOnly === true) &&
    readEmailVerifiedClaim(claims, config?.mapping) !== true
  ) {
    return { refusal: "SSO_EMAIL_NOT_VERIFIED" };
  }
  if (wanted.hostedDomain !== null) {
    const allowed =
      wanted.hostedDomain === true
        ? normalizeProviderDomains(provider.domain)
        : [...wanted.hostedDomain];
    if (!hostedDomainHolds(claims.hd, email, allowed)) {
      return { refusal: "SSO_HOSTED_DOMAIN_MISMATCH" };
    }
  }
  if (wanted.requirePkce && !config?.pkce) return { refusal: "SSO_PKCE_REQUIRED" };
  return { email };
}

async function findUser(
  database: Database,
  where: { field: string; value: string },
): Promise<UserRow | null> {
  return database.findOne<UserRow>({ model: "user", where: [where] });
}

/** The ban, membership and account-conflict checks on the user a sign-in is about to be bound to. Returns the refusal, or `null`. */
async function checkUserBinding(
  database: Database,
  sso: SsoOptions,
  provider: PersistedSsoProvider,
  user: UserRow,
  accountId: string,
  providerId: string,
): Promise<SsoPolicyRefusal | null> {
  if (isBanned(user, Date.now())) return "SSO_USER_BANNED";

  if (sso.requireMembership !== false) {
    const member = provider.organizationId
      ? await database.findOne({
          model: "member",
          where: [
            { field: "organizationId", value: provider.organizationId },
            { field: "userId", value: user.id },
          ],
        })
      : null;
    if (!member) return "SSO_NOT_MEMBER";
  }

  // The same subject already bound to another user through this provider; or
  // this user already bound to another subject through it. Upstream keys the
  // account on (providerId, accountId), so these two lookups are the whole
  // question.
  const sameSubject = await database.findOne<{ userId: string }>({
    model: "account",
    where: [
      { field: "providerId", value: providerId },
      { field: "accountId", value: accountId },
    ],
  });
  if (sameSubject && sameSubject.userId !== user.id) return "SSO_ACCOUNT_CONFLICT";
  const userAccounts = await database.findMany<{ accountId: string }>({
    model: "account",
    where: [
      { field: "userId", value: user.id },
      { field: "providerId", value: providerId },
    ],
  });
  if (userAccounts.some((account) => account.accountId !== accountId))
    return "SSO_ACCOUNT_CONFLICT";
  return null;
}

/** Links the existing user a sign-in may bind to (SCIM decision `scim` first), or refuses; shared by OIDC and SAML. */
async function linkExistingUser(
  input: ResolverInput,
  context: ResolverContext,
  sso: SsoOptions,
  provider: PersistedSsoProvider,
  email: string,
  scim: Awaited<ReturnType<SsoResolver>>,
) {
  const user =
    scim.action === "link"
      ? await findUser(context.database, { field: "id", value: scim.userId })
      : await findUser(context.database, { field: "email", value: email.toLowerCase() });
  if (!user) return refuse("SSO_USER_NOT_PROVISIONED");
  const refusal = await checkUserBinding(
    context.database,
    sso,
    provider,
    user,
    input.accountKey.accountId,
    input.providerId,
  );
  if (refusal) return refuse(refusal);
  return { action: "link", userId: user.id, profile: "preserve" } as const;
}

/**
 * The SAML half of the resolver. A SAML assertion carries no ID-token claims,
 * so `oidcClaims` do not apply: the provider is judged by `sso.samlPolicy`
 * (signed assertions, certificate pin — the signature, replay and IdP-initiated
 * checks themselves are upstream's, configured by the preset) and, under
 * `existingUsersOnly`, the user is linked with the same ban, membership and
 * one-subject checks as OIDC. The e-mail is the one upstream took from the
 * signature-verified assertion.
 */
async function resolveSaml(
  opts: EnterpriseOptions,
  policy: SamlPolicy | null,
  input: Extract<ResolverInput, { protocol: "saml" }>,
  context: ResolverContext,
  base: SsoResolver,
) {
  const sso = opts.sso ?? {};
  const existingUsersOnly = sso.existingUsersOnly === true;
  if (samlOptedOut(opts)) return refuse("SSO_POLICY_UNSUPPORTED_PROTOCOL");
  if (!existingUsersOnly && !policy) return base(input, context);

  const provider = await findPersistedSsoProvider(input, context);
  if (!provider) return refuse("SSO_PROVIDER_UNRESOLVED");
  if (policy) {
    const refusal = samlPolicyRefusal(
      opts,
      policy,
      parseOidcConfig(provider.samlConfig),
      provider.issuer,
    );
    if (refusal) return refuse(refusal);
  }
  const email = input.providerUser.email;
  if (typeof email !== "string" || email.length === 0) return refuse("SSO_EMAIL_CLAIM_MISMATCH");
  if (existingUsersOnly && !providerAuthorizesEmail(provider, email)) {
    return refuse("SSO_DOMAIN_NOT_ALLOWED");
  }
  const scim = await base(input, context);
  if (scim.action === "reject") return scim;
  if (!existingUsersOnly) return scim;
  return linkExistingUser(input, context, sso, provider, email, scim);
}

/**
 * Composes the SSO resolver for the 1.3 options (see the file header).
 * Returns `base` itself unless `existingUsersOnly`, an `oidcClaims` option or
 * `samlPolicy` is on.
 */
export function composeSsoResolvers(opts: EnterpriseOptions, base: SsoResolver): SsoResolver {
  const sso = opts.sso ?? {};
  const wanted = claimOptions(sso);
  const claimsOn =
    wanted.requireEmailVerified || wanted.requirePkce || wanted.hostedDomain !== null;
  const existingUsersOnly = sso.existingUsersOnly === true;
  const samlPolicy = effectiveSamlPolicy(opts);
  const samlOff = samlOptedOut(opts);
  if (!existingUsersOnly && !claimsOn && !samlPolicy && !samlOff) return base;

  return async (input, context) => {
    // 1. Protocol. The claim options read OIDC claims and bind OIDC only;
    // SAML has its own policy.
    if (input.protocol === "saml") return resolveSaml(opts, samlPolicy, input, context, base);

    // 2. Provider: persisted only (a `defaultSSO` entry has no row to judge).
    const provider = await findPersistedSsoProvider(input, context);
    if (!provider) return refuse("SSO_PROVIDER_UNRESOLVED");

    // 3. Verified ID-token claims.
    const checked = checkClaims(input, provider, sso);
    if ("refusal" in checked) return refuse(checked.refusal);

    // 4. Provider trust: only a verified provider whose domain list covers
    // the e-mail's domain may bind an existing account.
    if (existingUsersOnly && !providerAuthorizesEmail(provider, checked.email)) {
      return refuse("SSO_DOMAIN_NOT_ALLOWED");
    }

    // 5. SCIM. A reject stands; a link keeps its user but is still judged
    // below; a continue falls through to the existing-user lookup.
    const scim = await base(input, context);
    if (scim.action === "reject") return scim;
    if (!existingUsersOnly) return scim;

    // 6. The existing user this sign-in may bind to.
    return linkExistingUser(input, context, sso, provider, checked.email, scim);
  };
}
