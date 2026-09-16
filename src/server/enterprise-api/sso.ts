// Alpha Bros enterprise layer — enterpriseApi plugin: SSO wizard endpoints.
//
// Portal-facing wrappers around `@better-auth/sso`'s own endpoints, scoped
// to a single org and redacted for a browser client: `GET .../providers`
// (read model for the wizard — DNS verification record, ACS/redirect URLs,
// test-login state, enforcement state), `POST .../register` (forwards to
// upstream `/sso/register`, then strips `clientSecret`/cert material before
// returning), and the admin "test login" round trip (`.../test-login/start`
// + `.../test-login/finish`) that `../policy/plugin.ts`'s `setPolicy`
// requires before `ssoEnforced` can be flipped on (ruling (g), enforced in
// `./plugin.ts`'s `hooks.before`).
//
// `_better-auth-token-<providerId>` is `@better-auth/sso`'s own domain
// verification identifier format (`getVerificationIdentifier` in
// `node_modules/@better-auth/sso/dist/index.mjs`: `` `_${tokenPrefix ||
// "better-auth-token"}-${providerId}` ``, DNS record name = `` `${identifier}.
// ${domain}` ``) — reproduced here (not imported; not exported by the
// package) rather than re-derived some other way, so the wizard's displayed
// DNS record matches exactly what `/sso/verify-domain` actually checks.

import {
  APIError,
  createAuthEndpoint,
  getSessionFromCtx,
  sessionMiddleware,
} from "better-auth/api";
import type { GenericEndpointContext } from "better-auth";
import * as z from "zod";
import { requireFeature } from "../entitlements";
import { getOrgPolicy, requireOrgMember, requireOwnerOrAdmin } from "../policy/store";
import { forwardJson, forwardToAuth, relayStatus } from "./forward";

const DOMAIN_TOKEN_PREFIX = "better-auth-token";

function domainVerificationIdentifier(providerId: string): string {
  return `_${DOMAIN_TOKEN_PREFIX}-${providerId}`;
}

interface VerificationRow {
  value: string;
  expiresAt: Date;
}

/** A still-live (non-expired) `verification` row for `identifier`, or `null`. */
async function findLiveVerification(
  ctx: GenericEndpointContext,
  identifier: string,
): Promise<VerificationRow | null> {
  const row = await ctx.context.adapter.findOne<VerificationRow>({
    model: "verification",
    where: [{ field: "identifier", value: identifier }],
  });
  if (!row || new Date(row.expiresAt) <= new Date()) return null;
  return row;
}

/** Replaces any existing `identifier` row with a fresh one (delete-then-create — simpler than a conditional update, and every caller here treats the row as a single point-in-time flag). */
async function upsertVerification(
  ctx: GenericEndpointContext,
  identifier: string,
  value: string,
  expiresAt: Date,
): Promise<void> {
  await deleteVerification(ctx, identifier);
  await ctx.context.internalAdapter.createVerificationValue({ identifier, value, expiresAt });
}

async function deleteVerification(ctx: GenericEndpointContext, identifier: string): Promise<void> {
  await ctx.context.adapter.deleteMany({
    model: "verification",
    where: [{ field: "identifier", value: identifier }],
  });
}

/**
 * The OIDC callback URL for `providerId`: `@better-auth/sso`'s own
 * `getOIDCRedirectURI` (not exported), reproduced so a product that
 * configures `sso({ redirectURI })` still sees the right value in the
 * wizard — defaults to `${baseURL}/sso/callback/${providerId}` the same way.
 */
function oidcRedirectUri(ctx: GenericEndpointContext, providerId: string): string {
  const ssoOptions = ctx.context.getPlugin("sso")?.options as { redirectURI?: string } | undefined;
  const configured = ssoOptions?.redirectURI?.trim();
  if (configured) {
    try {
      return new URL(configured).toString();
    } catch {
      return `${ctx.context.baseURL}${configured.startsWith("/") ? configured : `/${configured}`}`;
    }
  }
  return `${ctx.context.baseURL}/sso/callback/${providerId}`;
}

interface SsoProviderRow {
  providerId: string;
  issuer: string;
  domain: string;
  domainVerified: boolean;
  samlConfig: string | null;
}

/**
 * The ACS (assertion consumer service) URL for a SAML provider: the custom
 * `samlConfig.callbackUrl` a caller registered with, if any — the same
 * override upstream's own SAML flows honor (e.g. `${ctx.context.baseURL}/
 * sso/saml2/sp/acs/${providerId}` is only ever the *fallback*,
 * `node_modules/@better-auth/sso/dist/index.mjs`'s several `Location:
 * parsedSamlConfig.callbackUrl || \`...sp/acs/${provider.providerId}\``
 * sites) — else that default. `row.samlConfig` is the raw JSON string
 * column (see `../types.ts`'s note on `ssoProvider`'s field types); parsed
 * defensively since a malformed/legacy row should fall back rather than
 * throw. Only ever reads `callbackUrl` (a plain URL, never secret
 * material) off it — never returns the parsed object itself.
 */
function acsUrl(ctx: GenericEndpointContext, row: SsoProviderRow): string {
  if (row.samlConfig) {
    try {
      const parsed = JSON.parse(row.samlConfig) as { callbackUrl?: unknown };
      if (typeof parsed.callbackUrl === "string" && parsed.callbackUrl) {
        return parsed.callbackUrl;
      }
    } catch {
      // Malformed samlConfig JSON — fall through to the default below.
    }
  }
  return `${ctx.context.baseURL}/sso/saml2/sp/acs/${row.providerId}`;
}

const providersQuerySchema = z.object({ orgId: z.string() });

function buildProvidersEndpoint() {
  return createAuthEndpoint(
    "/enterprise/sso/providers",
    { method: "GET", use: [sessionMiddleware], query: providersQuerySchema },
    async (ctx) => {
      const fullCtx = ctx as unknown as GenericEndpointContext;
      const { orgId } = ctx.query;
      // Owner/admin, not any member (M-08): this response contains the DNS
      // TXT verification token (`verificationRecord.value`) — whoever holds
      // it can complete domain verification for the org's SSO connection —
      // plus the IdP issuer, ACS/redirect URLs and enforcement state. None
      // of it is something a plain member needs.
      await requireOwnerOrAdmin(fullCtx, orgId);

      const rows = await ctx.context.adapter.findMany<SsoProviderRow>({
        model: "ssoProvider",
        where: [{ field: "organizationId", value: orgId }],
      });
      const policy = await getOrgPolicy(fullCtx, orgId);

      const providers = await Promise.all(
        rows.map(async (row) => {
          const verificationIdentifier = domainVerificationIdentifier(row.providerId);
          const verification = await findLiveVerification(fullCtx, verificationIdentifier);
          const testLoginOk = await findLiveVerification(
            fullCtx,
            `ab-sso-test-ok:${row.providerId}`,
          );
          return {
            providerId: row.providerId,
            type: row.samlConfig ? "saml" : "oidc",
            issuer: row.issuer,
            domain: row.domain,
            domainVerified: row.domainVerified,
            verificationRecord: {
              name: `${verificationIdentifier}.${row.domain}`,
              value: verification?.value ?? null,
            },
            spMetadataUrl: `${ctx.context.baseURL}/sso/saml2/sp/metadata?providerId=${encodeURIComponent(row.providerId)}`,
            acsUrl: acsUrl(fullCtx, row),
            redirectUri: oidcRedirectUri(fullCtx, row.providerId),
            testLoginPassedAt: testLoginOk?.value ?? null,
            enforced: policy.ssoEnforced,
          };
        }),
      );

      return ctx.json({ providers });
    },
  );
}

// Accepts the same body as upstream `/sso/register` (`organizationId` plus
// whatever `oidcConfig`/`samlConfig`/etc. the wizard sends) without
// re-declaring its full, evolving zod schema here — upstream is the
// authoritative validator once forwarded (see `./forward.ts`); this schema
// only pins down the one field *our* membership/role check needs.
const registerBodySchema = z.object({ organizationId: z.string() }).catchall(z.unknown());

/** Strips secret/private material from a (possibly error) upstream `/sso/register` JSON response before it's relayed to the portal. No-op on an error body (no `oidcConfig`/`samlConfig` keys to strip). */
function redactRegisterResponse(data: Record<string, unknown>): Record<string, unknown> {
  const result = { ...data };
  const oidcConfig = result.oidcConfig;
  if (oidcConfig && typeof oidcConfig === "object") {
    const rest = { ...(oidcConfig as Record<string, unknown>) };
    delete rest.clientSecret;
    result.oidcConfig = rest;
  }
  const samlConfig = result.samlConfig;
  if (samlConfig && typeof samlConfig === "object") {
    const saml = { ...(samlConfig as Record<string, unknown>) };
    delete saml.cert;
    delete saml.privateKey;
    delete saml.decryptionPvk;
    for (const key of ["idpMetadata", "spMetadata"] as const) {
      const nested = saml[key];
      if (nested && typeof nested === "object") {
        const copy = { ...(nested as Record<string, unknown>) };
        delete copy.cert;
        delete copy.privateKey;
        delete copy.privateKeyPass;
        delete copy.encPrivateKey;
        delete copy.encPrivateKeyPass;
        saml[key] = copy;
      }
    }
    result.samlConfig = saml;
  }
  return result;
}

function buildRegisterEndpoint() {
  return createAuthEndpoint(
    "/enterprise/sso/register",
    { method: "POST", use: [sessionMiddleware], body: registerBodySchema },
    async (ctx) => {
      const fullCtx = ctx as unknown as GenericEndpointContext;
      const { organizationId } = ctx.body;
      await requireOrgMember(fullCtx, organizationId);
      await requireOwnerOrAdmin(fullCtx, organizationId);
      await requireFeature(fullCtx, organizationId, "sso");

      const { status, data } = await forwardJson(fullCtx, "POST", "/sso/register", ctx.body);
      relayStatus(ctx, status);
      return ctx.json(data ? redactRegisterResponse(data) : data);
    },
  );
}

const testLoginStartBodySchema = z.object({ orgId: z.string(), providerId: z.string() });

const TEST_LOGIN_PENDING_TTL_MS = 10 * 60 * 1000;

function buildTestLoginStartEndpoint() {
  return createAuthEndpoint(
    "/enterprise/sso/test-login/start",
    { method: "POST", use: [sessionMiddleware], body: testLoginStartBodySchema },
    async (ctx) => {
      const fullCtx = ctx as unknown as GenericEndpointContext;
      const { orgId, providerId } = ctx.body;
      await requireOrgMember(fullCtx, orgId);
      await requireOwnerOrAdmin(fullCtx, orgId);
      await requireFeature(fullCtx, orgId, "sso");

      const provider = await ctx.context.adapter.findOne<{ providerId: string }>({
        model: "ssoProvider",
        where: [
          { field: "providerId", value: providerId },
          { field: "organizationId", value: orgId },
        ],
      });
      if (!provider) {
        throw new APIError("NOT_FOUND", {
          code: "SSO_PROVIDER_NOT_FOUND",
          message: "No SSO provider with this id exists for this organization.",
        });
      }

      // `use: [sessionMiddleware]` guarantees `ctx.context.session` here —
      // `requireOrgMember` above would already have thrown `UNAUTHORIZED`
      // otherwise.
      const userId = ctx.context.session?.user.id;
      if (!userId) throw new APIError("UNAUTHORIZED");
      await upsertVerification(
        fullCtx,
        `ab-sso-test:${providerId}`,
        userId,
        new Date(Date.now() + TEST_LOGIN_PENDING_TTL_MS),
      );

      const callbackURL = `${ctx.context.baseURL}/enterprise/sso/test-login/finish?providerId=${encodeURIComponent(providerId)}`;
      // Returns a raw `Response` (the same shape `../audit/plugin.ts`'s CSV
      // export endpoint uses) rather than `ctx.json`, because the upstream
      // `Set-Cookie` headers have to be relayed **verbatim** (C-1, second
      // half): `/sign-in/sso` ends in better-auth's `generateGenericState`
      // (`node_modules/better-auth/dist/state.mjs:61-62`), which stores the
      // OAuth state as a *signed* `state` cookie alongside the `verification`
      // row, and `parseGenericState` compares the two on the callback. A
      // wrapper that reads only the JSON body — as this one did — swallows
      // that cookie, so every test login came back from the IdP to
      // `/sso/callback/:providerId` and redirected to
      // `/api/auth/error?error=state_mismatch`. `ctx.setHeader` cannot carry
      // more than one `set-cookie` (it `set`s rather than `append`s —
      // `node_modules/better-call/dist/context.mjs:26`), and re-serialising
      // the cookie through `ctx.setCookie` would have to reconstruct its
      // attributes by hand; relaying the raw header keeps the signature,
      // `HttpOnly`/`SameSite`/`Path` and `Max-Age` exactly as upstream set
      // them.
      const upstream = await forwardToAuth(fullCtx, "POST", "/sign-in/sso", {
        providerId,
        callbackURL,
      });
      const data = (await upstream.json().catch(() => null)) as Record<string, unknown> | null;
      const headers = new Headers({ "content-type": "application/json" });
      for (const cookie of upstream.headers.getSetCookie()) headers.append("set-cookie", cookie);
      if (!upstream.ok || !data) {
        return new Response(JSON.stringify(data ?? {}), { status: upstream.status, headers });
      }
      return new Response(JSON.stringify({ url: data.url }), { status: 200, headers });
    },
  );
}

const testLoginFinishQuerySchema = z.object({ providerId: z.string() });

function emailDomain(email: string): string | null {
  const at = email.lastIndexOf("@");
  return at === -1 ? null : email.slice(at + 1).toLowerCase();
}

// Every check on this endpoint is local, and the org it acts on is derived
// from the **provider row**, never from the session (C-1).
//
// This is the one `/enterprise/*` path a browser arrives at straight out of
// an SSO sign-in, so the session it carries is the brand-new one that
// sign-in minted: no `activeOrganizationId` (nothing in better-auth or
// `@better-auth/sso` writes one — only `/organization/set-active` does), and
// the request is a GET with neither a body nor an `orgId` query parameter.
// The generic entitlement gate (`../gate.ts`) therefore had no org id to
// work with and rejected every real call with `400 ORG_REQUIRED`, which made
// the mandatory test login — and so `ssoEnforced` — unreachable for every
// org. This path is out of `GATED_PATHS` now and does the `sso` check itself,
// against `ssoProvider.organizationId`.
//
// It deliberately doesn't use `sessionMiddleware` either: a missing session
// is a normal "not signed in yet" outcome that redirects with
// `reason=no_session`, not a 401 JSON error. Everything that can go wrong
// here leaves the browser on a URL the wizard can read — including a revoked
// entitlement, which used to be a bare 403 JSON error page (the deferred
// minor recorded against Task 7, closed here).
//
// No separate membership check: the single-use `ab-sso-test:<providerId>`
// row is what authorizes this call. `.../test-login/start` only writes it
// for an owner/admin of the provider's own org, it is bound to that user's
// id, and this handler refuses a session that isn't that same user.
function buildTestLoginFinishEndpoint() {
  return createAuthEndpoint(
    "/enterprise/sso/test-login/finish",
    { method: "GET", query: testLoginFinishQuerySchema },
    async (ctx) => {
      const fullCtx = ctx as unknown as GenericEndpointContext;
      const { providerId } = ctx.query;
      // Typed `never`, and always called as `throw fail(...)` below: TS
      // only narrows a preceding `if` away when the branch itself contains a
      // `throw`/`return` — calling a `never`-typed function as a bare
      // statement doesn't get the same treatment (verified against this
      // repo's pinned TypeScript), hence `throw fail(...)` rather than just
      // `fail(...)` at every call site.
      const fail = (reason: string): never => {
        throw ctx.redirect(`/?ab_sso_test=failed&reason=${reason}`);
      };

      const session = await getSessionFromCtx(fullCtx).catch(() => null);
      if (!session) throw fail("no_session");

      const pendingIdentifier = `ab-sso-test:${providerId}`;
      const pending = await findLiveVerification(fullCtx, pendingIdentifier);
      if (!pending || pending.value !== session.user.id) throw fail("no_pending");

      // Consumed the moment it's confirmed valid — on *both* the success
      // path below and the `domain_mismatch` failure path, not only on
      // success: a pending test-login row is single-use regardless of
      // outcome, so it can't be replayed within its 10-minute TTL (e.g.
      // retried after a domain fix) and can't produce a second
      // `sso.test_login_passed` audit row for the same login attempt.
      await deleteVerification(fullCtx, pendingIdentifier);

      const provider = await ctx.context.adapter.findOne<{
        domain: string;
        organizationId: string | null;
      }>({
        model: "ssoProvider",
        where: [{ field: "providerId", value: providerId }],
      });
      const domains = (provider?.domain ?? "").split(",").map((d) => d.trim().toLowerCase());
      const userDomain = emailDomain(session.user.email);
      if (!provider || !userDomain || !domains.includes(userDomain)) throw fail("domain_mismatch");

      // The org this whole request is about. `enterprisePreset` only ever
      // registers org-scoped providers, so a row without one is a hand-made
      // or legacy "personal" provider: refused rather than audited into an
      // empty-string org chain (m-1).
      const orgId = provider.organizationId;
      if (!orgId) throw fail("provider_not_org_scoped");

      // The entitlement check the gate used to run, now against the org the
      // provider itself names — and redirecting instead of answering JSON,
      // so the wizard's landing page always gets a readable outcome.
      try {
        await requireFeature(fullCtx, orgId, "sso");
      } catch {
        throw fail("not_entitled");
      }

      const now = new Date();
      // Effectively permanent — `getPolicyPreconditions` (`../policy/
      // plugin.ts`) only ever checks *existence* of this row, and a passed
      // test login shouldn't silently lapse and re-block enforcement.
      const farFuture = new Date(now.getTime() + 100 * 365 * 24 * 60 * 60 * 1000);
      await upsertVerification(
        fullCtx,
        `ab-sso-test-ok:${providerId}`,
        now.toISOString(),
        farFuture,
      );

      // Audited explicitly (not via `AUDITED_PATHS`, since — unlike
      // `/sso/register`/`/scim/generate-token` — this action has no upstream
      // path to forward through): `writeAudit` is `../audit/chain.ts`'s
      // public, framework-agnostic append primitive, safe to call directly.
      const { writeAudit } = await import("../audit/chain");
      await writeAudit(fullCtx, {
        orgId,
        actorType: "user",
        actorId: session.user.id,
        action: "sso.test_login_passed",
        targetType: "sso_provider",
        targetId: providerId,
      }).catch((err) => {
        ctx.context.logger.error("enterprise-api: failed to audit sso.test_login_passed", err);
      });

      throw ctx.redirect("/?ab_sso_test=ok");
    },
  );
}

// No `EnterpriseOptions` parameter: entitlement checks go through
// `requireFeature`, which reads `EnterpriseOptions` back off `ctx.context`
// itself (see `../entitlements.ts`) rather than a closure, so none of these
// builders need it passed in directly.
export function buildSsoEndpoints() {
  return {
    enterpriseSsoProviders: buildProvidersEndpoint(),
    enterpriseSsoRegister: buildRegisterEndpoint(),
    enterpriseSsoTestLoginStart: buildTestLoginStartEndpoint(),
    enterpriseSsoTestLoginFinish: buildTestLoginFinishEndpoint(),
  };
}
