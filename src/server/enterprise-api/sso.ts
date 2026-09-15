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
import { forwardJson, relayStatus } from "./forward";

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
  await ctx.context.adapter.deleteMany({
    model: "verification",
    where: [{ field: "identifier", value: identifier }],
  });
  await ctx.context.internalAdapter.createVerificationValue({ identifier, value, expiresAt });
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

const providersQuerySchema = z.object({ orgId: z.string() });

function buildProvidersEndpoint() {
  return createAuthEndpoint(
    "/enterprise/sso/providers",
    { method: "GET", use: [sessionMiddleware], query: providersQuerySchema },
    async (ctx) => {
      const fullCtx = ctx as unknown as GenericEndpointContext;
      const { orgId } = ctx.query;
      await requireOrgMember(fullCtx, orgId);

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
            acsUrl: `${ctx.context.baseURL}/sso/saml2/sp/acs/${row.providerId}`,
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
      const { status, data } = await forwardJson(fullCtx, "POST", "/sign-in/sso", {
        providerId,
        callbackURL,
      });
      if (status < 200 || status >= 300 || !data) {
        relayStatus(ctx, status);
        return ctx.json(data);
      }
      return ctx.json({ url: data.url });
    },
  );
}

const testLoginFinishQuerySchema = z.object({ providerId: z.string() });

function emailDomain(email: string): string | null {
  const at = email.lastIndexOf("@");
  return at === -1 ? null : email.slice(at + 1).toLowerCase();
}

// Entitlement/membership are enforced generically here: unlike the other
// SSO endpoints, this one deliberately doesn't use `sessionMiddleware` (a
// missing session is a normal "not signed in yet" outcome that redirects
// with `reason=no_session`, not a 401 JSON error) — `GATED_PATHS`
// (`../gate.ts`) still runs `requireFeature` for a caller who *does* have a
// session, via its `activeOrganizationId` fallback (this path carries no
// `orgId` of its own — see the controller ruling).
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

      const pending = await findLiveVerification(fullCtx, `ab-sso-test:${providerId}`);
      if (!pending || pending.value !== session.user.id) throw fail("no_pending");

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
        orgId: provider.organizationId ?? "",
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
