// 1.3 `sso.domainVerificationMode: "operator"` — domain ownership attested by
// server code instead of a DNS lookup (`verifySsoDomainOperator`), for
// runtimes where upstream's `node:dns` check cannot run. The attestation is an
// assertion by the operator, not a proof, so it is: unreachable over HTTP,
// refused unless the deployment opted in, unique per verified domain (the same
// F-30 rule the DNS path has), and audited with who vouched and why.
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createOrg, makeAuth, signUpOwner, type TestAuth } from "../helpers/auth";
import { isPg } from "../helpers/dialect";
import { startOidcIssuer, type OidcIssuer } from "../helpers/oidc-issuer";
import { auditRows } from "./helpers";
import { driveSsoSignIn, sessionCookieOf, sessionOf } from "./ghsa-sso-helpers";
import { verifySsoDomainOperator } from "../../src/server/sso-domain-operator";
import type { EnterpriseOptions } from "../../src/server/types";

let issuer: OidcIssuer;
beforeAll(async () => {
  issuer = await startOidcIssuer();
});
afterAll(async () => {
  await issuer.close();
});

/** Registers an OIDC provider through upstream and leaves its domain unverified. */
async function registerUnverified(
  t: TestAuth,
  cookie: string,
  orgId: string,
  providerId: string,
  domain: string,
): Promise<void> {
  const res = await t.api.post(
    "/sso/register",
    {
      providerId,
      issuer: issuer.issuerUrl,
      domain,
      organizationId: orgId,
      oidcConfig: {
        clientId: issuer.clientId,
        clientSecret: issuer.clientSecret,
        skipDiscovery: true,
        authorizationEndpoint: issuer.authorizationEndpoint,
        tokenEndpoint: issuer.tokenEndpoint,
        jwksEndpoint: issuer.jwksEndpoint,
      },
    },
    { cookie },
  );
  if (!res.ok) throw new Error(`register failed: ${res.status} ${await res.text()}`);
}

async function setup(sso: EnterpriseOptions["sso"]) {
  const t = await makeAuth({ trustedOrigins: [issuer.issuerUrl], ...(sso ? { sso } : {}) });
  const owner = await signUpOwner(t, "owner@acme.test");
  const { orgId } = await createOrg(t, owner.cookie, "acme");
  await registerUnverified(t, owner.cookie, orgId, "acme-oidc", "acme.test");
  return { t, owner, orgId };
}

async function domainVerified(t: TestAuth, providerId: string): Promise<boolean> {
  const rows = await t.client.execute({
    sql: `SELECT "domainVerified" FROM "ssoProvider" WHERE "providerId" = ?`,
    args: [providerId],
  });
  const value: unknown = rows.rows[0]!.domainVerified;
  return value === true || value === 1;
}

const OPERATOR = { domainVerificationMode: "operator" } as const;
const vouch = (providerId: string) => ({
  providerId,
  evidence: "DNS TXT checked by hand, ticket OPS-1",
  actor: "ops:alice",
});

describe("operator mode closes the DNS endpoints", () => {
  it("/sso/request-domain-verification and /sso/verify-domain answer SSO_DOMAIN_VERIFICATION_OPERATOR_ONLY, signed in or not", async () => {
    const { t, owner } = await setup(OPERATOR);
    for (const path of ["/sso/request-domain-verification", "/sso/verify-domain"]) {
      const callers: Array<Record<string, string>> = [{ cookie: owner.cookie }, {}];
      for (const headers of callers) {
        const res = await t.api.post(path, { providerId: "acme-oidc" }, headers);
        expect(res.status, path).toBe(403);
        expect(await res.json()).toMatchObject({ code: "SSO_DOMAIN_VERIFICATION_OPERATOR_ONLY" });
      }
    }
    expect(await domainVerified(t, "acme-oidc")).toBe(false);
  });

  it("by default (dns) both endpoints work as in 1.2", async () => {
    const { t, owner } = await setup(undefined);
    const request = await t.api.post(
      "/sso/request-domain-verification",
      { providerId: "acme-oidc" },
      { cookie: owner.cookie },
    );
    expect(request.status).toBe(201);
    const verify = await t.api.post(
      "/sso/verify-domain",
      { providerId: "acme-oidc" },
      { cookie: owner.cookie },
    );
    // No TXT record exists, so the DNS check itself refuses — not the 1.3 guard.
    expect(verify.status).not.toBe(403);
    expect(await verify.json()).not.toMatchObject({
      code: "SSO_DOMAIN_VERIFICATION_OPERATOR_ONLY",
    });
  });
});

describe("verifySsoDomainOperator", () => {
  it("is refused unless the deployment is in operator mode", async () => {
    for (const sso of [undefined, { domainVerificationMode: "dns" } as const]) {
      const { t } = await setup(sso);
      await expect(verifySsoDomainOperator(t.auth, vouch("acme-oidc"))).rejects.toMatchObject({
        body: { code: "SSO_DOMAIN_VERIFICATION_NOT_OPERATOR_MODE" },
      });
      expect(await domainVerified(t, "acme-oidc")).toBe(false);
    }
  });

  it("is not an HTTP route: it is not an endpoint of the auth instance", async () => {
    const { t } = await setup(OPERATOR);
    expect(Object.keys(t.auth.api).filter((name) => /operator/i.test(name))).toEqual([]);
    const res = await t.api.post("/sso/verify-domain-operator", vouch("acme-oidc"), {});
    expect(res.status).toBe(404);
  });

  it("verifies the domain, writes one sso.domain_verified row naming the operator and the evidence, and the chain still verifies", async () => {
    const { t, owner, orgId } = await setup(OPERATOR);
    await verifySsoDomainOperator(t.auth, vouch("acme-oidc"));
    expect(await domainVerified(t, "acme-oidc")).toBe(true);

    const rows = (await auditRows(t, orgId)).filter((r) => r.action === "sso.domain_verified");
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      actor_type: "system",
      target_type: "sso_provider",
      target_id: "acme-oidc",
    });
    const raw = rows[0]!.metadata;
    expect(typeof raw === "string" ? JSON.parse(raw) : raw).toEqual({
      method: "operator",
      actor: "ops:alice",
      evidence: "DNS TXT checked by hand, ticket OPS-1",
    });

    const verify = await t.api.get(`/enterprise/audit/verify?orgId=${orgId}`, {
      cookie: owner.cookie,
    });
    expect(await verify.json()).toEqual({ ok: true, keyed: false });
  });

  it("a verified provider signs in through upstream afterwards (the flag is the one upstream reads)", async () => {
    const { t } = await setup(OPERATOR);
    await verifySsoDomainOperator(t.auth, vouch("acme-oidc"));
    issuer.setUser({ sub: "sub-new", email: "new@acme.test" });
    const res = await driveSsoSignIn(t, issuer, "acme-oidc");
    expect((await sessionOf(t, sessionCookieOf(res))).user.email).toBe("new@acme.test");
  });

  it("refuses an unknown provider, one already verified, one that is not org-scoped, and a bad evidence or actor", async () => {
    const { t } = await setup(OPERATOR);
    await expect(verifySsoDomainOperator(t.auth, vouch("ghost"))).rejects.toMatchObject({
      body: { code: "SSO_PROVIDER_NOT_FOUND" },
    });
    for (const evidence of ["", "   ", "x".repeat(501), 42, undefined]) {
      await expect(
        verifySsoDomainOperator(t.auth, { ...vouch("acme-oidc"), evidence } as never),
      ).rejects.toMatchObject({ body: { code: "SSO_DOMAIN_VERIFICATION_INPUT_INVALID" } });
    }
    for (const actor of ["", " ", "a".repeat(201), 7, undefined]) {
      await expect(
        verifySsoDomainOperator(t.auth, { ...vouch("acme-oidc"), actor } as never),
      ).rejects.toMatchObject({ body: { code: "SSO_DOMAIN_VERIFICATION_INPUT_INVALID" } });
    }
    expect(await domainVerified(t, "acme-oidc")).toBe(false);

    await verifySsoDomainOperator(t.auth, {
      ...vouch("acme-oidc"),
      evidence: "x".repeat(500),
    });
    await expect(verifySsoDomainOperator(t.auth, vouch("acme-oidc"))).rejects.toMatchObject({
      body: { code: "DOMAIN_VERIFIED" },
    });

    await t.client.execute({
      sql: `UPDATE "ssoProvider" SET "organizationId" = NULL, "domainVerified" = ? WHERE "providerId" = ?`,
      args: [isPg ? false : 0, "acme-oidc"],
    });
    await expect(verifySsoDomainOperator(t.auth, vouch("acme-oidc"))).rejects.toMatchObject({
      body: { code: "SSO_PROVIDER_NOT_ORG_SCOPED" },
    });
  });

  it("refuses a domain another provider already holds verified (F-30), leaves the provider unverified, and writes no row", async () => {
    const { t, owner, orgId } = await setup(OPERATOR);
    const rival = await signUpOwner(t, "owner@rival.test");
    const { orgId: rivalOrg } = await createOrg(t, rival.cookie, "rival");
    // Registered while nobody holds the domain verified — allowed.
    await registerUnverified(t, rival.cookie, rivalOrg, "rival-oidc", "acme.test");
    await verifySsoDomainOperator(t.auth, vouch("rival-oidc"));
    await expect(verifySsoDomainOperator(t.auth, vouch("acme-oidc"))).rejects.toMatchObject({
      body: { code: "SSO_DOMAIN_TAKEN" },
    });
    expect(await domainVerified(t, "acme-oidc")).toBe(false);
    expect(
      (await auditRows(t, orgId)).filter((r) => r.action === "sso.domain_verified"),
    ).toHaveLength(0);
    expect(owner.userId).toBeTruthy();
  });
});
