// Task 8 — OIDC end-to-end: the full authorization-code flow against an
// in-process issuer (`test/helpers/oidc-issuer.ts`), driven through real
// upstream `@better-auth/sso` code paths (`/sign-in/sso`, `/sso/callback/
// :providerId`) — no mocking of better-auth itself. Controller ruling (b).
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { getNoRedirect, startOidcIssuer, type OidcIssuer } from "../helpers/oidc-issuer";
import { createOrg, extractCookie, makeAuth, signUpOwner, type TestAuth } from "../helpers/auth";

describe("OIDC end-to-end sign-in", () => {
  let issuer: OidcIssuer;

  beforeAll(async () => {
    issuer = await startOidcIssuer();
  });

  afterAll(async () => {
    await issuer.close();
  });

  async function registerProvider(
    t: TestAuth,
    cookie: string,
    orgId: string,
    providerId = "oidc-e2e",
  ) {
    const res = await t.api.post(
      "/sso/register",
      {
        providerId,
        issuer: issuer.issuerUrl,
        domain: "acme.test",
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
    await t.client.execute({
      sql: `UPDATE "ssoProvider" SET domainVerified = 1 WHERE providerId = ?`,
      args: [providerId],
    });
  }

  it("full code flow: sign-in -> issuer -> callback -> session -> member(role=member) -> audit row", async () => {
    const t = await makeAuth({ trustedOrigins: [issuer.issuerUrl] });
    const { cookie: ownerCookie } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, ownerCookie);
    await registerProvider(t, ownerCookie, orgId);

    const email = "newemployee@acme.test";
    issuer.setUser({ sub: "employee-1", email });

    const signInRes = await t.api.post(
      "/sign-in/sso",
      { providerId: "oidc-e2e", callbackURL: "/" },
      {},
    );
    expect(signInRes.status).toBe(200);
    const stateCookie = extractCookie(signInRes);
    expect(stateCookie).not.toBe("");
    const { url } = (await signInRes.json()) as { url: string };
    expect(url.startsWith(issuer.authorizationEndpoint)).toBe(true);

    const authorizeRedirect = await getNoRedirect(url);
    expect(authorizeRedirect.status).toBe(302);
    const callbackUrl = authorizeRedirect.location;
    expect(callbackUrl).toBeTruthy();
    expect(callbackUrl).toContain("/sso/callback/oidc-e2e");

    const callbackRes = await t.auth.handler(
      new Request(callbackUrl!, {
        headers: { cookie: stateCookie, origin: "http://localhost:3000" },
      }),
    );
    expect(callbackRes.status).toBe(302);
    const sessionCookie = extractCookie(callbackRes);
    expect(sessionCookie).toContain("session_token");

    const sessionRes = await t.api.get("/get-session", { cookie: sessionCookie });
    expect(sessionRes.status).toBe(200);
    const session = (await sessionRes.json()) as { user: { email: string; id: string } };
    expect(session.user.email).toBe(email);

    const memberRows = await t.client.execute({
      sql: `SELECT role FROM member WHERE organizationId = ? AND userId = ?`,
      args: [orgId, session.user.id],
    });
    expect(memberRows.rows.length).toBe(1);
    expect(memberRows.rows[0]!.role).toBe("member");

    const auditRows = await t.client.execute({
      sql: `SELECT * FROM audit_event WHERE action = 'auth.sso_sign_in' AND actor_id = ?`,
      args: [session.user.id],
    });
    expect(auditRows.rows.length).toBe(1);
  });
});
