// Task 8 — JIT provisioning edge cases, controller rulings (d) and (e).
//
// (d) A pending invitation is upstream's own signal that an org already has
// an intended role for this email — `assignOrganization` (`@better-auth/sso`)
// skips auto-join with `organizationProvisioning.defaultRole` when a pending
// invitation exists for the org/email (`"invitation-pending"`, verified
// directly against `node_modules/@better-auth/sso/dist/index.mjs`), rather
// than overriding the invited role. The invited role survives because JIT
// never creates a competing membership — accepting the invitation
// afterwards (`/organization/accept-invitation`, plain upstream `organization`
// plugin behaviour) is what actually creates the `member` row, with the
// role the invitation named.
//
// (e) "SSO only for SCIM-active users" (`src/server/policy/scim-required.ts`).
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { getNoRedirect, startOidcIssuer, type OidcIssuer } from "../helpers/oidc-issuer";
import { createOrg, extractCookie, makeAuth, signUpOwner, type TestAuth } from "../helpers/auth";

async function registerOidcProvider(
  t: TestAuth,
  cookie: string,
  orgId: string,
  issuer: OidcIssuer,
  providerId: string,
  domain = "acme.test",
) {
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
  await t.client.execute({
    sql: `UPDATE "ssoProvider" SET domainVerified = 1 WHERE providerId = ?`,
    args: [providerId],
  });
}

/** Drives `/sign-in/sso` -> issuer `/authorize` -> `/sso/callback/:providerId`, returning the callback's raw Response (never asserts success — the SCIM-required test needs to inspect a failure redirect). */
async function driveSsoSignIn(t: TestAuth, issuer: OidcIssuer, providerId: string) {
  const signInRes = await t.api.post("/sign-in/sso", { providerId, callbackURL: "/" }, {});
  expect(signInRes.status).toBe(200);
  const stateCookie = extractCookie(signInRes);
  const { url } = (await signInRes.json()) as { url: string };

  const authorizeRedirect = await getNoRedirect(url);
  expect(authorizeRedirect.status).toBe(302);
  const callbackUrl = authorizeRedirect.location!;

  return t.auth.handler(
    new Request(callbackUrl, { headers: { cookie: stateCookie, origin: "http://localhost:3000" } }),
  );
}

describe("JIT + pending invitation keeps the invited role", () => {
  let issuer: OidcIssuer;

  beforeAll(async () => {
    issuer = await startOidcIssuer();
  });

  afterAll(async () => {
    await issuer.close();
  });

  it("SSO JIT does not auto-join a member with a pending invitation; accepting it keeps role=admin", async () => {
    const t = await makeAuth({ trustedOrigins: [issuer.issuerUrl] });
    const { cookie: ownerCookie } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, ownerCookie);
    await registerOidcProvider(t, ownerCookie, orgId, issuer, "oidc-jit");

    const email = "invited-admin@acme.test";
    const inviteRes = await t.api.post(
      "/organization/invite-member",
      { email, role: "admin", organizationId: orgId },
      { cookie: ownerCookie },
    );
    expect(inviteRes.status).toBe(200);
    const invitation = (await inviteRes.json()) as { id: string };

    issuer.setUser({ sub: "invited-admin-1", email });
    const callbackRes = await driveSsoSignIn(t, issuer, "oidc-jit");
    expect(callbackRes.status).toBe(302);
    const sessionCookie = extractCookie(callbackRes);
    expect(sessionCookie).toContain("session_token");

    const sessionRes = await t.api.get("/get-session", { cookie: sessionCookie });
    const session = (await sessionRes.json()) as { user: { id: string; email: string } };
    expect(session.user.email).toBe(email);

    // Not auto-joined: `assignOrganization` skips creating a `member` row
    // when a pending invitation already exists for this org/email.
    const beforeAccept = await t.client.execute({
      sql: `SELECT role FROM member WHERE organizationId = ? AND userId = ?`,
      args: [orgId, session.user.id],
    });
    expect(beforeAccept.rows.length).toBe(0);

    const acceptRes = await t.api.post(
      "/organization/accept-invitation",
      { invitationId: invitation.id },
      { cookie: sessionCookie },
    );
    expect(acceptRes.status).toBe(200);

    const afterAccept = await t.client.execute({
      sql: `SELECT role FROM member WHERE organizationId = ? AND userId = ?`,
      args: [orgId, session.user.id],
    });
    expect(afterAccept.rows.length).toBe(1);
    expect(afterAccept.rows[0]!.role).toBe("admin");
  });
});

describe("SSO only for SCIM-active users (SCIM_PROVISIONING_REQUIRED)", () => {
  let issuer: OidcIssuer;

  beforeAll(async () => {
    issuer = await startOidcIssuer();
  });

  afterAll(async () => {
    await issuer.close();
  });

  it("refuses JIT with a redirect error and creates no user row once the org has a SCIM provider", async () => {
    const t = await makeAuth({ trustedOrigins: [issuer.issuerUrl] });
    const { cookie: ownerCookie } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, ownerCookie);
    await registerOidcProvider(t, ownerCookie, orgId, issuer, "oidc-scim-gate");

    const scimRes = await t.api.post(
      "/scim/generate-token",
      { providerId: "hris", organizationId: orgId },
      { cookie: ownerCookie },
    );
    expect(scimRes.status).toBe(201);

    const email = "blocked-jit@acme.test";
    issuer.setUser({ sub: "blocked-jit-1", email });

    const callbackRes = await driveSsoSignIn(t, issuer, "oidc-scim-gate");
    expect(callbackRes.status).toBe(302);
    const location = callbackRes.headers.get("location") ?? "";
    expect(location).toContain("error=");

    const userRows = await t.client.execute({
      sql: `SELECT * FROM user WHERE email = ?`,
      args: [email],
    });
    expect(userRows.rows.length).toBe(0);
  });

  it("does not block JIT for an org with no SCIM provider (control case)", async () => {
    const t = await makeAuth({ trustedOrigins: [issuer.issuerUrl] });
    const { cookie: ownerCookie } = await signUpOwner(t, "owner2@acme2.test");
    const { orgId } = await createOrg(t, ownerCookie, "acme2");
    await registerOidcProvider(t, ownerCookie, orgId, issuer, "oidc-scim-control", "acme2.test");

    const email = "allowed-jit@acme2.test";
    issuer.setUser({ sub: "allowed-jit-1", email });

    const callbackRes = await driveSsoSignIn(t, issuer, "oidc-scim-control");
    expect(callbackRes.status).toBe(302);
    expect(callbackRes.headers.get("location") ?? "").not.toContain("error=");

    const userRows = await t.client.execute({
      sql: `SELECT * FROM user WHERE email = ?`,
      args: [email],
    });
    expect(userRows.rows.length).toBe(1);
  });
});
