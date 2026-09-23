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
import { mintScimToken, createScimUser, coreUserId } from "../security/helpers";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { getNoRedirect, startOidcIssuer, type OidcIssuer } from "../helpers/oidc-issuer";
import { registerOidcProvider } from "../helpers/sso";
import { createOrg, extractCookie, makeAuth, signUpOwner, type TestAuth } from "../helpers/auth";

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

  it("allows a provisioned verified SSO identity, then blocks deactivation and preserves manual bans", async () => {
    const t = await makeAuth({ trustedOrigins: [issuer.issuerUrl] });
    const owner = await signUpOwner(t);
    const { orgId } = await createOrg(t, owner.cookie);
    await registerOidcProvider(t, owner.cookie, orgId, issuer, "provisioned-sso");
    const bearer = await mintScimToken(t, owner.cookie, orgId, "provisioned-sso");
    const mutation = await t.api.post(
      "/sso/update-provider",
      { providerId: "provisioned-sso", issuer: "https://attacker.example" },
      { cookie: owner.cookie },
    );
    expect(mutation.status).toBe(409);
    const deletion = await t.api.post(
      "/sso/delete-provider",
      { providerId: "provisioned-sso" },
      { cookie: owner.cookie },
    );
    expect(deletion.status).toBe(409);
    const email = "provisioned@acme.test";
    const scimId = await createScimUser(t, bearer, email, "stable-subject");
    const userId = await coreUserId(t, scimId);
    issuer.setUser({ sub: "stable-subject", email });
    const signedIn = await driveSsoSignIn(t, issuer, "provisioned-sso");
    expect(extractCookie(signedIn), signedIn.headers.get("location") ?? "").toContain(
      "session_token",
    );
    const sessionCookie = extractCookie(signedIn);
    const change = async (active: boolean) =>
      t.api.patch(
        `/scim/v2/Users/${scimId}`,
        {
          schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
          Operations: [{ op: "replace", path: "active", value: active }],
        },
        bearer,
      );
    expect((await change(false)).status).toBe(200);
    expect(await (await t.api.get("/get-session", { cookie: sessionCookie })).json()).toBeNull();
    const blocked = await driveSsoSignIn(t, issuer, "provisioned-sso");
    expect(extractCookie(blocked)).not.toContain("session_token");
    expect((await change(true)).status).toBe(200);
    expect(extractCookie(await driveSsoSignIn(t, issuer, "provisioned-sso"))).toContain(
      "session_token",
    );
    await t.client.execute({
      sql: "UPDATE user SET banned=1,banReason='Manual investigation' WHERE id=?",
      args: [userId],
    });
    await change(false);
    await change(true);
    const row = (
      await t.client.execute({
        sql: "SELECT banned,banReason FROM user WHERE id=?",
        args: [userId],
      })
    ).rows[0];
    expect(row).toMatchObject({ banned: 1, banReason: "Manual investigation" });
    expect(extractCookie(await driveSsoSignIn(t, issuer, "provisioned-sso"))).not.toContain(
      "session_token",
    );
  });

  it("refuses JIT with a redirect error and creates no user row once the org has a SCIM provider", async () => {
    const t = await makeAuth({ trustedOrigins: [issuer.issuerUrl] });
    const { cookie: ownerCookie } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, ownerCookie);
    await registerOidcProvider(t, ownerCookie, orgId, issuer, "oidc-scim-gate");

    const scimRes = await t.api.post(
      "/enterprise/scim/tokens/create",
      { providerId: "hris", orgId },
      { cookie: ownerCookie },
    );
    expect(scimRes.status).toBe(200);

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

    // A blocked JIT is audited as a failed sign-in, never as a successful
    // one — no session was created, so there's no user to (mis)attribute a
    // `auth.sso_sign_in` row to.
    const signInRows = await t.client.execute({
      sql: `SELECT * FROM audit_event WHERE action = 'auth.sso_sign_in' AND org_id = ?`,
      args: [orgId],
    });
    expect(signInRows.rows.length).toBe(0);
    const failedRows = await t.client.execute({
      sql: `SELECT * FROM audit_event WHERE action = 'auth.sso_sign_in_failed' AND org_id = ?`,
      args: [orgId],
    });
    expect(failedRows.rows.length).toBe(1);
    expect(failedRows.rows[0]!.actor_type).toBe("system");
    expect(failedRows.rows[0]!.actor_id).toBeNull();
    expect(failedRows.rows[0]!.target_type).toBe("sso_provider");
    expect(failedRows.rows[0]!.target_id).toBe("oidc-scim-gate");
    // `handleOAuthUserInfo` (`node_modules/better-auth/dist/oauth2/
    // link-account.mjs`) catches our hook's thrown `APIError` and surfaces
    // `e.message` (the human-readable `message`, not `code`) as `linked.
    // error`, which `handleOIDCCallback` then puts straight into the
    // redirect's `error=` query param — so that's what ends up here too.
    const metadata = JSON.parse(failedRows.rows[0]!.metadata as string) as { error?: string };
    expect(metadata.error).toBe("SCIM_PROVISIONING_REQUIRED");
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
