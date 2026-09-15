// Task 8 — SAML end-to-end: register a provider from the test IdP's
// metadata, verify SP metadata, then IdP-initiated sign-in against the real
// upstream ACS (`/sso/saml2/sp/acs/:providerId`) — no mocking of
// `@better-auth/sso`/samlify. Controller ruling (c).
import { describe, expect, it } from "vitest";
import { SP_KEY } from "../helpers/fixtures/saml-keys";
import { mintSamlResponse, tamperSamlResponse } from "../helpers/saml-idp";
import { registerSamlProvider } from "../helpers/sso";
import { createOrg, extractCookie, makeAuth, signUpOwner } from "../helpers/auth";

describe("SAML end-to-end (IdP-initiated)", () => {
  it("register -> SP metadata -> signed response -> 302 + session -> member(role=member) -> audit row", async () => {
    const t = await makeAuth();
    const { cookie: ownerCookie } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, ownerCookie);
    const providerId = "saml-e2e";
    const { acsUrl, spEntityID } = await registerSamlProvider(t, ownerCookie, orgId, providerId);

    const metadataRes = await t.api.get(`/sso/saml2/sp/metadata?providerId=${providerId}`, {});
    expect(metadataRes.status).toBe(200);
    const metadataXml = await metadataRes.text();
    expect(metadataXml).toContain("EntityDescriptor");
    expect(metadataXml).toContain(acsUrl);

    const email = "saml-newhire@acme.test";
    const samlResponse = await mintSamlResponse({ spEntityID, acsUrl, email });

    const acsRes = await t.api.postForm(`/sso/saml2/sp/acs/${providerId}`, {
      SAMLResponse: samlResponse,
      RelayState: "",
    });
    expect(acsRes.status).toBe(302);
    const sessionCookie = extractCookie(acsRes);
    expect(sessionCookie).toContain("session_token");

    const sessionRes = await t.api.get("/get-session", { cookie: sessionCookie });
    expect(sessionRes.status).toBe(200);
    const session = (await sessionRes.json()) as { user: { id: string; email: string } };
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

  it("a tampered response is rejected: redirects with error=, no session, and an auth.sso_sign_in_failed row (not auth.sso_sign_in)", async () => {
    const t = await makeAuth();
    const { cookie: ownerCookie } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, ownerCookie);
    const providerId = "saml-tamper";
    const { acsUrl, spEntityID } = await registerSamlProvider(t, ownerCookie, orgId, providerId);

    const email = "tamper-target@acme.test";
    const goodResponse = await mintSamlResponse({ spEntityID, acsUrl, email });
    const tampered = tamperSamlResponse(goodResponse, email, "attacker@acme.test");

    const acsRes = await t.api.postForm(`/sso/saml2/sp/acs/${providerId}`, {
      SAMLResponse: tampered,
      RelayState: "",
    });
    expect(acsRes.status).toBe(302);
    expect(acsRes.headers.get("location") ?? "").toContain("error=");
    expect(acsRes.headers.getSetCookie().length).toBe(0);

    const userRows = await t.client.execute({
      sql: `SELECT * FROM user WHERE email IN (?, ?)`,
      args: [email, "attacker@acme.test"],
    });
    expect(userRows.rows.length).toBe(0);

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
    expect(failedRows.rows[0]!.target_id).toBe(providerId);
  });

  it("a response signed with the wrong key is rejected: redirects with error=, no session, and an auth.sso_sign_in_failed row (not auth.sso_sign_in)", async () => {
    const t = await makeAuth();
    const { cookie: ownerCookie } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, ownerCookie);
    const providerId = "saml-wrongkey";
    const { acsUrl, spEntityID } = await registerSamlProvider(t, ownerCookie, orgId, providerId);

    const email = "wrongkey-target@acme.test";
    const wrongKeyResponse = await mintSamlResponse({
      spEntityID,
      acsUrl,
      email,
      signWithKey: SP_KEY,
    });

    const acsRes = await t.api.postForm(`/sso/saml2/sp/acs/${providerId}`, {
      SAMLResponse: wrongKeyResponse,
      RelayState: "",
    });
    expect(acsRes.status).toBe(302);
    expect(acsRes.headers.get("location") ?? "").toContain("error=");
    expect(acsRes.headers.getSetCookie().length).toBe(0);

    const userRows = await t.client.execute({
      sql: `SELECT * FROM user WHERE email = ?`,
      args: [email],
    });
    expect(userRows.rows.length).toBe(0);

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
    expect(failedRows.rows[0]!.target_id).toBe(providerId);
  });
});
