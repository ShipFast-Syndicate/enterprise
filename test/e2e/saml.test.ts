// Task 8 — SAML end-to-end: register a provider from the test IdP's
// metadata, verify SP metadata, then IdP-initiated sign-in against the real
// upstream ACS (`/sso/saml2/sp/acs/:providerId`) — no mocking of
// `@better-auth/sso`/samlify. Controller ruling (c).
import { describe, expect, it } from "vitest";
import { IDP_CERT, SP_KEY } from "../helpers/fixtures/saml-keys";
import { mintSamlResponse, tamperSamlResponse, TEST_IDP_ENTITY_ID } from "../helpers/saml-idp";
import { createOrg, extractCookie, makeAuth, signUpOwner, type TestAuth } from "../helpers/auth";

const BASE_URL = "http://localhost:3000/api/auth";

async function registerSamlProvider(
  t: TestAuth,
  cookie: string,
  orgId: string,
  providerId: string,
) {
  const acsUrl = `${BASE_URL}/sso/saml2/sp/acs/${providerId}`;
  const spEntityID = `${BASE_URL}/sso/saml2/sp/${providerId}`;

  const res = await t.api.post(
    "/sso/register",
    {
      providerId,
      issuer: TEST_IDP_ENTITY_ID,
      domain: "acme.test",
      organizationId: orgId,
      samlConfig: {
        entryPoint: `${TEST_IDP_ENTITY_ID}/sso`,
        cert: IDP_CERT,
        callbackUrl: acsUrl,
        spMetadata: { entityID: spEntityID },
      },
    },
    { cookie },
  );
  if (!res.ok) throw new Error(`register failed: ${res.status} ${await res.text()}`);
  await t.client.execute({
    sql: `UPDATE "ssoProvider" SET domainVerified = 1 WHERE providerId = ?`,
    args: [providerId],
  });
  return { acsUrl, spEntityID };
}

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

  it("a tampered response is rejected: redirects with error= and creates no session", async () => {
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
  });

  it("a response signed with the wrong key is rejected: redirects with error=", async () => {
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
  });
});
