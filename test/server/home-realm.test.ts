import { describe, expect, it } from "vitest";
import { makeAuth, signUpOwner, createOrg, type TestAuth } from "../helpers/auth";

async function insertVerifiedProvider(
  t: TestAuth,
  orgId: string,
  domain: string,
  providerId = "okta",
) {
  await t.client.execute({
    sql: `INSERT INTO "ssoProvider" (id, issuer, domain, domainVerified, organizationId, providerId, userId) VALUES (?, ?, ?, 1, ?, ?, ?)`,
    args: [
      `ssop_${providerId}`,
      "https://idp.test",
      domain,
      orgId,
      providerId,
      "test-provider-creator",
    ],
  });
}

describe("POST /enterprise/home-realm", () => {
  it("returns {method: 'sso', providerId} for an email whose domain has a verified provider", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, cookie);
    await insertVerifiedProvider(t, orgId, "acme.test", "okta");

    const res = await t.api.post("/enterprise/home-realm", { email: "anyone@acme.test" });

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ method: "sso", providerId: "okta" });
  });

  it("returns {method: 'local'} for a domain with no verified provider", async () => {
    const t = await makeAuth();

    const res = await t.api.post("/enterprise/home-realm", { email: "someone@unknown.test" });

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ method: "local" });
  });

  it("ignores an unverified provider on the domain (domainVerified must be true)", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, cookie);
    await t.client.execute({
      sql: `INSERT INTO "ssoProvider" (id, issuer, domain, domainVerified, organizationId, providerId, userId) VALUES (?, ?, ?, 0, ?, ?, ?)`,
      args: [
        "ssop_unverified",
        "https://idp.test",
        "acme.test",
        orgId,
        "okta",
        "test-provider-creator",
      ],
    });

    const res = await t.api.post("/enterprise/home-realm", { email: "anyone@acme.test" });

    expect(await res.json()).toEqual({ method: "local" });
  });

  it("never leaks whether a user exists — an existing local user and a nonexistent address on the same non-SSO domain answer identically", async () => {
    const t = await makeAuth();
    await signUpOwner(t, "real.person@nodomain.test");

    const existing = await t.api.post("/enterprise/home-realm", {
      email: "real.person@nodomain.test",
    });
    const missing = await t.api.post("/enterprise/home-realm", {
      email: "ghost@nodomain.test",
    });

    expect(existing.status).toBe(200);
    expect(missing.status).toBe(200);
    const existingBody = await existing.json();
    const missingBody = await missing.json();
    expect(existingBody).toEqual({ method: "local" });
    expect(existingBody).toEqual(missingBody);
  });

  it("is public — no session/cookie required", async () => {
    const t = await makeAuth();

    const res = await t.api.post("/enterprise/home-realm", { email: "anon@nowhere.test" });

    expect(res.status).toBe(200);
  });
});

describe("findOrgByEmailDomain via the home-realm endpoint (case-insensitivity)", () => {
  it("matches a verified domain regardless of the email's casing", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, cookie);
    await insertVerifiedProvider(t, orgId, "acme.test", "okta");

    const res = await t.api.post("/enterprise/home-realm", { email: "anyone@ACME.TEST" });

    expect(await res.json()).toEqual({ method: "sso", providerId: "okta" });
  });
});
