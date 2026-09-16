import { describe, expect, it } from "vitest";
import { makeAuth, signUpOwner, createOrg, type TestAuth } from "../helpers/auth";

// The rate limiter's in-memory store (`node_modules/better-auth/dist/api/
// rate-limiter/index.mjs`'s module-level `memory` Map) is shared by every
// `it()` in this file regardless of which test's `makeAuth()` instance made
// the call — vitest isolates modules per *file*, not per test — and its key
// is `<ip>|<path>` (`createRateLimitKey`). Every call in this file hits the
// same path (`/enterprise/home-realm`, whose own plugin-declared limit is
// 10/min — `HOME_REALM_RATE_LIMIT`), so without a distinguishing IP every
// test here would share one 10-request bucket. A unique
// `x-forwarded-for` per test keeps each test's own count independent of
// how many other tests in this file ran first.
let nextTestIp = 1;
function isolatedIpHeaders(): Record<string, string> {
  return { "x-forwarded-for": `203.0.113.${nextTestIp++}` };
}

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

    const res = await t.api.post(
      "/enterprise/home-realm",
      { email: "anyone@acme.test" },
      isolatedIpHeaders(),
    );

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ method: "sso", providerId: "okta" });
  });

  it("returns {method: 'local'} for a domain with no verified provider", async () => {
    const t = await makeAuth();

    const res = await t.api.post(
      "/enterprise/home-realm",
      { email: "someone@unknown.test" },
      isolatedIpHeaders(),
    );

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

    const res = await t.api.post(
      "/enterprise/home-realm",
      { email: "anyone@acme.test" },
      isolatedIpHeaders(),
    );

    expect(await res.json()).toEqual({ method: "local" });
  });

  it("never leaks whether a user exists — an existing local user and a nonexistent address on the same non-SSO domain answer identically", async () => {
    const t = await makeAuth();
    await signUpOwner(t, "real.person@nodomain.test");
    const headers = isolatedIpHeaders();

    const existing = await t.api.post(
      "/enterprise/home-realm",
      { email: "real.person@nodomain.test" },
      headers,
    );
    const missing = await t.api.post(
      "/enterprise/home-realm",
      { email: "ghost@nodomain.test" },
      headers,
    );

    expect(existing.status).toBe(200);
    expect(missing.status).toBe(200);
    const existingBody = await existing.json();
    const missingBody = await missing.json();
    expect(existingBody).toEqual({ method: "local" });
    expect(existingBody).toEqual(missingBody);
  });

  it("is public — no session/cookie required", async () => {
    const t = await makeAuth();

    const res = await t.api.post(
      "/enterprise/home-realm",
      { email: "anon@nowhere.test" },
      isolatedIpHeaders(),
    );

    expect(res.status).toBe(200);
  });

  it("throttles to 10/min per ip — the 11th call within the window is 429", async () => {
    const t = await makeAuth();
    const headers = isolatedIpHeaders();

    for (let i = 0; i < 10; i++) {
      const res = await t.api.post(
        "/enterprise/home-realm",
        { email: `probe${i}@nowhere.test` },
        headers,
      );
      expect(res.status).toBe(200);
    }

    const res11 = await t.api.post(
      "/enterprise/home-realm",
      { email: "probe10@nowhere.test" },
      headers,
    );
    expect(res11.status).toBe(429);
  });
});

describe("findOrgByEmailDomain via the home-realm endpoint (case-insensitivity)", () => {
  it("matches a verified domain regardless of the email's casing", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, cookie);
    await insertVerifiedProvider(t, orgId, "acme.test", "okta");

    const res = await t.api.post(
      "/enterprise/home-realm",
      { email: "anyone@ACME.TEST" },
      isolatedIpHeaders(),
    );

    expect(await res.json()).toEqual({ method: "sso", providerId: "okta" });
  });
});
