// GHSA-8p84-pc7q-69jr — audit gap 5: "personal" SSO providers. Upstream
// `/sso/register` runs its owner/admin check only when `body.organizationId`
// is present; without it, *any* signed-in user created a `userId`-bound,
// `organizationId: null` provider claiming any domain — and the entitlement
// gate resolved the `sso` feature from the caller's *active* org, so a plain
// member of an entitled org passed it. The gate now answers `400
// ORG_REQUIRED` on `/sso/register` before its fallback chain
// (`BODY_ORG_REQUIRED_PATHS`, `src/server/gate.ts`).
import { describe, expect, it } from "vitest";
import { createOrg, extractCookie, makeAuth, signUpOwner, type TestAuth } from "../helpers/auth";
import { insertMemberRow } from "./helpers";

const oidcConfig = {
  clientId: "c",
  clientSecret: "s",
  skipDiscovery: true,
  authorizationEndpoint: "https://idp.example.com/authorize",
  tokenEndpoint: "https://idp.example.com/token",
  jwksEndpoint: "https://idp.example.com/jwks",
};

async function providerRow(t: TestAuth, providerId: string) {
  const rows = await t.client.execute({
    sql: `SELECT organizationId, userId FROM "ssoProvider" WHERE providerId = ?`,
    args: [providerId],
  });
  return rows.rows[0] ?? null;
}

async function memberWithActiveOrg(t: TestAuth, orgId: string, email: string) {
  const member = await signUpOwner(t, email);
  await insertMemberRow(t, orgId, member.userId, "member");
  const setActive = await t.api.post(
    "/organization/set-active",
    { organizationId: orgId },
    { cookie: member.cookie },
  );
  expect(setActive.status).toBe(200);
  return { ...member, cookie: extractCookie(setActive) || member.cookie };
}

describe("gap 5 — /sso/register requires an organization in the body", () => {
  it("a plain member with an active, entitled org gets 400 ORG_REQUIRED and no provider row", async () => {
    const t = await makeAuth();
    const owner = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, owner.cookie, "acme");
    const member = await memberWithActiveOrg(t, orgId, "member@acme.test");

    const res = await t.api.post(
      "/sso/register",
      {
        providerId: "personal-squat",
        issuer: "https://idp.example.com",
        domain: "victim.test",
        oidcConfig,
      },
      { cookie: member.cookie },
    );
    expect(res.status).toBe(400);
    expect(((await res.json()) as { code?: string }).code).toBe("ORG_REQUIRED");
    expect(await providerRow(t, "personal-squat")).toBeNull();
  });

  it("even an owner whose active org would have satisfied the fallback chain gets 400 ORG_REQUIRED", async () => {
    const t = await makeAuth();
    const owner = await signUpOwner(t, "owner@acme.test");
    await createOrg(t, owner.cookie, "acme");
    const res = await t.api.post(
      "/sso/register",
      {
        providerId: "owner-personal",
        issuer: "https://idp.example.com",
        domain: "acme.test",
        oidcConfig,
      },
      { cookie: owner.cookie },
    );
    expect(res.status).toBe(400);
    expect(((await res.json()) as { code?: string }).code).toBe("ORG_REQUIRED");
    expect(await providerRow(t, "owner-personal")).toBeNull();
  });

  it("control: with organizationId an owner registers an org-scoped row, a plain member is refused by upstream", async () => {
    const t = await makeAuth();
    const owner = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, owner.cookie, "acme");
    const ok = await t.api.post(
      "/sso/register",
      {
        providerId: "acme-oidc",
        issuer: "https://idp.example.com",
        domain: "acme.test",
        organizationId: orgId,
        oidcConfig,
      },
      { cookie: owner.cookie },
    );
    expect(ok.status).toBe(200);
    expect(await providerRow(t, "acme-oidc")).toMatchObject({
      organizationId: orgId,
      userId: owner.userId,
    });

    const member = await memberWithActiveOrg(t, orgId, "member@acme.test");
    const refused = await t.api.post(
      "/sso/register",
      {
        providerId: "member-try",
        issuer: "https://idp.example.com",
        domain: "other.test",
        organizationId: orgId,
        oidcConfig,
      },
      { cookie: member.cookie },
    );
    expect(refused.status).toBe(403);
    expect(await providerRow(t, "member-try")).toBeNull();
  });
});
