// F-17 (gate half): changing or deleting an SSO provider needs the `sso`
// entitlement of the organization that owns the provider — the same gate
// `/sso/register`, `/sso/request-domain-verification` and
// `/sso/verify-domain` sit behind — and the org is always the stored
// provider's own, never one the caller names.
//
// - Without the entitlement, owners are refused (403 FEATURE_NOT_ENTITLED)
//   and the provider is left as it was.
// - With it, owners and admins of the provider's org update and delete it.
// - A provider without an organization (a legacy, personal provider) has no
//   org to be entitled: it is refused (403 NOT_ORG_MEMBER), through HTTP and
//   through a server-side `auth.api` call alike; the operator path in
//   docs/security.md binds it to an org first.
//
// Against the parent commit neither path was gated: the unentitled owner and
// the org-less provider's creator both got 200.

import { describe, expect, it } from "vitest";
import { createOrg, makeAuth, signUpOwner, type TestAuth } from "../helpers/auth";
import { GATED_PATHS } from "../../src/server/gate";
import { insertMemberRow } from "./helpers";

const OIDC = {
  clientId: "client",
  clientSecret: "secret-value-never-logged",
  skipDiscovery: true,
  authorizationEndpoint: "https://idp.test/authorize",
  tokenEndpoint: "https://idp.test/token",
  jwksEndpoint: "https://idp.test/jwks",
};

async function codeOf(res: Response): Promise<string | undefined> {
  return ((await res.clone().json()) as { code?: string }).code;
}

/** An entitled owner with an org and a registered provider `p1`. */
async function orgWithProvider(t: TestAuth) {
  const owner = await signUpOwner(t, "owner@acme.test");
  const { orgId } = await createOrg(t, owner.cookie);
  const res = await t.api.post(
    "/sso/register",
    {
      providerId: "p1",
      issuer: "https://idp.test",
      domain: "acme.test",
      organizationId: orgId,
      oidcConfig: OIDC,
    },
    { cookie: owner.cookie },
  );
  expect(res.status, await res.clone().text()).toBe(200);
  return { owner, orgId };
}

async function provider(t: TestAuth, providerId = "p1") {
  const res = await t.client.execute({
    sql: `SELECT providerId, organizationId, oidcConfig FROM "ssoProvider" WHERE providerId = ?`,
    args: [providerId],
  });
  return res.rows[0] ?? null;
}

const update = (t: TestAuth, cookie: string) =>
  t.api.post("/sso/update-provider", { providerId: "p1", domain: "acme.test" }, { cookie });
const remove = (t: TestAuth, cookie: string) =>
  t.api.post("/sso/delete-provider", { providerId: "p1" }, { cookie });

describe("F-17 — /sso/update-provider and /sso/delete-provider are entitlement-gated", () => {
  it("both paths are in GATED_PATHS under the sso feature", () => {
    expect(GATED_PATHS["/sso/update-provider"]).toBe("sso");
    expect(GATED_PATHS["/sso/delete-provider"]).toBe("sso");
  });

  it("without the sso entitlement the owner can neither update nor delete the org's provider", async () => {
    const t = await makeAuth();
    const { owner } = await orgWithProvider(t);
    const stored = await provider(t);
    t.entitled.delete("sso");

    const u = await update(t, owner.cookie);
    expect(u.status).toBe(403);
    expect(await codeOf(u)).toBe("FEATURE_NOT_ENTITLED");
    const d = await remove(t, owner.cookie);
    expect(d.status).toBe(403);
    expect(await codeOf(d)).toBe("FEATURE_NOT_ENTITLED");
    expect(await provider(t)).toEqual(stored);
  });

  it("with the entitlement, the owner updates and an admin deletes", async () => {
    const t = await makeAuth();
    const { owner, orgId } = await orgWithProvider(t);
    const admin = await signUpOwner(t, "admin@acme.test");
    await insertMemberRow(t, orgId, admin.userId, "admin");

    expect((await update(t, owner.cookie)).status).toBe(200);
    expect((await update(t, admin.cookie)).status).toBe(200);
    expect((await remove(t, admin.cookie)).status).toBe(200);
    expect(await provider(t)).toBeNull();
  });

  it("a plain member of the entitled org is still refused by upstream", async () => {
    const t = await makeAuth();
    const { orgId } = await orgWithProvider(t);
    const member = await signUpOwner(t, "member@acme.test");
    await insertMemberRow(t, orgId, member.userId, "member");
    expect((await update(t, member.cookie)).status).toBe(403);
    expect((await remove(t, member.cookie)).status).toBe(403);
    expect(await provider(t)).not.toBeNull();
  });

  it("the org is the provider's own: an entitled owner of another org naming their org is refused", async () => {
    const t = await makeAuth();
    await orgWithProvider(t);
    const other = await signUpOwner(t, "owner@evil.test");
    const { orgId: evil } = await createOrg(t, other.cookie, "evil");
    for (const path of ["/sso/update-provider", "/sso/delete-provider"]) {
      const res = await t.api.post(
        `${path}?orgId=${evil}`,
        { providerId: "p1", organizationId: evil, orgId: evil, domain: "acme.test" },
        { cookie: other.cookie },
      );
      expect(res.status).toBe(403);
      expect(await codeOf(res)).toBe("NOT_ORG_MEMBER");
    }
    expect(await provider(t)).not.toBeNull();
  });

  it("a provider without an organization is refused over HTTP and through auth.api; bound to an org, its owners manage it", async () => {
    const t = await makeAuth();
    const { owner, orgId } = await orgWithProvider(t);
    // A legacy personal provider: no org, bound to the user who created it.
    await t.client.execute({
      sql: `UPDATE "ssoProvider" SET organizationId = NULL, userId = ? WHERE providerId = 'p1'`,
      args: [owner.userId],
    });

    const u = await update(t, owner.cookie);
    expect(u.status).toBe(403);
    expect(await codeOf(u)).toBe("NOT_ORG_MEMBER");
    const d = await remove(t, owner.cookie);
    expect(d.status).toBe(403);
    expect(await codeOf(d)).toBe("NOT_ORG_MEMBER");

    const api = t.auth.api as unknown as Record<
      string,
      (input: { body: unknown; headers: Headers }) => Promise<unknown>
    >;
    await expect(
      api.deleteSSOProvider!({
        body: { providerId: "p1" },
        headers: new Headers({ cookie: owner.cookie }),
      }),
    ).rejects.toMatchObject({ body: { code: "NOT_ORG_MEMBER" } });
    expect(await provider(t)).not.toBeNull();

    // The documented operator path: bind the provider to an org, then its
    // owners and admins manage it through the gated endpoints.
    await t.client.execute({
      sql: `UPDATE "ssoProvider" SET organizationId = ? WHERE providerId = 'p1'`,
      args: [orgId],
    });
    expect((await update(t, owner.cookie)).status).toBe(200);
    expect((await remove(t, owner.cookie)).status).toBe(200);
  });
});
