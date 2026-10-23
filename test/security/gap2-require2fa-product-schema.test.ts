// GHSA-8p84-pc7q-69jr — audit gap 2, round 3: the require2fa enforcement
// must run on the tables products actually have.
//
// Every product maintains its better-auth Drizzle tables by hand
// (`../helpers/product-auth.ts` reproduces a product's `session` table and
// hand-maintained `member`/`org_policy` tables), and upstream's Drizzle adapter refuses to write a
// value key that its table does not declare. An enforcement that records
// anything new on a core row therefore fails every sign-in on every product —
// orgs without `require2fa` included. These cases drive the ordinary flows of
// a user on whom **no** policy requires a second factor, through that
// product-shaped schema, and expect nothing to change for them.
//
// Behavioural only (HTTP status and bodies): no symbol from the source tree
// is imported, so the file runs unchanged against any earlier head.
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { magicLink } from "better-auth/plugins";
import { createOrg, extractCookie, signUpOwner, type TestAuth } from "../helpers/auth";
import { startOidcIssuer, type OidcIssuer } from "../helpers/oidc-issuer";
import { insertProductMember, makeProductAuth } from "../helpers/product-auth";
import { registerOidcProvider } from "../helpers/sso";
import { driveSsoSignIn, sessionCookieOf } from "./ghsa-sso-helpers";

function magicSink() {
  const sent: Array<{ email: string; token: string }> = [];
  return {
    sent,
    plugin: magicLink({
      async sendMagicLink({ email, token }) {
        sent.push({ email, token });
      },
    }),
  };
}

async function sessionUser(t: TestAuth, cookie: string): Promise<{ id: string; email: string }> {
  const res = await t.api.get("/get-session", { cookie });
  expect(res.status).toBe(200);
  const body = (await res.json()) as { user?: { id: string; email: string } } | null;
  expect(body?.user, "a valid session").toBeTruthy();
  return body!.user!;
}

describe("gap 2 R3 — a product-shaped Drizzle schema, no require2fa anywhere: nothing changes", () => {
  it("sign-up, session, organization create/activate/list, policy read/write, sign-out and password sign-in all work", async () => {
    const t = await makeProductAuth();

    const signUp = await t.api.post("/sign-up/email", {
      name: "Owner",
      email: "owner@acme.test",
      password: "password1234",
    });
    expect(signUp.status, await signUp.clone().text()).toBe(200);
    const cookie = extractCookie(signUp);
    const owner = await sessionUser(t, cookie);
    expect(owner.email).toBe("owner@acme.test");

    // The row really is in the product shape: seconds, snake_case.
    const row = await t.client.execute({
      sql: `SELECT created_at FROM session WHERE user_id = ?`,
      args: [owner.id],
    });
    expect(Number(row.rows[0]!.created_at)).toBeLessThan(100_000_000_000);

    const { orgId } = await createOrg(t, cookie, "acme");
    const active = await t.api.post(
      "/organization/set-active",
      { organizationId: orgId },
      { cookie },
    );
    expect(active.status).toBe(200);
    const list = await t.api.get("/organization/list", { cookie });
    expect(list.status).toBe(200);
    expect(((await list.json()) as Array<{ id: string }>).map((o) => o.id)).toContain(orgId);

    // The policy row is written and read through the product's `org_policy`.
    const read = await t.api.get(`/enterprise/policy?orgId=${orgId}`, { cookie });
    expect(read.status).toBe(200);
    const write = await t.api.post(
      "/enterprise/policy/set",
      { orgId, sessionMaxAgeS: 3600 },
      { cookie },
    );
    expect(write.status, await write.clone().text()).toBe(200);
    expect((await t.api.get("/organization/list", { cookie })).status).toBe(200);

    const signOut = await t.api.post("/sign-out", {}, { cookie });
    expect(signOut.status).toBe(200);
    const signIn = await t.api.post("/sign-in/email", {
      email: "owner@acme.test",
      password: "password1234",
    });
    expect(signIn.status, await signIn.clone().text()).toBe(200);
    const again = extractCookie(signIn);
    expect((await sessionUser(t, again)).id).toBe(owner.id);
    expect((await t.api.get("/organization/list", { cookie: again })).status).toBe(200);
  });

  it("a magic-link user and a member added to the org sign in and use the org", async () => {
    const { sent, plugin } = magicSink();
    const t = await makeProductAuth({ plugins: [plugin] });
    const { cookie: ownerCookie } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, ownerCookie, "acme");

    const request = await t.api.post("/sign-in/magic-link", { email: "bob@acme.test" }, {});
    expect(request.status).toBe(200);
    const verify = await t.api.get(`/magic-link/verify?token=${sent[0]!.token}`);
    expect(verify.status, await verify.clone().text()).toBe(200);
    const bobCookie = extractCookie(verify);
    const bob = await sessionUser(t, bobCookie);

    await insertProductMember(t, orgId, bob.id, "member");
    const orgs = await t.api.get("/organization/list", { cookie: bobCookie });
    expect(orgs.status).toBe(200);
    expect(((await orgs.json()) as Array<{ id: string }>).map((o) => o.id)).toContain(orgId);
    expect(
      (
        await t.api.post(
          "/organization/set-active",
          { organizationId: orgId },
          { cookie: bobCookie },
        )
      ).status,
    ).toBe(200);
    expect((await sessionUser(t, bobCookie)).id).toBe(bob.id);
  });
});

describe("gap 2 R3 — product-shaped schema, SSO with just-in-time membership, no require2fa", () => {
  let issuer: OidcIssuer;
  beforeAll(async () => {
    issuer = await startOidcIssuer();
  });
  afterAll(async () => {
    await issuer.close();
  });

  it("the first SSO sign-in provisions the member and its session is valid; so is the next one", async () => {
    const t = await makeProductAuth({ trustedOrigins: [issuer.issuerUrl] });
    const { cookie: ownerCookie } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, ownerCookie, "acme");
    await registerOidcProvider(t, ownerCookie, orgId, issuer, "acme-oidc", "acme.test");

    issuer.setUser({ sub: "alice", email: "alice@acme.test" });
    const first = await driveSsoSignIn(t, issuer, "acme-oidc");
    expect(first.headers.get("location") ?? "").not.toContain("error=");
    const cookie = sessionCookieOf(first);
    const alice = await sessionUser(t, cookie);
    const orgs = await t.api.get("/organization/list", { cookie });
    expect(orgs.status).toBe(200);
    expect(((await orgs.json()) as Array<{ id: string }>).map((o) => o.id)).toContain(orgId);

    const second = await driveSsoSignIn(t, issuer, "acme-oidc");
    expect((await sessionUser(t, sessionCookieOf(second))).id).toBe(alice.id);
  });
});
