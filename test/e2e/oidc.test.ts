// Task 8 — OIDC end-to-end: the full authorization-code flow against an
// in-process issuer (`test/helpers/oidc-issuer.ts`), driven through real
// upstream `@better-auth/sso` code paths (`/sign-in/sso`, `/sso/callback/
// :providerId`) — no mocking of better-auth itself. Controller ruling (b).
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { getNoRedirect, startOidcIssuer, type OidcIssuer } from "../helpers/oidc-issuer";
import { registerOidcProvider } from "../helpers/sso";
import { createOrg, extractCookie, makeAuth, signUpOwner } from "../helpers/auth";

describe("OIDC end-to-end sign-in", () => {
  let issuer: OidcIssuer;

  beforeAll(async () => {
    issuer = await startOidcIssuer();
  });

  afterAll(async () => {
    await issuer.close();
  });

  it("full code flow: sign-in -> issuer -> callback -> session -> member(role=member) -> audit row -> provisionUser called", async () => {
    const provisionUser = vi.fn();
    const t = await makeAuth({ trustedOrigins: [issuer.issuerUrl], provisionUser });
    const { cookie: ownerCookie } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, ownerCookie);
    await registerOidcProvider(t, ownerCookie, orgId, issuer, "oidc-e2e");

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

    // `enterprisePreset` forwards `opts.provisionUser` verbatim into
    // `sso({ provisionUser })` — it must fire once, for this new user, on
    // the SSO-driven signup (`processOIDCCallback` calls it when
    // `linked.isRegister` is true, `node_modules/@better-auth/sso/dist/
    // index.mjs`).
    expect(provisionUser).toHaveBeenCalledTimes(1);
    const call = provisionUser.mock.calls[0]![0] as { user: { email: string } };
    expect(call.user.email).toBe(email);
  });
});

// C-1 — the mandatory SSO test login could not complete in a real browser.
//
// The reproduction the final review captured, driven end to end here rather
// than described: `/enterprise/sso/test-login/finish` is reached *after* an
// SSO sign-in, and the session that sign-in mints has **no**
// `activeOrganizationId` (nothing in better-auth or `@better-auth/sso` ever
// writes one — only `/organization/set-active` does). Before the fix the
// entitlement gate resolved this path's org id from that field alone and
// answered `400 ORG_REQUIRED`, so `ab-sso-test-ok:<providerId>` was never
// written, `testLoginPassed` never became true, and `ssoEnforced` could
// never be switched on for *any* org.
//
// The pre-existing `finish:` cases in `test/server/enterprise-api.test.ts`
// miss it because they reuse the pre-SSO cookie from `createOrg()`, which
// does carry `activeOrganizationId` — a state the browser is never in at
// this point in the flow. This test uses the cookie the SSO callback itself
// minted, which is the only cookie a real browser has here.
describe("SSO admin test login, end to end (C-1)", () => {
  let issuer: OidcIssuer;

  beforeAll(async () => {
    issuer = await startOidcIssuer();
  });

  afterAll(async () => {
    await issuer.close();
  });

  /**
   * A browser's cookie jar: merges `name=value` pairs across responses, later
   * ones replacing earlier ones of the same name, and drops the emptied
   * values a `Max-Age=0` deletion leaves behind. Needed because the SSO
   * callback clears `better-auth.state` while minting the session cookie, so
   * naively concatenating two `extractCookie()` strings would send back a
   * stale empty `state` ahead of the live one.
   */
  function jar(...cookieStrings: string[]): string {
    const pairs = new Map<string, string>();
    for (const raw of cookieStrings) {
      for (const pair of raw.split("; ")) {
        const eq = pair.indexOf("=");
        if (eq === -1) continue;
        pairs.set(pair.slice(0, eq), pair.slice(eq + 1));
      }
    }
    return [...pairs]
      .filter(([, value]) => value !== "")
      .map(([name, value]) => `${name}=${value}`)
      .join("; ");
  }

  /** Follows an `/authorize` URL to the issuer and posts the resulting callback back through `auth.handler`, returning the response (and the session cookie it minted). */
  async function completeAuthorize(
    t: Awaited<ReturnType<typeof makeAuth>>,
    url: string,
    cookie: string,
  ): Promise<{ res: Response; sessionCookie: string }> {
    const authorizeRedirect = await getNoRedirect(url);
    expect(authorizeRedirect.status).toBe(302);
    const callbackUrl = authorizeRedirect.location;
    expect(callbackUrl).toBeTruthy();
    const res = await t.auth.handler(
      new Request(callbackUrl!, {
        headers: { cookie, origin: "http://localhost:3000" },
      }),
    );
    return { res, sessionCookie: extractCookie(res) };
  }

  it("start -> issuer -> callback -> finish, with the cookie the callback minted, records the passed test login", async () => {
    const t = await makeAuth({ trustedOrigins: [issuer.issuerUrl] });
    const { cookie: ownerCookie } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, ownerCookie);
    await registerOidcProvider(t, ownerCookie, orgId, issuer, "oidc-testlogin");

    // The admin who will run the test login signs in through the IdP once
    // first, so their user is SSO-linked and JIT-joined to the org — exactly
    // the identity that then walks the wizard.
    issuer.setUser({ sub: "admin-1", email: "admin@acme.test" });
    const firstSignIn = await t.api.post(
      "/sign-in/sso",
      { providerId: "oidc-testlogin", callbackURL: "/" },
      {},
    );
    expect(firstSignIn.status).toBe(200);
    const { url: firstUrl } = (await firstSignIn.json()) as { url: string };
    const first = await completeAuthorize(t, firstUrl, extractCookie(firstSignIn));
    expect(first.res.status).toBe(302);
    const adminCookie = first.sessionCookie;
    const adminSession = (await (
      await t.api.get("/get-session", { cookie: adminCookie })
    ).json()) as { user: { id: string } };
    await t.client.execute({
      sql: `UPDATE member SET role = 'admin' WHERE organizationId = ? AND userId = ?`,
      args: [orgId, adminSession.user.id],
    });

    // Step 1 of the wizard's test-login step: this is a normal POST with an
    // explicit `orgId` in the body, so it is unaffected by C-1.
    const startRes = await t.api.post(
      "/enterprise/sso/test-login/start",
      { orgId, providerId: "oidc-testlogin" },
      { cookie: adminCookie },
    );
    expect(startRes.status).toBe(200);
    // The signed `state` cookie upstream `/sign-in/sso` sets has to survive
    // the wrapper — a browser holds it alongside the admin's session cookie
    // when it comes back from the IdP, and `parseGenericState` checks it
    // against the `state` query parameter on the callback.
    const stateCookie = extractCookie(startRes);
    expect(stateCookie).not.toBe("");
    const { url } = (await startRes.json()) as { url: string };

    // Step 2: the IdP round trip. The callback redirects the browser to the
    // `callbackURL` `start` handed upstream — the finish endpoint.
    const { res: callbackRes, sessionCookie } = await completeAuthorize(
      t,
      url,
      jar(adminCookie, stateCookie),
    );
    expect(callbackRes.status).toBe(302);
    expect(callbackRes.headers.get("location")).toContain(
      "/enterprise/sso/test-login/finish?providerId=oidc-testlogin",
    );
    expect(sessionCookie).toContain("session_token");

    // The precondition that made C-1 unreachable in the existing suite: the
    // session the callback just minted carries no active organization.
    const ssoSession = (await (
      await t.api.get("/get-session", { cookie: sessionCookie })
    ).json()) as {
      session: { activeOrganizationId?: string | null };
    };
    expect(ssoSession.session.activeOrganizationId ?? null).toBeNull();

    // Step 3: finish, with that cookie and nothing else — the only cookie a
    // real browser holds at this point.
    const finishRes = await t.api.get(
      "/enterprise/sso/test-login/finish?providerId=oidc-testlogin",
      { cookie: sessionCookie },
    );
    expect(finishRes.status).toBe(302);
    expect(finishRes.headers.get("location")).toBe("/?ab_sso_test=ok");

    // …and the flag the enforcement precondition reads is actually written.
    const providers = (await (
      await t.api.get(`/enterprise/sso/providers?orgId=${orgId}`, { cookie: ownerCookie })
    ).json()) as { providers: Array<{ testLoginPassedAt: string | null }> };
    expect(providers.providers[0]!.testLoginPassedAt).not.toBeNull();

    const audit = await t.client.execute({
      sql: `SELECT org_id FROM audit_event WHERE action = 'sso.test_login_passed'`,
    });
    expect(audit.rows.length).toBe(1);
    expect(audit.rows[0]!.org_id).toBe(orgId);
  });
});
