// Shared fixtures for the GHSA-8p84-pc7q-69jr jit-squat suite
// (`f01-*.test.ts`, `f28-*.test.ts`, `f30-*.test.ts`, `gap5-*.test.ts`):
// driving a real OIDC sign-in through the in-process issuer, minting the
// "admin test login passed" row `ssoEnforced` requires, and planting a
// *legacy* squat — a `user` + `account` pair already linked to a foreign
// tenant's IdP the way 1.0.x left it — without going through the (now
// refused) JIT path.
import { expect } from "vitest";
import { createOrg, extractCookie, signUpOwner, type TestAuth } from "../helpers/auth";
import { getNoRedirect, type OidcIssuer } from "../helpers/oidc-issuer";
import { registerOidcProvider } from "../helpers/sso";
import { insertMemberRow } from "./helpers";

/** `/sign-in/sso` → issuer `/authorize` → `/sso/callback/:providerId`; returns the callback's raw Response (a redirect either way — the caller inspects `location`/cookies). */
export async function driveSsoSignIn(
  t: TestAuth,
  issuer: OidcIssuer,
  providerId: string,
): Promise<Response> {
  const signInRes = await t.api.post("/sign-in/sso", { providerId, callbackURL: "/" }, {});
  expect(signInRes.status).toBe(200);
  const stateCookie = extractCookie(signInRes);
  const { url } = (await signInRes.json()) as { url: string };
  const authorizeRedirect = await getNoRedirect(url);
  expect(authorizeRedirect.status).toBe(302);
  return t.auth.handler(
    new Request(authorizeRedirect.location!, {
      headers: { cookie: stateCookie, origin: "http://localhost:3000" },
    }),
  );
}

/** Same flow through the **shared** `/sso/callback` (no provider in the URL — the provider comes from the OAuth state), the route `sso({ redirectURI })` deployments use. */
export async function driveSsoSignInViaSharedCallback(
  t: TestAuth,
  issuer: OidcIssuer,
  providerId: string,
): Promise<Response> {
  const signInRes = await t.api.post("/sign-in/sso", { providerId, callbackURL: "/" }, {});
  expect(signInRes.status).toBe(200);
  const stateCookie = extractCookie(signInRes);
  const { url } = (await signInRes.json()) as { url: string };
  const authorizeRedirect = await getNoRedirect(url);
  expect(authorizeRedirect.status).toBe(302);
  const perProvider = new URL(authorizeRedirect.location!);
  const shared = new URL(perProvider.toString());
  shared.pathname = "/api/auth/sso/callback";
  return t.auth.handler(
    new Request(shared.toString(), {
      headers: { cookie: stateCookie, origin: "http://localhost:3000" },
    }),
  );
}

export function sessionCookieOf(res: Response): string {
  const cookie = extractCookie(res);
  expect(cookie).toContain("session_token");
  return cookie;
}

export async function sessionOf(
  t: TestAuth,
  cookie: string,
): Promise<{ user: { id: string; email: string; emailVerified: boolean } }> {
  const res = await t.api.get("/get-session", { cookie });
  expect(res.status).toBe(200);
  return (await res.json()) as { user: { id: string; email: string; emailVerified: boolean } };
}

/** The `ab-sso-test-ok:<providerId>` row `POST /enterprise/policy/set { ssoEnforced: true }` requires. */
export async function insertTestLoginPassed(t: TestAuth, providerId: string): Promise<void> {
  await t.client.execute({
    sql: `INSERT INTO verification (id, identifier, value, expiresAt, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?, ?)`,
    args: [
      `verif_test_ok_${providerId}`,
      `ab-sso-test-ok:${providerId}`,
      new Date().toISOString(),
      Date.now() + 1000 * 60 * 60 * 24 * 365,
      Date.now(),
      Date.now(),
    ],
  });
}

export async function userRowsFor(t: TestAuth, email: string): Promise<number> {
  const rows = await t.client.execute({
    sql: `SELECT id FROM user WHERE email = ?`,
    args: [email],
  });
  return rows.rows.length;
}

export async function sessionCountFor(t: TestAuth, userId: string): Promise<number> {
  const rows = await t.client.execute({
    sql: `SELECT id FROM session WHERE userId = ?`,
    args: [userId],
  });
  return rows.rows.length;
}

/**
 * Two orgs, each with its own domain-verified OIDC provider against the same
 * in-process issuer: the victim `acme` (`acme.test`, provider `acme-oidc`)
 * and the attacker `evil` (`evil.test`, provider `evil-oidc`).
 */
export async function twoTenants(t: TestAuth, issuer: OidcIssuer) {
  const acmeOwner = await signUpOwner(t, "owner@acme.test");
  const { orgId: acmeOrg } = await createOrg(t, acmeOwner.cookie, "acme");
  await registerOidcProvider(t, acmeOwner.cookie, acmeOrg, issuer, "acme-oidc", "acme.test");
  const evilOwner = await signUpOwner(t, "owner@evil.test");
  const { orgId: evilOrg } = await createOrg(t, evilOwner.cookie, "evil");
  await registerOidcProvider(t, evilOwner.cookie, evilOrg, issuer, "evil-oidc", "evil.test");
  return { acmeOwner, acmeOrg, evilOwner, evilOrg };
}

/**
 * Plants the 1.0.x aftermath of a successful squat: a `user` row for
 * `email`, an `account` row linking it to `providerId` under `accountId`
 * (the IdP `sub`), and — as upstream's provider-bound auto-join would have
 * done — a `member` row in `memberOfOrgId`. Returns the user id.
 */
export async function insertLegacySquat(
  t: TestAuth,
  params: { email: string; providerId: string; accountId: string; memberOfOrgId: string },
): Promise<string> {
  const userId = `legacy_${params.accountId}`;
  const now = Date.now();
  await t.client.execute({
    sql: `INSERT INTO user (id, name, email, emailVerified, createdAt, updatedAt) VALUES (?, ?, ?, 0, ?, ?)`,
    args: [userId, "Squatted", params.email, now, now],
  });
  await t.client.execute({
    sql: `INSERT INTO account (id, accountId, providerId, userId, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?, ?)`,
    args: [`acct_${params.accountId}`, params.accountId, params.providerId, userId, now, now],
  });
  await insertMemberRow(t, params.memberOfOrgId, userId, "member");
  return userId;
}
