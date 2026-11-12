// 1.3 SSO options — `sso.existingUsersOnly`, `sso.requireMembership`,
// `sso.organizationProvisioning` and `sso.oidcClaims`, end to end through a
// real OIDC sign-in against the in-process issuer.
//
// The threat they close: an IdP-authenticated person (any tenant's, or a
// personal Google account) who signs in through SSO must not be able to create
// an account, join an organization, link themselves to somebody else's account
// or ride a claim the IdP did not sign. Every refusal asserts the whole
// contract: a 302 carrying `error=<code>`, no session cookie, no new `user`,
// `account` or `member` row, and an `auth.sign_in_refused` audit row naming
// the code and the provider. The link path bypasses better-auth's own
// `accountLinking` (which stays disabled here, as in a product that turned it
// off), so each case is also a regression test for that bypass.
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createOrg, extractCookie, makeAuth, signUpOwner, type TestAuth } from "../helpers/auth";
import { isPg, ts } from "../helpers/dialect";
import { getNoRedirect, startOidcIssuer, type OidcIssuer } from "../helpers/oidc-issuer";
import { registerOidcProvider, registerSamlProvider } from "../helpers/sso";
import { mintSamlResponse } from "../helpers/saml-idp";
import { createScimUser, insertMemberRow, mintScimToken, coreUserId } from "./helpers";
import { sessionCookieOf, sessionOf, userRowsFor } from "./ghsa-sso-helpers";
import { buildDomainBindingUserCreateBeforeHook } from "../../src/server/policy/sso-jit";
import type { EnterpriseOptions } from "../../src/server/types";

type SsoOptions = NonNullable<EnterpriseOptions["sso"]>;

const STRICT_ALL: SsoOptions = {
  existingUsersOnly: true,
  organizationProvisioning: "off",
  oidcClaims: { requireEmailVerified: true, requireHostedDomain: true, requirePkce: true },
};

let issuer: OidcIssuer;
beforeAll(async () => {
  issuer = await startOidcIssuer();
});
afterAll(async () => {
  await issuer.close();
});

async function insertUser(
  t: TestAuth,
  email: string,
  extra: { emailVerified?: boolean } = {},
): Promise<string> {
  const id = `usr_${email.replace(/[^a-z0-9]/g, "_")}`;
  const now = Date.now();
  await t.client.execute({
    sql: `INSERT INTO user (id, name, email, emailVerified, createdAt, updatedAt) VALUES (?, ?, ?, ${
      extra.emailVerified ? "1" : "0"
    }, ?, ?)`,
    args: [id, email.split("@")[0]!, email, now, now],
  });
  return id;
}

async function insertAccount(
  t: TestAuth,
  userId: string,
  providerId: string,
  accountId: string,
): Promise<void> {
  const now = Date.now();
  await t.client.execute({
    sql: `INSERT INTO account (id, accountId, providerId, userId, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?, ?)`,
    args: [`acct_${providerId}_${accountId}`, accountId, providerId, userId, now, now],
  });
}

async function count(t: TestAuth, table: string): Promise<number> {
  const rows = await t.client.execute({ sql: `SELECT COUNT(*) AS n FROM ${table}` });
  return Number(rows.rows[0]!.n);
}

async function counts(t: TestAuth) {
  return {
    user: await count(t, "user"),
    account: await count(t, "account"),
    member: await count(t, "member"),
  };
}

async function refusedAuditCodes(t: TestAuth): Promise<Array<Record<string, unknown>>> {
  const rows = await t.client.execute({
    sql: `SELECT metadata FROM audit_event WHERE action = 'auth.sign_in_refused'`,
  });
  return rows.rows.map((row) => {
    const raw = row.metadata;
    return (typeof raw === "string" ? JSON.parse(raw) : raw) as Record<string, unknown>;
  });
}

interface World {
  t: TestAuth;
  orgId: string;
  ownerId: string;
  ownerCookie: string;
  janeId: string;
}

/** An acme org with a domain-verified OIDC provider and one pre-provisioned member, `jane@acme.test`; account linking is off, as in a hardened product. */
async function world(
  sso: SsoOptions | undefined,
  register: Parameters<typeof registerOidcProvider>[6] = {},
  makeMember = true,
): Promise<World> {
  const t = await makeAuth({
    trustedOrigins: [issuer.issuerUrl],
    account: { accountLinking: { enabled: false } },
    ...(sso ? { sso } : {}),
  });
  const owner = await signUpOwner(t, "owner@acme.test");
  const { orgId } = await createOrg(t, owner.cookie, "acme");
  await registerOidcProvider(t, owner.cookie, orgId, issuer, "acme-oidc", "acme.test", register);
  const janeId = await insertUser(t, "jane@acme.test");
  if (makeMember) await insertMemberRow(t, orgId, janeId, "member");
  issuer.setUser({ sub: "sub-jane", email: "jane@acme.test", hd: "acme.test" });
  return { t, orgId, ownerId: owner.userId, ownerCookie: owner.cookie, janeId };
}

/** The refusal contract (see the file header). `before` is the row counts taken just before the sign-in. */
async function expectRefused(
  t: TestAuth,
  res: Response,
  code: string,
  before: Awaited<ReturnType<typeof counts>>,
): Promise<void> {
  expect(res.status).toBe(302);
  expect(res.headers.get("location") ?? "").toContain(`error=${code}`);
  expect(extractCookie(res)).not.toContain("session_token");
  expect(await counts(t)).toEqual(before);
  const refused = await refusedAuditCodes(t);
  expect(refused.some((m) => m.code === code && m.providerId === "acme-oidc")).toBe(true);
}

async function drive(t: TestAuth, body: Record<string, unknown> = {}): Promise<Response> {
  const signIn = await t.api.post(
    "/sign-in/sso",
    { providerId: "acme-oidc", callbackURL: "/", ...body },
    {},
  );
  expect(signIn.status).toBe(200);
  const stateCookie = extractCookie(signIn);
  const { url } = (await signIn.json()) as { url: string };
  const authorize = await getNoRedirect(url);
  return t.auth.handler(
    new Request(authorize.location!, {
      headers: { cookie: stateCookie, origin: "http://localhost:3000" },
    }),
  );
}

describe("existingUsersOnly — the accepted sign-in", () => {
  it("first login links the pre-existing user without creating anything; the second login works; account linking stays off and the local e-mail verification is untouched", async () => {
    const { t, janeId, orgId } = await world(STRICT_ALL);
    expect(t.auth.options.account?.accountLinking?.enabled).toBe(false);
    const before = await counts(t);

    const first = await drive(t);
    expect(first.headers.get("location") ?? "").not.toContain("error=");
    const session = await sessionOf(t, sessionCookieOf(first));
    expect(session.user.id).toBe(janeId);
    expect(session.user.emailVerified).toBe(false); // the IdP is the authority; the local flag is unchanged
    expect(await counts(t)).toEqual({ ...before, account: before.account + 1 });

    const second = await drive(t);
    expect(second.headers.get("location") ?? "").not.toContain("error=");
    expect((await sessionOf(t, sessionCookieOf(second))).user.id).toBe(janeId);
    expect(await counts(t)).toEqual({ ...before, account: before.account + 1 });

    const accounts = await t.client.execute({
      sql: `SELECT providerId, accountId, userId FROM account WHERE userId = ?`,
      args: [janeId],
    });
    expect(accounts.rows).toHaveLength(1);
    expect(accounts.rows[0]).toMatchObject({ providerId: "acme-oidc", accountId: "sub-jane" });
    const members = await t.client.execute({
      sql: `SELECT role FROM member WHERE organizationId = ? AND userId = ?`,
      args: [orgId, janeId],
    });
    expect(members.rows).toHaveLength(1); // the pre-provisioned row, no second one
    expect(await refusedAuditCodes(t)).toEqual([]);
  });

  it("requireMembership:false links a user who is not a member and, with organizationProvisioning:'off', creates no member row", async () => {
    const { t, janeId } = await world(
      { ...STRICT_ALL, requireMembership: false },
      {},
      /* makeMember */ false,
    );
    const before = await counts(t);
    const res = await drive(t);
    expect((await sessionOf(t, sessionCookieOf(res))).user.id).toBe(janeId);
    expect(await counts(t)).toEqual({ ...before, account: before.account + 1 });
    const member = await t.client.execute({
      sql: `SELECT id FROM member WHERE userId = ?`,
      args: [janeId],
    });
    expect(member.rows).toEqual([]);
  });

  it("without organizationProvisioning:'off' upstream's own provider-bound join still adds the member row (the option is what stops it)", async () => {
    const { t, janeId } = await world(
      { existingUsersOnly: true, requireMembership: false },
      {},
      false,
    );
    sessionCookieOf(await drive(t));
    const member = await t.client.execute({
      sql: `SELECT id FROM member WHERE userId = ?`,
      args: [janeId],
    });
    expect(member.rows).toHaveLength(1);
  });
});

describe("oidcClaims — hosted domain (hd)", () => {
  it("a missing hd, a wrong hd and a subdomain or suffix spoof are refused; nothing changes", async () => {
    const { t } = await world(STRICT_ALL);
    for (const hd of [
      undefined,
      "other.test",
      "eu.acme.test",
      "acme.test.evil.test",
      "ACME.TEST.x",
    ]) {
      issuer.setUser({ sub: "sub-jane", email: "jane@acme.test", hd });
      const before = await counts(t);
      await expectRefused(t, await drive(t), "SSO_HOSTED_DOMAIN_MISMATCH", before);
    }
  });

  it("a valid hd with an e-mail on another domain is refused", async () => {
    const { t, orgId } = await world(STRICT_ALL);
    const subId = await insertUser(t, "jane@eu.acme.test");
    await insertMemberRow(t, orgId, subId, "member");
    issuer.setUser({ sub: "sub-eu", email: "jane@eu.acme.test", hd: "acme.test" });
    const before = await counts(t);
    await expectRefused(t, await drive(t), "SSO_HOSTED_DOMAIN_MISMATCH", before);
  });

  it("an explicit hd allow-list is used instead of the provider's domain: a hd the provider covers but the list omits is refused", async () => {
    const { t, orgId } = await world({
      ...STRICT_ALL,
      oidcClaims: { requireEmailVerified: true, requireHostedDomain: ["other.test"] },
    });
    // The provider covers both domains, so only the allow-list can tell them apart.
    await t.client.execute({
      sql: `UPDATE "ssoProvider" SET domain = ? WHERE "providerId" = ?`,
      args: ["acme.test,other.test", "acme-oidc"],
    });
    const otherId = await insertUser(t, "jane@other.test");
    await insertMemberRow(t, orgId, otherId, "member");

    // jane@acme.test: the provider's own domain, and a valid hd for it, but not on the list.
    issuer.setUser({ sub: "sub-jane", email: "jane@acme.test", hd: "acme.test" });
    const before = await counts(t);
    await expectRefused(t, await drive(t), "SSO_HOSTED_DOMAIN_MISMATCH", before);

    // jane@other.test: on the list, so the same provider signs her in.
    issuer.setUser({ sub: "sub-other", email: "jane@other.test", hd: "other.test" });
    const ok = await drive(t);
    expect(ok.headers.get("location") ?? "").not.toContain("error=");
    expect((await sessionOf(t, sessionCookieOf(ok))).user.id).toBe(otherId);
  });
});

describe("oidcClaims — email_verified and the e-mail claim", () => {
  it("email_verified false, absent and the string 'true' are refused", async () => {
    const { t } = await world(STRICT_ALL);
    for (const emailVerified of [false, null, "true"] as const) {
      issuer.setUser({ sub: "sub-jane", email: "jane@acme.test", hd: "acme.test", emailVerified });
      const before = await counts(t);
      await expectRefused(t, await drive(t), "SSO_EMAIL_NOT_VERIFIED", before);
    }
  });

  it("existingUsersOnly implies requireEmailVerified even without an oidcClaims block", async () => {
    const { t } = await world({ existingUsersOnly: true, organizationProvisioning: "off" });
    issuer.setUser({ sub: "sub-jane", email: "jane@acme.test", emailVerified: false });
    const before = await counts(t);
    await expectRefused(t, await drive(t), "SSO_EMAIL_NOT_VERIFIED", before);
  });

  it("a userinfo e-mail that differs from the ID-token e-mail is refused, and the user it names is untouched", async () => {
    const { t, orgId } = await world(STRICT_ALL, { userInfo: true });
    const malloryId = await insertUser(t, "mallory@acme.test");
    await insertMemberRow(t, orgId, malloryId, "member");
    issuer.setUser({
      sub: "sub-jane",
      email: "jane@acme.test",
      hd: "acme.test",
      userinfoEmail: "mallory@acme.test",
    });
    const before = await counts(t);
    await expectRefused(t, await drive(t), "SSO_EMAIL_CLAIM_MISMATCH", before);
    const accounts = await t.client.execute({
      sql: `SELECT id FROM account WHERE userId = ?`,
      args: [malloryId],
    });
    expect(accounts.rows).toEqual([]);
  });
});

describe("existingUsersOnly — who may be linked", () => {
  it("no local user: refused, zero users created, also with a forged requestSignUp:true", async () => {
    const { t } = await world(STRICT_ALL);
    issuer.setUser({ sub: "sub-ghost", email: "ghost@acme.test", hd: "acme.test" });
    const before = await counts(t);
    await expectRefused(t, await drive(t), "SSO_USER_NOT_PROVISIONED", before);
    await expectRefused(
      t,
      await drive(t, { requestSignUp: true }),
      "SSO_USER_NOT_PROVISIONED",
      before,
    );
    expect(await userRowsFor(t, "ghost@acme.test")).toBe(0);
  });

  it("a banned user is refused whether the ban is permanent or unexpired; an expired ban signs in", async () => {
    const { t, janeId } = await world(STRICT_ALL);
    const ban = async (expiresMs: number | null) =>
      t.client.execute({
        sql: `UPDATE user SET banned = ?, banExpires = ? WHERE id = ?`,
        args: [isPg ? true : 1, expiresMs === null ? null : ts(expiresMs), janeId],
      });
    for (const expires of [null, Date.now() + 3_600_000]) {
      await ban(expires);
      const before = await counts(t);
      await expectRefused(t, await drive(t), "SSO_USER_BANNED", before);
    }
    await ban(Date.now() - 3_600_000);
    sessionCookieOf(await drive(t));
  });

  it("a provider whose domain does not cover the e-mail is SSO_DOMAIN_NOT_ALLOWED", async () => {
    const { t } = await world({ existingUsersOnly: true, organizationProvisioning: "off" });
    await t.client.execute({
      sql: `UPDATE "ssoProvider" SET domain = ? WHERE "providerId" = ?`,
      args: ["other.test", "acme-oidc"],
    });
    const before = await counts(t);
    await expectRefused(t, await drive(t), "SSO_DOMAIN_NOT_ALLOWED", before);
  });

  it("an unverified provider never reaches the resolver: upstream refuses the sign-in itself (401), and nothing is created", async () => {
    const { t } = await world(STRICT_ALL);
    await t.client.execute({
      sql: `UPDATE "ssoProvider" SET "domainVerified" = ? WHERE "providerId" = ?`,
      args: [isPg ? false : 0, "acme-oidc"],
    });
    const before = await counts(t);
    const res = await t.api.post("/sign-in/sso", { providerId: "acme-oidc", callbackURL: "/" }, {});
    expect(res.status).toBe(401);
    expect(extractCookie(res)).not.toContain("session_token");
    expect(await counts(t)).toEqual(before);
  });

  it("requireMembership (default true): a user who is not a member of the provider's org is refused", async () => {
    const { t } = await world(STRICT_ALL, {}, false);
    const before = await counts(t);
    await expectRefused(t, await drive(t), "SSO_NOT_MEMBER", before);
  });

  it("the same subject linked to another user is refused (and the check, not upstream's, is what answers)", async () => {
    const { t } = await world(STRICT_ALL);
    const bobId = await insertUser(t, "bob@acme.test");
    await insertAccount(t, bobId, "acme-oidc", "sub-jane");
    const before = await counts(t);
    await expectRefused(t, await drive(t), "SSO_ACCOUNT_CONFLICT", before);
  });

  it("a different subject for a user already linked through this provider is refused (without the check upstream would link a second account)", async () => {
    const { t, janeId } = await world(STRICT_ALL);
    await insertAccount(t, janeId, "acme-oidc", "sub-old");
    const before = await counts(t);
    await expectRefused(t, await drive(t), "SSO_ACCOUNT_CONFLICT", before);
  });
});

describe("oidcClaims — PKCE", () => {
  it("requirePkce refuses a stored provider whose pkce was switched off after registration", async () => {
    const { t } = await world(STRICT_ALL);
    await t.client.execute({
      sql: `UPDATE "ssoProvider" SET "oidcConfig" = REPLACE("oidcConfig", '"pkce":true', '"pkce":false') WHERE "providerId" = ?`,
      args: ["acme-oidc"],
    });
    const before = await counts(t);
    await expectRefused(t, await drive(t), "SSO_PKCE_REQUIRED", before);
  });

  // A spike that documents a gap rather than closing it: upstream sends no
  // OIDC `nonce` on the authorization request (and `nonce` is a reserved
  // parameter its `additionalParams` refuses), so the ID token is not bound to
  // the browser session by a nonce. What binds it instead is the signed state
  // cookie, PKCE, client authentication at the token endpoint and the
  // iss/aud/azp checks. If upstream ever starts sending one, this test is the
  // reminder to start requiring it.
  it("the authorization request carries state and a PKCE challenge, and no nonce (documented gap)", async () => {
    const { t } = await world(STRICT_ALL);
    issuer.authorizeRequests.length = 0;
    sessionCookieOf(await drive(t));
    const request = issuer.authorizeRequests.at(-1)!;
    expect(request.has("nonce")).toBe(false);
    expect(request.get("code_challenge")).toBeTruthy();
    expect(request.get("code_challenge_method")).toBe("S256");
    expect(request.get("state")).toBeTruthy();
  });
});

describe("existingUsersOnly — SAML", () => {
  // Upstream's SAML ACS passes `disableSignUp: disableImplicitSignUp` with no
  // `requestSignUp` escape, so it refuses first (`signup_disabled`, upstream's
  // own code); the `user.create.before` backstop is not reached on this path.
  // The backstop's own contract is test/security/sso-signup-backstop.test.ts.
  it("SAML with only existingUsersOnly creates no user and no session for an unknown address (upstream's own signup_disabled)", async () => {
    const { t, orgId, ownerCookie } = await world({
      existingUsersOnly: true,
      organizationProvisioning: "off",
    });
    const saml = await registerSamlProvider(
      t,
      ownerCookie,
      orgId,
      "acme-saml",
      undefined,
      "acme.test",
    );
    const before = await counts(t);
    const res = await t.api.postForm(`/sso/saml2/sp/acs/acme-saml`, {
      SAMLResponse: await mintSamlResponse({ ...saml, email: "ghost@acme.test" }),
      RelayState: "",
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location") ?? "").toContain("error=signup_disabled");
    expect(extractCookie(res)).not.toContain("session_token");
    expect(await counts(t)).toEqual(before);
    expect(await userRowsFor(t, "ghost@acme.test")).toBe(0);
  });

  it("SAML for an existing, unlinked user is not linked (upstream's 'account not linked'), whatever the claims options say", async () => {
    const { t, orgId, ownerCookie } = await world({
      existingUsersOnly: true,
      organizationProvisioning: "off",
    });
    const saml = await registerSamlProvider(
      t,
      ownerCookie,
      orgId,
      "acme-saml",
      undefined,
      "acme.test",
    );
    const before = await counts(t);
    const res = await t.api.postForm(`/sso/saml2/sp/acs/acme-saml`, {
      SAMLResponse: await mintSamlResponse({ ...saml, email: "jane@acme.test" }),
      RelayState: "",
    });
    expect(extractCookie(res)).not.toContain("session_token");
    expect(await counts(t)).toEqual(before);
  });

  it("with oidcClaims set, a SAML provider is refused at registration (the resolver refuses a SAML sign-in too: test/server/sso-resolve.test.ts)", async () => {
    const { t, orgId, ownerCookie } = await world(STRICT_ALL);
    const register = await t.api.post(
      "/sso/register",
      {
        providerId: "acme-saml",
        issuer: "https://test-idp.alphabros.test/idp",
        domain: "acme.test",
        organizationId: orgId,
        samlConfig: {
          entryPoint: "https://test-idp.alphabros.test/idp/sso",
          cert: "x",
          callbackUrl: "http://localhost:3000/api/auth/sso/saml2/sp/acs/acme-saml",
          spMetadata: { entityID: "http://localhost:3000/api/auth/sso/saml2/sp/acme-saml" },
        },
      },
      { cookie: ownerCookie },
    );
    expect(register.status).toBe(403);
    expect(await register.json()).toMatchObject({ code: "SSO_POLICY_UNSUPPORTED_PROTOCOL" });
    const rows = await t.client.execute({
      sql: `SELECT id FROM "ssoProvider" WHERE "providerId" = ?`,
      args: ["acme-saml"],
    });
    expect(rows.rows).toEqual([]);
  });
});

describe("registration guards — requirePkce", () => {
  it("refuses pkce:false at registration and when an update would turn it off; accepts the default and an explicit true", async () => {
    const { t, orgId, ownerCookie } = await world({ oidcClaims: { requirePkce: true } });
    const body = (providerId: string, oidcConfig: Record<string, unknown>) => ({
      providerId,
      issuer: issuer.issuerUrl,
      domain: "acme.test",
      organizationId: orgId,
      oidcConfig: {
        clientId: issuer.clientId,
        clientSecret: issuer.clientSecret,
        skipDiscovery: true,
        authorizationEndpoint: issuer.authorizationEndpoint,
        tokenEndpoint: issuer.tokenEndpoint,
        jwksEndpoint: issuer.jwksEndpoint,
        ...oidcConfig,
      },
    });
    const refused = await t.api.post("/sso/register", body("no-pkce", { pkce: false }), {
      cookie: ownerCookie,
    });
    expect(refused.status).toBe(400);
    expect(await refused.json()).toMatchObject({ code: "SSO_PKCE_REQUIRED" });
    for (const [id, config] of [
      ["default-pkce", {}],
      ["explicit-pkce", { pkce: true }],
    ] as const) {
      const ok = await t.api.post("/sso/register", body(id, config), { cookie: ownerCookie });
      expect(ok.status, await ok.clone().text()).toBe(200);
    }

    const update = await t.api.post(
      "/sso/update-provider",
      { providerId: "explicit-pkce", oidcConfig: { pkce: false } },
      { cookie: ownerCookie },
    );
    expect(update.status).toBe(400);
    expect(await update.json()).toMatchObject({ code: "SSO_PKCE_REQUIRED" });
    const fine = await t.api.post(
      "/sso/update-provider",
      { providerId: "explicit-pkce", oidcConfig: { scopes: ["openid", "email"] } },
      { cookie: ownerCookie },
    );
    expect(fine.status, await fine.clone().text()).toBe(200);
  });

  it("without requirePkce, pkce:false registers as before", async () => {
    const { t, orgId, ownerCookie } = await world(undefined);
    const ok = await t.api.post(
      "/sso/register",
      {
        providerId: "no-pkce",
        issuer: issuer.issuerUrl,
        domain: "acme.test",
        organizationId: orgId,
        oidcConfig: {
          clientId: issuer.clientId,
          clientSecret: issuer.clientSecret,
          skipDiscovery: true,
          authorizationEndpoint: issuer.authorizationEndpoint,
          tokenEndpoint: issuer.tokenEndpoint,
          jwksEndpoint: issuer.jwksEndpoint,
          pkce: false,
        },
      },
      { cookie: ownerCookie },
    );
    expect(ok.status).toBe(200);
  });
});

describe("a SCIM-managed organization under existingUsersOnly", () => {
  it("still enforces SCIM, and a SCIM link still gets the ban and conflict checks", async () => {
    const { t, orgId, ownerCookie } = await world(
      { existingUsersOnly: true, organizationProvisioning: "off" },
      {},
      false,
    );
    const bearer = await mintScimToken(t, ownerCookie, orgId, "acme-oidc");
    const scimId = await createScimUser(t, bearer, "scim@acme.test", "sub-scim");
    const scimUserId = await coreUserId(t, scimId);
    issuer.setUser({ sub: "sub-scim", email: "scim@acme.test" });

    // A user SCIM did not provision is refused by the SCIM resolver, as in 1.2.
    issuer.setUser({ sub: "sub-jane", email: "jane@acme.test" });
    const unprovisioned = await drive(t);
    expect(unprovisioned.headers.get("location") ?? "").toContain("error=SCIM_USER_NOT_ACTIVE");

    // The provisioned user signs in (membership comes from SCIM, not from SSO).
    issuer.setUser({ sub: "sub-scim", email: "scim@acme.test" });
    const ok = await drive(t);
    expect(ok.headers.get("location") ?? "", ok.headers.get("location") ?? "").not.toContain(
      "error=",
    );
    expect((await sessionOf(t, sessionCookieOf(ok))).user.id).toBe(scimUserId);

    // A manual ban survives SCIM's own link.
    await t.client.execute({
      sql: `UPDATE user SET banned = ? WHERE id = ?`,
      args: [isPg ? true : 1, scimUserId],
    });
    const before = await counts(t);
    const banned = await drive(t);
    expect(banned.headers.get("location") ?? "").toContain("error=SSO_USER_BANNED");
    expect(extractCookie(banned)).not.toContain("session_token");
    expect(await counts(t)).toEqual(before);
  });
});

describe("the wizard's test login goes through the same resolver", () => {
  it("/enterprise/sso/test-login/start hands the browser to /sign-in/sso, so an unprovisioned identity is refused there and nothing is created", async () => {
    const { t, orgId, ownerCookie } = await world(STRICT_ALL);
    issuer.setUser({ sub: "sub-ghost", email: "ghost@acme.test", hd: "acme.test" });
    const start = await t.api.post(
      "/enterprise/sso/test-login/start",
      { orgId, providerId: "acme-oidc" },
      { cookie: ownerCookie },
    );
    expect(start.status).toBe(200);
    const stateCookie = extractCookie(start);
    const { url } = (await start.json()) as { url: string };
    const authorize = await getNoRedirect(url);
    const before = await counts(t);
    const res = await t.auth.handler(
      new Request(authorize.location!, {
        headers: { cookie: stateCookie, origin: "http://localhost:3000" },
      }),
    );
    expect(res.headers.get("location") ?? "").toContain("error=SSO_USER_NOT_PROVISIONED");
    expect(extractCookie(res)).not.toContain("session_token");
    expect(await counts(t)).toEqual(before);
    const passed = await t.client.execute({
      sql: `SELECT id FROM verification WHERE identifier = ?`,
      args: ["ab-sso-test-ok:acme-oidc"],
    });
    expect(passed.rows).toEqual([]);
  });
});

describe("organizationProvisioning:'off' also stops the social verified-domain join", () => {
  /** Runs upstream's own `after` hook for `/callback/*` the way the router would for a social sign-in that minted `user`'s session. */
  async function runSocialJoinHook(t: TestAuth, user: { id: string; email: string }) {
    const context = await t.auth.$context;
    const plugin = context.options.plugins?.find((p) => p.id === "sso");
    const hook = (
      plugin?.hooks as {
        after: Array<{
          matcher: (c: { path?: string }) => boolean;
          handler: (c: unknown) => Promise<unknown>;
        }>;
      }
    ).after[0]!;
    expect(hook.matcher({ path: "/callback/google" })).toBe(true);
    await hook.handler({
      path: "/callback/google",
      context: { ...context, newSession: { user: { ...user, emailVerified: true } } },
    });
  }

  it("default: a verified-domain social sign-in joins the provider's org; 'off': it does not", async () => {
    for (const [sso, joins] of [
      [undefined, true],
      [{ organizationProvisioning: "off" } as SsoOptions, false],
    ] as const) {
      const { t, orgId } = await world(sso, {}, false);
      const verifiedId = await insertUser(t, "viv@acme.test", { emailVerified: true });
      await runSocialJoinHook(t, { id: verifiedId, email: "viv@acme.test" });
      const members = await t.client.execute({
        sql: `SELECT id FROM member WHERE organizationId = ? AND userId = ?`,
        args: [orgId, verifiedId],
      });
      expect(members.rows.length > 0).toBe(joins);
    }
  });
});

describe("a deployment that opts into nothing keeps its 1.2 behaviour", () => {
  it("JIT creates and verifies the user, links implicitly and joins the org, as before", async () => {
    const t = await makeAuth({ trustedOrigins: [issuer.issuerUrl] });
    const owner = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, owner.cookie, "acme");
    await registerOidcProvider(t, owner.cookie, orgId, issuer, "acme-oidc", "acme.test");
    issuer.setUser({ sub: "sub-new", email: "new@acme.test" });
    const res = await drive(t);
    const session = await sessionOf(t, sessionCookieOf(res));
    expect(session.user.email).toBe("new@acme.test");
    expect(session.user.emailVerified).toBe(true);
    const member = await t.client.execute({
      sql: `SELECT role FROM member WHERE organizationId = ? AND userId = ?`,
      args: [orgId, session.user.id],
    });
    expect(member.rows).toHaveLength(1);
    expect(await refusedAuditCodes(t)).toEqual([]);
  });
});

describe("the user.create.before backstop", () => {
  const ctxFor = (path: string) =>
    ({
      path,
      params: {},
      context: { adapter: { findOne: async () => null }, logger: { error: () => {} } },
    }) as never;

  it("refuses any user created from an SSO callback with existingUsersOnly on, even with the domain binding and the allow-list both off", async () => {
    const hook = buildDomainBindingUserCreateBeforeHook({
      product: "test",
      secretsKey: "s".repeat(32),
      scimCredentialHashSecret: "catalog-test-key-".repeat(3),
      sso: { domainBinding: "off", existingUsersOnly: true },
    });
    for (const path of [
      "/sso/callback/:providerId",
      "/sso/callback/acme-oidc",
      "/sso/callback",
      "/sso/saml2/sp/acs/:providerId",
    ]) {
      await expect(hook({ email: "new@acme.test" }, ctxFor(path))).rejects.toMatchObject({
        body: { code: "SSO_SIGNUP_DISABLED" },
      });
    }
  });

  it("never touches a user created from another path, or outside a request, and does nothing without the option", async () => {
    const base = {
      product: "test",
      secretsKey: "s".repeat(32),
      scimCredentialHashSecret: "catalog-test-key-".repeat(3),
    };
    const on = buildDomainBindingUserCreateBeforeHook({
      ...base,
      sso: { domainBinding: "off", existingUsersOnly: true },
    });
    expect(await on({ email: "x@acme.test" }, ctxFor("/sign-up/email"))).toBeUndefined();
    expect(await on({ email: "x@acme.test" }, ctxFor("/callback/:id"))).toBeUndefined();
    expect(await on({ email: "x@acme.test" }, null)).toBeUndefined();
    const off = buildDomainBindingUserCreateBeforeHook({ ...base, sso: { domainBinding: "off" } });
    expect(await off({ email: "x@acme.test" }, ctxFor("/sso/callback/acme-oidc"))).toBeUndefined();
  });

  it("is registered as a policy refusal code (the end-to-end audit contract is test/security/sso-signup-backstop.test.ts)", async () => {
    const { POLICY_REFUSAL_CODES } = await import("../../src/server/audit/routes");
    expect(POLICY_REFUSAL_CODES.has("SSO_SIGNUP_DISABLED")).toBe(true);
  });
});

describe("concurrent first logins", () => {
  // Upstream locks the provider row (`lockSSOProviderForAccountLink`, an UPDATE
  // of the row inside the sign-in transaction), which serializes two first
  // logins of the same subject on Postgres: the second finds the first's
  // account. SQLite's single writer makes the question moot there.
  it.runIf(isPg)(
    "two parallel first logins for one subject yield exactly one account row",
    async () => {
      const { t, janeId } = await world(STRICT_ALL);
      const [a, b] = await Promise.all([drive(t), drive(t)]);
      for (const res of [a, b]) {
        expect(res.status).toBe(302);
        expect(res.headers.get("location") ?? "").not.toContain("error=");
      }
      const accounts = await t.client.execute({
        sql: `SELECT id FROM account WHERE "providerId" = ? AND "accountId" = ?`,
        args: ["acme-oidc", "sub-jane"],
      });
      expect(accounts.rows).toHaveLength(1);
      const owner = await t.client.execute({
        sql: `SELECT "userId" FROM account WHERE "providerId" = ? AND "accountId" = ?`,
        args: ["acme-oidc", "sub-jane"],
      });
      expect(owner.rows[0]).toMatchObject({ userId: janeId });
    },
  );
});
