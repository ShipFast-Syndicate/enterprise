import { describe, expect, it } from "vitest";
import { makeAuth, signUpOwner, createOrg, type TestAuth } from "../helpers/auth";
import type { Feature } from "../../src/server/types";

// `jwksEndpoint` is required alongside `authorizationEndpoint`/`tokenEndpoint`
// for `skipDiscovery` to actually avoid a runtime OIDC discovery fetch on
// `/sign-in/sso` later (`needsRuntimeDiscovery` in
// `node_modules/@better-auth/sso/dist/index.mjs` triggers discovery whenever
// *any* of the three is missing — `skipDiscovery` itself only affects
// `/sso/register`'s own registration-time discovery, not sign-in).
const oidcConfig = {
  clientId: "client-id",
  clientSecret: "supersecret-client-secret",
  skipDiscovery: true,
  authorizationEndpoint: "https://idp.test/authorize",
  tokenEndpoint: "https://idp.test/token",
  jwksEndpoint: "https://idp.test/jwks",
};

async function insertMemberRow(t: TestAuth, orgId: string, userId: string, role: string) {
  await t.client.execute({
    sql: `INSERT INTO member (id, organizationId, userId, role, createdAt) VALUES (?, ?, ?, ?, ?)`,
    args: [`member_${userId}`, orgId, userId, role, Date.now()],
  });
}

async function registerProvider(
  t: TestAuth,
  cookie: string,
  orgId: string,
  providerId = "okta",
  domain = "acme.test",
) {
  const res = await t.api.post(
    "/enterprise/sso/register",
    {
      organizationId: orgId,
      providerId,
      issuer: "https://idp.test",
      domain,
      oidcConfig,
    },
    { cookie },
  );
  if (!res.ok) throw new Error(`register failed: ${res.status} ${await res.text()}`);
  return (await res.json()) as Record<string, unknown>;
}

// Upstream `/sign-in/sso` refuses an unverified domain ("Provider domain has
// not been verified") — real DNS verification is out of scope for these
// tests, so this flips the flag directly, the same way `policy.test.ts`'s
// `insertVerifiedProvider` bypasses it.
async function verifyProviderDomain(t: TestAuth, providerId = "okta") {
  await t.client.execute({
    sql: `UPDATE "ssoProvider" SET domainVerified = 1 WHERE providerId = ?`,
    args: [providerId],
  });
}

function redirectReason(res: Response): string | null {
  const location = res.headers.get("location");
  if (!location) return null;
  return new URL(location, "http://localhost").searchParams.get("reason");
}

describe("GET /enterprise/features", () => {
  it("reflects resolveEntitlements for the org", async () => {
    const t = await makeAuth({ resolveEntitlements: async () => ["sso", "audit_log"] });
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);

    const res = await t.api.get(`/enterprise/features?orgId=${orgId}`, { cookie });

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ features: ["sso", "audit_log"] });
  });
});

describe("GET /enterprise/sso/providers", () => {
  it("carries the DNS verification record name/value, redirect URLs, and enforcement state", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, cookie);
    const registered = await registerProvider(t, cookie, orgId);

    const res = await t.api.get(`/enterprise/sso/providers?orgId=${orgId}`, { cookie });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { providers: Array<Record<string, unknown>> };
    expect(body.providers).toHaveLength(1);
    const provider = body.providers[0]!;

    expect(provider.providerId).toBe("okta");
    expect(provider.type).toBe("oidc");
    expect(provider.domain).toBe("acme.test");
    expect(provider.domainVerified).toBe(false);
    expect(provider.verificationRecord).toEqual({
      name: "_better-auth-token-okta.acme.test",
      value: registered.domainVerificationToken,
    });
    expect(provider.spMetadataUrl).toContain("/sso/saml2/sp/metadata?providerId=okta");
    expect(provider.acsUrl).toContain("/sso/saml2/sp/acs/okta");
    expect(provider.redirectUri).toContain("/sso/callback/okta");
    expect(provider.testLoginPassedAt).toBeNull();
    expect(provider.enforced).toBe(false);
  });

  it("value is null when no domain verification is pending", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, cookie);
    // Raw insert (not through /sso/register) never creates the `verification` row.
    await t.client.execute({
      sql: `INSERT INTO "ssoProvider" (id, issuer, domain, domainVerified, organizationId, providerId, userId) VALUES (?, ?, ?, 0, ?, ?, ?)`,
      args: ["ssop_bare", "https://idp.test", "acme.test", orgId, "bare", "someone"],
    });

    const res = await t.api.get(`/enterprise/sso/providers?orgId=${orgId}`, { cookie });
    const body = (await res.json()) as { providers: Array<Record<string, unknown>> };
    expect((body.providers[0]!.verificationRecord as { value: unknown }).value).toBeNull();
  });
});

describe("POST /enterprise/sso/register", () => {
  it("forwards to upstream and never returns clientSecret", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, cookie);

    const body = await registerProvider(t, cookie, orgId);

    expect(body.providerId).toBe("okta");
    const returnedOidc = body.oidcConfig as Record<string, unknown>;
    expect("clientSecret" in returnedOidc).toBe(false);
    expect(returnedOidc.clientId).toBe("client-id");

    const rows = await t.client.execute(`SELECT * FROM "ssoProvider"`);
    expect(rows.rows.length).toBe(1);

    // Exactly one audit row — proves forwarding through `/sso/register`
    // doesn't also get audited a second time under this wrapper's own path
    // (`../../src/server/audit/plugin.ts`'s header comment on why
    // `/enterprise/sso/register` has no `AUDITED_PATHS` entry of its own).
    const auditRows = await t.client.execute(
      `SELECT * FROM audit_event WHERE action='sso.provider_registered'`,
    );
    expect(auditRows.rows.length).toBe(1);
  });

  it("requires owner/admin — a plain member is refused", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, cookie);
    const { cookie: memberCookie, userId: memberId } = await signUpOwner(t, "member@acme.test");
    await insertMemberRow(t, orgId, memberId, "member");

    const res = await t.api.post(
      "/enterprise/sso/register",
      {
        organizationId: orgId,
        providerId: "okta",
        issuer: "https://idp.test",
        domain: "acme.test",
        oidcConfig,
      },
      { cookie: memberCookie },
    );

    expect(res.status).toBe(403);
    expect((await res.json()).code).toBe("NOT_ORG_ADMIN");
  });

  it("passes upstream 4xx errors through", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, cookie);
    await registerProvider(t, cookie, orgId, "okta");

    // Re-registering the same providerId is rejected by upstream (422).
    const res = await t.api.post(
      "/enterprise/sso/register",
      {
        organizationId: orgId,
        providerId: "okta",
        issuer: "https://idp.test",
        domain: "acme.test",
        oidcConfig,
      },
      { cookie },
    );

    expect(res.status).toBe(422);
  });
});

describe("SSO test login (start + finish)", () => {
  async function startTestLogin(t: TestAuth, cookie: string, orgId: string, providerId = "okta") {
    return t.api.post("/enterprise/sso/test-login/start", { orgId, providerId }, { cookie });
  }

  it("start returns a URL on the provider's own authorization endpoint", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, cookie);
    await registerProvider(t, cookie, orgId);
    await verifyProviderDomain(t);

    const res = await startTestLogin(t, cookie, orgId);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { url: string };
    expect(body.url.startsWith("https://idp.test/authorize")).toBe(true);
  });

  it("requires owner/admin", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, cookie);
    await registerProvider(t, cookie, orgId);
    const { cookie: memberCookie, userId: memberId } = await signUpOwner(t, "member@acme.test");
    await insertMemberRow(t, orgId, memberId, "member");

    const res = await startTestLogin(t, memberCookie, orgId);
    expect(res.status).toBe(403);
    expect((await res.json()).code).toBe("NOT_ORG_ADMIN");
  });

  it("404s for a providerId that doesn't belong to the org", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, cookie);

    const res = await startTestLogin(t, cookie, orgId, "does-not-exist");
    expect(res.status).toBe(404);
    expect((await res.json()).code).toBe("SSO_PROVIDER_NOT_FOUND");
  });

  it("finish: success sets testLoginPassedAt and redirects to ?ab_sso_test=ok", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, cookie);
    await registerProvider(t, cookie, orgId);
    await verifyProviderDomain(t);
    await startTestLogin(t, cookie, orgId);

    const res = await t.api.get("/enterprise/sso/test-login/finish?providerId=okta", { cookie });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/?ab_sso_test=ok");

    const providersRes = await t.api.get(`/enterprise/sso/providers?orgId=${orgId}`, { cookie });
    const providers = (await providersRes.json()) as { providers: Array<Record<string, unknown>> };
    expect(providers.providers[0]!.testLoginPassedAt).not.toBeNull();

    // The audit trail records the passed test login.
    const rows = await t.client.execute(
      `SELECT * FROM audit_event WHERE action='sso.test_login_passed'`,
    );
    expect(rows.rows.length).toBe(1);
  });

  it("finish: the pending row is consumed — a replay with the same session fails with no_pending, and only one audit row ever exists", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, cookie);
    await registerProvider(t, cookie, orgId);
    await verifyProviderDomain(t);
    await startTestLogin(t, cookie, orgId);

    const first = await t.api.get("/enterprise/sso/test-login/finish?providerId=okta", {
      cookie,
    });
    expect(first.status).toBe(302);
    expect(first.headers.get("location")).toBe("/?ab_sso_test=ok");

    const replay = await t.api.get("/enterprise/sso/test-login/finish?providerId=okta", {
      cookie,
    });
    expect(replay.status).toBe(302);
    expect(redirectReason(replay)).toBe("no_pending");

    const rows = await t.client.execute(
      `SELECT * FROM audit_event WHERE action='sso.test_login_passed'`,
    );
    expect(rows.rows.length).toBe(1);
  });

  it("finish: no session -> redirects with reason=no_session", async () => {
    const t = await makeAuth();
    const res = await t.api.get("/enterprise/sso/test-login/finish?providerId=okta");
    expect(res.status).toBe(302);
    expect(redirectReason(res)).toBe("no_session");
  });

  it("finish: no pending test login -> redirects with reason=no_pending", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, cookie);
    await registerProvider(t, cookie, orgId);
    // Never called .../test-login/start.

    const res = await t.api.get("/enterprise/sso/test-login/finish?providerId=okta", { cookie });
    expect(res.status).toBe(302);
    expect(redirectReason(res)).toBe("no_pending");
  });

  // C-1 — the single line the rest of this block was missing: every other
  // `finish:` case here reuses the pre-SSO cookie from `createOrg()`, which
  // carries an `activeOrganizationId`. A real browser arrives here on the
  // session the SSO callback just minted, and nothing ever sets that field on
  // a fresh session, so the entitlement gate's org-id resolution had no
  // source and answered `400 ORG_REQUIRED` — permanently blocking the
  // mandatory test login for every org. The org now comes from the provider
  // row. (`test/e2e/oidc.test.ts` drives the same thing through the real
  // issuer; this is the narrow, fast reproduction.)
  it("finish: succeeds on a session with no activeOrganizationId (the state SSO leaves behind)", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, cookie);
    await registerProvider(t, cookie, orgId);
    await verifyProviderDomain(t);
    await startTestLogin(t, cookie, orgId);

    await t.client.execute(`UPDATE session SET activeOrganizationId = NULL`);

    const res = await t.api.get("/enterprise/sso/test-login/finish?providerId=okta", { cookie });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/?ab_sso_test=ok");

    const flag = await t.client.execute({
      sql: `SELECT identifier FROM verification WHERE identifier = ?`,
      args: ["ab-sso-test-ok:okta"],
    });
    expect(flag.rows.length).toBe(1);
  });

  // The deferred minor recorded against Task 7, closed by the same change:
  // an entitlement lost mid-flow used to surface as a bare 403 JSON error
  // page the wizard cannot read. It redirects like every other failure now.
  it("finish: entitlement revoked mid-flow -> redirects with reason=not_entitled, not a JSON 403", async () => {
    let entitled = new Set<Feature>(["sso", "scim", "audit_log", "enforce_2fa"]);
    const t = await makeAuth({ resolveEntitlements: async () => entitled });
    const { cookie } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, cookie);
    await registerProvider(t, cookie, orgId);
    await verifyProviderDomain(t);
    await startTestLogin(t, cookie, orgId);

    entitled = new Set<Feature>();

    const res = await t.api.get("/enterprise/sso/test-login/finish?providerId=okta", { cookie });
    expect(res.status).toBe(302);
    expect(redirectReason(res)).toBe("not_entitled");

    const flag = await t.client.execute({
      sql: `SELECT identifier FROM verification WHERE identifier = ?`,
      args: ["ab-sso-test-ok:okta"],
    });
    expect(flag.rows.length).toBe(0);
  });

  it("finish: mismatched email domain -> redirects with reason=domain_mismatch", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t, "owner@other-domain.test");
    const { orgId } = await createOrg(t, cookie);
    await registerProvider(t, cookie, orgId, "okta", "acme.test"); // provider domain != owner's email domain
    await startTestLogin(t, cookie, orgId);

    const res = await t.api.get("/enterprise/sso/test-login/finish?providerId=okta", { cookie });
    expect(res.status).toBe(302);
    expect(redirectReason(res)).toBe("domain_mismatch");
  });
});

describe("POST /enterprise/policy/set — mandatory test login before ssoEnforced", () => {
  async function passTestLogin(t: TestAuth, cookie: string, orgId: string, providerId = "okta") {
    await t.api.post("/enterprise/sso/test-login/start", { orgId, providerId }, { cookie });
    const res = await t.api.get(`/enterprise/sso/test-login/finish?providerId=${providerId}`, {
      cookie,
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/?ab_sso_test=ok");
  }

  it("400 SSO_TEST_LOGIN_REQUIRED when a verified provider + owner break-glass exist but no test login was passed", async () => {
    const t = await makeAuth();
    const { cookie, userId: ownerId } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, cookie);
    await t.client.execute({
      sql: `INSERT INTO "ssoProvider" (id, issuer, domain, domainVerified, organizationId, providerId, userId) VALUES (?, ?, ?, 1, ?, ?, ?)`,
      args: ["ssop_okta", "https://idp.test", "acme.test", orgId, "okta", ownerId],
    });

    const res = await t.api.post(
      "/enterprise/policy/set",
      { orgId, ssoEnforced: true, breakGlassUserId: ownerId },
      { cookie },
    );

    expect(res.status).toBe(400);
    expect((await res.json()).code).toBe("SSO_TEST_LOGIN_REQUIRED");
  });

  it("succeeds once the test login has been passed", async () => {
    const t = await makeAuth();
    const { cookie, userId: ownerId } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, cookie);
    await registerProvider(t, cookie, orgId);
    await t.client.execute({
      sql: `UPDATE "ssoProvider" SET domainVerified = 1 WHERE providerId = 'okta'`,
    });
    await passTestLogin(t, cookie, orgId);

    const res = await t.api.post(
      "/enterprise/policy/set",
      { orgId, ssoEnforced: true, breakGlassUserId: ownerId },
      { cookie },
    );

    expect(res.status).toBe(200);
    expect((await res.json()).ssoEnforced).toBe(true);
  });
});

describe("SCIM token endpoints", () => {
  it("create returns the token once; list shows the providerId with null createdAt/lastUsedAt; revoke removes it", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, cookie);

    const createRes = await t.api.post(
      "/enterprise/scim/tokens/create",
      { orgId, providerId: "hris" },
      { cookie },
    );
    expect(createRes.status).toBe(200);
    const created = (await createRes.json()) as { scimToken: string; baseUrl: string };
    expect(typeof created.scimToken).toBe("string");
    expect(created.scimToken.length).toBeGreaterThan(0);
    expect(created.baseUrl.endsWith("/scim/v2")).toBe(true);

    const listRes = await t.api.get(`/enterprise/scim/tokens?orgId=${orgId}`, { cookie });
    expect(listRes.status).toBe(200);
    const list = (await listRes.json()) as {
      tokens: Array<{ providerId: string; createdAt: string | null; lastUsedAt: string | null }>;
    };
    expect(list.tokens).toEqual([{ providerId: "hris", createdAt: null, lastUsedAt: null }]);

    const revokeRes = await t.api.post(
      "/enterprise/scim/tokens/revoke",
      { orgId, providerId: "hris" },
      { cookie },
    );
    expect(revokeRes.status).toBe(200);
    expect(await revokeRes.json()).toEqual({ ok: true });

    const listAfter = await t.api.get(`/enterprise/scim/tokens?orgId=${orgId}`, { cookie });
    expect((await listAfter.json()).tokens).toEqual([]);

    // Exactly one audit row per action — same double-audit-avoidance proof
    // as the SSO register test above, for the SCIM token wrappers.
    const created2 = await t.client.execute(
      `SELECT * FROM audit_event WHERE action='scim.token_created'`,
    );
    expect(created2.rows.length).toBe(1);
    const revoked = await t.client.execute(
      `SELECT * FROM audit_event WHERE action='scim.token_revoked'`,
    );
    expect(revoked.rows.length).toBe(1);
  });

  // M-01 (security audit 2026-09-15): minting a SCIM token is owner-only —
  // it is the second half of the admin→owner escalation. Admins keep
  // list/revoke.
  it("create requires owner (403 NOT_ORG_OWNER for an admin)", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, cookie);
    const { cookie: adminCookie, userId: adminId } = await signUpOwner(t, "admin@acme.test");
    await insertMemberRow(t, orgId, adminId, "admin");

    const res = await t.api.post(
      "/enterprise/scim/tokens/create",
      { orgId, providerId: "hris" },
      { cookie: adminCookie },
    );
    expect(res.status).toBe(403);
    expect((await res.json()).code).toBe("NOT_ORG_OWNER");
  });
});

describe("GET /enterprise/members", () => {
  it("lists members with team names and pending invitations", async () => {
    const t = await makeAuth();
    const { cookie, userId: ownerId } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, cookie);
    const { userId: memberId } = await signUpOwner(t, "member@acme.test");
    await insertMemberRow(t, orgId, memberId, "member");

    const teamRes = await t.api.post(
      "/organization/create-team",
      { name: "Platform", organizationId: orgId },
      { cookie },
    );
    expect(teamRes.status).toBe(200);
    const team = (await teamRes.json()) as { id: string };
    const addRes = await t.api.post(
      "/organization/add-team-member",
      { teamId: team.id, userId: memberId, organizationId: orgId },
      { cookie },
    );
    expect(addRes.status).toBe(200);

    const inviteRes = await t.api.post(
      "/organization/invite-member",
      { email: "pending@acme.test", role: "member", organizationId: orgId },
      { cookie },
    );
    expect(inviteRes.status).toBe(200);

    const res = await t.api.get(`/enterprise/members?orgId=${orgId}`, { cookie });
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      members: Array<{ userId: string; email: string; role: string; teams: string[] }>;
      invitations: Array<{ email: string; status: string }>;
    };

    const owner = body.members.find((m) => m.userId === ownerId)!;
    expect(owner.email).toBe("owner@acme.test");
    expect(owner.role).toBe("owner");
    // better-auth's `organization` plugin (teams enabled) auto-creates a
    // default team named after the org on `/organization/create` and adds
    // the creator to it — confirmed empirically, not documented behavior
    // this test relies on beyond "some team named after the org exists".
    expect(owner.teams).toEqual(["acme"]);

    const member = body.members.find((m) => m.userId === memberId)!;
    expect(member.email).toBe("member@acme.test");
    expect(member.teams).toEqual(["Platform"]);

    expect(body.invitations).toHaveLength(1);
    expect(body.invitations[0]!.email).toBe("pending@acme.test");
    expect(body.invitations[0]!.status).toBe("pending");
  });
});

// --- ruling (h): every endpoint 403s for a non-member; every gated ---------
// endpoint 403 FEATURE_NOT_ENTITLED when the org lacks the feature. -------
//
// `/enterprise/sso/test-login/finish` is deliberately excluded: it has no
// `orgId` of its own and is driven by session + a pending row + email-domain
// matching rather than org membership (see `../src/server/enterprise-api/
// sso.ts`'s header comment on that endpoint) — its own dedicated describe
// block above covers its failure modes (`no_session`/`no_pending`/
// `domain_mismatch`).
interface EndpointCase {
  name: string;
  gated: "sso" | "scim" | false;
  invoke: (t: TestAuth, cookie: string, orgId: string) => Promise<Response>;
}

const ENDPOINT_CASES: EndpointCase[] = [
  {
    name: "GET /enterprise/features",
    gated: false,
    invoke: (t, cookie, orgId) => t.api.get(`/enterprise/features?orgId=${orgId}`, { cookie }),
  },
  {
    name: "GET /enterprise/members",
    gated: false,
    invoke: (t, cookie, orgId) => t.api.get(`/enterprise/members?orgId=${orgId}`, { cookie }),
  },
  {
    name: "GET /enterprise/sso/providers",
    gated: "sso",
    invoke: (t, cookie, orgId) => t.api.get(`/enterprise/sso/providers?orgId=${orgId}`, { cookie }),
  },
  {
    name: "POST /enterprise/sso/register",
    gated: "sso",
    invoke: (t, cookie, orgId) =>
      t.api.post(
        "/enterprise/sso/register",
        {
          organizationId: orgId,
          providerId: "case-p",
          issuer: "https://idp.test",
          domain: "acme.test",
          oidcConfig,
        },
        { cookie },
      ),
  },
  {
    name: "POST /enterprise/sso/test-login/start",
    gated: "sso",
    invoke: (t, cookie, orgId) =>
      t.api.post(
        "/enterprise/sso/test-login/start",
        { orgId, providerId: "does-not-matter" },
        { cookie },
      ),
  },
  {
    name: "GET /enterprise/scim/tokens",
    gated: "scim",
    invoke: (t, cookie, orgId) => t.api.get(`/enterprise/scim/tokens?orgId=${orgId}`, { cookie }),
  },
  {
    name: "POST /enterprise/scim/tokens/create",
    gated: "scim",
    invoke: (t, cookie, orgId) =>
      t.api.post("/enterprise/scim/tokens/create", { orgId, providerId: "case-scim" }, { cookie }),
  },
  {
    name: "POST /enterprise/scim/tokens/revoke",
    gated: "scim",
    invoke: (t, cookie, orgId) =>
      t.api.post("/enterprise/scim/tokens/revoke", { orgId, providerId: "case-scim" }, { cookie }),
  },
];

describe("every enterpriseApi endpoint — 403 for a non-member", () => {
  it.each(ENDPOINT_CASES)("$name", async ({ invoke }) => {
    const t = await makeAuth(); // default: every feature entitled, so the gate never preempts this
    const { cookie: ownerCookie } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, ownerCookie);
    const { cookie: outsiderCookie } = await signUpOwner(t, "outsider@other.test");

    const res = await invoke(t, outsiderCookie, orgId);

    expect(res.status).toBe(403);
    expect((await res.json()).code).toBe("NOT_ORG_MEMBER");
  });
});

describe("every gated enterpriseApi endpoint — 403 FEATURE_NOT_ENTITLED", () => {
  const gatedCases = ENDPOINT_CASES.filter((c) => c.gated !== false);
  it.each(gatedCases)("$name", async ({ invoke, gated }) => {
    const t = await makeAuth({ resolveEntitlements: async () => [] });
    const { cookie } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, cookie);

    const res = await invoke(t, cookie, orgId);

    expect(res.status).toBe(403);
    expect((await res.json()).code).toBe("FEATURE_NOT_ENTITLED");
    expect(gated).not.toBe(false); // sanity: only gated cases reach this block
  });
});
