import { describe, expect, it } from "vitest";
import { magicLink } from "better-auth/plugins";
import { orgPolicy } from "../../src/server/policy/plugin";
import {
  deriveSessionCreateMethod,
  buildSessionCreateBeforeHook,
} from "../../src/server/policy/enforcement";
import { ALLOWED_METHOD_VALUES } from "../../src/server/policy/store";
import { makeAuth, signUpOwner, createOrg, type TestAuth } from "../helpers/auth";

async function insertVerifiedProvider(
  t: TestAuth,
  orgId: string,
  domain: string,
  providerId = "okta",
) {
  // `userId` (the registering user) is NOT NULL on `ssoProvider`
  // (`node_modules/@better-auth/sso/dist/index.mjs`'s schema) even for an
  // org-scoped provider — real `/sso/register` calls always set it to the
  // caller's id; a placeholder is fine here since this raw insert bypasses
  // that endpoint entirely and nothing in these tests reads it back.
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

async function insertMemberRow(t: TestAuth, orgId: string, userId: string, role: string) {
  await t.client.execute({
    sql: `INSERT INTO member (id, organizationId, userId, role, createdAt) VALUES (?, ?, ?, ?, ?)`,
    args: [`member_${userId}`, orgId, userId, role, Date.now()],
  });
}

// Task 7 (`../../src/server/enterprise-api/plugin.ts`, ruling (g)) added a
// further precondition to `ssoEnforced:true`: a passed admin test login for
// a verified provider (`ab-sso-test-ok:<providerId>` in `verification`,
// normally written by `POST /enterprise/sso/test-login/finish`). Every test
// below that successfully flips `ssoEnforced` on now seeds that row directly
// rather than driving the full test-login round trip, the same way
// `insertVerifiedProvider` above bypasses `/sso/register` — this file is
// about policy enforcement, not the SSO wizard (covered by
// `test/server/enterprise-api.test.ts`).
async function insertTestLoginPassed(t: TestAuth, providerId = "okta") {
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

describe("GET /enterprise/policy", () => {
  it("returns defaults when no row exists", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);

    const res = await t.api.get(`/enterprise/policy?orgId=${orgId}`, { cookie });

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      orgId,
      require2fa: false,
      ssoEnforced: false,
      breakGlassUserId: null,
      sessionMaxAgeS: null,
      allowedMethods: [...ALLOWED_METHOD_VALUES],
      groupRoleMap: {},
    });
  });

  it("403 NOT_ORG_MEMBER for a caller who isn't a member of the org", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, cookie);
    const { cookie: outsiderCookie } = await signUpOwner(t, "outsider@other.test");

    const res = await t.api.get(`/enterprise/policy?orgId=${orgId}`, { cookie: outsiderCookie });

    expect(res.status).toBe(403);
    expect((await res.json()).code).toBe("NOT_ORG_MEMBER");
  });

  // M-08 (security audit 2026-09-15): a plain member used to be able to read
  // the whole security policy — `breakGlassUserId`, `groupRoleMap`,
  // `allowedMethods`. It is owner/admin-only now; `require2fa` still reaches
  // ordinary members through `/get-session`.
  it("a plain member (not owner/admin) is refused (403 NOT_ORG_ADMIN)", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, cookie);
    const { cookie: memberCookie, userId: memberId } = await signUpOwner(t, "member@acme.test");
    await insertMemberRow(t, orgId, memberId, "member");

    const res = await t.api.get(`/enterprise/policy?orgId=${orgId}`, { cookie: memberCookie });

    expect(res.status).toBe(403);
    expect(((await res.json()) as { code: string }).code).toBe("NOT_ORG_ADMIN");
  });
});

describe("POST /enterprise/policy/set", () => {
  it("requires the enforce_2fa feature (403 without it)", async () => {
    const t = await makeAuth({ resolveEntitlements: async () => [] });
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);

    const res = await t.api.post("/enterprise/policy/set", { orgId, require2fa: true }, { cookie });

    expect(res.status).toBe(403);
    expect((await res.json()).code).toBe("FEATURE_NOT_ENTITLED");
  });

  it("requires owner/admin (403 NOT_ORG_ADMIN for a plain member)", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, cookie);
    const { cookie: memberCookie, userId: memberId } = await signUpOwner(t, "member@acme.test");
    await insertMemberRow(t, orgId, memberId, "member");

    const res = await t.api.post(
      "/enterprise/policy/set",
      { orgId, require2fa: true },
      { cookie: memberCookie },
    );

    expect(res.status).toBe(403);
    expect((await res.json()).code).toBe("NOT_ORG_ADMIN");
  });

  it("persists require2fa:true, readable back from GET, and audits policy.updated targeting org_policy/orgId", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);

    const setRes = await t.api.post(
      "/enterprise/policy/set",
      { orgId, require2fa: true },
      { cookie },
    );
    expect(setRes.status).toBe(200);
    expect((await setRes.json()).require2fa).toBe(true);

    const getRes = await t.api.get(`/enterprise/policy?orgId=${orgId}`, { cookie });
    expect((await getRes.json()).require2fa).toBe(true);

    const auditRows = await t.client.execute({
      sql: `SELECT * FROM audit_event WHERE org_id = ? AND action = 'policy.updated'`,
      args: [orgId],
    });
    expect(auditRows.rows.length).toBe(1);
    expect(auditRows.rows[0]!.target_type).toBe("org_policy");
    expect(auditRows.rows[0]!.target_id).toBe(orgId);
  });

  it("a second call only patches the fields it sends, leaving the rest as previously set", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);

    await t.api.post("/enterprise/policy/set", { orgId, require2fa: true }, { cookie });
    const res = await t.api.post(
      "/enterprise/policy/set",
      { orgId, allowedMethods: ["password", "sso"] },
      { cookie },
    );

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.require2fa).toBe(true); // untouched by the second call
    expect(body.allowedMethods).toEqual(["password", "sso"]);
  });

  it("400s on an allowedMethods value outside the closed ALLOWED_METHOD_VALUES set", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);

    const res = await t.api.post(
      "/enterprise/policy/set",
      { orgId, allowedMethods: ["password", "carrier_pigeon"] },
      { cookie },
    );

    expect(res.status).toBe(400);
  });

  it("ssoEnforced:true with no verified provider and no break-glass owner -> 400 SSO_ENFORCE_PRECONDITION", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);

    const res = await t.api.post(
      "/enterprise/policy/set",
      { orgId, ssoEnforced: true },
      { cookie },
    );

    expect(res.status).toBe(400);
    expect((await res.json()).code).toBe("SSO_ENFORCE_PRECONDITION");
  });

  it("ssoEnforced:true with a verified provider but a breakGlassUserId who isn't an owner -> 400", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, cookie);
    await insertVerifiedProvider(t, orgId, "acme.test");
    const { userId: memberId } = await signUpOwner(t, "member@acme.test");
    await insertMemberRow(t, orgId, memberId, "member");

    const res = await t.api.post(
      "/enterprise/policy/set",
      { orgId, ssoEnforced: true, breakGlassUserId: memberId },
      { cookie },
    );

    expect(res.status).toBe(400);
    expect((await res.json()).code).toBe("SSO_ENFORCE_PRECONDITION");
  });

  it("ssoEnforced:true with a verified provider and an owner breakGlassUserId succeeds", async () => {
    const t = await makeAuth();
    const { cookie, userId: ownerId } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, cookie);
    await insertVerifiedProvider(t, orgId, "acme.test");
    await insertTestLoginPassed(t);

    const res = await t.api.post(
      "/enterprise/policy/set",
      { orgId, ssoEnforced: true, breakGlassUserId: ownerId },
      { cookie },
    );

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.ssoEnforced).toBe(true);
    expect(body.breakGlassUserId).toBe(ownerId);
  });
});

describe("home-realm rate limit wiring on the orgPolicy plugin", () => {
  it("registers window:60 max:10 scoped to /enterprise/home-realm", () => {
    const plugin = orgPolicy({
      product: "test",
      secretsKey: "s".repeat(32),
      resolveEntitlements: async () => new Set(),
    });
    const entry = plugin.rateLimit?.[0];
    expect(entry).toBeDefined();
    expect(entry?.window).toBe(60);
    expect(entry?.max).toBe(10);
    expect(entry?.pathMatcher("/enterprise/home-realm")).toBe(true);
    expect(entry?.pathMatcher("/enterprise/policy")).toBe(false);
  });
});

describe("require2fa on GET /get-session", () => {
  it("adds enterprise.require2fa + twoFactorEnabled once the org's policy requires it", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, cookie); // sets this as the active org

    const before = await t.api.get("/get-session", { cookie });
    expect((await before.json()).enterprise).toBeUndefined();

    const setRes = await t.api.post(
      "/enterprise/policy/set",
      { orgId, require2fa: true },
      { cookie },
    );
    expect(setRes.status).toBe(200);

    const after = await t.api.get("/get-session", { cookie });
    expect(after.status).toBe(200);
    const body = await after.json();
    expect(body.enterprise).toEqual({ require2fa: true, twoFactorEnabled: false });
  });
});

describe("sign-in enforcement + session-creation backstop", () => {
  // Signs up any `preExistingEmails` *before* flipping `ssoEnforced` on:
  // sign-up itself creates a session, which the `databaseHooks.session.
  // create.before` backstop would otherwise immediately block once the
  // policy is enforced (correct behavior — it's what proves the backstop
  // covers more than just the sign-in paths — but it means a test user who
  // is supposed to exist in an SSO-enforced org has to be created first).
  async function setUpSsoEnforcedOrg(t: TestAuth, preExistingEmails: string[] = []) {
    const { cookie, userId: ownerId } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, cookie);
    for (const email of preExistingEmails) {
      await signUpOwner(t, email);
    }
    await insertVerifiedProvider(t, orgId, "acme.test");
    await insertTestLoginPassed(t);
    const setRes = await t.api.post(
      "/enterprise/policy/set",
      { orgId, ssoEnforced: true, breakGlassUserId: ownerId },
      { cookie },
    );
    expect(setRes.status).toBe(200);
    return { cookie, ownerId, orgId };
  }

  it("magic-link sign-in for a non-break-glass user in the SSO-enforced org -> 403 SSO_REQUIRED", async () => {
    const sent: Array<{ email: string; token: string }> = [];
    const t = await makeAuth({
      plugins: [
        magicLink({
          async sendMagicLink({ email, token }) {
            sent.push({ email, token });
          },
        }),
      ],
    });
    await setUpSsoEnforcedOrg(t, ["bob@acme.test"]);

    const res = await t.api.post("/sign-in/magic-link", { email: "bob@acme.test" }, {});

    expect(res.status).toBe(403);
    expect((await res.json()).code).toBe("SSO_REQUIRED");
    expect(sent).toHaveLength(0); // blocked before the link was ever sent
  });

  it("magic-link sign-in for the break-glass owner succeeds end to end (request + verify)", async () => {
    const sent: Array<{ email: string; token: string }> = [];
    const t = await makeAuth({
      plugins: [
        magicLink({
          async sendMagicLink({ email, token }) {
            sent.push({ email, token });
          },
        }),
      ],
    });
    await setUpSsoEnforcedOrg(t);

    const requestRes = await t.api.post("/sign-in/magic-link", { email: "owner@acme.test" }, {});
    expect(requestRes.status).toBe(200);
    expect(sent).toHaveLength(1);

    const verifyRes = await t.api.get(`/magic-link/verify?token=${sent[0]!.token}`);
    expect(verifyRes.status).toBe(200);
  });

  it("magic-link with storeToken:'hashed' still resolves the pending email pre-flight and 403s SSO_REQUIRED on verify for a non-break-glass user", async () => {
    const sent: Array<{ email: string; token: string }> = [];
    const t = await makeAuth({
      plugins: [
        magicLink({
          storeToken: "hashed",
          async sendMagicLink({ email, token }) {
            sent.push({ email, token });
          },
        }),
      ],
    });
    // bob's link is requested *before* ssoEnforced flips on, so the request
    // stage itself isn't what's under test — /magic-link/verify is.
    const { cookie, userId: ownerId } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, cookie);
    await signUpOwner(t, "bob@acme.test");
    const requestRes = await t.api.post("/sign-in/magic-link", { email: "bob@acme.test" }, {});
    expect(requestRes.status).toBe(200);
    expect(sent).toHaveLength(1);

    await insertVerifiedProvider(t, orgId, "acme.test");
    await insertTestLoginPassed(t);
    await t.api.post(
      "/enterprise/policy/set",
      { orgId, ssoEnforced: true, breakGlassUserId: ownerId },
      { cookie },
    );

    const verifyRes = await t.api.get(`/magic-link/verify?token=${sent[0]!.token}`);
    expect(verifyRes.status).toBe(403);
    expect((await verifyRes.json()).code).toBe("SSO_REQUIRED");

    // Proves the *pre-flight* hook (not just the session-creation backstop)
    // is what caught this: if it failed to resolve bob's email from the
    // hashed verification identifier (the bug this test guards against),
    // the real `magicLinkVerify` handler would have run far enough to
    // consume (delete) the verification row before the backstop rejected
    // the resulting session — so the row still existing here proves the
    // request was rejected before the real endpoint ever ran. Filtered to
    // the magic-link identifier specifically: `insertTestLoginPassed` above
    // leaves its own, unrelated `ab-sso-test-ok:*` row in the table too.
    const rows = await t.client.execute({
      sql: `SELECT * FROM verification WHERE identifier NOT LIKE 'ab-sso-test-ok:%'`,
      args: [],
    });
    expect(rows.rows.length).toBe(1);
  });

  it("allowedMethods excluding password blocks /sign-in/email with 403 METHOD_NOT_ALLOWED", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, cookie);
    await insertVerifiedProvider(t, orgId, "acme.test");
    const setRes = await t.api.post(
      "/enterprise/policy/set",
      { orgId, allowedMethods: ["sso"] },
      { cookie },
    );
    expect(setRes.status).toBe(200);

    const res = await t.api.post(
      "/sign-in/email",
      { email: "owner@acme.test", password: "password1234" },
      {},
    );

    expect(res.status).toBe(403);
    expect((await res.json()).code).toBe("METHOD_NOT_ALLOWED");
  });

  it("a password sign-in for a user with no org membership and no SSO provider on their domain is never enforced (no policy resolvable)", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t, "freeagent@nodomain.test");
    await t.api.post("/sign-out", {}, { cookie });

    const res = await t.api.post(
      "/sign-in/email",
      { email: "freeagent@nodomain.test", password: "password1234" },
      {},
    );

    expect(res.status).toBe(200);
  });

  it("the break-glass user is exempt from allowedMethods too, not only SSO_REQUIRED", async () => {
    const t = await makeAuth();
    const { cookie, userId: ownerId } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, cookie);
    // ssoEnforced stays false, so the SSO_ENFORCE_PRECONDITION check never
    // runs — this isolates the allowedMethods exemption specifically.
    const setRes = await t.api.post(
      "/enterprise/policy/set",
      { orgId, allowedMethods: ["sso"], breakGlassUserId: ownerId },
      { cookie },
    );
    expect(setRes.status).toBe(200);

    const res = await t.api.post(
      "/sign-in/email",
      { email: "owner@acme.test", password: "password1234" },
      {},
    );

    expect(res.status).toBe(200);
  });
});

describe("resolvePolicyOrgForUser (via the sign-in backstop, membership priority)", () => {
  it("a single, unambiguous org membership resolves the policy even with no SSO provider configured at all", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, cookie);
    const setRes = await t.api.post(
      "/enterprise/policy/set",
      { orgId, allowedMethods: ["sso"] }, // excludes password — no ssoProvider row exists for this org at all
      { cookie },
    );
    expect(setRes.status).toBe(200);

    const res = await t.api.post(
      "/sign-in/email",
      { email: "owner@acme.test", password: "password1234" },
      {},
    );

    expect(res.status).toBe(403);
    expect((await res.json()).code).toBe("METHOD_NOT_ALLOWED");
  });

  it("a user belonging to two orgs is ambiguous — membership resolution defers, so no policy applies without a matching SSO domain", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t, "owner@acme.test");
    const { orgId: orgA } = await createOrg(t, cookie, "acme-a");
    const { orgId: orgB } = await createOrg(t, cookie, "acme-b"); // now a member of 2 orgs
    await t.api.post(
      "/enterprise/policy/set",
      { orgId: orgA, allowedMethods: ["sso"] },
      { cookie },
    );
    await t.api.post(
      "/enterprise/policy/set",
      { orgId: orgB, allowedMethods: ["sso"] },
      { cookie },
    );

    const res = await t.api.post(
      "/sign-in/email",
      { email: "owner@acme.test", password: "password1234" },
      {},
    );

    // Neither org's policy is applied — ambiguous membership, and
    // owner@acme.test's domain has no verified ssoProvider either.
    expect(res.status).toBe(200);
  });
});

describe("deriveSessionCreateMethod (session-creation backstop's path -> method mapping)", () => {
  it("maps every session-creating path this preset's plugins register to its method", () => {
    expect(deriveSessionCreateMethod({ path: "/sign-in/email" })).toBe("password");
    expect(deriveSessionCreateMethod({ path: "/magic-link/verify" })).toBe("magic_link");
    expect(deriveSessionCreateMethod({ path: "/passkey/verify-authentication" })).toBe("passkey");
    expect(deriveSessionCreateMethod({ path: "/sso/callback/okta-prod" })).toBe("sso");
    expect(deriveSessionCreateMethod({ path: "/sso/saml2/sp/acs/okta-prod" })).toBe("sso");
    // Concrete resolved path (provider embedded directly)
    expect(deriveSessionCreateMethod({ path: "/callback/google" })).toBe("google");
    // Registered pattern form (provider in params)
    expect(deriveSessionCreateMethod({ path: "/callback/:id", params: { id: "github" } })).toBe(
      "github",
    );
    expect(
      deriveSessionCreateMethod({ path: "/sign-in/social", body: { provider: "linkedin" } }),
    ).toBe("linkedin");
  });

  it("returns null (never blocked) for unrecognized paths", () => {
    expect(deriveSessionCreateMethod({ path: "/some/other/endpoint" })).toBeNull();
    expect(deriveSessionCreateMethod({})).toBeNull();
    expect(deriveSessionCreateMethod({ path: "/callback/:id" })).toBeNull(); // pattern, no params.id
  });
});

describe("session-creation backstop enforces allowedMethods independent of the pre-flight hook", () => {
  it("blocks a session-creating call whose derived method is excluded, for a path the pre-flight hook never inspects", async () => {
    const t = await makeAuth();
    const { cookie, userId: ownerId } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, cookie);
    const setRes = await t.api.post(
      "/enterprise/policy/set",
      { orgId, allowedMethods: ["password"] },
      { cookie },
    );
    expect(setRes.status).toBe(200);

    // `buildSignInBeforeHook`'s matcher never fires for an OAuth callback
    // path at all (`/callback/:id`/`/callback/google` isn't one of the 5
    // sign-in paths it matches) — driving this through a real request would
    // require a full OAuth round trip against a mocked provider. Calling
    // the exported backstop builder directly against the real auth
    // instance's context (`$context`, better-auth's own escape hatch for
    // this — `node_modules/better-auth/dist/auth/base.mjs`) proves the
    // backstop enforces `allowedMethods` on its own, independent of the
    // pre-flight hook, for exactly the paths the pre-flight hook can't see.
    const context = await (t.auth as unknown as { $context: Promise<unknown> }).$context;
    const hook = buildSessionCreateBeforeHook();

    await expect(
      hook({ userId: ownerId } as never, { path: "/callback/google", context } as never),
    ).rejects.toMatchObject({ body: { code: "METHOD_NOT_ALLOWED" } });
  });
});

describe("sessionMaxAgeS", () => {
  it("caps a newly created session's lifetime to ~sessionMaxAgeS seconds — resolved via org membership, no SSO provider needed", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, cookie);
    // `resolvePolicyOrgForUser` (`../../src/server/policy/enforcement.ts`)
    // resolves the org via the owner's single, unambiguous `member` row —
    // no `ssoProvider` row exists for this org at all, proving
    // `sessionMaxAgeS` enforcement isn't tied to SSO being configured.
    const setRes = await t.api.post(
      "/enterprise/policy/set",
      { orgId, sessionMaxAgeS: 600 },
      { cookie },
    );
    expect(setRes.status).toBe(200);

    const before = Date.now();
    const signInRes = await t.api.post(
      "/sign-in/email",
      { email: "owner@acme.test", password: "password1234" },
      {},
    );
    expect(signInRes.status).toBe(200);

    const rows = await t.client.execute({
      sql: `SELECT expiresAt, createdAt FROM session WHERE userId = ? ORDER BY createdAt DESC LIMIT 1`,
      args: [(await signInRes.json()).user.id as string],
    });
    expect(rows.rows.length).toBe(1);
    const expiresAt = Number(rows.rows[0]!.expiresAt);
    expect(Math.abs(expiresAt - (before + 600_000))).toBeLessThan(10_000);
  });
});
