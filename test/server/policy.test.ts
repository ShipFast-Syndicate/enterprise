import { describe, expect, it } from "vitest";
import { magicLink } from "better-auth/plugins";
import { orgPolicy } from "../../src/server/policy/plugin";
import {
  classifySessionCreate,
  deriveSessionCreateMethod,
  buildSessionCreateBeforeHook,
  magicLinkRecordEmail,
  magicLinkVerificationIdentifier,
} from "../../src/server/policy/enforcement";
import { ALLOWED_METHOD_VALUES } from "../../src/server/policy/store";
import { makeAuth, signUpOwner, createOrg, type TestAuth } from "../helpers/auth";
import { enrollTotp } from "../security/helpers";

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
    const { cookie: signUpCookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, signUpCookie);
    // Requiring a second factor is done by someone who has one: an
    // un-enrolled password user is refused (`REQUIRE_2FA_PRECONDITION`,
    // `test/security/gap2-require2fa.test.ts`), so the owner enrols first.
    const { cookie } = await enrollTotp(t, signUpCookie);

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
    const { cookie: signUpCookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, signUpCookie);
    const { cookie } = await enrollTotp(t, signUpCookie); // see the previous case

    const first = await t.api.post(
      "/enterprise/policy/set",
      { orgId, require2fa: true },
      { cookie },
    );
    expect(first.status).toBe(200);
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
      scimCredentialHashSecret: "catalog-test-key-".repeat(3),
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
  it("adds enterprise.require2fa + twoFactorEnabled + enrollmentRequired once the org's policy requires it", async () => {
    const t = await makeAuth();
    const { cookie: signUpCookie } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, signUpCookie); // sets this as the active org
    const { cookie } = await enrollTotp(t, signUpCookie); // the enabler must be enrolled
    // A plain member who has not enrolled — reached through the membership,
    // not through an active organization (nothing sets one by default).
    const { cookie: memberCookie, userId: memberId } = await signUpOwner(t, "member@acme.test");
    await insertMemberRow(t, orgId, memberId, "member");

    const before = await t.api.get("/get-session", { cookie });
    expect((await before.json()).enterprise).toBeUndefined();
    const memberBefore = await t.api.get("/get-session", { cookie: memberCookie });
    expect((await memberBefore.json()).enterprise).toBeUndefined();

    const setRes = await t.api.post(
      "/enterprise/policy/set",
      { orgId, require2fa: true },
      { cookie },
    );
    expect(setRes.status).toBe(200);

    const after = await t.api.get("/get-session", { cookie });
    expect(after.status).toBe(200);
    expect((await after.json()).enterprise).toEqual({
      require2fa: true,
      twoFactorEnabled: true,
      enrollmentRequired: false,
    });
    const memberAfter = await t.api.get("/get-session", { cookie: memberCookie });
    expect(memberAfter.status).toBe(200);
    expect((await memberAfter.json()).enterprise).toEqual({
      require2fa: true,
      twoFactorEnabled: false,
      enrollmentRequired: true,
    });
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

  it("magic-link for a non-break-glass user in the SSO-enforced org: the request is not an oracle, the verify step is 403 SSO_REQUIRED", async () => {
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

    // Audit gap 3: refusing `/sign-in/magic-link` before any credential was
    // presented told a stranger "this address belongs to an SSO-enforced
    // org's member". The request now answers exactly as for any address;
    // the link itself is what gets refused.
    const res = await t.api.post("/sign-in/magic-link", { email: "bob@acme.test" }, {});
    expect(res.status).toBe(200);
    expect(sent).toHaveLength(1);

    const sessionsBefore = (await t.client.execute(`SELECT id FROM session`)).rows.length;
    const verifyRes = await t.api.get(`/magic-link/verify?token=${sent[0]!.token}`);
    expect(verifyRes.status).toBe(403);
    expect((await verifyRes.json()).code).toBe("SSO_REQUIRED");
    const sessionsAfter = (await t.client.execute(`SELECT id FROM session`)).rows.length;
    expect(sessionsAfter).toBe(sessionsBefore); // the refused link minted no session
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

  it("the pre-flight reads the row better-auth writes: identifier `magic-link:<token>`, value tagged `type: magic-link`", async () => {
    // better-auth 1.7.7 (GHSA-965c-763c-88jm) moved magic links from a bare
    // `<token>` identifier to `magic-link:<token>`. If a future release moves
    // them again, this fails here, by name, rather than only through the
    // pre-flight tests above.
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
    const res = await t.api.post("/sign-in/magic-link", { email: "carol@example.test" }, {});
    expect(res.status).toBe(200);
    expect(sent).toHaveLength(1);

    const rows = await t.client.execute({
      sql: `SELECT value FROM verification WHERE identifier = ?`,
      args: [magicLinkVerificationIdentifier(sent[0]!.token)],
    });
    expect(rows.rows).toHaveLength(1);
    expect(magicLinkRecordEmail(rows.rows[0]!.value)).toBe("carol@example.test");
  });

  it("a pre-1.7.7 magic-link row (bare identifier, or an untyped value) is not resolved by the pre-flight: upstream answers INVALID_TOKEN, not a policy refusal", async () => {
    const t = await makeAuth({ plugins: [magicLink({ async sendMagicLink() {} })] });
    await setUpSsoEnforcedOrg(t, ["bob@acme.test"]);
    const legacyValue = JSON.stringify({ email: "bob@acme.test" });
    const bare = "legacyBareToken0123456789abcdefgh";
    const untyped = "legacyUntypedToken0123456789abcd";
    // As 1.7.6 wrote it, and that value under the new key. 1.7.7's handler
    // redeems neither, so the pre-flight must not refuse on their behalf.
    const legacyRows: ReadonlyArray<readonly [id: string, identifier: string]> = [
      ["verif_legacy_bare", bare],
      ["verif_legacy_untyped", magicLinkVerificationIdentifier(untyped)],
    ];
    for (const [id, identifier] of legacyRows) {
      await t.client.execute({
        sql: `INSERT INTO verification (id, identifier, value, expiresAt, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?, ?)`,
        args: [id, identifier, legacyValue, Date.now() + 1000 * 60 * 5, Date.now(), Date.now()],
      });
    }
    const sessionsBefore = (await t.client.execute(`SELECT id FROM session`)).rows.length;

    for (const token of [bare, untyped]) {
      const res = await t.api.get(`/magic-link/verify?token=${token}`);
      expect(res.status).toBe(302);
      expect(res.headers.get("location")).toContain("error=INVALID_TOKEN");
    }

    expect((await t.client.execute(`SELECT id FROM session`)).rows.length).toBe(sessionsBefore);
    const remaining = await t.client.execute(
      `SELECT id FROM verification WHERE id IN ('verif_legacy_bare', 'verif_legacy_untyped')`,
    );
    expect(remaining.rows).toHaveLength(2);
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

describe("resolvePolicyOrgsForUser (via the sign-in backstop, union of every org with a claim)", () => {
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

  it("a user belonging to two orgs gets the union of both policies — never none (F-03)", async () => {
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

    // Both orgs exclude `password`; two memberships used to resolve to *no*
    // org at all (the F-03 escape hatch: any member could create a second
    // org to shed the first one's policy). The intersection binds.
    expect(res.status).toBe(403);
    expect((await res.json()).code).toBe("METHOD_NOT_ALLOWED");
  });

  it("two orgs, only one of them restrictive — the restrictive one still binds", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t, "owner@acme.test");
    const { orgId: orgA } = await createOrg(t, cookie, "acme-a");
    await createOrg(t, cookie, "acme-b"); // unrestricted second org
    await t.api.post(
      "/enterprise/policy/set",
      { orgId: orgA, allowedMethods: ["sso"] },
      { cookie },
    );

    const res = await t.api.post(
      "/sign-in/email",
      { email: "owner@acme.test", password: "password1234" },
      {},
    );

    expect(res.status).toBe(403);
    expect((await res.json()).code).toBe("METHOD_NOT_ALLOWED");
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

  it("returns null for unrecognized paths, which classifySessionCreate reports as `unknown` (refused under a restricted policy, gap 4)", () => {
    expect(deriveSessionCreateMethod({ path: "/some/other/endpoint" })).toBeNull();
    expect(deriveSessionCreateMethod({})).toBeNull();
    expect(deriveSessionCreateMethod({ path: "/callback/:id" })).toBeNull(); // pattern, no params.id
    expect(classifySessionCreate({ path: "/some/other/endpoint" })).toEqual({
      kind: "unknown",
      path: "/some/other/endpoint",
    });
    expect(classifySessionCreate({})).toEqual({ kind: "unknown", path: null });
    expect(classifySessionCreate({ path: "/callback/:id" })).toEqual({
      kind: "unknown",
      path: "/callback/:id",
    });
  });
});

describe("magicLinkRecordEmail (the /magic-link/verify pre-flight's value check)", () => {
  it("returns the e-mail of a value better-auth >= 1.7.7 writes", () => {
    expect(magicLinkRecordEmail(JSON.stringify({ type: "magic-link", email: "a@acme.test" }))).toBe(
      "a@acme.test",
    );
    expect(
      magicLinkRecordEmail(JSON.stringify({ type: "magic-link", email: "a@acme.test", name: "A" })),
    ).toBe("a@acme.test");
  });

  it("returns null for any value 1.7.7's verify handler would not redeem", () => {
    expect(magicLinkRecordEmail(JSON.stringify({ email: "a@acme.test" }))).toBeNull(); // 1.7.6 shape
    expect(
      magicLinkRecordEmail(JSON.stringify({ type: "auth-state", email: "a@acme.test" })),
    ).toBeNull();
    expect(magicLinkRecordEmail(JSON.stringify({ type: "magic-link", email: 1 }))).toBeNull();
    expect(magicLinkRecordEmail(JSON.stringify({ type: "magic-link" }))).toBeNull();
    expect(magicLinkRecordEmail(JSON.stringify("a@acme.test"))).toBeNull();
    expect(magicLinkRecordEmail("null")).toBeNull();
    expect(magicLinkRecordEmail("not json")).toBeNull();
    expect(magicLinkRecordEmail(undefined)).toBeNull();
    expect(magicLinkRecordEmail(42)).toBeNull();
  });

  it("keys a magic link under its purpose prefix", () => {
    expect(magicLinkVerificationIdentifier("tok")).toBe("magic-link:tok");
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
    // `resolvePolicyOrgsForUser` (`../../src/server/policy/enforcement.ts`)
    // resolves the org via the owner's `member` row —
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
