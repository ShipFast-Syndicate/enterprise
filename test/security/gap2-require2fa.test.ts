// GHSA-8p84-pc7q-69jr — audit gap 2: `require2fa` is enforced.
//
// Every assertion states the FIXED behaviour. Against the parent commit
// (api-keys), `org_policy.require_2fa` was read by one `/get-session`
// annotation and nothing else: an un-enrolled member reached every endpoint,
// a magic-link or passkey session stood without any second factor, and an
// admin who had never enrolled could switch the requirement on for everyone
// else. This file drives the HTTP surface and the session-creation hook with
// freshly signed-up users; the route table and the pure decision helpers
// are in `gap2-require2fa-routes.test.ts`.
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { BetterAuthPlugin } from "better-auth";
import { createAuthEndpoint, sessionMiddleware } from "better-auth/api";
import { magicLink } from "better-auth/plugins";
import { buildSessionCreateBeforeHook } from "../../src/server/policy/enforcement";
import type { EnterpriseOptions } from "../../src/server/types";
import {
  createOrg,
  extractCookie,
  makeAuth as makeAuthBase,
  signUpOwner,
  type TestAuth,
} from "../helpers/auth";
import { startOidcIssuer, type OidcIssuer } from "../helpers/oidc-issuer";
import { registerOidcProvider } from "../helpers/sso";
import { driveSsoSignIn, sessionCookieOf, sessionOf } from "./ghsa-sso-helpers";
import { enrollTotp, insertMemberRow, setPolicy } from "./helpers";

/**
 * The paths a signed-in user who still has to enrol may call — pinned as a
 * literal here (the public contract a product's enrolment UI relies on) and
 * cross-checked against `TWO_FACTOR_ENROLLMENT_ALLOWED_PATHS` in
 * `gap2-require2fa-routes.test.ts`.
 */
const ENROLLMENT_PATHS = [
  "/get-session",
  "/sign-out",
  "/enterprise/home-realm",
  "/two-factor/enable",
  "/two-factor/get-totp-uri",
  "/two-factor/verify-totp",
  "/two-factor/send-otp",
  "/two-factor/verify-otp",
];

/**
 * Every instance in this file enrols several users through
 * `/two-factor/enable` + `/two-factor/verify-totp`, which upstream's
 * `twoFactor()` rate-limits at 3 per 10 s per IP with a store shared across
 * the whole file; relaxed here the way the sign-in special rule is in the
 * helper. The gate under test is not a rate limit.
 */
function makeAuth(overrides: Parameters<typeof makeAuthBase>[0] = {}) {
  return makeAuthBase({
    ...overrides,
    rateLimitCustomRules: { "/two-factor/*": { window: 10, max: 10_000 } },
  });
}

async function insertVerifiedProvider(
  t: TestAuth,
  orgId: string,
  domain: string,
  providerId: string,
) {
  await t.client.execute({
    sql: `INSERT INTO "ssoProvider" (id, issuer, domain, domainVerified, organizationId, providerId, userId) VALUES (?, ?, ?, 1, ?, ?, ?)`,
    args: [`ssop_${providerId}`, "https://idp.test", domain, orgId, providerId, "creator"],
  });
}

async function authContext(t: TestAuth): Promise<unknown> {
  return (t.auth as unknown as { $context: Promise<unknown> }).$context;
}

/** An owner who has enrolled a real TOTP factor — the only kind of password user allowed to switch `require2fa` on. */
async function enrolledOwner(t: TestAuth, email = "owner@acme.test", slug = "acme") {
  const { cookie: signUpCookie, userId } = await signUpOwner(t, email);
  const { orgId } = await createOrg(t, signUpCookie, slug);
  const { cookie, totp } = await enrollTotp(t, signUpCookie);
  return { cookie, userId, orgId, totp };
}

async function requireTwoFactor(t: TestAuth, cookie: string, orgId: string) {
  const res = await setPolicy(t, cookie, { orgId, require2fa: true });
  expect(res.status).toBe(200);
}

/** A freshly signed-up password user made a plain member of `orgId`. */
async function freshMember(t: TestAuth, orgId: string, email: string) {
  const { cookie, userId } = await signUpOwner(t, email);
  await insertMemberRow(t, orgId, userId, "member");
  return { cookie, userId };
}

/** Session rows minted for `userId` at or after `sinceMs` — what a refused sign-in must leave at zero. */
async function sessionsMintedSince(t: TestAuth, userId: string, sinceMs: number): Promise<number> {
  const rows = await t.client.execute({
    sql: `SELECT id FROM session WHERE userId = ? AND createdAt >= ?`,
    args: [userId, sinceMs],
  });
  return rows.rows.length;
}

/** A `Set-Cookie` list that carries no *non-empty* session token (a challenge or a refusal may still clear the cookie). */
function noSessionCookie(cookie: string): boolean {
  return !/session_token=[^;]+/.test(cookie);
}

async function codeOf(res: Response): Promise<string> {
  return ((await res.json()) as { code?: string }).code ?? "";
}

async function passwordSignIn(t: TestAuth, email: string): Promise<Response> {
  return t.api.post("/sign-in/email", { email, password: "password1234" });
}

describe("gap 2 — switching require2fa on needs an enrolled caller", () => {
  it("an owner who has not enrolled is refused (400 REQUIRE_2FA_PRECONDITION), the row stays off, and the same owner succeeds once enrolled", async () => {
    const t = await makeAuth();
    const { cookie: signUpCookie } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, signUpCookie);

    const refused = await setPolicy(t, signUpCookie, { orgId, require2fa: true });
    expect(refused.status).toBe(400);
    expect(await codeOf(refused)).toBe("REQUIRE_2FA_PRECONDITION");
    const read = await t.api.get(`/enterprise/policy?orgId=${orgId}`, { cookie: signUpCookie });
    expect(((await read.json()) as { require2fa: boolean }).require2fa).toBe(false);

    // Other fields are still writable by the un-enrolled owner; only the
    // false → true transition of `require2fa` is guarded.
    expect((await setPolicy(t, signUpCookie, { orgId, sessionMaxAgeS: 3600 })).status).toBe(200);
    expect((await setPolicy(t, signUpCookie, { orgId, require2fa: false })).status).toBe(200);

    const { cookie } = await enrollTotp(t, signUpCookie);
    await requireTwoFactor(t, cookie, orgId);
    // A later write that leaves `require2fa` on is not a transition.
    expect((await setPolicy(t, cookie, { orgId, sessionMaxAgeS: 900 })).status).toBe(200);
    expect((await setPolicy(t, cookie, { orgId, require2fa: true })).status).toBe(200);
    const after = await t.api.get(`/enterprise/policy?orgId=${orgId}`, { cookie });
    expect(((await after.json()) as { require2fa: boolean }).require2fa).toBe(true);
  });
});

describe("gap 2 — the enrolment gate confines an un-enrolled password user", () => {
  it("a member who has not enrolled reaches only the enrolment allow-list once the org requires 2FA; /get-session says enrollmentRequired", async () => {
    const t = await makeAuth();
    const owner = await enrolledOwner(t);
    const bob = await freshMember(t, owner.orgId, "bob@acme.test");

    // Before the policy: nothing on the deployment requires 2FA, the gate is idle.
    expect(
      (await t.api.get(`/enterprise/members?orgId=${owner.orgId}`, { cookie: bob.cookie })).status,
    ).toBe(200);
    expect((await t.api.get("/organization/list", { cookie: bob.cookie })).status).toBe(200);

    await requireTwoFactor(t, owner.cookie, owner.orgId);

    const members = await t.api.get(`/enterprise/members?orgId=${owner.orgId}`, {
      cookie: bob.cookie,
    });
    expect(members.status).toBe(403);
    const body = (await members.json()) as { code: string; enrollmentPaths: string[] };
    expect(body.code).toBe("TWO_FACTOR_ENROLLMENT_REQUIRED");
    expect(body.enrollmentPaths).toEqual(ENROLLMENT_PATHS);
    for (const [method, path, payload] of [
      ["get", "/organization/list", undefined],
      ["get", `/enterprise/policy?orgId=${owner.orgId}`, undefined],
      ["get", "/list-sessions", undefined],
      ["get", "/api-key/list", undefined],
      ["post", "/organization/create", { name: "mine", slug: "mine" }],
      ["post", "/update-user", { name: "Bob" }],
    ] as const) {
      const res =
        method === "get"
          ? await t.api.get(path, { cookie: bob.cookie })
          : await t.api.post(path, payload, { cookie: bob.cookie });
      expect(res.status, path).toBe(403);
      expect(await codeOf(res), path).toBe("TWO_FACTOR_ENROLLMENT_REQUIRED");
    }

    // The allow-list: the session read that carries the flag, and sign-out.
    const session = await t.api.get("/get-session", { cookie: bob.cookie });
    expect(session.status).toBe(200);
    expect(((await session.json()) as { enterprise: unknown }).enterprise).toEqual({
      require2fa: true,
      twoFactorEnabled: false,
      enrollmentRequired: true,
    });
    expect(
      (
        await t.api.post(
          "/enterprise/home-realm",
          { email: "bob@acme.test" },
          { cookie: bob.cookie },
        )
      ).status,
    ).toBe(200);
    expect((await t.api.post("/sign-out", {}, { cookie: bob.cookie })).status).toBe(200);

    // A fresh password sign-in still mints a session (the enrolment-only
    // one), and that session is confined the same way.
    const signIn = await passwordSignIn(t, "bob@acme.test");
    expect(signIn.status).toBe(200);
    expect((await signIn.json()) as object).not.toMatchObject({ twoFactorRedirect: true });
    const again = extractCookie(signIn);
    expect(again).toContain("session_token");
    expect((await t.api.get("/organization/list", { cookie: again })).status).toBe(403);

    // Meanwhile the enrolled owner is untouched.
    expect(
      (await t.api.get(`/enterprise/members?orgId=${owner.orgId}`, { cookie: owner.cookie }))
        .status,
    ).toBe(200);
    // And so is a password user no org has a claim on.
    const { cookie: stranger } = await signUpOwner(t, "dave@gmail.test");
    expect((await t.api.get("/organization/list", { cookie: stranger })).status).toBe(200);
  });

  it("a real TOTP enrolment through the allow-listed endpoints lifts the gate, and the next password sign-in is challenged and completed as a continuation", async () => {
    const t = await makeAuth();
    const owner = await enrolledOwner(t);
    await requireTwoFactor(t, owner.cookie, owner.orgId);
    // Signed up *after* the policy: `/sign-up/email` still mints the
    // enrolment-only session.
    const bob = await freshMember(t, owner.orgId, "bob@acme.test");
    expect((await t.api.get("/organization/list", { cookie: bob.cookie })).status).toBe(403);

    const enrolled = await enrollTotp(t, bob.cookie);
    expect(
      (await t.api.get(`/enterprise/members?orgId=${owner.orgId}`, { cookie: enrolled.cookie }))
        .status,
    ).toBe(200);
    const session = await t.api.get("/get-session", { cookie: enrolled.cookie });
    expect(((await session.json()) as { enterprise: unknown }).enterprise).toEqual({
      require2fa: true,
      twoFactorEnabled: true,
      enrollmentRequired: false,
    });

    const signIn = await passwordSignIn(t, "bob@acme.test");
    expect(signIn.status).toBe(200);
    expect(await signIn.json()).toMatchObject({ twoFactorRedirect: true });
    const challenge = extractCookie(signIn);
    expect(noSessionCookie(challenge)).toBe(true);
    const verify = await t.api.post(
      "/two-factor/verify-totp",
      { code: await enrolled.totp() },
      { cookie: challenge },
    );
    expect(verify.status).toBe(200);
    const fresh = extractCookie(verify);
    expect(
      (await t.api.get(`/enterprise/members?orgId=${owner.orgId}`, { cookie: fresh })).status,
    ).toBe(200);
  });

  it("a user the org claims through its verified domain is gated too, membership or not", async () => {
    const t = await makeAuth();
    const owner = await enrolledOwner(t);
    await insertVerifiedProvider(t, owner.orgId, "acme.test", "acme-okta");
    await requireTwoFactor(t, owner.cookie, owner.orgId);

    const { cookie } = await signUpOwner(t, "carol@acme.test"); // no member row
    const res = await t.api.get("/organization/list", { cookie });
    expect(res.status).toBe(403);
    expect(await codeOf(res)).toBe("TWO_FACTOR_ENROLLMENT_REQUIRED");
  });

  it("policy.twoFactor.enrollmentPaths extends the allow-list; a product endpoint outside it is refused; anonymous calls are never gated", async () => {
    const productPlugin = (): BetterAuthPlugin => ({
      id: "zz-product",
      endpoints: {
        enrol: createAuthEndpoint(
          "/zz-product/enrol",
          { method: "GET", use: [sessionMiddleware] },
          async (ctx) => ctx.json({ userId: ctx.context.session.user.id }),
        ),
        ping: createAuthEndpoint("/zz-product/ping", { method: "GET" }, async (ctx) =>
          ctx.json({ ok: true }),
        ),
      },
    });
    const t = await makeAuth({
      plugins: [productPlugin()],
      policy: { twoFactor: { enrollmentPaths: ["/zz-product/enrol"] } },
    });
    const owner = await enrolledOwner(t);
    await requireTwoFactor(t, owner.cookie, owner.orgId);
    const bob = await freshMember(t, owner.orgId, "bob@acme.test");

    const gated = await t.api.get("/zz-product/ping", { cookie: bob.cookie });
    expect(gated.status).toBe(403);
    expect(await codeOf(gated)).toBe("TWO_FACTOR_ENROLLMENT_REQUIRED");
    const members = await t.api.get(`/enterprise/members?orgId=${owner.orgId}`, {
      cookie: bob.cookie,
    });
    expect(((await members.json()) as { enrollmentPaths: string[] }).enrollmentPaths).toEqual([
      ...ENROLLMENT_PATHS,
      "/zz-product/enrol",
    ]);
    expect((await t.api.get("/zz-product/enrol", { cookie: bob.cookie })).status).toBe(200);
    expect((await t.api.get("/zz-product/ping")).status).toBe(200);
  });
});

describe("gap 2 — which sessions stand under require2fa (session-creation hook)", () => {
  async function member(t: TestAuth, orgId: string, email: string, enrolled: boolean) {
    const { cookie, userId } = await freshMember(t, orgId, email);
    if (enrolled) await enrollTotp(t, cookie);
    return userId;
  }

  it("magic link, passkey, social and unclassified paths are refused whether or not the user is enrolled; password, sign-up and continuations stand", async () => {
    const t = await makeAuth();
    const owner = await enrolledOwner(t);
    await requireTwoFactor(t, owner.cookie, owner.orgId);
    const context = await authContext(t);
    const hook = buildSessionCreateBeforeHook();

    for (const enrolled of [false, true]) {
      const userId = await member(
        t,
        owner.orgId,
        `u-${enrolled ? "on" : "off"}@acme.test`,
        enrolled,
      );
      const run = (ctx: Record<string, unknown>) =>
        hook({ userId } as never, { ...ctx, context } as never);

      for (const ctx of [
        { path: "/magic-link/verify" }, // no challenge exists for a magic link
        { path: "/verify-email" }, // the auto-sign-in of a verification link
        { path: "/passkey/verify-authentication" },
        { path: "/passkey/verify-registration" },
        { path: "/sign-in/social", body: { provider: "google" } },
        { path: "/callback/:id", params: { id: "github" } },
        { path: "/callback/google" },
      ]) {
        await expect(run(ctx), `${ctx.path} enrolled=${enrolled}`).rejects.toMatchObject({
          body: { code: "TWO_FACTOR_REQUIRED" },
        });
      }
      for (const path of ["/email-otp/verify-email", "/phone/verify", "/zz/unknown"]) {
        await expect(run({ path }), `${path} enrolled=${enrolled}`).rejects.toMatchObject({
          body: { code: "METHOD_NOT_ALLOWED" },
        });
      }
      for (const ctx of [
        { path: "/sign-in/email" }, // upstream challenges an enrolled user; the gate confines an un-enrolled one
        { path: "/sign-up/email" },
        { path: "/two-factor/verify-totp" },
        { path: "/two-factor/verify-otp" },
        { path: "/two-factor/verify-backup-code" },
        { path: "/two-factor/enable" },
        { path: "/two-factor/disable" },
        { path: "/change-password" },
        { path: "/admin/impersonate-user" },
        { path: "/verify-email", context: { session: { user: { id: userId } } } },
      ]) {
        // A continuation needs the live auth context *plus* the current
        // session upstream would have loaded: layered over the real one.
        const merged = {
          ...ctx,
          context: Object.assign(Object.create(context as object), ctx.context ?? {}),
        };
        await expect(
          hook({ userId } as never, merged as never),
          `${ctx.path} enrolled=${enrolled}`,
        ).resolves.toBeUndefined();
      }
    }
  });

  it("policy.twoFactor.satisfiedBy names the methods that carry their own second factor", async () => {
    const opts = { policy: { twoFactor: { satisfiedBy: ["passkey"] } } } as EnterpriseOptions;
    const t = await makeAuth(opts);
    const owner = await enrolledOwner(t);
    await requireTwoFactor(t, owner.cookie, owner.orgId);
    const userId = await member(t, owner.orgId, "bob@acme.test", false);
    const context = await authContext(t);
    const hook = buildSessionCreateBeforeHook(opts);

    await expect(
      hook({ userId } as never, { path: "/passkey/verify-authentication", context } as never),
    ).resolves.toBeUndefined();
    await expect(
      hook({ userId } as never, { path: "/magic-link/verify", context } as never),
    ).rejects.toMatchObject({ body: { code: "TWO_FACTOR_REQUIRED" } });
  });

  it("end to end: a magic link for a member of a require2fa org is refused at verification and mints no session, enrolled or not", async () => {
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
    const owner = await enrolledOwner(t);
    await requireTwoFactor(t, owner.cookie, owner.orgId);
    const enrolledId = await member(t, owner.orgId, "enrolled@acme.test", true);
    const plainId = await member(t, owner.orgId, "plain@acme.test", false);

    for (const [email, userId] of [
      ["enrolled@acme.test", enrolledId],
      ["plain@acme.test", plainId],
    ] as const) {
      sent.length = 0;
      const request = await t.api.post("/sign-in/magic-link", { email }, {});
      expect(request.status).toBe(200);
      expect(sent).toHaveLength(1);
      // Upstream treats the proven address as the moment to revoke sessions
      // created before it was proven, so the count may *drop*; what must
      // not happen is a new row.
      const since = Date.now();
      const verify = await t.api.get(`/magic-link/verify?token=${sent[0]!.token}`);
      expect(verify.status, email).toBe(403);
      expect(await codeOf(verify), email).toBe("TWO_FACTOR_REQUIRED");
      expect(noSessionCookie(extractCookie(verify))).toBe(true);
      expect(await sessionsMintedSince(t, userId, since), email).toBe(0);
    }
  });

  it("end to end: under require2fa + allowedMethods:[password] an enrolled member is challenged and finishes through /two-factor/verify-totp; an un-enrolled one gets the enrolment-only session", async () => {
    const t = await makeAuth();
    const owner = await enrolledOwner(t);
    expect(
      (
        await setPolicy(t, owner.cookie, {
          orgId: owner.orgId,
          require2fa: true,
          allowedMethods: ["password"],
        })
      ).status,
    ).toBe(200);
    const { cookie } = await freshMember(t, owner.orgId, "bob@acme.test");
    const enrolled = await enrollTotp(t, cookie);
    await freshMember(t, owner.orgId, "carol@acme.test");

    const signIn = await passwordSignIn(t, "bob@acme.test");
    expect(signIn.status).toBe(200);
    expect(await signIn.json()).toMatchObject({ twoFactorRedirect: true });
    const verify = await t.api.post(
      "/two-factor/verify-totp",
      { code: await enrolled.totp() },
      { cookie: extractCookie(signIn) },
    );
    expect(verify.status).toBe(200);
    expect(
      (
        await t.api.get(`/enterprise/members?orgId=${owner.orgId}`, {
          cookie: extractCookie(verify),
        })
      ).status,
    ).toBe(200);

    const carol = await passwordSignIn(t, "carol@acme.test");
    expect(carol.status).toBe(200);
    const carolCookie = extractCookie(carol);
    expect(carolCookie).toContain("session_token");
    const gated = await t.api.get(`/enterprise/members?orgId=${owner.orgId}`, {
      cookie: carolCookie,
    });
    expect(gated.status).toBe(403);
    expect(await codeOf(gated)).toBe("TWO_FACTOR_ENROLLMENT_REQUIRED");
  });
});

describe("gap 2 — SSO users", () => {
  let issuer: OidcIssuer;
  beforeAll(async () => {
    issuer = await startOidcIssuer();
  });
  afterAll(async () => {
    await issuer.close();
  });

  it("an SSO-only admin can switch require2fa on (nothing to enrol), keeps signing in through the IdP and is never gated; the org's un-enrolled password owner is", async () => {
    const t = await makeAuth({ trustedOrigins: [issuer.issuerUrl] });
    const { cookie: ownerCookie } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, ownerCookie);
    await registerOidcProvider(t, ownerCookie, orgId, issuer, "acme-oidc", "acme.test");

    issuer.setUser({ sub: "alice", email: "alice@acme.test" });
    const first = await driveSsoSignIn(t, issuer, "acme-oidc");
    const aliceCookie = sessionCookieOf(first);
    const alice = await sessionOf(t, aliceCookie);
    await t.client.execute({
      sql: `UPDATE member SET role = 'admin' WHERE organizationId = ? AND userId = ?`,
      args: [orgId, alice.user.id],
    });

    // No password account: exempt from the precondition and from the gate.
    expect((await setPolicy(t, aliceCookie, { orgId, require2fa: true })).status).toBe(200);
    expect(
      (await t.api.get(`/enterprise/members?orgId=${orgId}`, { cookie: aliceCookie })).status,
    ).toBe(200);
    const annotated = await t.api.get("/get-session", { cookie: aliceCookie });
    expect(((await annotated.json()) as { enterprise: unknown }).enterprise).toEqual({
      require2fa: true,
      twoFactorEnabled: false,
      enrollmentRequired: false,
    });

    // A new SSO session under the policy: `sso` satisfies it by default.
    const second = await driveSsoSignIn(t, issuer, "acme-oidc");
    expect(second.headers.get("location") ?? "").not.toContain("error=");
    expect(
      (await t.api.get("/organization/list", { cookie: sessionCookieOf(second) })).status,
    ).toBe(200);

    // The password owner who never enrolled is confined.
    const gated = await t.api.get(`/enterprise/members?orgId=${orgId}`, { cookie: ownerCookie });
    expect(gated.status).toBe(403);
    expect(await codeOf(gated)).toBe("TWO_FACTOR_ENROLLMENT_REQUIRED");
  });

  it("with satisfiedBy: [] an SSO sign-in no longer stands under require2fa (TWO_FACTOR_REQUIRED, no session)", async () => {
    const t = await makeAuth({
      trustedOrigins: [issuer.issuerUrl],
      policy: { twoFactor: { satisfiedBy: [] } },
    });
    const owner = await enrolledOwner(t);
    await registerOidcProvider(t, owner.cookie, owner.orgId, issuer, "acme-oidc", "acme.test");
    issuer.setUser({ sub: "alice-2", email: "alice@acme.test" });
    const before = await driveSsoSignIn(t, issuer, "acme-oidc");
    expect(before.headers.get("location") ?? "").not.toContain("error=");
    const alice = await sessionOf(t, sessionCookieOf(before));

    await requireTwoFactor(t, owner.cookie, owner.orgId);
    const since = Date.now();
    const refused = await driveSsoSignIn(t, issuer, "acme-oidc");
    expect(refused.headers.get("location") ?? "").toContain("error=TWO_FACTOR_REQUIRED");
    expect(noSessionCookie(extractCookie(refused))).toBe(true);
    expect(await sessionsMintedSince(t, alice.user.id, since)).toBe(0);
  });
});
