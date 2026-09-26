// GHSA-8p84-pc7q-69jr — policy core (F-03, F-04, F-05, audit gaps 3 and 4).
//
// Every assertion states the FIXED behaviour; each `it()` fails against the
// parent commit (the foundations branch, where `resolvePolicyOrgForUser`
// still picked one org or none, the read paths still matched domains
// exactly, no `session.update` hook existed, `/sign-in/email` was
// pre-flighted before the password check, and an unclassified path was
// never blocked) and passes once `src/server/policy/enforcement.ts` is
// rewritten on top of `getEffectivePolicy`.
import { describe, expect, it } from "vitest";
import {
  buildSessionCreateBeforeHook,
  buildSessionUpdateBeforeHook,
  classifySessionCreate,
  deriveSessionCreateMethod,
} from "../../src/server/policy/enforcement";
import { buildScimRequiredUserCreateBeforeHook } from "../../src/server/policy/scim-required";
import { makeAuth, signUpOwner, createOrg, extractCookie, type TestAuth } from "../helpers/auth";
import { enrollTotp, insertMemberRow, mintScimToken, setPolicy } from "./helpers";

async function insertVerifiedProvider(
  t: TestAuth,
  orgId: string,
  domain: string,
  providerId = "okta",
) {
  await t.client.execute({
    sql: `INSERT INTO "ssoProvider" (id, issuer, domain, domainVerified, organizationId, providerId, userId) VALUES (?, ?, ?, 1, ?, ?, ?)`,
    args: [`ssop_${providerId}`, "https://idp.test", domain, orgId, providerId, "creator"],
  });
  // `ssoEnforced:true` also requires a passed admin test login for the org.
  await t.client.execute({
    sql: `INSERT INTO verification (id, identifier, value, expiresAt, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?, ?)`,
    args: [
      `v_${providerId}`,
      `ab-sso-test-ok:${providerId}`,
      "x",
      Date.now() + 1e9,
      Date.now(),
      Date.now(),
    ],
  });
}

async function authContext(t: TestAuth): Promise<unknown> {
  return (t.auth as unknown as { $context: Promise<unknown> }).$context;
}

const oidcConfig = {
  clientId: "client-id",
  clientSecret: "supersecret-client-secret",
  skipDiscovery: true,
  authorizationEndpoint: "https://idp.test/authorize",
  tokenEndpoint: "https://idp.test/token",
  jwksEndpoint: "https://idp.test/jwks",
};

describe("F-03 — a self-created second org is no escape from the first org's policy", () => {
  it("member of two orgs, one with allowedMethods:[sso] -> password sign-in stays 403", async () => {
    const t = await makeAuth();
    const { cookie: ownerCookie } = await signUpOwner(t, "owner@acme.test");
    const { orgId: orgA } = await createOrg(t, ownerCookie, "acme-a");
    const { cookie: c, userId } = await signUpOwner(t, "contractor@gmail.test");
    await insertMemberRow(t, orgA, userId, "member");
    expect((await setPolicy(t, ownerCookie, { orgId: orgA, allowedMethods: ["sso"] })).status).toBe(
      200,
    );

    const blocked = await t.api.post("/sign-in/email", {
      email: "contractor@gmail.test",
      password: "password1234",
    });
    expect(blocked.status).toBe(403);

    // The escape hatch: create an org of one's own, become a member of two.
    const created = await t.api.post(
      "/organization/create",
      { name: "mine", slug: "mine" },
      { cookie: c },
    );
    expect(created.status).toBe(200);

    const after = await t.api.post("/sign-in/email", {
      email: "contractor@gmail.test",
      password: "password1234",
    });
    expect(after.status).toBe(403);
    expect((await after.json()).code).toBe("METHOD_NOT_ALLOWED");
  });

  it("ssoEnforced: a non-domain member who creates a second org is still SSO_REQUIRED", async () => {
    const t = await makeAuth();
    const { cookie: ownerCookie, userId: ownerId } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, ownerCookie);
    await insertVerifiedProvider(t, orgId, "acme.test");
    const { cookie: c, userId } = await signUpOwner(t, "contractor@gmail.test");
    await insertMemberRow(t, orgId, userId, "member");
    expect(
      (await setPolicy(t, ownerCookie, { orgId, ssoEnforced: true, breakGlassUserId: ownerId }))
        .status,
    ).toBe(200);

    expect(
      (await t.api.post("/organization/create", { name: "mine", slug: "mine" }, { cookie: c }))
        .status,
    ).toBe(200);

    const res = await t.api.post("/sign-in/email", {
      email: "contractor@gmail.test",
      password: "password1234",
    });
    expect(res.status).toBe(403);
    expect((await res.json()).code).toBe("SSO_REQUIRED");
  });

  it("break-glass is per org: the break-glass owner of org A is still bound by org B's allowedMethods", async () => {
    const t = await makeAuth();
    const { cookie, userId: ownerId } = await signUpOwner(t, "owner@acme.test");
    const { orgId: orgA } = await createOrg(t, cookie, "acme-a");
    const { orgId: orgB } = await createOrg(t, cookie, "acme-b");
    expect(
      (
        await setPolicy(t, cookie, {
          orgId: orgA,
          allowedMethods: ["sso"],
          breakGlassUserId: ownerId,
        })
      ).status,
    ).toBe(200);
    expect((await setPolicy(t, cookie, { orgId: orgB, allowedMethods: ["sso"] })).status).toBe(200);

    const res = await t.api.post("/sign-in/email", {
      email: "owner@acme.test",
      password: "password1234",
    });
    expect(res.status).toBe(403);
    expect((await res.json()).code).toBe("METHOD_NOT_ALLOWED");
  });
});

describe("F-04 — every enterprise read path matches provider domains like upstream", () => {
  it("comma-list + mixed case + subdomain all resolve to the org for home-realm and sign-up enforcement", async () => {
    const t = await makeAuth();
    const { cookie, userId } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, cookie);
    await insertVerifiedProvider(t, orgId, "Acme.test, acme-two.test");
    expect(
      (await setPolicy(t, cookie, { orgId, ssoEnforced: true, breakGlassUserId: userId })).status,
    ).toBe(200);

    let ip = 1;
    for (const email of ["x@acme.test", "x@acme-two.test", "x@eu.acme.test", "x@ACME.TEST"]) {
      const hr = await t.api.post(
        "/enterprise/home-realm",
        { email },
        { "x-forwarded-for": `203.0.113.${ip++}` },
      );
      expect([email, (await hr.json()).method]).toEqual([email, "sso"]);
      const su = await t.api.post("/sign-up/email", { name: "x", email, password: "password1234" });
      expect([email, su.status]).toEqual([email, 403]);
      expect([email, (await su.json()).code]).toEqual([email, "SSO_REQUIRED"]);
    }
  });

  it("scim-required JIT guard fires for the second domain of a comma-list SCIM-active org", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, cookie);
    await insertVerifiedProvider(t, orgId, "acme.test, acme-two.test");
    await mintScimToken(t, cookie, orgId, "okta"); // creates the org's scimManagedConnection

    const context = await authContext(t);
    const hook = buildScimRequiredUserCreateBeforeHook();
    for (const email of ["emp@acme-two.test", "emp@eu.acme.test", "emp@ACME.test"]) {
      await expect(
        hook({ email } as never, { path: "/sso/callback/okta", context } as never),
      ).rejects.toMatchObject({ body: { code: "SCIM_PROVISIONING_REQUIRED" } });
    }
    // A look-alike domain is still not a subdomain.
    await expect(
      hook(
        { email: "emp@evilacme.test" } as never,
        {
          path: "/sso/callback/okta",
          context,
        } as never,
      ),
    ).resolves.toBeUndefined();
  });

  it("scim-required JIT guard fires when ANY matched org has SCIM, not only the most specific match", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t, "owner@acme.test");
    const { orgId: narrow } = await createOrg(t, cookie, "acme-eu"); // eu.acme.test, no SCIM
    const { orgId: broad } = await createOrg(t, cookie, "acme"); // acme.test, SCIM active
    await insertVerifiedProvider(t, narrow, "eu.acme.test", "aaa-narrow");
    await insertVerifiedProvider(t, broad, "acme.test", "zzz-broad");
    await mintScimToken(t, cookie, broad, "zzz-broad");

    const context = await authContext(t);
    const hook = buildScimRequiredUserCreateBeforeHook();
    // First match by specificity is the SCIM-less `eu.acme.test` org; the
    // broad `acme.test` org still claims the address and has SCIM.
    await expect(
      hook(
        { email: "emp@eu.acme.test" } as never,
        {
          path: "/sso/callback/aaa-narrow",
          context,
        } as never,
      ),
    ).rejects.toMatchObject({ body: { code: "SCIM_PROVISIONING_REQUIRED" } });
  });

  it("/enterprise/sso/register stores the normalised domain list and refuses one that could never match", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, cookie);

    const ok = await t.api.post(
      "/enterprise/sso/register",
      {
        organizationId: orgId,
        providerId: "okta",
        issuer: "https://idp.test",
        domain: " Acme.test ,acme-two.test., ACME.test",
        oidcConfig,
      },
      { cookie },
    );
    expect(ok.status).toBe(200);
    const rows = await t.client.execute(`SELECT domain FROM "ssoProvider" WHERE providerId='okta'`);
    expect(rows.rows[0]!.domain).toBe("acme.test,acme-two.test");

    const bad = await t.api.post(
      "/enterprise/sso/register",
      {
        organizationId: orgId,
        providerId: "okta-2",
        issuer: "https://idp.test",
        domain: "acme.test, http://evil.test",
        oidcConfig,
      },
      { cookie },
    );
    expect(bad.status).toBe(400);
    expect((await bad.json()).code).toBe("SSO_DOMAIN_INVALID");
    const after = await t.client.execute(`SELECT providerId FROM "ssoProvider"`);
    expect(after.rows.map((r) => r.providerId)).toEqual(["okta"]);
  });
});

describe("F-05 — sessionMaxAgeS survives the /get-session refresh", () => {
  it("expiresAt stays <= createdAt + cap after a refresh", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, cookie);
    expect((await setPolicy(t, cookie, { orgId, sessionMaxAgeS: 600 })).status).toBe(200);

    const signIn = await t.api.post("/sign-in/email", {
      email: "owner@acme.test",
      password: "password1234",
    });
    expect(signIn.status).toBe(200);
    const c2 = extractCookie(signIn);

    // The default `updateAge` (1 day) is larger than a 600 s cap, so the very
    // first `/get-session` takes upstream's refresh branch and writes
    // `expiresAt = now + expiresIn` (7 days) — the F-05 reset.
    const gs = await t.api.get("/get-session", { cookie: c2 });
    expect(gs.status).toBe(200);
    const s = (await gs.json()).session as { createdAt: string; expiresAt: string };
    const lifetime = (new Date(s.expiresAt).getTime() - new Date(s.createdAt).getTime()) / 1000;
    expect(lifetime).toBeLessThanOrEqual(600 + 5);

    const row = await t.client.execute(
      `SELECT expiresAt, createdAt FROM session ORDER BY createdAt DESC LIMIT 1`,
    );
    const stored = (Number(row.rows[0]!.expiresAt) - Number(row.rows[0]!.createdAt)) / 1000;
    expect(stored).toBeLessThanOrEqual(600 + 5);
  });

  it("the update hook clamps only expiresAt writes for a capped user and leaves other session writes alone", async () => {
    const t = await makeAuth();
    const { cookie, userId } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, cookie);
    expect((await setPolicy(t, cookie, { orgId, sessionMaxAgeS: 3600 })).status).toBe(200);

    const context = (await authContext(t)) as Record<string, unknown>;
    const createdAt = new Date(Date.now() - 30 * 60 * 1000);
    const ctx = {
      path: "/get-session",
      context: {
        ...context,
        session: {
          session: { userId, createdAt, activeOrganizationId: orgId, token: "t" },
          user: { id: userId, email: "owner@acme.test" },
        },
      },
    } as never;
    const hook = buildSessionUpdateBeforeHook();

    const sevenDays = new Date(Date.now() + 7 * 24 * 3600 * 1000);
    const clamped = (await hook({ expiresAt: sevenDays, updatedAt: new Date() }, ctx)) as {
      data: { expiresAt: Date };
    };
    expect(clamped.data.expiresAt.getTime()).toBe(createdAt.getTime() + 3600 * 1000);

    // Within the cap: untouched.
    const within = new Date(createdAt.getTime() + 10 * 60 * 1000);
    await expect(hook({ expiresAt: within }, ctx)).resolves.toBeUndefined();
    // No `expiresAt` in the write (e.g. `/organization/set-active`): untouched.
    await expect(hook({ activeOrganizationId: orgId }, ctx)).resolves.toBeUndefined();
  });
});

describe("gap 3 — no pre-authentication membership oracle", () => {
  it("wrong password for a non-domain member of an ssoEnforced org -> 401, not 403 SSO_REQUIRED", async () => {
    const t = await makeAuth();
    const { cookie, userId: ownerId } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, cookie);
    await insertVerifiedProvider(t, orgId, "acme.test");
    const { userId } = await signUpOwner(t, "contractor@gmail.test");
    await insertMemberRow(t, orgId, userId, "member");
    expect(
      (await setPolicy(t, cookie, { orgId, ssoEnforced: true, breakGlassUserId: ownerId })).status,
    ).toBe(200);

    const wrong = await t.api.post("/sign-in/email", {
      email: "contractor@gmail.test",
      password: "WRONG-password",
    });
    expect(wrong.status).toBe(401);

    // The right password is still refused — by the session backstop, after
    // the credential check.
    const right = await t.api.post("/sign-in/email", {
      email: "contractor@gmail.test",
      password: "password1234",
    });
    expect(right.status).toBe(403);
    expect((await right.json()).code).toBe("SSO_REQUIRED");

    // A magic-link *request* answers the same for members and strangers.
    const ml = await t.api.post("/sign-in/magic-link", { email: "contractor@gmail.test" });
    expect(ml.status).not.toBe(403);
  });
});

describe("gap 4 — unknown sign-in methods are not silently exempt", () => {
  it("classifies sign-up as password, 2FA/e-mail-verification/impersonation as continuations, the rest as unknown", () => {
    expect(deriveSessionCreateMethod({ path: "/sign-up/email" })).toBe("password");
    expect(deriveSessionCreateMethod({ path: "/passkey/verify-registration" })).toBe("passkey");
    for (const path of [
      "/two-factor/verify-totp",
      "/two-factor/verify-otp",
      "/two-factor/verify-backup-code",
      "/two-factor/enable",
      "/two-factor/disable",
      "/verify-email",
      "/change-password",
      "/admin/impersonate-user",
    ]) {
      expect(classifySessionCreate({ path })).toEqual({ kind: "continuation", path });
    }
    expect(classifySessionCreate({ path: "/email-otp/verify-email" })).toEqual({
      kind: "unknown",
      path: "/email-otp/verify-email",
    });
    expect(classifySessionCreate({ path: "/callback/:id" })).toEqual({
      kind: "unknown",
      path: "/callback/:id",
    });
    expect(classifySessionCreate({})).toEqual({ kind: "unknown", path: null });
  });

  it("an unclassified session-creating path is refused for a user under a restricted allowedMethods", async () => {
    const t = await makeAuth();
    const { cookie, userId } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, cookie);
    expect((await setPolicy(t, cookie, { orgId, allowedMethods: ["sso"] })).status).toBe(200);

    const context = await authContext(t);
    const hook = buildSessionCreateBeforeHook();
    await expect(
      hook({ userId } as never, { path: "/email-otp/verify-email", context } as never),
    ).rejects.toMatchObject({ body: { code: "METHOD_NOT_ALLOWED" } });
    // A continuation is never a method and is never refused as one.
    await expect(
      hook({ userId } as never, { path: "/two-factor/verify-totp", context } as never),
    ).resolves.toBeUndefined();
  });

  it("an unclassified path is still allowed for a user whose orgs never narrowed sign-in", async () => {
    const t = await makeAuth();
    const { cookie, userId } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, cookie);
    expect((await setPolicy(t, cookie, { orgId, require2fa: true })).status).toBe(200);

    const context = await authContext(t);
    const hook = buildSessionCreateBeforeHook();
    await expect(
      hook({ userId } as never, { path: "/email-otp/verify-email", context } as never),
    ).resolves.toBeUndefined();
  });

  it("policy.signInMethods names the path so an org can allow it explicitly, and the policy endpoint accepts the name", async () => {
    const t = await makeAuth({
      policy: { signInMethods: { "/email-otp/verify-email": "email_otp", "/phone/*": "phone" } },
    });
    const { cookie, userId } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, cookie);
    const context = await authContext(t);
    const opts = { policy: { signInMethods: { "/email-otp/verify-email": "email_otp" } } };

    expect(deriveSessionCreateMethod({ path: "/email-otp/verify-email" }, opts as never)).toBe(
      "email_otp",
    );
    expect(
      deriveSessionCreateMethod({ path: "/phone/verify" }, {
        policy: { signInMethods: { "/phone/*": "phone" } },
      } as never),
    ).toBe("phone");

    // The endpoint's vocabulary grew with the declared names.
    expect(
      (await setPolicy(t, cookie, { orgId, allowedMethods: ["sso", "email_otp"] })).status,
    ).toBe(200);
    const hook = buildSessionCreateBeforeHook(opts as never);
    await expect(
      hook({ userId } as never, { path: "/email-otp/verify-email", context } as never),
    ).resolves.toBeUndefined();
    await expect(
      hook({ userId } as never, { path: "/sign-in/email", context } as never),
    ).rejects.toMatchObject({ body: { code: "METHOD_NOT_ALLOWED" } });

    // Narrow the org away from the declared method: now refused by name.
    expect((await setPolicy(t, cookie, { orgId, allowedMethods: ["sso"] })).status).toBe(200);
    await expect(
      hook({ userId } as never, { path: "/email-otp/verify-email", context } as never),
    ).rejects.toMatchObject({
      body: { code: "METHOD_NOT_ALLOWED", message: expect.stringContaining("email_otp") },
    });
  });
});

describe("continuations end to end", () => {
  it("a 2FA-enrolled user under allowedMethods:[password] signs in with a password and completes the TOTP challenge", async () => {
    const t = await makeAuth();
    const { cookie, userId } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, cookie);
    const enrolled = await enrollTotp(t, cookie);
    expect(
      (await setPolicy(t, enrolled.cookie, { orgId, allowedMethods: ["password"] })).status,
    ).toBe(200);

    // Password sign-in: the session is created (and the backstop classifies
    // it as `password`) before `twoFactor()` withdraws it for the challenge.
    const signIn = await t.api.post("/sign-in/email", {
      email: "owner@acme.test",
      password: "password1234",
    });
    expect(signIn.status).toBe(200);
    expect(await signIn.json()).toMatchObject({ twoFactorRedirect: true });
    const challengeCookie = extractCookie(signIn);

    // The verification re-creates the session from `/two-factor/verify-totp`
    // — a continuation, never refused as an unknown method.
    const verify = await t.api.post(
      "/two-factor/verify-totp",
      { code: await enrolled.totp() },
      { cookie: challengeCookie },
    );
    expect(verify.status).toBe(200);
    const session = await t.api.get("/get-session", { cookie: extractCookie(verify) });
    expect(((await session.json()) as { user: { id: string } }).user.id).toBe(userId);
  });
});
