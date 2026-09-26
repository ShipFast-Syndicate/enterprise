// Audit log correctness and coverage (audit 3: F-08, F-09, F-10, F-11,
// F-12, F-13; completeness critique: the 2FA-pending sign-in, the
// `/two-factor/*` session creation, `/api-key/update`; plan R6: refusal rows
// written once).
//
// Every assertion states the FIXED behaviour; against the parent commit
// each of these fails (sign-ins recorded nowhere by default, the target
// recorded as the actor of a role change, joins filed in the wrong org or
// nowhere, impersonation invisible, IdP rewrites/deletions and staff actions
// unrecorded, a 2FA-pending sign-in recorded as a success).

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { BetterAuthPlugin } from "better-auth";
import { createAuthEndpoint } from "better-auth/api";
import { setSessionCookie } from "better-auth/cookies";
import { bearer, magicLink } from "better-auth/plugins";
import * as z from "zod";
import { createOrg, extractCookie, makeAuth, signUpOwner, type TestAuth } from "../helpers/auth";
import { startOidcIssuer, type OidcIssuer } from "../helpers/oidc-issuer";
import { enrollTotp, insertMemberRow, setPolicy } from "./helpers";
import { insertProductMember, makeProductAuth } from "../helpers/product-auth";
import { resetSessionRefusalThrottleForTest } from "../../src/server/audit/refusal";
import {
  driveSsoSignIn,
  driveSsoSignInViaSharedCallback,
  insertLegacySquat,
  sessionOf,
  sessionCookieOf,
  twoTenants,
} from "./ghsa-sso-helpers";

type Row = Record<string, unknown> & { metadata: Record<string, unknown> };

async function rows(t: TestAuth, orgId: string, action?: string): Promise<Row[]> {
  const res = await t.client.execute({
    sql: action
      ? `SELECT * FROM audit_event WHERE org_id = ? AND action = ? ORDER BY seq`
      : `SELECT * FROM audit_event WHERE org_id = ? ORDER BY seq`,
    args: action ? [orgId, action] : [orgId],
  });
  return res.rows.map((r) => ({
    ...(r as unknown as Record<string, unknown>),
    metadata: JSON.parse(String(r.metadata)) as Record<string, unknown>,
  }));
}

async function allRows(t: TestAuth, action: string): Promise<Row[]> {
  const res = await t.client.execute({
    sql: `SELECT * FROM audit_event WHERE action = ? ORDER BY org_id, seq`,
    args: [action],
  });
  return res.rows.map((r) => ({
    ...(r as unknown as Record<string, unknown>),
    metadata: JSON.parse(String(r.metadata)) as Record<string, unknown>,
  }));
}

async function signIn(t: TestAuth, email: string, password = "password1234", query = "") {
  return t.api.post(`/sign-in/email${query}`, { email, password });
}

async function codeOf(res: Response): Promise<string | undefined> {
  return ((await res.clone().json()) as { code?: string }).code;
}

/** An owner with an org, plus a plain member (signed up, then given a member row). */
async function orgWithMember(t: TestAuth, slug = "acme", memberEmail = "member@acme.test") {
  const owner = await signUpOwner(t, `owner@${slug}.test`);
  const { orgId } = await createOrg(t, owner.cookie, slug);
  const member = await signUpOwner(t, memberEmail);
  await insertMemberRow(t, orgId, member.userId, "member");
  return { owner, orgId, member };
}

/** A domain-verified SSO provider row claiming `domain` for `orgId` (raw insert, as the policy tests do). */
async function insertVerifiedProvider(
  t: TestAuth,
  orgId: string,
  domain: string,
  providerId: string,
  userId: string,
) {
  await t.client.execute({
    sql: `INSERT INTO "ssoProvider" (id, issuer, domain, domainVerified, organizationId, providerId, userId) VALUES (?, ?, ?, 1, ?, ?, ?)`,
    args: [`ssop_${providerId}`, "https://idp.test", domain, orgId, providerId, userId],
  });
}

async function registerProvider(
  t: TestAuth,
  cookie: string,
  orgId: string,
  providerId = "p1",
  domain = "acme.test",
) {
  const res = await t.api.post(
    "/sso/register",
    {
      providerId,
      issuer: "https://idp.test",
      domain,
      organizationId: orgId,
      oidcConfig: {
        clientId: "client",
        clientSecret: "secret-value-never-logged",
        skipDiscovery: true,
        authorizationEndpoint: "https://idp.test/authorize",
        tokenEndpoint: "https://idp.test/token",
        jwksEndpoint: "https://idp.test/jwks",
      },
    },
    { cookie },
  );
  expect(res.status, await res.clone().text()).toBe(200);
  return (await res.json()) as { domainVerificationToken?: string };
}

function lastCookieJar(res: Response): string {
  const jar = new Map<string, string>();
  for (const raw of res.headers.getSetCookie()) {
    const kv = raw.split(";")[0]!;
    jar.set(kv.split("=")[0]!, kv);
  }
  return [...jar.values()].join("; ");
}

async function makeStaff(t: TestAuth, email = "staff@vendor.test") {
  const staff = await signUpOwner(t, email);
  await t.client.execute({ sql: "UPDATE user SET role='admin' WHERE id=?", args: [staff.userId] });
  return staff;
}

const TWO_FACTOR_RULES = {
  "/two-factor/*": { window: 10, max: 10_000 },
} as const;

// ---------------------------------------------------------------------------

describe("F-08 — sign-in, sign-out and failed sign-ins land in the user's own orgs, with no ?orgId", () => {
  it("a plain /sign-in/email writes auth.sign_in into the member's org (actor = the user, method = password)", async () => {
    const t = await makeAuth();
    const { orgId, member } = await orgWithMember(t);
    const res = await signIn(t, "member@acme.test");
    expect(res.status).toBe(200);
    const signIns = await rows(t, orgId, "auth.sign_in");
    expect(signIns).toHaveLength(1);
    expect(signIns[0]).toMatchObject({
      actor_type: "user",
      actor_id: member.userId,
      target_type: "user",
      target_id: member.userId,
    });
    expect(signIns[0]!.metadata).toMatchObject({ method: "password" });
  });

  it("fans out: a user in two orgs gets one row in each org's chain", async () => {
    const t = await makeAuth();
    const { orgId: a, member } = await orgWithMember(t, "a", "multi@x.test");
    const ownerB = await signUpOwner(t, "owner@b.test");
    const { orgId: b } = await createOrg(t, ownerB.cookie, "b");
    await insertMemberRow(t, b, member.userId, "member");
    expect((await signIn(t, "multi@x.test")).status).toBe(200);
    expect(await rows(t, a, "auth.sign_in")).toHaveLength(1);
    expect(await rows(t, b, "auth.sign_in")).toHaveLength(1);
  });

  it("an org that owns a verified SSO domain sees a non-member's sign-in at that domain (its policy governs them)", async () => {
    const t = await makeAuth();
    const owner = await signUpOwner(t, "owner@claim.test");
    const { orgId } = await createOrg(t, owner.cookie, "claim");
    await insertVerifiedProvider(t, orgId, "acme.test", "acme-okta", owner.userId);
    const contractor = await signUpOwner(t, "contractor@acme.test");
    expect((await signIn(t, "contractor@acme.test")).status).toBe(200);
    const signIns = await rows(t, orgId, "auth.sign_in");
    expect(signIns.map((r) => r.actor_id)).toContain(contractor.userId);
  });

  it("a wrong password is auth.sign_in_failed for the user (code, never the password), actor system", async () => {
    const t = await makeAuth();
    const { orgId, member } = await orgWithMember(t);
    for (let i = 0; i < 3; i++) {
      expect((await signIn(t, "member@acme.test", "not-the-password")).status).toBe(401);
    }
    const failed = await rows(t, orgId, "auth.sign_in_failed");
    expect(failed).toHaveLength(3);
    for (const row of failed) {
      expect(row).toMatchObject({ actor_type: "system", actor_id: null, target_id: member.userId });
      expect(row.metadata).toMatchObject({
        code: "INVALID_EMAIL_OR_PASSWORD",
        path: "/sign-in/email",
      });
      expect(JSON.stringify(row)).not.toContain("not-the-password");
    }
    expect(await rows(t, orgId, "auth.sign_in")).toHaveLength(0);
  });

  it("an unknown address at a claimed domain is auth.sign_in_failed in the claiming org, with the address and no target", async () => {
    const t = await makeAuth();
    const owner = await signUpOwner(t, "owner@claim.test");
    const { orgId } = await createOrg(t, owner.cookie, "claim");
    await insertVerifiedProvider(t, orgId, "acme.test", "acme-okta", owner.userId);
    expect((await signIn(t, "nobody@acme.test", "whatever-123")).status).toBe(401);
    const failed = await rows(t, orgId, "auth.sign_in_failed");
    expect(failed).toHaveLength(1);
    expect(failed[0]).toMatchObject({ target_id: null });
    expect(failed[0]!.metadata).toMatchObject({ email: "nobody@acme.test" });
  });

  it("a plain /sign-out of a fresh session writes auth.sign_out into the member's org", async () => {
    const t = await makeAuth();
    const { orgId, member } = await orgWithMember(t);
    const session = extractCookie(await signIn(t, "member@acme.test"));
    expect((await t.api.post("/sign-out", {}, { cookie: session })).status).toBe(200);
    const out = await rows(t, orgId, "auth.sign_out");
    expect(out).toHaveLength(1);
    expect(out[0]).toMatchObject({ actor_id: member.userId, actor_type: "user" });
  });

  it("?orgId is ignored for sign-in rows: a member naming a foreign org writes into their own org only", async () => {
    const t = await makeAuth();
    const { orgId, member } = await orgWithMember(t);
    const other = await signUpOwner(t, "owner@other.test");
    const { orgId: foreign } = await createOrg(t, other.cookie, "other");
    const before = (await rows(t, foreign)).length;
    expect((await signIn(t, "member@acme.test", "password1234", `?orgId=${foreign}`)).status).toBe(
      200,
    );
    expect(await rows(t, foreign)).toHaveLength(before);
    expect((await rows(t, orgId, "auth.sign_in")).map((r) => r.actor_id)).toEqual([member.userId]);
  });

  it("a magic-link sign-in (/magic-link/verify) is auth.sign_in with method magic_link", async () => {
    const sent: string[] = [];
    const t = await makeAuth({
      plugins: [magicLink({ sendMagicLink: async ({ token }) => void sent.push(token) })],
    });
    const { orgId, member } = await orgWithMember(t);
    const request = await t.api.post("/sign-in/magic-link", { email: "member@acme.test" });
    expect(request.status).toBe(200);
    const requested = await rows(t, orgId, "auth.magic_link_requested");
    expect(requested.map((r) => r.target_id)).toEqual([member.userId]);
    const verify = await t.api.get(`/magic-link/verify?token=${sent[0]}`);
    expect(verify.status).toBe(200);
    const signIns = await rows(t, orgId, "auth.sign_in");
    expect(signIns).toHaveLength(1);
    expect(signIns[0]).toMatchObject({ actor_id: member.userId });
    expect(signIns[0]!.metadata).toMatchObject({ method: "magic_link" });
  });

  it("fail-closed for unknown sign-in plugins: a session minted by a path this package does not know is still auth.sign_in", async () => {
    const productSignIn: BetterAuthPlugin = {
      id: "zz-product-sign-in",
      endpoints: {
        productSignIn: createAuthEndpoint(
          "/zz-product/sign-in",
          { method: "POST", body: z.object({ email: z.string() }) },
          async (ctx) => {
            const found = await ctx.context.internalAdapter.findUserByEmail(ctx.body.email);
            const session = await ctx.context.internalAdapter.createSession(found!.user.id);
            await setSessionCookie(ctx, { session, user: found!.user });
            return ctx.json({ ok: true });
          },
        ),
      },
    };
    const t = await makeAuth({ plugins: [productSignIn] });
    const { orgId, member } = await orgWithMember(t);
    const res = await t.api.post("/zz-product/sign-in", { email: "member@acme.test" });
    expect(res.status).toBe(200);
    const signIns = await rows(t, orgId, "auth.sign_in");
    expect(signIns).toHaveLength(1);
    expect(signIns[0]).toMatchObject({ actor_id: member.userId });
    expect(signIns[0]!.metadata).toMatchObject({ path: "/zz-product/sign-in" });
  });

  it.each([
    ["cookie", false],
    ["bearer()", true],
  ] as const)(
    "a session refresh on /get-session (%s) re-issues the session but is not a sign-in",
    async (_carrier, useBearer) => {
      const t = await makeAuth(useBearer ? { plugins: [bearer()] } : {});
      const { orgId, member } = await orgWithMember(t);
      const res = await signIn(t, "member@acme.test");
      const token = res.headers.get("set-auth-token");
      const headers: Record<string, string> = useBearer
        ? { authorization: `Bearer ${token}` }
        : { cookie: extractCookie(res) };
      if (useBearer) expect(token).toBeTruthy();
      // Age the session past `updateAge` so /get-session refreshes it
      // (upstream re-sets the cookie and `newSession` for the same session).
      const soon = Date.now() + 3600_000;
      await t.client.execute({
        sql: `UPDATE session SET expiresAt = ? WHERE userId = ?`,
        args: [soon, member.userId],
      });
      const refreshed = await t.api.get("/get-session", headers);
      expect(refreshed.status).toBe(200);
      // (The member has two sessions — sign-up and sign-in; the one in use was refreshed.)
      const after = await t.client.execute({
        sql: `SELECT max(expiresAt) AS e FROM session WHERE userId = ?`,
        args: [member.userId],
      });
      expect(Number(after.rows[0]!.e)).toBeGreaterThan(soon); // it was refreshed
      expect(await rows(t, orgId, "auth.sign_in")).toHaveLength(1);
    },
  );

  it("a signed-in caller requesting a magic link for someone else: the row is about the address, not the caller", async () => {
    const t = await makeAuth({
      plugins: [magicLink({ sendMagicLink: async () => {} })],
    });
    const { orgId, member } = await orgWithMember(t);
    const outsider = await signUpOwner(t, "outsider@elsewhere.test");
    const res = await t.api.post(
      "/sign-in/magic-link",
      { email: "member@acme.test" },
      { cookie: outsider.cookie },
    );
    expect(res.status).toBe(200);
    const [row] = await rows(t, orgId, "auth.magic_link_requested");
    expect(row).toMatchObject({ target_id: member.userId, actor_id: outsider.userId });
  });
});

describe("R6 — policy refusals are auth.sign_in_refused, never auth.sign_in_failed, and written once", () => {
  it("ssoEnforced + a non-break-glass password sign-in → auth.sign_in_refused (SSO_REQUIRED) from the session hook", async () => {
    const t = await makeAuth();
    const { owner, orgId, member } = await orgWithMember(t);
    await insertVerifiedProvider(t, orgId, "acme.test", "acme-okta", owner.userId);
    await t.client.execute({
      sql: `INSERT INTO verification (id, identifier, value, expiresAt, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?, ?)`,
      args: [
        "v_test_ok",
        "ab-sso-test-ok:acme-okta",
        new Date().toISOString(),
        Date.now() + 1e10,
        Date.now(),
        Date.now(),
      ],
    });
    const set = await setPolicy(t, owner.cookie, {
      orgId,
      ssoEnforced: true,
      breakGlassUserId: owner.userId,
    });
    expect(set.status, await set.clone().text()).toBe(200);
    const res = await signIn(t, "member@acme.test");
    expect(res.status).toBe(403);
    expect(await codeOf(res)).toBe("SSO_REQUIRED");
    const refused = await rows(t, orgId, "auth.sign_in_refused");
    expect(refused).toHaveLength(1);
    expect(refused[0]).toMatchObject({ target_id: member.userId, actor_type: "system" });
    expect(refused[0]!.metadata).toMatchObject({ code: "SSO_REQUIRED", method: "password" });
    expect(await rows(t, orgId, "auth.sign_in_failed")).toHaveLength(0);
  });

  it("require2fa + a magic link → auth.sign_in_refused (TWO_FACTOR_REQUIRED)", async () => {
    const sent: string[] = [];
    const t = await makeAuth({
      plugins: [magicLink({ sendMagicLink: async ({ token }) => void sent.push(token) })],
      rateLimitCustomRules: TWO_FACTOR_RULES,
    });
    const { owner, orgId, member } = await orgWithMember(t);
    const enrolled = await enrollTotp(t, owner.cookie);
    expect((await setPolicy(t, enrolled.cookie, { orgId, require2fa: true })).status).toBe(200);
    await t.api.post("/sign-in/magic-link", { email: "member@acme.test" });
    const verify = await t.api.get(`/magic-link/verify?token=${sent[0]}`);
    expect(verify.status).toBe(403);
    expect(await codeOf(verify)).toBe("TWO_FACTOR_REQUIRED");
    const refused = await rows(t, orgId, "auth.sign_in_refused");
    expect(refused).toHaveLength(1);
    expect(refused[0]).toMatchObject({ target_id: member.userId });
    expect(refused[0]!.metadata).toMatchObject({
      code: "TWO_FACTOR_REQUIRED",
      method: "magic_link",
      path: "/magic-link/verify",
    });
  });

  it("no duplicate: /magic-link/verify refused by the pre-flight hook (allowedMethods) writes exactly one row, from auditRefusal", async () => {
    const sent: string[] = [];
    const t = await makeAuth({
      plugins: [magicLink({ sendMagicLink: async ({ token }) => void sent.push(token) })],
    });
    const { owner, orgId, member } = await orgWithMember(t);
    expect((await setPolicy(t, owner.cookie, { orgId, allowedMethods: ["password"] })).status).toBe(
      200,
    );
    await t.api.post("/sign-in/magic-link", { email: "member@acme.test" });
    const verify = await t.api.get(`/magic-link/verify?token=${sent[0]}`);
    expect(verify.status).toBe(403);
    expect(await codeOf(verify)).toBe("METHOD_NOT_ALLOWED");
    const refused = await rows(t, orgId, "auth.sign_in_refused");
    expect(refused).toHaveLength(1);
    expect(refused[0]).toMatchObject({ target_id: member.userId });
    expect(refused[0]!.metadata).toMatchObject({
      code: "METHOD_NOT_ALLOWED",
      method: "magic_link",
    });
    expect(await rows(t, orgId, "auth.sign_in_failed")).toHaveLength(0);
  });

  it("the require2fa enrolment gate records auth.session_refused once per user and code, not once per request", async () => {
    resetSessionRefusalThrottleForTest();
    const t = await makeAuth({ rateLimitCustomRules: TWO_FACTOR_RULES });
    const { owner, orgId, member } = await orgWithMember(t);
    const enrolled = await enrollTotp(t, owner.cookie);
    expect((await setPolicy(t, enrolled.cookie, { orgId, require2fa: true })).status).toBe(200);
    const cookie = extractCookie(await signIn(t, "member@acme.test"));
    for (let i = 0; i < 4; i++) {
      const res = await t.api.get("/organization/list", { cookie });
      expect(res.status).toBe(403);
      expect(await codeOf(res)).toBe("TWO_FACTOR_ENROLLMENT_REQUIRED");
    }
    const refused = await rows(t, orgId, "auth.session_refused");
    expect(refused).toHaveLength(1);
    expect(refused[0]).toMatchObject({ target_id: member.userId });
    expect(refused[0]!.metadata).toMatchObject({
      code: "TWO_FACTOR_ENROLLMENT_REQUIRED",
      path: "/organization/list",
    });
  });
});

describe("F-09 — the actor of an org change is the caller, never the target", () => {
  it("update-member-role: actor = the owner, target = the member row, target user in metadata", async () => {
    const t = await makeAuth();
    const { owner, orgId, member } = await orgWithMember(t);
    const memberId = `member_${member.userId}_${orgId}`;
    const res = await t.api.post(
      "/organization/update-member-role",
      { memberId, role: "admin", organizationId: orgId },
      { cookie: owner.cookie },
    );
    expect(res.status).toBe(200);
    const [row] = await rows(t, orgId, "member.role_changed");
    expect(row).toMatchObject({ actor_id: owner.userId, actor_type: "user", target_id: memberId });
    expect(row!.metadata).toMatchObject({ targetUserId: member.userId, role: "admin" });
  });

  it("remove-member: actor = the owner, target user in metadata", async () => {
    const t = await makeAuth();
    const { owner, orgId, member } = await orgWithMember(t);
    const res = await t.api.post(
      "/organization/remove-member",
      { memberIdOrEmail: "member@acme.test", organizationId: orgId },
      { cookie: owner.cookie },
    );
    expect(res.status).toBe(200);
    const [row] = await rows(t, orgId, "member.removed");
    expect(row).toMatchObject({ actor_id: owner.userId });
    expect(row!.metadata).toMatchObject({ targetUserId: member.userId });
  });

  it("leave: the member who left, in the org they left (resolved before the membership is gone)", async () => {
    const t = await makeAuth();
    const { orgId, member } = await orgWithMember(t);
    const cookie = extractCookie(await signIn(t, "member@acme.test"));
    const res = await t.api.post("/organization/leave", { organizationId: orgId }, { cookie });
    expect(res.status).toBe(200);
    const [row] = await rows(t, orgId, "member.left");
    expect(row).toMatchObject({ actor_id: member.userId });
  });
});

describe("F-10 — member.joined lands in the org joined", () => {
  async function invite(t: TestAuth, cookie: string, orgId: string, email: string) {
    const res = await t.api.post(
      "/organization/invite-member",
      { email, role: "member", organizationId: orgId },
      { cookie },
    );
    expect(res.status).toBe(200);
    return ((await res.json()) as { id: string }).id;
  }

  it("a fresh invitee with no active org: the row is in the joined org, actor = the invitee", async () => {
    const t = await makeAuth({ organization: { requireEmailVerificationOnInvitation: false } });
    const owner = await signUpOwner(t);
    const { orgId } = await createOrg(t, owner.cookie);
    const invitationId = await invite(t, owner.cookie, orgId, "new@acme.test");
    const newbie = await signUpOwner(t, "new@acme.test");
    const res = await t.api.post(
      "/organization/accept-invitation",
      { invitationId },
      { cookie: newbie.cookie },
    );
    expect(res.status, await res.clone().text()).toBe(200);
    const [row] = await rows(t, orgId, "member.joined");
    expect(row).toMatchObject({ actor_id: newbie.userId });
    expect(row!.metadata).toMatchObject({ invitationId });
  });

  it("a user active in org A accepting org B's invitation: row in B only", async () => {
    const t = await makeAuth({ organization: { requireEmailVerificationOnInvitation: false } });
    const ownerB = await signUpOwner(t, "owner@b.test");
    const { orgId: b } = await createOrg(t, ownerB.cookie, "b");
    const user = await signUpOwner(t, "u@acme.test");
    const { orgId: a } = await createOrg(t, user.cookie, "a");
    const invitationId = await invite(t, ownerB.cookie, b, "u@acme.test");
    const res = await t.api.post(
      "/organization/accept-invitation",
      { invitationId },
      { cookie: user.cookie },
    );
    expect(res.status).toBe(200);
    expect(await rows(t, b, "member.joined")).toHaveLength(1);
    expect(await rows(t, a, "member.joined")).toHaveLength(0);
  });

  it("?orgId cannot steer the row into another org the acceptor belongs to", async () => {
    const t = await makeAuth({ organization: { requireEmailVerificationOnInvitation: false } });
    const ownerB = await signUpOwner(t, "owner@b.test");
    const { orgId: b } = await createOrg(t, ownerB.cookie, "b");
    const user = await signUpOwner(t, "u@acme.test");
    const { orgId: a } = await createOrg(t, user.cookie, "a");
    const invitationId = await invite(t, ownerB.cookie, b, "u@acme.test");
    const res = await t.api.post(
      `/organization/accept-invitation?orgId=${a}`,
      { invitationId },
      { cookie: user.cookie },
    );
    expect(res.status).toBe(200);
    expect(await rows(t, a, "member.joined")).toHaveLength(0);
    expect(await rows(t, b, "member.joined")).toHaveLength(1);
  });
});

describe("F-11 — sso.domain_verified lands in the provider's own org", () => {
  it("request-domain-verification with no active org → row in the provider's org", async () => {
    const t = await makeAuth();
    const owner = await signUpOwner(t);
    const { orgId } = await createOrg(t, owner.cookie);
    await registerProvider(t, owner.cookie, orgId);
    await t.client.execute("UPDATE session SET activeOrganizationId = NULL");
    const res = await t.api.post(
      "/sso/request-domain-verification",
      { providerId: "p1" },
      { cookie: owner.cookie },
    );
    expect(res.status).toBe(201);
    const [row] = await rows(t, orgId, "sso.domain_verification_requested");
    expect(row).toMatchObject({ actor_id: owner.userId, target_id: "p1" });
  });

  it("verify-domain with another org active → the row is in the provider's org, not the active one", async () => {
    const dns = await import("node:dns/promises");
    const { syncBuiltinESMExports } = await import("node:module");
    const { vi } = await import("vitest");
    const t = await makeAuth();
    const owner = await signUpOwner(t);
    const { orgId: a } = await createOrg(t, owner.cookie, "a");
    const reg = await registerProvider(t, owner.cookie, a, "p2", "b.test");
    const { orgId: b } = await createOrg(t, owner.cookie, "b"); // active = b
    const spy = vi.spyOn(dns.default, "resolveTxt");
    syncBuiltinESMExports();
    try {
      const requested = await t.api.post(
        "/sso/request-domain-verification",
        { providerId: "p2" },
        { cookie: owner.cookie },
      );
      const token =
        ((await requested.json()) as { domainVerificationToken?: string })
          .domainVerificationToken ?? reg.domainVerificationToken;
      spy.mockResolvedValue([[`better-auth-token-p2=${token}`], [String(token)]]);
      syncBuiltinESMExports();
      // The TXT lookup is stubbed: upstream's handler runs for real.
      const v = await t.api.post(
        "/sso/verify-domain",
        { providerId: "p2" },
        { cookie: owner.cookie },
      );
      expect(v.status, await v.clone().text()).toBe(204);
    } finally {
      spy.mockRestore();
      syncBuiltinESMExports();
    }
    expect(await rows(t, a, "sso.domain_verified")).toHaveLength(1);
    expect(await rows(t, b, "sso.domain_verified")).toHaveLength(0);
  });

  it("register → sso.provider_registered in the provider's org", async () => {
    const t = await makeAuth();
    const owner = await signUpOwner(t);
    const { orgId } = await createOrg(t, owner.cookie);
    await registerProvider(t, owner.cookie, orgId, "p3");
    const [row] = await rows(t, orgId, "sso.provider_registered");
    expect(row).toMatchObject({ actor_id: owner.userId, target_id: "p3" });
  });
});

describe("F-12 — impersonation is attributed to the staff member and survives stop-impersonating", () => {
  async function impersonate(t: TestAuth) {
    const staff = await makeStaff(t);
    const victim = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, victim.cookie);
    const imp = await t.api.post(
      "/admin/impersonate-user",
      { userId: victim.userId },
      { cookie: staff.cookie },
    );
    expect(imp.status).toBe(200);
    return { staff, victim, orgId, impCookie: lastCookieJar(imp) };
  }

  it("impersonate-user → admin.impersonation_started in the victim's org, actor = staff", async () => {
    const t = await makeAuth();
    const { staff, victim, orgId } = await impersonate(t);
    const [row] = await rows(t, orgId, "admin.impersonation_started");
    expect(row).toMatchObject({
      actor_type: "user",
      actor_id: staff.userId,
      target_id: victim.userId,
    });
    // Not recorded as the victim signing in.
    expect(await rows(t, orgId, "auth.sign_in")).toHaveLength(0);
  });

  it("an invite made under impersonation is actorType impersonated with metadata.impersonatedBy = staff", async () => {
    const t = await makeAuth();
    const { staff, victim, orgId, impCookie } = await impersonate(t);
    const inv = await t.api.post(
      "/organization/invite-member",
      { email: "mole@evil.test", role: "admin", organizationId: orgId },
      { cookie: impCookie },
    );
    expect(inv.status).toBe(200);
    const [row] = await rows(t, orgId, "member.invited");
    expect(row).toMatchObject({ actor_type: "impersonated", actor_id: victim.userId });
    expect(row!.metadata).toMatchObject({ impersonatedBy: staff.userId });
  });

  it("stop-impersonating → admin.impersonation_stopped, actor = staff, even though the session row is gone", async () => {
    const t = await makeAuth();
    const { staff, victim, orgId, impCookie } = await impersonate(t);
    const stop = await t.api.post("/admin/stop-impersonating", {}, { cookie: impCookie });
    expect(stop.status).toBe(200);
    const s = await t.client.execute(
      "SELECT count(*) AS c FROM session WHERE impersonatedBy IS NOT NULL",
    );
    expect(Number(s.rows[0]!.c)).toBe(0);
    const [row] = await rows(t, orgId, "admin.impersonation_stopped");
    expect(row).toMatchObject({
      actor_type: "user",
      actor_id: staff.userId,
      target_id: victim.userId,
    });
  });
});

describe("F-13 — every privileged path is recorded, once, in the right org", () => {
  it("sso/update-provider → sso.provider_updated with the changed keys and never a value", async () => {
    const t = await makeAuth();
    const owner = await signUpOwner(t);
    const { orgId } = await createOrg(t, owner.cookie);
    await registerProvider(t, owner.cookie, orgId);
    const res = await t.api.post(
      "/sso/update-provider",
      { providerId: "p1", oidcConfig: { clientSecret: "rotated-secret-value" } },
      { cookie: owner.cookie },
    );
    expect(res.status, await res.clone().text()).toBe(200);
    const updated = await rows(t, orgId, "sso.provider_updated");
    expect(updated).toHaveLength(1);
    expect(updated[0]).toMatchObject({ actor_id: owner.userId, target_id: "p1" });
    expect(updated[0]!.metadata).toMatchObject({ changed: ["oidcConfig.clientSecret"] });
    expect(JSON.stringify(updated[0])).not.toContain("rotated-secret-value");
  });

  it("sso/delete-provider → sso.provider_deleted in the (now gone) provider's org, with the linked-account count", async () => {
    const t = await makeAuth();
    const owner = await signUpOwner(t);
    const { orgId } = await createOrg(t, owner.cookie);
    await registerProvider(t, owner.cookie, orgId);
    await t.client.execute({
      sql: `INSERT INTO account (id, accountId, providerId, userId, createdAt, updatedAt) VALUES ('acct_x', 'sub-1', 'p1', ?, ?, ?)`,
      args: [owner.userId, Date.now(), Date.now()],
    });
    const res = await t.api.post(
      "/sso/delete-provider",
      { providerId: "p1" },
      { cookie: owner.cookie },
    );
    expect(res.status).toBe(200);
    const [row] = await rows(t, orgId, "sso.provider_deleted");
    expect(row).toMatchObject({ actor_id: owner.userId, target_id: "p1" });
    expect(row!.metadata).toMatchObject({ linkedAccounts: 1 });
  });

  it.each([
    ["/admin/set-role", (userId: string) => ({ userId, role: "admin" }), "admin.user_role_changed"],
    ["/admin/ban-user", (userId: string) => ({ userId }), "admin.user_banned"],
    [
      "/admin/set-user-password",
      (userId: string) => ({ userId, newPassword: "a-new-password-123" }),
      "admin.user_password_set",
    ],
    [
      "/admin/revoke-user-sessions",
      (userId: string) => ({ userId }),
      "admin.user_sessions_revoked",
    ],
    [
      "/admin/update-user",
      (userId: string) => ({ userId, data: { name: "Renamed" } }),
      "admin.user_updated",
    ],
    ["/admin/remove-user", (userId: string) => ({ userId }), "admin.user_removed"],
  ] as const)(
    "%s → %s in every org of the target, actor = the staff member",
    async (path, body, action) => {
      const t = await makeAuth();
      const { orgId, member } = await orgWithMember(t);
      const staff = await makeStaff(t);
      const res = await t.api.post(path, body(member.userId), { cookie: staff.cookie });
      expect(res.status, await res.clone().text()).toBe(200);
      const found = await rows(t, orgId, action);
      expect(found).toHaveLength(1);
      expect(found[0]).toMatchObject({ actor_id: staff.userId, target_id: member.userId });
      expect(JSON.stringify(found[0])).not.toContain("a-new-password-123");
    },
  );

  it("/admin/unban-user → admin.user_unbanned", async () => {
    const t = await makeAuth();
    const { orgId, member } = await orgWithMember(t);
    const staff = await makeStaff(t);
    await t.api.post("/admin/ban-user", { userId: member.userId }, { cookie: staff.cookie });
    const res = await t.api.post(
      "/admin/unban-user",
      { userId: member.userId },
      { cookie: staff.cookie },
    );
    expect(res.status).toBe(200);
    expect(await rows(t, orgId, "admin.user_unbanned")).toHaveLength(1);
  });

  it("/organization/delete → org.deleted, the terminal row of the org's chain", async () => {
    const t = await makeAuth();
    const owner = await signUpOwner(t);
    const { orgId } = await createOrg(t, owner.cookie);
    const res = await t.api.post(
      "/organization/delete",
      { organizationId: orgId },
      { cookie: owner.cookie },
    );
    expect(res.status).toBe(200);
    const chain = await rows(t, orgId);
    expect(chain.at(-1)).toMatchObject({
      action: "org.deleted",
      actor_id: owner.userId,
      target_id: orgId,
    });
  });

  it("/organization/update → org.updated with the changed keys", async () => {
    const t = await makeAuth();
    const owner = await signUpOwner(t);
    const { orgId } = await createOrg(t, owner.cookie);
    const res = await t.api.post(
      "/organization/update",
      { organizationId: orgId, data: { name: "Acme Two" } },
      { cookie: owner.cookie },
    );
    expect(res.status).toBe(200);
    const [row] = await rows(t, orgId, "org.updated");
    expect(row!.metadata).toMatchObject({ changed: ["name"] });
  });

  it("/change-password → user.password_changed; /revoke-sessions → session.revoked_all (no token recorded)", async () => {
    const t = await makeAuth();
    const { orgId, member } = await orgWithMember(t);
    const cookie = extractCookie(await signIn(t, "member@acme.test"));
    const cp = await t.api.post(
      "/change-password",
      { currentPassword: "password1234", newPassword: "password12345" },
      { cookie },
    );
    expect(cp.status).toBe(200);
    expect((await rows(t, orgId, "user.password_changed")).map((r) => r.actor_id)).toEqual([
      member.userId,
    ]);
    const cookie2 = extractCookie(await signIn(t, "member@acme.test", "password12345"));
    const rs = await t.api.post("/revoke-sessions", {}, { cookie: cookie2 });
    expect(rs.status).toBe(200);
    const [row] = await rows(t, orgId, "session.revoked_all");
    expect(row).toMatchObject({ actor_id: member.userId, target_id: null });
  });

  it("/api-key/update → api_key.updated in the key owner's orgs (never ?orgId-only)", async () => {
    const t = await makeAuth();
    const owner = await signUpOwner(t);
    const { orgId } = await createOrg(t, owner.cookie);
    const c = await t.api.post("/api-key/create", { name: "k" }, { cookie: owner.cookie });
    expect(c.status).toBe(200);
    const { id } = (await c.json()) as { id: string };
    expect((await rows(t, orgId, "api_key.created")).map((r) => r.target_id)).toEqual([id]);
    const u = await t.api.post(
      "/api-key/update",
      { keyId: id, name: "k2" },
      { cookie: owner.cookie },
    );
    expect(u.status).toBe(200);
    const [row] = await rows(t, orgId, "api_key.updated");
    expect(row).toMatchObject({ actor_id: owner.userId, target_id: id });
    expect(row!.metadata).toMatchObject({ changed: ["name"] });
  });

  it("/enterprise/audit/export → audit.exported, written after the CSV (the export never holds its own row)", async () => {
    const t = await makeAuth();
    const owner = await signUpOwner(t);
    const { orgId } = await createOrg(t, owner.cookie);
    await t.api.post(
      "/organization/invite-member",
      { email: "x@acme.test", role: "member", organizationId: orgId },
      { cookie: owner.cookie },
    );
    const ex = await t.api.get(`/enterprise/audit/export?orgId=${orgId}`, { cookie: owner.cookie });
    expect(ex.status).toBe(200);
    const csv = await ex.text();
    expect(csv).not.toContain("audit.exported");
    const [row] = await rows(t, orgId, "audit.exported");
    expect(row).toMatchObject({ actor_id: owner.userId, target_id: orgId });
    expect(row!.metadata).toMatchObject({ rows: 1 });
  });

  it("/enterprise/audit/compact → the anchor row carries the caller", async () => {
    const t = await makeAuth({ audit: { retentionDays: 1 } });
    const owner = await signUpOwner(t);
    const { orgId } = await createOrg(t, owner.cookie);
    await t.api.post(
      "/organization/invite-member",
      { email: "x@acme.test", role: "member", organizationId: orgId },
      { cookie: owner.cookie },
    );
    await t.client.execute({
      sql: `UPDATE audit_event SET created_at = ? WHERE org_id = ?`,
      args: [Date.now() - 3 * 24 * 3600 * 1000, orgId],
    });
    // The raw timestamp edit broke the hash of the row; compaction removes
    // it anyway (it is expired) and anchors on its stored hash.
    const res = await t.api.post("/enterprise/audit/compact", { orgId }, { cookie: owner.cookie });
    expect(await res.json()).toMatchObject({ compacted: true });
    const [anchor] = await rows(t, orgId, "audit.retention_compacted");
    expect(anchor).toMatchObject({ actor_type: "user", actor_id: owner.userId });
  });
});

describe("critique — 2FA-pending is not a sign-in; /two-factor/* sessions are", () => {
  it("a 2FA-pending /sign-in/email is auth.sign_in_2fa_pending (not auth.sign_in); the TOTP step is auth.sign_in", async () => {
    const t = await makeAuth({ rateLimitCustomRules: TWO_FACTOR_RULES });
    const { orgId, member } = await orgWithMember(t);
    const enrolled = await enrollTotp(t, extractCookie(await signIn(t, "member@acme.test")));
    const enabled = await rows(t, orgId, "two_factor.enabled");
    expect(enabled.map((r) => r.actor_id)).toEqual([member.userId]);
    const baseline = (await rows(t, orgId, "auth.sign_in")).length;

    const pending = await signIn(t, "member@acme.test");
    expect(await pending.json()).toMatchObject({ twoFactorRedirect: true });
    expect(await rows(t, orgId, "auth.sign_in")).toHaveLength(baseline);
    const [row] = await rows(t, orgId, "auth.sign_in_2fa_pending");
    expect(row).toMatchObject({ target_id: member.userId, actor_type: "system" });

    const verify = await t.api.post(
      "/two-factor/verify-totp",
      { code: await enrolled.totp() },
      { cookie: extractCookie(pending) },
    );
    expect(verify.status).toBe(200);
    const signIns = await rows(t, orgId, "auth.sign_in");
    expect(signIns).toHaveLength(baseline + 1);
    expect(signIns.at(-1)).toMatchObject({ actor_id: member.userId });
  });

  it("a wrong TOTP answer is auth.sign_in_failed for the challenged user", async () => {
    const t = await makeAuth({ rateLimitCustomRules: TWO_FACTOR_RULES });
    const { orgId, member } = await orgWithMember(t);
    await enrollTotp(t, extractCookie(await signIn(t, "member@acme.test")));
    const pending = await signIn(t, "member@acme.test");
    const verify = await t.api.post(
      "/two-factor/verify-totp",
      { code: "000000" },
      { cookie: extractCookie(pending) },
    );
    expect(verify.status).toBe(401);
    const [row] = await rows(t, orgId, "auth.sign_in_failed");
    expect(row).toMatchObject({ target_id: member.userId });
    expect(row!.metadata).toMatchObject({ path: "/two-factor/verify-totp" });
  });

  it("/two-factor/disable → two_factor.disabled", async () => {
    const t = await makeAuth({ rateLimitCustomRules: TWO_FACTOR_RULES });
    const { orgId, member } = await orgWithMember(t);
    const enrolled = await enrollTotp(t, extractCookie(await signIn(t, "member@acme.test")));
    const res = await t.api.post(
      "/two-factor/disable",
      { password: "password1234" },
      { cookie: enrolled.cookie },
    );
    expect(res.status).toBe(200);
    expect((await rows(t, orgId, "two_factor.disabled")).map((r) => r.actor_id)).toEqual([
      member.userId,
    ]);
  });
});

describe("chain key — every writer keys its rows, and the log verifies under the key", () => {
  it("with audit.chainKey, plugin rows, refusal rows and SCIM token rows are all HMAC links and /enterprise/audit/verify is ok", async () => {
    const chainKey = "k".repeat(40);
    const t = await makeAuth({ audit: { chainKey } });
    const { owner, orgId } = await orgWithMember(t);
    await signIn(t, "member@acme.test");
    await signIn(t, "member@acme.test", "wrong-password-1");
    const token = await t.api.post(
      "/enterprise/scim/tokens/create",
      { providerId: "okta", orgId },
      { cookie: owner.cookie },
    );
    expect(token.status).toBe(200);
    const chain = await rows(t, orgId);
    expect(chain.map((r) => r.action)).toEqual(
      expect.arrayContaining(["auth.sign_in", "auth.sign_in_failed", "scim.token_created"]),
    );
    for (const row of chain) expect(String(row.hash)).toMatch(/^hmac:[0-9a-f]{64}$/);
    const verify = await t.api.get(`/enterprise/audit/verify?orgId=${orgId}`, {
      cookie: owner.cookie,
    });
    expect(await verify.json()).toEqual({ ok: true });
  });
});

describe("SSO callbacks — sign-ins, and refusals that reach the victim org's chain", () => {
  let issuer: OidcIssuer;
  beforeAll(async () => {
    issuer = await startOidcIssuer();
  });
  afterAll(async () => {
    await issuer.close();
  });

  it("a legacy squat refused at session time (SSO_DOMAIN_NOT_ALLOWED, R4) is auth.sign_in_refused for the squatted user in the attacker's org AND in the org owning the domain", async () => {
    const t = await makeAuth({ trustedOrigins: [issuer.issuerUrl] });
    const { acmeOrg, evilOrg } = await twoTenants(t, issuer);
    const userId = await insertLegacySquat(t, {
      email: "ceo@acme.test",
      providerId: "evil-oidc",
      accountId: "attacker-1",
      memberOfOrgId: evilOrg,
    });
    issuer.setUser({ sub: "attacker-1", email: "ceo@acme.test" });
    const res = await driveSsoSignIn(t, issuer, "evil-oidc");
    expect(res.headers.get("location") ?? "").toContain("error=SSO_DOMAIN_NOT_ALLOWED");
    const refused = await allRows(t, "auth.sign_in_refused");
    expect(refused.map((r) => r.org_id).sort()).toEqual([acmeOrg, evilOrg].sort());
    for (const row of refused) {
      expect(row).toMatchObject({ target_id: userId, actor_type: "system" });
      expect(row.metadata).toMatchObject({
        code: "SSO_DOMAIN_NOT_ALLOWED",
        providerId: "evil-oidc",
        method: "sso",
      });
    }
    expect(await allRows(t, "auth.sso_sign_in_failed")).toHaveLength(0);
    expect(await allRows(t, "auth.sso_sign_in")).toHaveLength(0);
  });

  it("a sign-in through the shared /sso/callback (provider only in the OAuth state) is auth.sso_sign_in in the provider's org, with the provider named", async () => {
    const t = await makeAuth({ trustedOrigins: [issuer.issuerUrl] });
    const { acmeOrg, evilOrg } = await twoTenants(t, issuer);
    issuer.setUser({ sub: "cfo-real", email: "cfo@acme.test" });
    const res = await driveSsoSignInViaSharedCallback(t, issuer, "acme-oidc");
    expect(res.headers.get("location") ?? "").not.toContain("error=");
    const user = (await sessionOf(t, sessionCookieOf(res))).user;
    const signIns = await rows(t, acmeOrg, "auth.sso_sign_in");
    expect(signIns).toHaveLength(1);
    expect(signIns[0]).toMatchObject({ actor_id: user.id, target_id: user.id });
    expect(signIns[0]!.metadata).toMatchObject({ providerId: "acme-oidc", method: "sso" });
    expect(await rows(t, evilOrg, "auth.sso_sign_in")).toHaveLength(0);
  });
});

describe("integrators — the product-shaped Drizzle schema (hand-maintained session/member/org_policy tables)", () => {
  it("sign-up, org, invite, sign-in fan-out, failed sign-in, magic link, sign-out and org delete are all recorded, and nothing the adapter writes changes shape", async () => {
    const sent: string[] = [];
    const t = await makeProductAuth({
      plugins: [magicLink({ sendMagicLink: async ({ token }) => void sent.push(token) })],
    });
    const owner = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, owner.cookie);
    const { orgId: other } = await createOrg(t, owner.cookie, "other");
    const member = await signUpOwner(t, "member@acme.test");
    await insertProductMember(t, orgId, member.userId);
    await insertProductMember(t, other, member.userId);
    const invite = await t.api.post(
      "/organization/invite-member",
      { email: "invitee@acme.test", role: "member", organizationId: orgId },
      { cookie: owner.cookie },
    );
    expect(invite.status, await invite.clone().text()).toBe(200);

    const session = await signIn(t, "member@acme.test");
    expect(session.status).toBe(200);
    expect(await signIn(t, "member@acme.test", "wrong-password-9")).toHaveProperty("status", 401);
    expect((await t.api.post("/sign-out", {}, { cookie: extractCookie(session) })).status).toBe(
      200,
    );
    await t.api.post("/sign-in/magic-link", { email: "member@acme.test" });
    expect((await t.api.get(`/magic-link/verify?token=${sent[0]}`)).status).toBe(200);

    for (const org of [orgId, other]) {
      const actions = (await rows(t, org)).map((r) => r.action);
      expect(actions, org).toEqual(
        expect.arrayContaining(["auth.sign_in", "auth.sign_in_failed", "auth.sign_out"]),
      );
      expect(
        actions.filter((a) => a === "auth.sign_in"),
        org,
      ).toHaveLength(2);
    }
    expect((await rows(t, orgId, "member.invited")).map((r) => r.actor_id)).toEqual([owner.userId]);

    const del = await t.api.post(
      "/organization/delete",
      { organizationId: other },
      { cookie: owner.cookie },
    );
    expect(del.status).toBe(200);
    expect((await rows(t, other)).at(-1)).toMatchObject({ action: "org.deleted" });
    const verify = await t.api.get(`/enterprise/audit/verify?orgId=${orgId}`, {
      cookie: owner.cookie,
    });
    expect(await verify.json()).toEqual({ ok: true });
  });
});
