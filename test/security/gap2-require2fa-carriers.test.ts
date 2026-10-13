// GHSA-8p84-pc7q-69jr — audit gap 2, round 2: two ways a `require2fa`-bound
// session slipped the enrolment gate.
//
// Every assertion states the FIXED behaviour and is written to fail (RED) on
// the parent commit (the first round of require2fa enforcement) and pass
// (GREEN) after this round — so it drives HTTP and asserts status/codes only,
// importing no symbol the parent lacks.
//
// F1 — a session carried by `Authorization: Bearer` (upstream's `bearer()`
//      plugin) reached a gated path 200 while the same session via cookie was
//      confined 403: the gate read the session before upstream merged bearer's
//      header→cookie rewrite, so it saw no session and stood aside.
// F2 — a session minted BEFORE a `require2fa` policy came to apply to its user
//      (the org flips it on, or the user later joins/being domain-claimed by an
//      org that already required it) was never re-judged for a no-credential
//      user (SSO/magic-link/social/passkey): the create hook never saw the
//      policy and the gate exempted anyone who could not enrol. Such a session
//      stayed fully usable, its lifetime even extended by `/get-session`, and
//      impersonating such a user inherited the same unconfined session.
import { describe, expect, it } from "vitest";
import { bearer, magicLink } from "better-auth/plugins";
import type { BetterAuthOptions } from "better-auth";
import {
  createOrg,
  extractCookie,
  makeAuth as makeAuthBase,
  signUpOwner,
  type TestAuth,
} from "../helpers/auth";
import { applyMigration } from "../../src/schema";
import { enrollTotp, insertMemberRow, insertSessionCookie, setPolicy } from "./helpers";

/** Same `/two-factor/*` rate-limit relaxation the sibling suite uses — several enrolments per file share one limiter store. */
function makeAuth(overrides: Parameters<typeof makeAuthBase>[0] = {}) {
  return makeAuthBase({
    ...overrides,
    rateLimitCustomRules: {
      "/two-factor/*": { window: 10, max: 10_000 },
    } as NonNullable<BetterAuthOptions["rateLimit"]>["customRules"],
  });
}

async function codeOf(res: Response): Promise<string> {
  return ((await res.json()) as { code?: string }).code ?? "";
}

/**
 * The effective (non-empty) `session_token` cookie from a response that sets
 * more than one — `/admin/impersonate-user` first clears the admin's own token
 * and then sets the impersonation one under the same name.
 */
function effectiveSessionCookie(res: Response): string {
  const cookie = res.headers
    .getSetCookie()
    .map((raw) => raw.split(";")[0])
    .filter((c) => /better-auth\.session_token=.+/.test(c))
    .pop();
  expect(cookie, "a non-empty session_token cookie").toBeTruthy();
  return cookie as string;
}

/** An org owner who has enrolled a real TOTP factor — the only password user allowed to switch `require2fa` on. */
async function enrolledOwner(t: TestAuth, email = "owner@acme.test", slug = "acme") {
  const { cookie: signUpCookie, userId } = await signUpOwner(t, email);
  const { orgId } = await createOrg(t, signUpCookie, slug);
  const { cookie } = await enrollTotp(t, signUpCookie);
  return { cookie, userId, orgId };
}

async function requireTwoFactor(t: TestAuth, cookie: string, orgId: string) {
  const res = await setPolicy(t, cookie, { orgId, require2fa: true });
  expect(res.status).toBe(200);
}

/** The user id behind a session cookie, via `/get-session`. */
async function userIdOf(t: TestAuth, cookie: string): Promise<string> {
  const res = await t.api.get("/get-session", { cookie });
  return ((await res.json()) as { user: { id: string } }).user.id;
}

/** The smallest `expiresAt` among a user's session rows (ms). The forged 24 h session is the smallest until a refresh jumps it to the 7 d lifetime. */
async function minSessionExpiry(t: TestAuth, userId: string): Promise<number> {
  const rows = await t.client.execute({
    sql: `SELECT expiresAt FROM session WHERE userId = ? ORDER BY expiresAt ASC LIMIT 1`,
    args: [userId],
  });
  return Number(rows.rows[0]!.expiresAt);
}

/** Signs a fresh no-password user in through a real magic link and returns their cookie + id (a no-credential session, method `magic_link`). */
async function magicLinkSignIn(t: TestAuth, sent: Array<{ token: string }>, email: string) {
  sent.length = 0;
  const request = await t.api.post("/sign-in/magic-link", { email }, {});
  expect(request.status).toBe(200);
  expect(sent).toHaveLength(1);
  const verify = await t.api.get(`/magic-link/verify?token=${sent[0]!.token}`);
  expect(verify.status).toBe(200);
  const cookie = extractCookie(verify);
  expect(cookie).toContain("session_token");
  return { cookie, userId: await userIdOf(t, cookie) };
}

describe("gap 2 R2 — the Authorization: Bearer carrier is gated like the cookie (F1)", () => {
  it("an un-enrolled password member under require2fa is confined whether the session arrives by cookie or by bearer token, and /get-session by bearer is still annotated", async () => {
    const t = await makeAuth({ plugins: [bearer()] });
    const owner = await enrolledOwner(t);
    await requireTwoFactor(t, owner.cookie, owner.orgId);

    const { userId } = await signUpOwner(t, "bob@acme.test");
    await insertMemberRow(t, owner.orgId, userId, "member");

    // Bob signs in with his password: upstream does not challenge an
    // un-enrolled user, so a real (enrolment-only) session is minted, and
    // bearer's after-hook exposes its token in `set-auth-token`.
    const signIn = await t.api.post("/sign-in/email", {
      email: "bob@acme.test",
      password: "password1234",
    });
    expect(signIn.status).toBe(200);
    const token = signIn.headers.get("set-auth-token");
    expect(token, "bearer after-hook exposes the session token").toBeTruthy();
    const cookie = extractCookie(signIn);
    expect(cookie).toContain("session_token");

    // Cookie carrier — confined (the control).
    const viaCookie = await t.api.get("/organization/list", { cookie });
    expect(viaCookie.status).toBe(403);
    expect(await codeOf(viaCookie)).toBe("TWO_FACTOR_ENROLLMENT_REQUIRED");

    // Bearer carrier — must be confined too (200 before the fix).
    const viaBearer = await t.api.get("/organization/list", {
      authorization: `Bearer ${token}`,
    });
    expect(viaBearer.status, "gated path via bearer must be confined").toBe(403);
    expect(await codeOf(viaBearer)).toBe("TWO_FACTOR_ENROLLMENT_REQUIRED");

    // A second gated read, this time a write-shaped one, is confined via bearer too.
    const viaBearerWrite = await t.api.post(
      "/organization/create",
      { name: "sneaky", slug: "sneaky" },
      { authorization: `Bearer ${token}` },
    );
    expect(viaBearerWrite.status).toBe(403);

    // `/get-session` is allow-listed, so it is reachable by bearer and still
    // carries the enterprise annotation the product's redirect keys on.
    const gs = await t.api.get("/get-session", { authorization: `Bearer ${token}` });
    expect(gs.status).toBe(200);
    expect(await gs.json()).toMatchObject({
      enterprise: { require2fa: true, twoFactorEnabled: false, enrollmentRequired: true },
    });
  });
});

describe("gap 2 R2 — a session is re-judged for a policy that came to apply after it was minted (F2)", () => {
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

  it("a magic-link session minted before the org flipped require2fa on is refused on every gated path afterwards", async () => {
    const { sent, plugin } = magicSink();
    const t = await makeAuth({ plugins: [plugin] });
    const owner = await enrolledOwner(t);

    // Bob signs in by magic link while no policy applies (not yet a member).
    const bob = await magicLinkSignIn(t, sent, "bob@acme.test");
    expect((await t.api.get("/organization/list", { cookie: bob.cookie })).status).toBe(200);

    // He becomes a member, then the owner flips require2fa on.
    await insertMemberRow(t, owner.orgId, bob.userId, "member");
    await requireTwoFactor(t, owner.cookie, owner.orgId);

    const gated = await t.api.get("/organization/list", { cookie: bob.cookie });
    expect(gated.status, "the pre-flip magic-link session must now be refused").toBe(403);
    expect(await codeOf(gated)).toBe("TWO_FACTOR_REQUIRED");
    // No path to enrol (no password account): the answer is REQUIRED, not the
    // enrolment redirect — and `/get-session`, which the product's own routes
    // authorize with, no longer presents the session at all (round 3).
    const gs = await t.api.get("/get-session", { cookie: bob.cookie });
    expect(gs.status).toBe(200);
    expect(await gs.json()).toBeNull();
  });

  it("a session minted before the upgrade in an org that already required 2FA is refused once the 0003 data migration ran, and /get-session does not extend it", async () => {
    const { sent, plugin } = magicSink();
    const t = await makeAuth({ plugins: [plugin] });
    const owner = await enrolledOwner(t);
    const bob = await magicLinkSignIn(t, sent, "bob@acme.test");
    await insertMemberRow(t, owner.orgId, bob.userId, "member");
    await requireTwoFactor(t, owner.cookie, owner.orgId);

    // A session row the running version never minted — what a 1.0.x session
    // looks like: 1.0.x surfaced `require2fa` but enforced nothing, so a
    // member's magic-link session could be created after the org required a
    // second factor. Its near expiry puts it inside upstream's refresh window,
    // so `/get-session` would extend it to the 7-day lifetime unless the clamp
    // stops it.
    const forged = await insertSessionCookie(t, bob.userId);
    const beforeExpiry = await minSessionExpiry(t, bob.userId);

    // The upgrade's data migration (0003) — applied through the package runner.
    await applyMigration(t.client);

    // An enrolled member is unaffected by the migration.
    expect((await t.api.get("/organization/list", { cookie: owner.cookie })).status).toBe(200);

    const gated = await t.api.get("/organization/list", { cookie: forged });
    expect(gated.status, "a pre-upgrade no-credential session must be refused").toBe(403);
    expect(await codeOf(gated)).toBe("TWO_FACTOR_REQUIRED");

    const gs = await t.api.get("/get-session", { cookie: forged });
    expect(gs.status).toBe(200);
    expect(await gs.json()).toBeNull();
    const afterExpiry = await minSessionExpiry(t, bob.userId);
    // A refresh would push the forged session's expiry out by days; the clamp
    // keeps it where it was (allowing only clock jitter).
    expect(afterExpiry - beforeExpiry).toBeLessThan(60_000);
  });

  it("a magic-link user who joins a require2fa org after signing in is refused on the next request (a later membership, not only a flip)", async () => {
    const { sent, plugin } = magicSink();
    const t = await makeAuth({ plugins: [plugin] });
    const owner = await enrolledOwner(t);
    // require2fa is already on before Bob exists at all.
    await requireTwoFactor(t, owner.cookie, owner.orgId);

    const bob = await magicLinkSignIn(t, sent, "bob@acme.test");
    // Not a member yet — no policy reaches him, his session stands.
    expect((await t.api.get("/organization/list", { cookie: bob.cookie })).status).toBe(200);

    // He is added to the org that already required 2FA; his existing session
    // was never judged against it and must now be refused.
    await insertMemberRow(t, owner.orgId, bob.userId, "member");
    const gated = await t.api.get("/organization/list", { cookie: bob.cookie });
    expect(gated.status).toBe(403);
    expect(await codeOf(gated)).toBe("TWO_FACTOR_REQUIRED");
  });

  it("impersonating a no-credential member of a require2fa org yields a confined session, not an unconfined one", async () => {
    const { sent, plugin } = magicSink();
    const t = await makeAuth({ plugins: [plugin] });
    const owner = await enrolledOwner(t);
    const bob = await magicLinkSignIn(t, sent, "bob@acme.test");
    await insertMemberRow(t, owner.orgId, bob.userId, "member");
    await requireTwoFactor(t, owner.cookie, owner.orgId);

    // Grant the (enrolled) owner the global admin role the impersonation
    // endpoint requires, then impersonate Bob.
    await t.client.execute({
      sql: `UPDATE user SET role = ? WHERE id = ?`,
      args: ["admin", owner.userId],
    });
    const imp = await t.api.post(
      "/admin/impersonate-user",
      { userId: bob.userId },
      { cookie: owner.cookie },
    );
    expect(imp.status).toBe(200);
    const impCookie = effectiveSessionCookie(imp);

    const gated = await t.api.get("/organization/list", { cookie: impCookie });
    expect(gated.status, "the impersonation session inherits Bob's confinement").toBe(403);
    expect(await codeOf(gated)).toBe("TWO_FACTOR_REQUIRED");
  });
});
