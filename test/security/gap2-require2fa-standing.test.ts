// GHSA-8p84-pc7q-69jr — audit gap 2, round 3: which sessions stand under
// `require2fa`, as the products see it, and who may switch it on.
//
// Every assertion states the FIXED behaviour and drives HTTP (plus the
// `auth.api.getSession({ headers })` call every product authorizes its own
// routes with); no symbol the previous head lacks is imported. Each case runs
// against two deployments:
//
// - the derived schema `makeAuth` builds (millisecond timestamps), and
// - the product-shaped one (`../helpers/product-auth.ts`: klar's `session`
//   with **second**-precision timestamps, dispatch's millisecond `member` and
//   `org_policy`) — the units the requirement's timestamps are compared in
//   differ there, which is the point.
//
// C3 — a session that does not stand under the requirement was refused on
//      `/api/auth/*` but `/get-session` still returned it in full, so every
//      product route kept honouring it. It must answer `null`.
// F2 — the sessions in question: minted before the org switched the
//      requirement on, before the user joined the org, an impersonation of
//      such a user, and a session from before the upgrade (after the 0003
//      data migration).
// C2 — switching the requirement on must leave the caller a way back in.
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { BetterAuthOptions } from "better-auth";
import { magicLink } from "better-auth/plugins";
import { applyMigration } from "../../src/schema";
import {
  createOrg,
  extractCookie,
  makeAuth as makeAuthBase,
  signUpOwner,
  type TestAuth,
} from "../helpers/auth";
import { startOidcIssuer, type OidcIssuer } from "../helpers/oidc-issuer";
import {
  insertProductMember,
  insertProductSessionCookie,
  makeProductAuth,
} from "../helpers/product-auth";
import { registerOidcProvider } from "../helpers/sso";
import { driveSsoSignIn, sessionCookieOf } from "./ghsa-sso-helpers";
import { enrollTotp, insertMemberRow, insertSessionCookie, setPolicy } from "./helpers";

type Overrides = Parameters<typeof makeAuthBase>[0];

/**
 * Every case here signs in by magic link and enrols through `/two-factor/*`
 * more often than upstream's per-path limits allow (the limiter store is
 * shared across the file); relaxed as in the sibling suites — the rules under
 * test are not rate limits.
 */
const relaxed = (overrides: Overrides = {}): Overrides => ({
  ...overrides,
  rateLimitCustomRules: {
    "/two-factor/*": { window: 10, max: 10_000 },
    "/magic-link/*": { window: 10, max: 10_000 },
    "/sign-in/magic-link": { window: 10, max: 10_000 },
  } as NonNullable<BetterAuthOptions["rateLimit"]>["customRules"],
});

interface Deployment {
  name: string;
  make: (overrides?: Overrides) => Promise<TestAuth>;
  addMember: (t: TestAuth, orgId: string, userId: string, role: string) => Promise<void>;
  /** A session row this deployment never minted (created now). */
  forgeSession: (t: TestAuth, userId: string) => Promise<string>;
}

const DEPLOYMENTS: Deployment[] = [
  {
    name: "derived schema, millisecond timestamps",
    make: (o) => makeAuthBase(relaxed(o)),
    addMember: insertMemberRow,
    forgeSession: insertSessionCookie,
  },
  {
    name: "product schema, seconds session.created_at",
    make: (o) => makeProductAuth(relaxed(o)),
    addMember: (t, orgId, userId, role) => insertProductMember(t, orgId, userId, role),
    forgeSession: (t, userId) => insertProductSessionCookie(t, userId),
  },
];

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

async function codeOf(res: Response): Promise<string> {
  return ((await res.json()) as { code?: string }).code ?? "";
}

async function magicLinkSignIn(t: TestAuth, sent: Array<{ token: string }>, email: string) {
  sent.length = 0;
  expect((await t.api.post("/sign-in/magic-link", { email }, {})).status).toBe(200);
  expect(sent).toHaveLength(1);
  const verify = await t.api.get(`/magic-link/verify?token=${sent[0]!.token}`);
  expect(verify.status, await verify.clone().text()).toBe(200);
  const cookie = extractCookie(verify);
  expect(cookie).toContain("session_token");
  const gs = (await (await t.api.get("/get-session", { cookie })).json()) as {
    user: { id: string };
  };
  return { cookie, userId: gs.user.id };
}

async function enrolledOwner(t: TestAuth, email = "owner@acme.test", slug = "acme") {
  const { cookie: signUpCookie, userId } = await signUpOwner(t, email);
  const { orgId } = await createOrg(t, signUpCookie, slug);
  const { cookie, totp } = await enrollTotp(t, signUpCookie);
  return { cookie, userId, orgId, totp };
}

async function requireTwoFactor(t: TestAuth, cookie: string, orgId: string) {
  const res = await setPolicy(t, cookie, { orgId, require2fa: true });
  expect(res.status, await res.clone().text()).toBe(200);
}

/** What a product sees for this cookie: the HTTP `/get-session` body and the in-process `auth.api.getSession`. */
async function productView(t: TestAuth, cookie: string) {
  const http = await t.api.get("/get-session", { cookie });
  expect(http.status).toBe(200);
  const api = await (
    t.auth.api as unknown as { getSession: (i: { headers: Headers }) => Promise<unknown> }
  ).getSession({ headers: new Headers({ cookie }) });
  return { http: (await http.json()) as { user?: { id: string } } | null, api };
}

/** The session is refused everywhere a product could look: gate, `/get-session`, `auth.api.getSession`. */
async function expectRefused(t: TestAuth, cookie: string, label: string) {
  const gated = await t.api.get("/organization/list", { cookie });
  expect(gated.status, `${label}: gated path`).toBe(403);
  expect(await codeOf(gated), label).toBe("TWO_FACTOR_REQUIRED");
  const view = await productView(t, cookie);
  expect(view.http, `${label}: GET /get-session`).toBeNull();
  expect(view.api, `${label}: auth.api.getSession`).toBeNull();
}

/** The session stands: the product sees the user, the gated path answers. */
async function expectStands(t: TestAuth, cookie: string, userId: string, label: string) {
  const view = await productView(t, cookie);
  expect(view.http?.user?.id, `${label}: GET /get-session`).toBe(userId);
  expect((view.api as { user?: { id: string } } | null)?.user?.id, `${label}: api`).toBe(userId);
  expect((await t.api.get("/organization/list", { cookie })).status, label).toBe(200);
}

describe.each(DEPLOYMENTS)("gap 2 R3 — sessions that never stood under require2fa ($name)", (d) => {
  it("a magic-link session minted before the org switched require2fa on is invisible to the product", async () => {
    const { sent, plugin } = magicSink();
    const t = await d.make({ plugins: [plugin] });
    const owner = await enrolledOwner(t);
    const bob = await magicLinkSignIn(t, sent, "bob@acme.test");
    await d.addMember(t, owner.orgId, bob.userId, "member");
    await expectStands(t, bob.cookie, bob.userId, "before the flip");

    await requireTwoFactor(t, owner.cookie, owner.orgId);
    await expectRefused(t, bob.cookie, "pre-flip session");
    // The enrolled owner is unaffected by the flip.
    await expectStands(t, owner.cookie, owner.userId, "enrolled owner");
  });

  it("a session minted before the user joined an org that already required 2FA is invisible to the product", async () => {
    const { sent, plugin } = magicSink();
    const t = await d.make({ plugins: [plugin] });
    const owner = await enrolledOwner(t);
    await requireTwoFactor(t, owner.cookie, owner.orgId);

    const bob = await magicLinkSignIn(t, sent, "bob@acme.test");
    await expectStands(t, bob.cookie, bob.userId, "no policy reaches him yet");
    await d.addMember(t, owner.orgId, bob.userId, "member");
    await expectRefused(t, bob.cookie, "later membership");
  });

  it("an impersonation of such a user is invisible to the product", async () => {
    const { sent, plugin } = magicSink();
    const t = await d.make({ plugins: [plugin] });
    const owner = await enrolledOwner(t);
    const bob = await magicLinkSignIn(t, sent, "bob@acme.test");
    await d.addMember(t, owner.orgId, bob.userId, "member");
    await requireTwoFactor(t, owner.cookie, owner.orgId);
    await t.client.execute({
      sql: `UPDATE user SET role = ? WHERE id = ?`,
      args: ["admin", owner.userId],
    });

    const imp = await t.api.post(
      "/admin/impersonate-user",
      { userId: bob.userId },
      { cookie: owner.cookie },
    );
    expect(imp.status, await imp.clone().text()).toBe(200);
    const impCookie = imp.headers
      .getSetCookie()
      .map((raw) => raw.split(";")[0]!)
      .filter((c) => /better-auth\.session_token=.+/.test(c))
      .pop()!;
    expect(impCookie).toBeTruthy();
    await expectRefused(t, impCookie, "impersonation of a no-password member");
  });

  it("a session from before the upgrade is invisible to the product once the 0003 data migration ran", async () => {
    const { sent, plugin } = magicSink();
    const t = await d.make({ plugins: [plugin] });
    const owner = await enrolledOwner(t);
    const bob = await magicLinkSignIn(t, sent, "bob@acme.test");
    await d.addMember(t, owner.orgId, bob.userId, "member");
    await requireTwoFactor(t, owner.cookie, owner.orgId);
    // What 1.0.x left behind: a member's session created after the org
    // required 2FA (1.0.x enforced nothing).
    const legacy = await d.forgeSession(t, bob.userId);

    await applyMigration(t.client);
    await expectRefused(t, legacy, "pre-upgrade session");
    await expectStands(t, owner.cookie, owner.userId, "enrolled owner after the migration");
  });
});

describe.each(DEPLOYMENTS)(
  "gap 2 R3 — sessions judged under require2fa keep standing ($name)",
  (d) => {
    it("a session minted right after the flip through a satisfying method stands, whatever unit created_at is kept in", async () => {
      const { sent, plugin } = magicSink();
      const t = await d.make({
        plugins: [plugin],
        policy: { twoFactor: { satisfiedBy: ["magic_link"] } },
      });
      const owner = await enrolledOwner(t);
      const bob = await magicLinkSignIn(t, sent, "bob@acme.test");
      await d.addMember(t, owner.orgId, bob.userId, "member");
      await requireTwoFactor(t, owner.cookie, owner.orgId);
      await expectRefused(t, bob.cookie, "the pre-flip session");

      // Same second as the flip, in all likelihood: a seconds column would read
      // this session back as no later than the policy write.
      const again = await magicLinkSignIn(t, sent, "bob@acme.test");
      await expectStands(t, again.cookie, bob.userId, "post-flip session");
      const annotated = (await (
        await t.api.get("/get-session", { cookie: again.cookie })
      ).json()) as {
        enterprise?: unknown;
      };
      expect(annotated.enterprise).toEqual({
        require2fa: true,
        twoFactorEnabled: false,
        enrollmentRequired: false,
      });
    });

    it("any later edit of a requiring org's policy re-judges its members' older sessions (documented)", async () => {
      const { sent, plugin } = magicSink();
      const t = await d.make({
        plugins: [plugin],
        policy: { twoFactor: { satisfiedBy: ["magic_link"] } },
      });
      const owner = await enrolledOwner(t);
      await requireTwoFactor(t, owner.cookie, owner.orgId);
      const { userId } = await magicLinkSignIn(t, sent, "bob@acme.test");
      await d.addMember(t, owner.orgId, userId, "member");
      const bob = await magicLinkSignIn(t, sent, "bob@acme.test");
      await expectStands(t, bob.cookie, bob.userId, "judged session");

      // Past the judged session's stamp (the second after next), then an edit.
      await new Promise((resolve) => setTimeout(resolve, 2100));
      const edit = await setPolicy(t, owner.cookie, { orgId: owner.orgId, sessionMaxAgeS: 3600 });
      expect(edit.status).toBe(200);
      await expectRefused(t, bob.cookie, "session older than the policy edit");
      const fresh = await magicLinkSignIn(t, sent, "bob@acme.test");
      await expectStands(t, fresh.cookie, bob.userId, "a new sign-in");
    });
  },
);

describe.each(DEPLOYMENTS)(
  "gap 2 R3 — SSO with just-in-time membership into a require2fa org ($name)",
  (d) => {
    let issuer: OidcIssuer;
    beforeAll(async () => {
      issuer = await startOidcIssuer();
    });
    afterAll(async () => {
      await issuer.close();
    });

    it("the first SSO sign-in stands although upstream provisions the membership after creating the session", async () => {
      const t = await d.make({ trustedOrigins: [issuer.issuerUrl] });
      const owner = await enrolledOwner(t);
      await registerOidcProvider(t, owner.cookie, owner.orgId, issuer, "acme-oidc", "acme.test");
      await requireTwoFactor(t, owner.cookie, owner.orgId);

      issuer.setUser({ sub: `alice-${d.name.length}`, email: "alice@acme.test" });
      const first = await driveSsoSignIn(t, issuer, "acme-oidc");
      expect(first.headers.get("location") ?? "").not.toContain("error=");
      const cookie = sessionCookieOf(first);
      const view = await productView(t, cookie);
      const aliceId = view.http?.user?.id;
      expect(aliceId, "first SSO session visible").toBeTruthy();
      const orgs = await t.api.get("/organization/list", { cookie });
      expect(orgs.status).toBe(200);
      expect(((await orgs.json()) as Array<{ id: string }>).map((o) => o.id)).toContain(
        owner.orgId,
      );
    });
  },
);

describe("gap 2 R3 — switching require2fa on leaves the caller a way back in (C2)", () => {
  let issuer: OidcIssuer;
  beforeAll(async () => {
    issuer = await startOidcIssuer();
  });
  afterAll(async () => {
    await issuer.close();
  });

  async function readRequire2fa(t: TestAuth, cookie: string, orgId: string): Promise<boolean> {
    const res = await t.api.get(`/enterprise/policy?orgId=${orgId}`, { cookie });
    expect(res.status).toBe(200);
    return ((await res.json()) as { require2fa: boolean }).require2fa;
  }

  it.each(DEPLOYMENTS)(
    "a magic-link-only admin (no password, no SSO) is refused with REQUIRE_2FA_PRECONDITION and keeps a working org ($name)",
    async (d) => {
      const { sent, plugin } = magicSink();
      const t = await d.make({ plugins: [plugin] });
      const admin = await magicLinkSignIn(t, sent, "alice@acme.test");
      const { orgId } = await createOrg(t, admin.cookie, "acme");

      const refused = await setPolicy(t, admin.cookie, { orgId, require2fa: true });
      expect(refused.status).toBe(400);
      expect(await codeOf(refused)).toBe("REQUIRE_2FA_PRECONDITION");
      expect(await readRequire2fa(t, admin.cookie, orgId)).toBe(false);
      await expectStands(t, admin.cookie, admin.userId, "the admin after the refusal");
      // A fresh magic-link sign-in still works: nothing was bricked.
      const again = await magicLinkSignIn(t, sent, "alice@acme.test");
      await expectStands(t, again.cookie, admin.userId, "a new sign-in");
    },
  );

  it("an org SSO provider for another domain, or satisfiedBy without sso, does not qualify a magic-link admin", async () => {
    for (const setup of ["other-domain", "no-sso-in-satisfiedBy"] as const) {
      const { sent, plugin } = magicSink();
      const t = await makeAuthBase(
        relaxed({
          plugins: [plugin],
          trustedOrigins: [issuer.issuerUrl],
          ...(setup === "no-sso-in-satisfiedBy"
            ? { policy: { twoFactor: { satisfiedBy: [] } } }
            : {}),
        }),
      );
      const admin = await magicLinkSignIn(t, sent, "alice@acme.test");
      const { orgId } = await createOrg(t, admin.cookie, "acme");
      await registerOidcProvider(
        t,
        admin.cookie,
        orgId,
        issuer,
        `p-${setup}`,
        setup === "other-domain" ? "elsewhere.test" : "acme.test",
      );

      const refused = await setPolicy(t, admin.cookie, { orgId, require2fa: true });
      expect(refused.status, setup).toBe(400);
      expect(await codeOf(refused), setup).toBe("REQUIRE_2FA_PRECONDITION");
      expect(await readRequire2fa(t, admin.cookie, orgId), setup).toBe(false);
    }
  });

  it("an enrolled admin may switch it on, keeps working, and signs in again through the 2FA challenge", async () => {
    const t = await makeAuthBase(relaxed());
    const owner = await enrolledOwner(t);
    await requireTwoFactor(t, owner.cookie, owner.orgId);
    await expectStands(t, owner.cookie, owner.userId, "enrolled owner right after the flip");

    const signIn = await t.api.post("/sign-in/email", {
      email: "owner@acme.test",
      password: "password1234",
    });
    expect(signIn.status).toBe(200);
    expect(await signIn.json()).toMatchObject({ twoFactorRedirect: true });
    const verify = await t.api.post(
      "/two-factor/verify-totp",
      { code: await owner.totp() },
      { cookie: extractCookie(signIn) },
    );
    expect(verify.status).toBe(200);
    const cookie = extractCookie(verify);
    await expectStands(t, cookie, owner.userId, "re-signed-in owner");
    expect(await readRequire2fa(t, cookie, owner.orgId)).toBe(true);
  });
});
