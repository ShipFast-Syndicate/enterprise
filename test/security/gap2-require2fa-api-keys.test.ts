// GHSA-8p84-pc7q-69jr — audit gap 2, round 4: `require2fa` and the API-key
// carrier under the opt-in mock session (`apiKeys.enableSessionForAPIKeys`).
//
// Every assertion states the FIXED behaviour and drives HTTP plus the two
// server-side calls products make (`auth.api.getSession({ headers })`,
// `auth.api.verifyApiKey`); no symbol the previous head lacks is imported, so
// the file runs — and fails — there too.
//
// S1 — upstream's api-key before-hook builds a mock session from the key and,
//      on `/get-session`, returns it itself: better-auth's dispatcher returns a
//      before-hook's answer without running any after-hook, so the
//      `/get-session` judgement never saw a key. A key created before its
//      no-password owner's org switched `require2fa` on (E1), and a key of an
//      un-enrolled password holder (E2), kept yielding the owner's full
//      session while the owner's cookie session was refused or confined. The
//      key's owner must be judged by the session rule, with the key row's own
//      `createdAt` in place of the session's.
//
// Each case runs on the derived schema and on the product-shaped one
// (`../helpers/product-auth.ts`: klar's `session` in seconds, dispatch's
// millisecond `member` and `org_policy`).
import { describe, expect, it } from "vitest";
import type { BetterAuthOptions } from "better-auth";
import { apiKey } from "@better-auth/api-key";
import { magicLink } from "better-auth/plugins";
import {
  createOrg,
  extractCookie,
  makeAuth as makeAuthBase,
  signUpOwner,
  type TestAuth,
} from "../helpers/auth";
import { insertProductMember, makeProductAuth } from "../helpers/product-auth";
import { enterpriseApiKeyValidator } from "../../src/server/api-keys";
import { enrollTotp, insertMemberRow, setPolicy } from "./helpers";

type Overrides = Parameters<typeof makeAuthBase>[0];

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
}

const DEPLOYMENTS: Deployment[] = [
  {
    name: "derived schema, millisecond timestamps",
    make: (o) => makeAuthBase(relaxed(o)),
    addMember: insertMemberRow,
  },
  {
    name: "product schema, seconds session.created_at",
    make: (o) => makeProductAuth(relaxed(o)),
    addMember: (t, orgId, userId, role) => insertProductMember(t, orgId, userId, role),
  },
];

/** The supported opt-in: the preset builds the api-key plugin with the mock session on. */
const OPT_IN = { apiKeys: { enableSessionForAPIKeys: true } } as const;

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
  const { cookie } = await enrollTotp(t, signUpCookie);
  return { cookie, userId, orgId };
}

async function requireTwoFactor(t: TestAuth, cookie: string, orgId: string) {
  const res = await setPolicy(t, cookie, { orgId, require2fa: true });
  expect(res.status, await res.clone().text()).toBe(200);
}

async function createKey(t: TestAuth, cookie: string, orgId: string) {
  const res = await t.api.post(
    "/api-key/create",
    { name: "ci", organizationId: orgId },
    { cookie },
  );
  expect(res.status, await res.clone().text()).toBe(200);
  return ((await res.json()) as { key: string }).key;
}

interface ServerApi {
  getSession: (input: { headers: Headers }) => Promise<unknown>;
  verifyApiKey: (input: {
    body: { key: string };
  }) => Promise<{ valid: boolean; error: { code?: string } | null }>;
}
const serverApi = (t: TestAuth) => t.auth.api as unknown as ServerApi;

/** What a product sees for a key: the HTTP `/get-session` body and `auth.api.getSession`. */
async function keyView(t: TestAuth, key: string) {
  const http = await t.api.get("/get-session", { "x-api-key": key });
  const body =
    http.status === 200 ? ((await http.json()) as { user?: { id: string } } | null) : undefined;
  const api = (await serverApi(t)
    .getSession({ headers: new Headers({ "x-api-key": key }) })
    .catch((e: { body?: { code?: string } }) => ({ thrown: e.body?.code ?? "error" }))) as
    { user?: { id: string } } | { thrown: string } | null;
  return { status: http.status, body, api };
}

async function expectKeyRefused(t: TestAuth, key: string, code: string, label: string) {
  const view = await keyView(t, key);
  expect(view.status, `${label}: GET /get-session status`).toBe(200);
  expect(view.body, `${label}: GET /get-session`).toBeNull();
  expect(view.api, `${label}: auth.api.getSession`).toBeNull();
  const verified = await serverApi(t).verifyApiKey({ body: { key } });
  expect(verified.valid, `${label}: verifyApiKey`).toBe(false);
  expect(verified.error?.code, `${label}: verifyApiKey code`).toBe(code);
}

async function expectKeyStands(t: TestAuth, key: string, userId: string, label: string) {
  const view = await keyView(t, key);
  expect(view.status, `${label}: GET /get-session status`).toBe(200);
  expect(view.body?.user?.id, `${label}: GET /get-session`).toBe(userId);
  expect((view.api as { user?: { id: string } } | null)?.user?.id, `${label}: api`).toBe(userId);
  expect((await serverApi(t).verifyApiKey({ body: { key } })).valid, `${label}: verify`).toBe(true);
}

describe.each(DEPLOYMENTS)(
  "gap 2 R4 — a key's owner is judged under require2fa like a session ($name)",
  (d) => {
    it("E1: a no-password member's key created before the org switched require2fa on yields no session — HTTP /get-session and auth.api.getSession answer null, verifyApiKey refuses; a key created later by a judged session stands", async () => {
      const { sent, plugin } = magicSink();
      const t = await d.make({
        ...OPT_IN,
        plugins: [plugin],
        policy: { twoFactor: { satisfiedBy: ["magic_link"] } },
      });
      const owner = await enrolledOwner(t);
      const bob = await magicLinkSignIn(t, sent, "bob@other.test");
      await d.addMember(t, owner.orgId, bob.userId, "member");
      const oldKey = await createKey(t, bob.cookie, owner.orgId);
      await expectKeyStands(t, oldKey, bob.userId, "before the flip");

      await requireTwoFactor(t, owner.cookie, owner.orgId);
      // The owner's cookie session is refused (round 3) and cannot mint a key.
      expect((await t.api.get("/organization/list", { cookie: bob.cookie })).status).toBe(403);
      const mint = await t.api.post(
        "/api-key/create",
        { name: "ci2", organizationId: owner.orgId },
        { cookie: bob.cookie },
      );
      expect(mint.status).toBe(403);
      expect(await codeOf(mint)).toBe("TWO_FACTOR_REQUIRED");
      // …and neither does the key he minted before it.
      await expectKeyRefused(t, oldKey, "TWO_FACTOR_REQUIRED", "pre-flip key");

      // A sign-in through a satisfying method is judged; a key it mints stands.
      const judged = await magicLinkSignIn(t, sent, "bob@other.test");
      const newKey = await createKey(t, judged.cookie, owner.orgId);
      await expectKeyStands(t, newKey, bob.userId, "key minted by a judged session");
      await expectKeyRefused(t, oldKey, "TWO_FACTOR_REQUIRED", "pre-flip key, still");
      // The key is still confined to the allow-list (PR-4), whatever its standing.
      const gated = await t.api.get("/organization/list", { "x-api-key": newKey });
      expect(gated.status).toBe(403);
      expect(await codeOf(gated)).toBe("API_KEY_NOT_ALLOWED_HERE");
    });

    it("E1: joining a requiring org makes the joiner's older key stand no more", async () => {
      const { sent, plugin } = magicSink();
      const t = await d.make({ ...OPT_IN, plugins: [plugin] });
      const owner = await enrolledOwner(t);
      await requireTwoFactor(t, owner.cookie, owner.orgId);
      const bob = await magicLinkSignIn(t, sent, "bob@other.test");
      const { orgId: bobOrg } = await createOrg(t, bob.cookie, "bob-co");
      const key = await createKey(t, bob.cookie, bobOrg);
      await expectKeyStands(t, key, bob.userId, "no requiring org yet");
      // Membership one second later, so it reads as after the key in any unit.
      await new Promise((resolve) => setTimeout(resolve, 1100));
      await d.addMember(t, owner.orgId, bob.userId, "member");
      await expectKeyRefused(t, key, "TWO_FACTOR_REQUIRED", "key older than the membership");
    });

    it("E2: an un-enrolled password member's key yields no session under require2fa (a key cannot carry enrollmentRequired); it stands again once the member enrols", async () => {
      const t = await d.make(OPT_IN);
      const owner = await enrolledOwner(t);
      const carol = await signUpOwner(t, "carol@other.test");
      await d.addMember(t, owner.orgId, carol.userId, "member");
      const key = await createKey(t, carol.cookie, owner.orgId);
      await expectKeyStands(t, key, carol.userId, "before the flip");

      await requireTwoFactor(t, owner.cookie, owner.orgId);
      const viaCookie = await t.api.get("/organization/list", { cookie: carol.cookie });
      expect(viaCookie.status).toBe(403);
      expect(await codeOf(viaCookie)).toBe("TWO_FACTOR_ENROLLMENT_REQUIRED");
      await expectKeyRefused(t, key, "TWO_FACTOR_ENROLLMENT_REQUIRED", "un-enrolled owner");

      await enrollTotp(t, carol.cookie);
      await expectKeyStands(t, key, carol.userId, "after enrolment");
    });

    it("control: keys of members of orgs that do not require 2FA keep working, next to an org that does", async () => {
      const { sent, plugin } = magicSink();
      const t = await d.make({ ...OPT_IN, plugins: [plugin] });
      const strict = await enrolledOwner(t, "strict@acme.test", "strict");
      await requireTwoFactor(t, strict.cookie, strict.orgId);
      const other = await signUpOwner(t, "other@beta.test");
      const { orgId: otherOrg } = await createOrg(t, other.cookie, "beta");
      const dave = await magicLinkSignIn(t, sent, "dave@beta.test");
      await d.addMember(t, otherOrg, dave.userId, "member");
      await expectKeyStands(t, await createKey(t, other.cookie, otherOrg), other.userId, "owner");
      await expectKeyStands(t, await createKey(t, dave.cookie, otherOrg), dave.userId, "member");
    });
  },
);

describe("gap 2 R4 — the key-owner judgement holds for a key carried another way", () => {
  it("a hand-composed apiKey() reading the key from its own header (customAPIKeyGetter, no header-alone layer, no preset companion) is refused 403 by enterpriseApiKeyValidator", async () => {
    const { sent, plugin } = magicSink();
    const t = await makeAuthBase(
      relaxed({
        plugins: [plugin],
        apiKeyPlugin: apiKey({
          enableSessionForAPIKeys: true,
          customAPIKeyGetter: (ctx) => ctx.headers?.get("x-custom-key") ?? null,
          customAPIKeyValidator: enterpriseApiKeyValidator,
          keyExpiration: { defaultExpiresIn: 90 * 24 * 3600, maxExpiresIn: 365 },
        }),
      }),
    );
    const owner = await enrolledOwner(t);
    const bob = await magicLinkSignIn(t, sent, "bob@other.test");
    await insertMemberRow(t, owner.orgId, bob.userId, "member");
    const key = await createKey(t, bob.cookie, owner.orgId);
    const before = await t.api.get("/get-session", { "x-custom-key": key });
    expect(((await before.json()) as { user: { id: string } }).user.id).toBe(bob.userId);

    await requireTwoFactor(t, owner.cookie, owner.orgId);
    const after = await t.api.get("/get-session", { "x-custom-key": key });
    expect(after.status).toBe(403);
    expect(await codeOf(after)).toBe("TWO_FACTOR_REQUIRED");
    await expect(
      serverApi(t).getSession({ headers: new Headers({ "x-custom-key": key }) }),
    ).rejects.toMatchObject({ body: { code: "TWO_FACTOR_REQUIRED" } });
  });
});
