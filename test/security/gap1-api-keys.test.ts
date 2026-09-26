// Gap 1 (security audit 3 critique, 2026-09-25; F-21 inverse) — API keys
// were a complete ban/deprovisioning bypass.
//
// Upstream `@better-auth/api-key` keys are user-global bearer credentials
// that never pass through session creation, so none of the session-time
// controls ran for them: `/admin/ban-user` and `/admin/remove-user` killed
// the sessions and left every key working (the row even outlived the user
// row), a key had no expiry unless the caller asked, the opt-in mock session
// (`enableSessionForAPIKeys`) authenticated a *banned* user, and — with that
// mock session on — a key could mint further keys and drive the whole
// `/enterprise/*` management surface as its owner. Only a SCIM deactivation
// deleted keys, and PR-1's owner carve-out let a SCIM user who had created
// their own organization keep them through that too.
//
// Fix (`src/server/api-keys.ts`, wired by `preset.ts`, `gate.ts`, `scim.ts`):
// every key use is bound to the live user row (`USER_BANNED` /
// `USER_NOT_FOUND`), keys expire (90 days by default, never longer than
// `apiKeys.maxExpiresInDays`), every deprovisioning path revokes them and
// audits `api_key.revoked` into every org the user belonged to, and the
// management surface refuses any request carrying an API key
// (`API_KEY_NOT_ALLOWED_HERE`).

import { describe, expect, it } from "vitest";
import { apiKey } from "@better-auth/api-key";
import {
  API_KEY_HEADERS,
  assertNotApiKeyRequest,
  enterpriseApiKeyValidator,
  revokeUserApiKeys,
} from "../../src/server/api-keys";
import { makeAuth, signUpOwner, createOrg, type TestAuth } from "../helpers/auth";
import {
  auditRows,
  coreUserId,
  createScimUser,
  insertMemberRow,
  insertSessionCookie,
  mintScimToken,
} from "./helpers";

const DAY_S = 24 * 60 * 60;

async function makeAdmin(t: TestAuth, userId: string) {
  await t.client.execute({ sql: `UPDATE user SET role = 'admin' WHERE id = ?`, args: [userId] });
}

async function createKey(
  t: TestAuth,
  cookie: string,
  orgId: string,
  extra: Record<string, unknown> = {},
) {
  const res = await t.api.post(
    "/api-key/create",
    { name: "ci", organizationId: orgId, ...extra },
    {
      cookie,
    },
  );
  return {
    res,
    body: res.ok
      ? ((await res.json()) as { key: string; id: string; expiresAt: string | null })
      : null,
  };
}

/** A plain member of `orgId` holding one key. */
async function memberWithKey(t: TestAuth, orgId: string, email = "member@acme.test") {
  const { cookie, userId } = await signUpOwner(t, email);
  await insertMemberRow(t, orgId, userId, "member");
  const { res, body } = await createKey(t, cookie, orgId);
  expect(res.status).toBe(200);
  return { cookie, userId, key: body!.key, keyId: body!.id, expiresAt: body!.expiresAt };
}

/** `auth.api.verifyApiKey` — the server-only path products use (not part of the preset's inferred endpoint type). */
const verify = (t: TestAuth, key: string) =>
  (
    t.auth.api as unknown as {
      verifyApiKey: (input: {
        body: { key: string };
      }) => Promise<{ valid: boolean; error: { code?: string } | null }>;
    }
  ).verifyApiKey({ body: { key } });

async function keyRows(t: TestAuth, userId: string) {
  const res = await t.client.execute({
    sql: `SELECT id FROM apikey WHERE referenceId = ?`,
    args: [userId],
  });
  return res.rows.length;
}

async function revokedRows(t: TestAuth, orgId: string) {
  return (await auditRows(t, orgId)).filter((r) => r.action === "api_key.revoked");
}

/** The integrator's documented opt-in recipe: mock sessions from `x-api-key`, still bound to the user. */
const optIn = () =>
  makeAuth({
    apiKeyPlugin: apiKey({
      enableSessionForAPIKeys: true,
      apiKeyHeaders: [...API_KEY_HEADERS],
      customAPIKeyValidator: enterpriseApiKeyValidator,
    }),
  });

const errorCode = async (res: Response) => ((await res.json()) as { code?: string }).code;

describe("gap 1 — keys are bounded by expiry", () => {
  it("a key created without expiresIn expires after 90 days by default; apiKeys.defaultExpiresInS is in seconds and null means never", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);
    const { expiresAt } = await memberWithKey(t, orgId);
    expect(expiresAt).not.toBeNull();
    const days = (new Date(expiresAt!).getTime() - Date.now()) / 86_400_000;
    expect(days).toBeGreaterThan(89.9);
    expect(days).toBeLessThanOrEqual(90);

    // Seconds, not milliseconds (upstream's `.d.mts` says ms; `create` uses
    // `getDate(…, "sec")`): 3600 must land one hour out, not one second.
    const hourly = await makeAuth({ apiKeys: { defaultExpiresInS: 3600 } });
    const h = await signUpOwner(hourly);
    const { orgId: hOrg } = await createOrg(hourly, h.cookie);
    const { expiresAt: hExpires } = await memberWithKey(hourly, hOrg);
    const seconds = (new Date(hExpires!).getTime() - Date.now()) / 1000;
    expect(seconds).toBeGreaterThan(3500);
    expect(seconds).toBeLessThanOrEqual(3600);

    const never = await makeAuth({ apiKeys: { defaultExpiresInS: null } });
    const n = await signUpOwner(never);
    const { orgId: nOrg } = await createOrg(never, n.cookie);
    expect((await memberWithKey(never, nOrg)).expiresAt).toBeNull();
  });

  it("a requested lifetime above apiKeys.maxExpiresInDays (default 365) is refused", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);
    const tooLong = await createKey(t, cookie, orgId, { expiresIn: 366 * DAY_S });
    expect(tooLong.res.status).toBe(400);
    expect(await errorCode(tooLong.res)).toBe("EXPIRES_IN_IS_TOO_LARGE");
    const atMax = await createKey(t, cookie, orgId, { expiresIn: 365 * DAY_S });
    expect(atMax.res.status).toBe(200);

    const tight = await makeAuth({ apiKeys: { maxExpiresInDays: 30 } });
    const o = await signUpOwner(tight);
    const { orgId: tOrg } = await createOrg(tight, o.cookie);
    expect((await createKey(tight, o.cookie, tOrg, { expiresIn: 31 * DAY_S })).res.status).toBe(
      400,
    );
    expect((await createKey(tight, o.cookie, tOrg, { expiresIn: 30 * DAY_S })).res.status).toBe(
      200,
    );
  });
});

describe("gap 1 — keys are bound to the user at use time (verify path, preset defaults)", () => {
  it("a healthy user's key verifies; an unknown key is still upstream's INVALID_API_KEY (controls)", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);
    const { key } = await memberWithKey(t, orgId);
    expect((await verify(t, key)).valid).toBe(true);
    const unknown = await verify(t, "not-a-key-".repeat(8));
    expect(unknown.valid).toBe(false);
    expect(unknown.error?.code).toBe("INVALID_API_KEY");
  });

  it("/admin/ban-user deletes the keys, audits api_key.revoked into every org the user belongs to, and the key is gone at verify", async () => {
    const t = await makeAuth();
    const { cookie, userId: ownerId } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);
    const other = await signUpOwner(t, "other@beta.test");
    const { orgId: orgB } = await createOrg(t, other.cookie, "beta");
    const { userId, key, keyId } = await memberWithKey(t, orgId);
    await insertMemberRow(t, orgB, userId, "member");
    await makeAdmin(t, ownerId);

    expect((await t.api.post("/admin/ban-user", { userId }, { cookie })).status).toBe(200);

    expect(await keyRows(t, userId)).toBe(0);
    for (const org of [orgId, orgB]) {
      const rows = await revokedRows(t, org);
      expect(rows).toHaveLength(1);
      expect(rows[0]!.target_type).toBe("api_key");
      expect(rows[0]!.target_id).toBe(keyId);
      expect(rows[0]!.actor_type).toBe("user");
      expect(rows[0]!.actor_id).toBe(ownerId);
      expect(JSON.parse(String(rows[0]!.metadata))).toEqual({ reason: "admin.ban", userId });
    }
    const after = await verify(t, key);
    expect(after.valid).toBe(false);
    expect(after.error?.code).toBe("INVALID_API_KEY"); // the row is gone
  });

  it("a ban written straight to the database is honoured at use time (USER_BANNED); an expired temporary ban is not a ban", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);
    const { key, userId } = await memberWithKey(t, orgId);
    await t.client.execute({ sql: `UPDATE user SET banned = 1 WHERE id = ?`, args: [userId] });
    const banned = await verify(t, key);
    expect(banned.valid).toBe(false);
    expect(banned.error?.code).toBe("USER_BANNED");
    // A live temporary ban is a ban …
    await t.client.execute({
      sql: `UPDATE user SET banExpires = ? WHERE id = ?`,
      args: [Date.now() + 60_000, userId],
    });
    expect((await verify(t, key)).error?.code).toBe("USER_BANNED");
    // … an expired one is not (mirrors `admin()`'s session hook).
    await t.client.execute({
      sql: `UPDATE user SET banExpires = ? WHERE id = ?`,
      args: [Date.now() - 1000, userId],
    });
    expect((await verify(t, key)).valid).toBe(true);
  });

  it("/admin/remove-user leaves no orphan key and audits into the orgs captured before the member rows vanished; a stale orphan is refused USER_NOT_FOUND", async () => {
    const t = await makeAuth();
    const { cookie, userId: ownerId } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);
    const { userId, key, keyId } = await memberWithKey(t, orgId);
    await makeAdmin(t, ownerId);
    expect((await t.api.post("/admin/remove-user", { userId }, { cookie })).status).toBe(200);
    expect(await keyRows(t, userId)).toBe(0);
    const rows = await revokedRows(t, orgId);
    expect(rows).toHaveLength(1);
    expect(rows[0]!.target_id).toBe(keyId);
    expect(rows[0]!.actor_id).toBe(ownerId);
    expect(JSON.parse(String(rows[0]!.metadata))).toEqual({ reason: "admin.remove", userId });
    expect((await verify(t, key)).valid).toBe(false);

    // A key row that outlived its user before this release — refused at use.
    const { key: k2, userId: u2 } = await memberWithKey(t, orgId, "m2@acme.test");
    for (const table of ["session", "account", "member"]) {
      await t.client.execute({ sql: `DELETE FROM ${table} WHERE userId = ?`, args: [u2] });
    }
    await t.client.execute({ sql: `DELETE FROM user WHERE id = ?`, args: [u2] });
    const orphan = await verify(t, k2);
    expect(orphan.valid).toBe(false);
    expect(orphan.error?.code).toBe("USER_NOT_FOUND");
  });

  it("a refused ban-user (non-admin caller) keeps the keys and writes no api_key.revoked row", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);
    const { userId } = await memberWithKey(t, orgId);
    const res = await t.api.post("/admin/ban-user", { userId }, { cookie }); // owner is not admin
    expect(res.status).toBe(403);
    expect(await keyRows(t, userId)).toBe(1);
    expect(await revokedRows(t, orgId)).toHaveLength(0);
  });

  it("revoking sessions alone is not a key revocation (documented: the identity is unchanged)", async () => {
    const t = await makeAuth();
    const { cookie, userId: ownerId } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);
    const { userId, key } = await memberWithKey(t, orgId);
    await makeAdmin(t, ownerId);
    expect((await t.api.post("/admin/revoke-user-sessions", { userId }, { cookie })).status).toBe(
      200,
    );
    expect((await verify(t, key)).valid).toBe(true);
    expect(await revokedRows(t, orgId)).toHaveLength(0);
  });

  it("with audit.chainKey set, api_key.revoked rows are keyed links of the org chain", async () => {
    const t = await makeAuth({ audit: { chainKey: "k".repeat(32) } });
    const { cookie, userId: ownerId } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);
    const { userId } = await memberWithKey(t, orgId);
    await makeAdmin(t, ownerId);
    expect((await t.api.post("/admin/ban-user", { userId }, { cookie })).status).toBe(200);
    const rows = await revokedRows(t, orgId);
    expect(rows).toHaveLength(1);
    expect(String(rows[0]!.hash).startsWith("hmac:")).toBe(true);
  });
});

describe("gap 1 — opt-in mock session (enableSessionForAPIKeys) stays bound to the user", () => {
  it("a banned user's key is refused 401 USER_BANNED on /get-session; a removed user's orphan key 401 USER_NOT_FOUND", async () => {
    const t = await optIn();
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);
    const { userId, key } = await memberWithKey(t, orgId);
    const before = await t.api.get("/get-session", { "x-api-key": key });
    expect(before.status).toBe(200);
    expect(((await before.json()) as { user: { id: string } }).user.id).toBe(userId);

    await t.client.execute({ sql: `UPDATE user SET banned = 1 WHERE id = ?`, args: [userId] });
    const banned = await t.api.get("/get-session", { "x-api-key": key });
    expect(banned.status).toBe(401);
    expect(await errorCode(banned)).toBe("USER_BANNED");

    const { key: k2, userId: u2 } = await memberWithKey(t, orgId, "m2@acme.test");
    for (const table of ["session", "account", "member"]) {
      await t.client.execute({ sql: `DELETE FROM ${table} WHERE userId = ?`, args: [u2] });
    }
    await t.client.execute({ sql: `DELETE FROM user WHERE id = ?`, args: [u2] });
    const orphan = await t.api.get("/get-session", { "x-api-key": k2 });
    expect(orphan.status).toBe(401);
    expect(await errorCode(orphan)).toBe("USER_NOT_FOUND");
  });

  it("a key cannot self-mint, reach /enterprise/*, mint SCIM tokens or register SSO; a product endpoint still works", async () => {
    const t = await optIn();
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);
    const { body } = await createKey(t, cookie, orgId);
    const headers = { "x-api-key": body!.key };

    const mint = await t.api.post(
      "/api-key/create",
      { name: "child", organizationId: orgId },
      headers,
    );
    expect(mint.status).toBe(403);
    expect(await errorCode(mint)).toBe("API_KEY_NOT_ALLOWED_HERE");
    const keys = await t.client.execute(`SELECT id FROM apikey`);
    expect(keys.rows).toHaveLength(1); // nothing minted

    const refused = [
      t.api.get(`/enterprise/policy?orgId=${orgId}`, headers),
      t.api.post("/enterprise/policy/set", { orgId, require2fa: false }, headers),
      t.api.post("/enterprise/scim/tokens/create", { providerId: "okta", orgId }, headers),
      t.api.get(`/enterprise/scim/tokens?orgId=${orgId}`, headers),
      t.api.get(`/enterprise/audit/list?orgId=${orgId}`, headers),
      t.api.get(`/enterprise/members?orgId=${orgId}`, headers),
      t.api.post(
        "/sso/register",
        {
          providerId: "okta",
          issuer: "https://idp.acme.test",
          domain: "acme.test",
          organizationId: orgId,
          oidcConfig: { clientId: "x", clientSecret: "y" },
        },
        headers,
      ),
      t.api.post("/organization/create-team", { name: "t", organizationId: orgId }, headers),
    ];
    for (const res of await Promise.all(refused)) {
      expect(res.status).toBe(403);
      expect(await errorCode(res)).toBe("API_KEY_NOT_ALLOWED_HERE");
    }
    expect((await t.client.execute(`SELECT id FROM scimManagedConnection`)).rows).toHaveLength(0);
    expect((await t.client.execute(`SELECT id FROM ssoProvider`)).rows).toHaveLength(0);

    const gs = await t.api.get("/get-session", headers);
    expect(gs.status).toBe(200);
  });
});

describe("gap 1 — the management surface refuses any request carrying an API key (preset defaults too)", () => {
  it("the header alone is refused on /api-key/create even next to a valid session cookie; the same request without it succeeds", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);
    const { body } = await createKey(t, cookie, orgId);
    const withHeader = await t.api.post(
      "/api-key/create",
      { name: "child", organizationId: orgId },
      { cookie, "x-api-key": body!.key },
    );
    expect(withHeader.status).toBe(403);
    expect(await errorCode(withHeader)).toBe("API_KEY_NOT_ALLOWED_HERE");
    const pol = await t.api.get(`/enterprise/policy?orgId=${orgId}`, {
      cookie,
      "x-api-key": "anything",
    });
    expect(pol.status).toBe(403);
    expect(await errorCode(pol)).toBe("API_KEY_NOT_ALLOWED_HERE");
    expect((await createKey(t, cookie, orgId)).res.status).toBe(200);
  });

  it("assertNotApiKeyRequest: throws API_KEY_NOT_ALLOWED_HERE for any configured header, passes otherwise", () => {
    expect(() => assertNotApiKeyRequest({})).not.toThrow();
    expect(() => assertNotApiKeyRequest({ headers: null })).not.toThrow();
    expect(() => assertNotApiKeyRequest({ headers: new Headers({ cookie: "a=b" }) })).not.toThrow();
    expect(() =>
      assertNotApiKeyRequest({ headers: new Headers({ "x-api-key": "" }) }),
    ).not.toThrow();
    for (const name of API_KEY_HEADERS) {
      expect(() =>
        assertNotApiKeyRequest({ headers: new Headers({ [name.toUpperCase()]: "k" }) }),
      ).toThrow(
        expect.objectContaining({
          body: expect.objectContaining({ code: "API_KEY_NOT_ALLOWED_HERE" }),
        }),
      );
    }
  });
});

describe("gap 1 — revokeUserApiKeys", () => {
  it("returns 0 and writes nothing for a user without keys; otherwise audits per key per org, orgIds option included", async () => {
    const t = await makeAuth();
    const { cookie, userId: ownerId } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);
    const ctx = { context: await t.auth.$context };
    const actor = { actorType: "system" as const, actorId: null };
    expect(await revokeUserApiKeys(ctx, ownerId, actor, "test")).toBe(0);
    expect(await revokedRows(t, orgId)).toHaveLength(0);

    const { userId } = await memberWithKey(t, orgId);
    expect((await createKey(t, await insertSessionCookie(t, userId), orgId)).res.status).toBe(200);
    expect(await revokeUserApiKeys(ctx, userId, actor, "test", { orgIds: ["org_gone"] })).toBe(2);
    expect(await keyRows(t, userId)).toBe(0);
    expect(await revokedRows(t, orgId)).toHaveLength(2);
    const gone = await revokedRows(t, "org_gone");
    expect(gone).toHaveLength(2);
    expect(gone[0]!.actor_type).toBe("system");
    expect(JSON.parse(String(gone[0]!.metadata))).toEqual({ reason: "test", userId });
  });
});

describe("gap 1 — SCIM deactivation of a user who owns another organization (PR-1 residual)", () => {
  it("a SCIM user who created their own org is not banned (F-07) but loses every key; audited into both orgs, the skipped ban into the provisioning org", async () => {
    const t = await makeAuth();
    const owner = await signUpOwner(t);
    const { orgId } = await createOrg(t, owner.cookie);
    const bearer = await mintScimToken(t, owner.cookie, orgId, "hris");
    const scimId = await createScimUser(t, bearer, "x@acme.test");
    const userId = await coreUserId(t, scimId);
    const cookie = await insertSessionCookie(t, userId);
    // Self-serve org creation stays on (R13): the SCIM user makes themselves
    // an owner somewhere, which used to exempt them from the key wipe.
    const { orgId: ownOrg } = await createOrg(t, cookie, "mine");
    const { res, body } = await createKey(t, cookie, orgId);
    expect(res.status).toBe(200);
    expect((await verify(t, body!.key)).valid).toBe(true);

    expect((await t.api.delete(`/scim/v2/Users/${scimId}`, bearer)).status).toBe(204);

    const user = await t.client.execute({
      sql: `SELECT banned FROM user WHERE id = ?`,
      args: [userId],
    });
    expect(Boolean(user.rows[0]!.banned)).toBe(false); // F-07 kept: owners are not banned
    const members = await t.client.execute({
      sql: `SELECT organizationId, role FROM member WHERE userId = ?`,
      args: [userId],
    });
    expect(members.rows.map((r) => [r.organizationId, r.role])).toEqual([[ownOrg, "owner"]]);

    expect(await keyRows(t, userId)).toBe(0);
    const refused = await verify(t, body!.key);
    expect(refused.valid).toBe(false);
    for (const org of [orgId, ownOrg]) {
      const rows = await revokedRows(t, org);
      expect(rows).toHaveLength(1);
      expect(rows[0]!.target_id).toBe(body!.id);
      expect(rows[0]!.actor_type).toBe("scim");
      expect(rows[0]!.actor_id).toBeNull();
      expect(JSON.parse(String(rows[0]!.metadata))).toEqual({
        reason: "scim.deactivate",
        userId,
      });
    }
    const skipped = (await auditRows(t, orgId)).filter(
      (r) => r.action === "scim.user_deactivation_skipped",
    );
    expect(skipped).toHaveLength(1);
    expect(skipped[0]!.actor_type).toBe("scim");
    expect(skipped[0]!.target_id).toBe(userId);
    expect(JSON.parse(String(skipped[0]!.metadata))).toEqual({ reason: "owner_protected" });
    expect(
      (await auditRows(t, ownOrg)).filter((r) => r.action === "scim.user_deactivation_skipped"),
    ).toHaveLength(0);
  });
});
