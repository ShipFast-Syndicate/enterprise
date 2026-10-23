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
// audits `api_key.revoked` into every org the user belonged to, and a request
// carrying an API key reaches an explicit allow-list of endpoints only
// (`API_KEY_ALLOWED_PATHS`: `/get-session`; plus upstream's own server-only
// verify call, recognised by `isApiKeyVerifyCall`) — everything else answers
// `API_KEY_NOT_ALLOWED_HERE`.
//
// Round 4 (security verifier round 3, F6/F7; lead decision): rounds 2–3 kept
// a deny-list, which is fail-open for every endpoint it does not know —
// `/list-sessions` handed a key the owner's raw session tokens (with the
// first-party `bearer()` plugin mounted, that token then drove the entire
// refused surface), and a `jwt()` or `oneTimeToken()` plugin a product adds
// minted a fresh credential from a key. The list is now an allow-list built
// from what embedding products do with a key (all of them:
// `auth.api.getSession({ headers })`; none opts into the mock session), so
// the reads rounds 2–3 allow-listed (`/organization/*` reads, `/api-key/list`,
// `/sso/providers`, `/list-accounts`, …) are refused too — the inversions are
// listed in plan §5.4.

import { describe, expect, it } from "vitest";
import { apiKey } from "@better-auth/api-key";
import { sso } from "@better-auth/sso";
import type { BetterAuthPlugin, GenericEndpointContext } from "better-auth";
import { createAuthEndpoint, sessionMiddleware } from "better-auth/api";
import { bearer, jwt, oneTimeToken } from "better-auth/plugins";
import {
  API_KEY_ALLOWED_PATHS,
  API_KEY_HEADERS,
  assertNotApiKeyRequest,
  enterpriseApiKeyValidator,
  isApiKeyAllowedPath,
  isApiKeyRefusedPath,
  isApiKeyVerifyCall,
  isServerOnlyPath,
  revokeUserApiKeys,
  SERVER_ONLY_PATHS,
} from "../../src/server/api-keys";
import { GATED_PATHS } from "../../src/server/gate";
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

/**
 * The hand-composed opt-in recipe (a product replacing the preset's
 * `api-key` plugin with its own `apiKey()`): mock sessions from `x-api-key`,
 * still bound to the user, keys still expiring. `keyExpiration` mirrors the
 * preset so these cases exercise expiring keys, not perpetual ones (verifier
 * round 2 housekeeping); the supported opt-in is `presetOptIn` below.
 */
const optIn = (extra: Record<string, unknown> = {}) =>
  makeAuth({
    apiKeyPlugin: apiKey({
      enableSessionForAPIKeys: true,
      apiKeyHeaders: [...API_KEY_HEADERS],
      customAPIKeyValidator: enterpriseApiKeyValidator,
      keyExpiration: { defaultExpiresIn: 90 * DAY_S, maxExpiresIn: 365 },
      ...extra,
    }),
  });

/** The supported opt-in: the preset builds the plugin (`apiKeys.enableSessionForAPIKeys`). */
const presetOptIn = () => makeAuth({ apiKeys: { enableSessionForAPIKeys: true } });

/** An org-scoped, domain-verified SSO provider row (raw insert, like `test/server/policy.test.ts`). */
async function insertProvider(t: TestAuth, orgId: string, userId: string, providerId = "okta") {
  await t.client.execute({
    sql: `INSERT INTO "ssoProvider" (id, issuer, domain, domainVerified, organizationId, providerId, userId) VALUES (?, ?, ?, 1, ?, ?, ?)`,
    args: [`ssop_${providerId}`, "https://idp.test", "acme.test", orgId, providerId, userId],
  });
}

async function providerRow(t: TestAuth, providerId = "okta") {
  const res = await t.client.execute({
    sql: `SELECT issuer, domain, domainVerified FROM "ssoProvider" WHERE providerId = ?`,
    args: [providerId],
  });
  const row = res.rows[0];
  return row
    ? { issuer: row.issuer, domain: row.domain, domainVerified: row.domainVerified }
    : null;
}

/** A second linked `account` row for `userId` (as an OAuth or SSO sign-in would leave). */
async function insertAccount(t: TestAuth, userId: string, providerId: string) {
  const id = `acc_${providerId}_${userId}`;
  const now = Date.now();
  await t.client.execute({
    sql: `INSERT INTO account (id, accountId, providerId, userId, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?, ?)`,
    args: [id, `${providerId}-sub-1`, providerId, userId, now, now],
  });
  return id;
}

async function accountRows(t: TestAuth, userId: string) {
  const res = await t.client.execute({
    sql: `SELECT providerId FROM account WHERE userId = ? ORDER BY providerId`,
    args: [userId],
  });
  return res.rows.map((r) => String(r.providerId));
}

/** An `admin` member of `orgId` holding one key (upstream's `checkProviderAccess` = `isOrgAdmin`). */
async function adminWithKey(t: TestAuth, orgId: string, email = "admin@acme.test") {
  const { cookie, userId } = await signUpOwner(t, email);
  await insertMemberRow(t, orgId, userId, "admin");
  const { res, body } = await createKey(t, cookie, orgId);
  expect(res.status).toBe(200);
  return { cookie, userId, key: body!.key };
}

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

  it("/api-key/update { expiresIn: null } cannot strip the expiry (400 API_KEY_EXPIRY_REQUIRED); over-max stays 400; the operator's `defaultExpiresInS: null` opt-out allows it", async () => {
    // Upstream `updateApiKey` skips the min/max check for `null` and writes
    // `expiresAt = null` — a perpetual key past both the default and the
    // `maxExpiresInDays` ceiling (PR-4 verifier round 1, A1).
    const t = await makeAuth({ apiKeys: { maxExpiresInDays: 30 } });
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);
    const { body } = await createKey(t, cookie, orgId);
    expect(body!.expiresAt).not.toBeNull();
    const expiresAtOf = async (keyId: string) =>
      (
        await t.client.execute({
          sql: `SELECT expiresAt FROM apikey WHERE id = ?`,
          args: [keyId],
        })
      ).rows[0]!.expiresAt;
    const before = await expiresAtOf(body!.id);

    const stripped = await t.api.post(
      "/api-key/update",
      { keyId: body!.id, expiresIn: null },
      { cookie },
    );
    expect(stripped.status).toBe(400);
    expect(await errorCode(stripped)).toBe("API_KEY_EXPIRY_REQUIRED");
    expect(await expiresAtOf(body!.id)).toBe(before);

    const tooLong = await t.api.post(
      "/api-key/update",
      { keyId: body!.id, expiresIn: 31 * DAY_S },
      { cookie },
    );
    expect(tooLong.status).toBe(400);
    expect(await errorCode(tooLong)).toBe("EXPIRES_IN_IS_TOO_LARGE");
    expect(await expiresAtOf(body!.id)).toBe(before);

    // A lifetime within the ceiling, and a rename that leaves the expiry
    // alone, still work (controls).
    const atMax = await t.api.post(
      "/api-key/update",
      { keyId: body!.id, expiresIn: 30 * DAY_S },
      { cookie },
    );
    expect(atMax.status).toBe(200);
    expect(await expiresAtOf(body!.id)).not.toBeNull();
    const renamed = await t.api.post(
      "/api-key/update",
      { keyId: body!.id, name: "renamed" },
      { cookie },
    );
    expect(renamed.status).toBe(200);
    expect(await expiresAtOf(body!.id)).not.toBeNull();

    // The operator who chose "never expire" as the default may also clear an
    // expiry: that is their explicit opt-out, not a bypass.
    const never = await makeAuth({ apiKeys: { defaultExpiresInS: null } });
    const n = await signUpOwner(never);
    const { orgId: nOrg } = await createOrg(never, n.cookie);
    const nk = await createKey(never, n.cookie, nOrg, { expiresIn: 7 * DAY_S });
    expect(nk.body!.expiresAt).not.toBeNull();
    const cleared = await never.api.post(
      "/api-key/update",
      { keyId: nk.body!.id, expiresIn: null },
      { cookie: n.cookie },
    );
    expect(cleared.status).toBe(200);
    const row = await never.client.execute({
      sql: `SELECT expiresAt FROM apikey WHERE id = ?`,
      args: [nk.body!.id],
    });
    expect(row.rows[0]!.expiresAt).toBeNull();
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

  it("a key cannot re-issue its own lifetime or delete keys: /api-key/update and /api-key/delete are refused and the row is untouched", async () => {
    // "A key never mints another key" also has to mean "a key never
    // re-mints itself": with the mock session on, the leaked key could
    // extend, un-expire, rename or delete its own row (verifier A3).
    const t = await optIn();
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);
    const { body } = await createKey(t, cookie, orgId);
    const headers = { "x-api-key": body!.key };
    const rowOf = async () =>
      (
        await t.client.execute({
          sql: `SELECT expiresAt, name, enabled FROM apikey WHERE id = ?`,
          args: [body!.id],
        })
      ).rows[0]!;
    const before = await rowOf();

    const attempts = [
      t.api.post("/api-key/update", { keyId: body!.id, expiresIn: 365 * DAY_S }, headers),
      t.api.post("/api-key/update", { keyId: body!.id, expiresIn: null }, headers),
      t.api.post("/api-key/update", { keyId: body!.id, enabled: true, name: "renamed" }, headers),
      t.api.post("/api-key/delete", { keyId: body!.id }, headers),
    ];
    for (const res of await Promise.all(attempts)) {
      expect(res.status).toBe(403);
      expect(await errorCode(res)).toBe("API_KEY_NOT_ALLOWED_HERE");
    }
    expect(await rowOf()).toEqual(before);
    // The owner's browser session still manages the key.
    expect(
      (await t.api.post("/api-key/update", { keyId: body!.id, name: "mine" }, { cookie })).status,
    ).toBe(200);
  });

  it("a key cannot reconfigure the organization, the account or its credentials; only the product's own session lookup still works", async () => {
    // Verifier B2: with the mock session on, a leaked owner key reached
    // `/organization/create` (attacker = owner of a fresh org),
    // `/organization/invite-member` (pending admin invitation),
    // `/organization/update-member-role`, `/update-user` and
    // `/passkey/generate-register-options` (a new long-lived credential).
    // Upstream's per-key rate limit (10 requests/day by default) is consumed
    // by the mock-session hook *before* the gate runs, so a refused request
    // still counts; this case makes ~20 of them with one key, hence the
    // plugin-level opt-out — the property under test is the 403, not the
    // 429 that would otherwise follow it.
    const t = await optIn({ rateLimit: { enabled: false } });
    const { cookie, userId: ownerId } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);
    const victim = await memberWithKey(t, orgId, "victim@acme.test");
    const { body } = await createKey(t, cookie, orgId);
    const headers = { "x-api-key": body!.key };
    const memberId = `member_${victim.userId}_${orgId}`;

    const refused: Array<[string, Promise<Response>]> = [
      [
        "/organization/create",
        t.api.post("/organization/create", { name: "viakey", slug: "viakey" }, headers),
      ],
      [
        "/organization/invite-member",
        t.api.post(
          "/organization/invite-member",
          { email: "inv@acme.test", role: "admin", organizationId: orgId },
          headers,
        ),
      ],
      [
        "/organization/update-member-role",
        t.api.post(
          "/organization/update-member-role",
          { memberId, role: "admin", organizationId: orgId },
          headers,
        ),
      ],
      [
        "/organization/remove-member",
        t.api.post(
          "/organization/remove-member",
          { memberIdOrEmail: memberId, organizationId: orgId },
          headers,
        ),
      ],
      [
        "/organization/update",
        t.api.post(
          "/organization/update",
          { data: { name: "pwned" }, organizationId: orgId },
          headers,
        ),
      ],
      [
        "/organization/delete",
        t.api.post("/organization/delete", { organizationId: orgId }, headers),
      ],
      ["/update-user", t.api.post("/update-user", { name: "pwned" }, headers)],
      ["/change-email", t.api.post("/change-email", { newEmail: "attacker@evil.test" }, headers)],
      [
        "/change-password",
        t.api.post(
          "/change-password",
          { currentPassword: "x", newPassword: "y".repeat(12) },
          headers,
        ),
      ],
      [
        "/passkey/generate-register-options",
        t.api.get("/passkey/generate-register-options", headers),
      ],
      ["/two-factor/enable", t.api.post("/two-factor/enable", { password: "x" }, headers)],
      ["/admin/list-users", t.api.get("/admin/list-users?limit=5", headers)],
      ["/admin/ban-user", t.api.post("/admin/ban-user", { userId: victim.userId }, headers)],
    ];
    for (const [name, pending] of refused) {
      const res = await pending;
      expect(res.status, name).toBe(403);
      expect(await errorCode(res), name).toBe("API_KEY_NOT_ALLOWED_HERE");
    }
    // Nothing changed.
    expect((await t.client.execute(`SELECT id FROM organization`)).rows).toHaveLength(1);
    expect((await t.client.execute(`SELECT id FROM invitation`)).rows).toHaveLength(0);
    const member = await t.client.execute({
      sql: `SELECT role FROM member WHERE id = ?`,
      args: [memberId],
    });
    expect(member.rows[0]!.role).toBe("member");
    const owner = await t.client.execute({
      sql: `SELECT name, email, banned FROM user WHERE id = ?`,
      args: [ownerId],
    });
    expect(owner.rows[0]!.name).not.toBe("pwned");
    expect(owner.rows[0]!.email).not.toBe("attacker@evil.test");
    const v = await t.client.execute({
      sql: `SELECT banned FROM user WHERE id = ?`,
      args: [victim.userId],
    });
    expect(Boolean(v.rows[0]!.banned)).toBe(false);

    // The one read a product needs from a key — its owner — still works;
    // the reads rounds 2–3 allow-listed are refused since round 4 (no
    // product reads them with a key; the owner resolves through
    // `/get-session` — plan §5.4).
    expect((await t.api.get("/get-session", headers)).status).toBe(200);
    const formerlyAllowed: Array<[string, () => Promise<Response>]> = [
      ["/organization/list", () => t.api.get("/organization/list", headers)],
      [
        "/organization/get-full-organization",
        () => t.api.get(`/organization/get-full-organization?organizationId=${orgId}`, headers),
      ],
      ["/api-key/list", () => t.api.get("/api-key/list", headers)],
      ["/passkey/list-user-passkeys", () => t.api.get("/passkey/list-user-passkeys", headers)],
    ];
    for (const [name, pending] of formerlyAllowed) {
      const res = await pending();
      expect(res.status, name).toBe(403);
      expect(await errorCode(res), name).toBe("API_KEY_NOT_ALLOWED_HERE");
    }
    // The owner's cookie still reads them (controls).
    for (const res of await Promise.all([
      t.api.get("/organization/list", { cookie }),
      t.api.get("/api-key/list", { cookie }),
    ])) {
      expect(res.status).toBe(200);
    }
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

  it("the header alone is refused on /api-key/update, /organization/create and /update-user next to a valid cookie; the same requests without it succeed", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);
    const { body } = await createKey(t, cookie, orgId);
    const both = { cookie, "x-api-key": body!.key };
    const refused = [
      t.api.post("/api-key/update", { keyId: body!.id, name: "x" }, both),
      t.api.post("/api-key/delete", { keyId: body!.id }, both),
      t.api.post("/organization/create", { name: "second", slug: "second" }, both),
      t.api.post("/update-user", { name: "x" }, both),
    ];
    for (const res of await Promise.all(refused)) {
      expect(res.status).toBe(403);
      expect(await errorCode(res)).toBe("API_KEY_NOT_ALLOWED_HERE");
    }
    expect((await t.client.execute(`SELECT id FROM organization`)).rows).toHaveLength(1);
    expect((await t.client.execute(`SELECT id FROM apikey`)).rows).toHaveLength(1);
    expect(
      (await t.api.post("/api-key/update", { keyId: body!.id, name: "x" }, { cookie })).status,
    ).toBe(200);
    expect(
      (await t.api.post("/organization/create", { name: "second", slug: "second" }, { cookie }))
        .status,
    ).toBe(200);
    expect((await t.api.post("/update-user", { name: "x" }, { cookie })).status).toBe(200);
  });

  it("isApiKeyRefusedPath: an allow-list of exactly /get-session; every other path — writes, reads, sign-in flows, other plugins' endpoints, path-less server-only calls, near-misses — is refused", () => {
    // Round 4: the predicate is `!API_KEY_ALLOWED_PATHS.has(path)`. Pinned
    // both ways so widening the set is a visible, reviewed change.
    expect([...API_KEY_ALLOWED_PATHS]).toEqual(["/get-session"]);
    // better-call's markers: `virtual:` inside a path-less endpoint
    // (`dist/context.mjs`), `/` inside a before-hook on one (`dist/middleware.mjs`).
    expect([...SERVER_ONLY_PATHS].sort()).toEqual(["/", "virtual:"]);
    for (const path of SERVER_ONLY_PATHS) expect(isServerOnlyPath(path), path).toBe(true);
    expect(isServerOnlyPath("/get-session")).toBe(false);
    expect(isServerOnlyPath("/virtual:")).toBe(false);
    for (const path of API_KEY_ALLOWED_PATHS) {
      expect(isApiKeyAllowedPath(path), path).toBe(true);
      expect(isApiKeyRefusedPath(path), path).toBe(false);
    }
    for (const path of [
      // Management, credential minting, key/org/account/credential writes
      // (rounds 1–3).
      "/enterprise/policy",
      "/enterprise/scim/tokens/create",
      "/organization/create-team",
      "/api-key/create",
      "/api-key/update",
      "/api-key/delete",
      "/organization/create",
      "/organization/update",
      "/organization/delete",
      "/organization/invite-member",
      "/organization/accept-invitation",
      "/organization/update-member-role",
      "/organization/remove-member",
      "/organization/leave",
      "/organization/create-role",
      "/organization/set-active",
      "/passkey/generate-register-options",
      "/passkey/verify-registration",
      "/passkey/delete-passkey",
      "/two-factor/enable",
      "/two-factor/disable",
      "/update-user",
      "/change-email",
      "/change-password",
      "/set-password",
      "/delete-user",
      "/admin/list-users",
      "/admin/ban-user",
      "/sso/register",
      "/sso/update-provider",
      "/sso/delete-provider",
      "/sso/request-domain-verification",
      "/sso/verify-domain",
      "/sso/saml2/logout/:providerId",
      "/sso/some-future-write",
      "/link-social",
      "/unlink-account",
      "/get-access-token",
      "/refresh-token",
      // Credential-yielding read (round 3 verifier, F6) and the other
      // first-party plugins' credential mints (F7) — refused without being
      // named anywhere: they are simply not allow-listed.
      "/list-sessions",
      "/token",
      "/one-time-token/generate",
      "/one-time-token/verify",
      "/device/approve",
      "/device/deny",
      "/multi-session/set-active",
      "/multi-session/revoke",
      "/email-otp/change-email",
      "/delete-anonymous-user",
      // A product's own plugin endpoint this package has never heard of.
      "/zz-product/whoami",
      // Path-less server-only calls (`auth.api.*` only, no HTTP route) —
      // refused by path; upstream's own verify call is let through by
      // `isApiKeyVerifyCall` on its shape, not by this predicate.
      ...SERVER_ONLY_PATHS,
      "/api-key/verify",
      // The reads rounds 2–3 allow-listed (plan §5.4): no product reads
      // them with a key.
      "/api-key/list",
      "/api-key/get",
      "/organization/list",
      "/organization/get-full-organization",
      "/organization/get-organization",
      "/organization/list-members",
      "/organization/get-active-member",
      "/organization/get-active-member-role",
      "/organization/has-permission",
      "/organization/check-slug",
      "/organization/get-invitation",
      "/organization/list-invitations",
      "/organization/list-user-invitations",
      "/organization/list-teams",
      "/organization/list-user-teams",
      "/organization/list-team-members",
      "/organization/list-roles",
      "/organization/get-role",
      "/passkey/list-user-passkeys",
      "/passkey/generate-authenticate-options",
      "/passkey/verify-authentication",
      "/list-accounts",
      "/account-info",
      "/sso/providers",
      "/sso/get-provider",
      // Sign-in flows: no key is ever sent to them.
      "/sign-in/email",
      "/sign-up/email",
      "/sign-out",
      "/sign-in/sso",
      "/sso/callback",
      "/sso/callback/:providerId",
      "/sso/saml2/sp/acs/:providerId",
      "/sso/saml2/sp/slo/:providerId",
      "/sso/saml2/sp/metadata",
      "/enterprise",
      "/enterprise/home-realm",
      "/organizations/create",
      // Near-misses of the allow-listed paths: exact match only.
      "/get-session/",
      "/GET-SESSION",
      "/get-session/x",
      "/api-key/verify/",
      "/api-key/verify/x",
      "",
      "/",
    ]) {
      expect(isApiKeyRefusedPath(path), path).toBe(true);
      expect(isApiKeyAllowedPath(path), path).toBe(false);
    }
  });

  it("route table: every upstream /sso/* endpoint (sign-in, callbacks, reads and writes alike) is refused to a key; GATED_PATHS is a subset of the refusal set", () => {
    // Enumerated from the pinned `@better-auth/sso` plugin itself. Rounds 2–3
    // allow-listed the sign-in/callback/read half; since round 4 nothing
    // under `/sso/` is reachable with a key (no key is ever sent to a
    // sign-in flow, and no product reads a provider with one — plan §5.4),
    // so a route upstream adds later is refused by construction and this pin
    // only says when the table changed. `ctx.path` in hooks is the
    // endpoint's declared pattern (`/sso/callback/:providerId`), which is
    // what the predicate is fed.
    const table = Object.values(
      sso({ domainVerification: { enabled: true } }).endpoints, // as the preset builds it
    ).map((e) => (e as { path: string }).path);
    const pinned = [
      "/sign-in/sso",
      "/sso/callback",
      "/sso/callback/:providerId",
      "/sso/saml2/sp/acs/:providerId",
      "/sso/saml2/sp/slo/:providerId",
      "/sso/saml2/sp/metadata",
      "/sso/providers",
      "/sso/get-provider",
      "/sso/register",
      "/sso/update-provider",
      "/sso/delete-provider",
      "/sso/request-domain-verification",
      "/sso/verify-domain",
      "/sso/saml2/logout/:providerId",
    ];
    for (const path of pinned) expect(table, path).toContain(path);
    expect(table).toHaveLength(pinned.length); // the pinned route table, nothing unreviewed
    for (const path of table) expect(isApiKeyRefusedPath(path), path).toBe(true);
    // The validator-level check (`enterpriseApiKeyValidator`) relies on the
    // predicate alone, so the gate's own table must be a subset of it.
    for (const path of Object.keys(GATED_PATHS)) {
      expect(isApiKeyRefusedPath(path), path).toBe(true);
    }
  });

  it("enterpriseApiKeyValidator refuses a refused path before any lookup, whatever the key; upstream's own verify call (path-less, key in the body) is never refused, any other path-less call is", async () => {
    const t = await makeAuth();
    const context = await t.auth.$context;
    const unknownKey = "not-a-key-".repeat(8);
    const validate = (path: string, key = unknownKey, body?: unknown) =>
      enterpriseApiKeyValidator({
        ctx: { path, body, context } as unknown as GenericEndpointContext,
        key,
      });
    // The verify call: `auth.api.verifyApiKey({ body: { key } })` runs the
    // validator with the key in the body and `ctx.path === "virtual:"`
    // (from the endpoint) or `"/"` (from the mock-session hook, when a
    // product forwards headers carrying the key).
    for (const path of SERVER_ONLY_PATHS) {
      expect(isApiKeyVerifyCall({ path, body: { key: "k" } }, "k"), path).toBe(true);
      expect(isApiKeyVerifyCall({ path, body: { key: "other" } }, "k"), path).toBe(false);
      expect(isApiKeyVerifyCall({ path, body: {} }, "k"), path).toBe(false);
      expect(isApiKeyVerifyCall({ path, body: null }, "k"), path).toBe(false);
      expect(isApiKeyVerifyCall({ path }, "k"), path).toBe(false);
      expect(await validate(path, unknownKey, { key: unknownKey }), path).toBe(true); // unknown key → upstream's INVALID_API_KEY
      await expect(validate(path, unknownKey, { userId: "u" }), path).rejects.toMatchObject({
        body: { code: "API_KEY_NOT_ALLOWED_HERE" },
      });
      await expect(validate(path, unknownKey, { key: "another" }), path).rejects.toMatchObject({
        body: { code: "API_KEY_NOT_ALLOWED_HERE" },
      });
    }
    expect(isApiKeyVerifyCall({ path: "/get-session", body: { key: "k" } }, "k")).toBe(false);
    expect(isApiKeyVerifyCall({ path: "/api-key/verify", body: { key: "k" } }, "k")).toBe(false);
    expect(isApiKeyVerifyCall({}, "k")).toBe(false);
    for (const path of [
      "/sso/update-provider",
      "/organization/create",
      "/api-key/create",
      "/list-sessions",
      "/token",
      "/organization/list",
      "/zz-product/whoami",
    ]) {
      await expect(validate(path)).rejects.toMatchObject({
        body: { code: "API_KEY_NOT_ALLOWED_HERE" },
      });
    }
    // `/api-key/verify` as a *path* is not a thing (the endpoint declares
    // none), so a request that names it is refused like any other path.
    await expect(
      validate("/api-key/verify", unknownKey, { key: unknownKey }),
    ).rejects.toMatchObject({ body: { code: "API_KEY_NOT_ALLOWED_HERE" } });
    expect(await validate("/get-session")).toBe(true);
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

describe("gap 1 — SSO provider writes are refused to a key (verifier round 2, F1)", () => {
  it("an owner's or an admin member's key cannot update or delete the org's SSO provider (provider and linked account rows untouched); the header next to a cookie is refused too; the owner's cookie still can; provider reads via key still work", async () => {
    // Verifier round 2, A1–A3/C2: under the mock session a leaked owner or
    // admin key rewrote the tenant IdP (`/sso/update-provider` → 200, issuer
    // and domain replaced) and deleted it (`/sso/delete-provider` → 200,
    // which upstream follows by deleting every `account` row of that
    // provider) — the identity boundary PR-3's domain binding hangs on, and
    // neither path sits in `GATED_PATHS`. Both are session-authenticated
    // (`checkProviderAccess` = `isOrgAdmin`), so the mock session was enough.
    // Hand-composed recipe here (the preset opt-in has its own case below).
    const t = await optIn();
    const { cookie, userId: ownerId } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);
    await insertProvider(t, orgId, ownerId);
    await insertAccount(t, ownerId, "okta");
    const before = await providerRow(t);
    expect(before).toEqual({ issuer: "https://idp.test", domain: "acme.test", domainVerified: 1 });
    const { body } = await createKey(t, cookie, orgId);
    const admin = await adminWithKey(t, orgId);

    // Domain-only, as the verifiers proved it: upstream itself refuses an
    // issuer change while linked accounts exist (409), a domain move it
    // accepts (and resets `domainVerified`).
    const rewrite = { providerId: "okta", domain: "evil.test" };
    for (const [who, key] of [
      ["owner", body!.key],
      ["admin", admin.key],
    ] as const) {
      const headers = { "x-api-key": key };
      // Sequential (not `Promise.all`): on an unfixed tree these all reach
      // the mock-session hook's row updates at once and SQLite answers
      // `SQLITE_BUSY` (500), which would blur the RED signal.
      const attempts: Array<[string, () => Promise<Response>]> = [
        ["/sso/update-provider", () => t.api.post("/sso/update-provider", rewrite, headers)],
        [
          "/sso/delete-provider",
          () => t.api.post("/sso/delete-provider", { providerId: "okta" }, headers),
        ],
        [
          "/sso/request-domain-verification",
          () => t.api.post("/sso/request-domain-verification", { providerId: "okta" }, headers),
        ],
        [
          "/sso/verify-domain",
          () => t.api.post("/sso/verify-domain", { providerId: "okta" }, headers),
        ],
      ];
      for (const [name, pending] of attempts) {
        const res = await pending();
        expect(res.status, `${who} ${name}`).toBe(403);
        expect(await errorCode(res), `${who} ${name}`).toBe("API_KEY_NOT_ALLOWED_HERE");
      }
    }
    expect(await providerRow(t)).toEqual(before);
    expect(await accountRows(t, ownerId)).toEqual(["credential", "okta"]);

    // Header-alone principle: the key next to the owner's valid cookie.
    const both = await t.api.post("/sso/update-provider", rewrite, {
      cookie,
      "x-api-key": body!.key,
    });
    expect(both.status).toBe(403);
    expect(await errorCode(both)).toBe("API_KEY_NOT_ALLOWED_HERE");
    expect(await providerRow(t)).toEqual(before);

    // The sanitized provider reads are refused to a key too since round 4
    // (no product reads a provider with a key — plan §5.4); the owner's
    // cookie still reads them, sanitized (control).
    for (const path of ["/sso/get-provider?providerId=okta", "/sso/providers"]) {
      const viaKey = await t.api.get(path, { "x-api-key": body!.key });
      expect(viaKey.status, path).toBe(403);
      expect(await errorCode(viaKey), path).toBe("API_KEY_NOT_ALLOWED_HERE");
    }
    const get = await t.api.get("/sso/get-provider?providerId=okta", { cookie });
    expect(get.status).toBe(200);
    expect(JSON.stringify(await get.json())).not.toContain("clientSecret");

    // Controls: the owner's browser session manages the provider as before.
    const moved = await t.api.post(
      "/sso/update-provider",
      { providerId: "okta", domain: "acme-moved.test" },
      { cookie },
    );
    expect(moved.status).toBe(200);
    expect(await providerRow(t)).toEqual({
      issuer: "https://idp.test",
      domain: "acme-moved.test",
      domainVerified: 0,
    });
    expect(
      (await t.api.post("/sso/delete-provider", { providerId: "okta" }, { cookie })).status,
    ).toBe(200);
    expect(await providerRow(t)).toBeNull();
  });

  it("the header alone is refused on /sso/update-provider and /sso/delete-provider under the preset default too", async () => {
    const t = await makeAuth();
    const { cookie, userId: ownerId } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);
    await insertProvider(t, orgId, ownerId);
    const before = await providerRow(t);
    const both = { cookie, "x-api-key": "anything" };
    for (const res of await Promise.all([
      t.api.post("/sso/update-provider", { providerId: "okta", domain: "evil.test" }, both),
      t.api.post("/sso/delete-provider", { providerId: "okta" }, both),
    ])) {
      expect(res.status).toBe(403);
      expect(await errorCode(res)).toBe("API_KEY_NOT_ALLOWED_HERE");
    }
    expect(await providerRow(t)).toEqual(before);
  });
});

describe("gap 1 — account linking and OAuth-token reads are refused to a key (verifier round 2, F2–F4)", () => {
  it("/unlink-account, /link-social, /get-access-token and /refresh-token are refused before upstream's business logic; the owner's fresh session still unlinks", async () => {
    // F2: `/unlink-account` deleted a second linked account row with only a
    // key (upstream's `freshSessionMiddleware` is satisfied by the mock
    // session, whose `createdAt` is "now"). F3: `/link-social` passed the
    // session gate (404 `PROVIDER_NOT_FOUND` only because no social provider
    // is configured here; with one, a key starts a link flow for its
    // owner). F4: `/get-access-token` and `/refresh-token` reached their
    // handler; with the provider configured they hand the key holder the
    // owner's OAuth tokens — a stronger credential than the key.
    const t = await optIn();
    const { cookie, userId: ownerId } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);
    const accountId = await insertAccount(t, ownerId, "google");
    expect(await accountRows(t, ownerId)).toEqual(["credential", "google"]);
    const { body } = await createKey(t, cookie, orgId);
    const headers = { "x-api-key": body!.key };

    const refused: Array<[string, () => Promise<Response>]> = [
      ["/unlink-account", () => t.api.post("/unlink-account", { accountId }, headers)],
      [
        "/link-social",
        () => t.api.post("/link-social", { provider: "google", callbackURL: "/" }, headers),
      ],
      ["/get-access-token", () => t.api.post("/get-access-token", { accountId }, headers)],
      ["/refresh-token", () => t.api.post("/refresh-token", { accountId }, headers)],
    ];
    for (const [name, pending] of refused) {
      const res = await pending(); // sequential: see the SSO case
      expect(res.status, name).toBe(403);
      expect(await errorCode(res), name).toBe("API_KEY_NOT_ALLOWED_HERE");
    }
    expect(await accountRows(t, ownerId)).toEqual(["credential", "google"]);

    // Controls: anonymous is upstream's 401 (the endpoints exist); the
    // owner's cookie reaches upstream's own logic (no social provider is
    // configured, so the token read answers upstream's 400) and unlinks.
    expect((await t.api.post("/link-social", { provider: "google" })).status).toBe(401);
    const token = await t.api.post("/get-access-token", { accountId }, { cookie });
    expect(token.status).toBe(400);
    expect(await errorCode(token)).not.toBe("API_KEY_NOT_ALLOWED_HERE");
    expect((await t.api.post("/unlink-account", { accountId }, { cookie })).status).toBe(200);
    expect(await accountRows(t, ownerId)).toEqual(["credential"]);
    // The metadata read is refused to a key too since round 4 (no product
    // reads it with a key — plan §5.4); the owner's cookie still lists
    // accounts, and that list exposes no token (control).
    const viaKey = await t.api.get("/list-accounts", headers);
    expect(viaKey.status).toBe(403);
    expect(await errorCode(viaKey)).toBe("API_KEY_NOT_ALLOWED_HERE");
    const list = await t.api.get("/list-accounts", { cookie });
    expect(list.status).toBe(200);
    expect(JSON.stringify(await list.json())).not.toMatch(/accessToken|refreshToken/);
  });
});

describe("gap 1 — the refusal does not depend on how the key is carried (verifier round 2, E1/E2)", () => {
  // E1/E2: a hand-composed `apiKey()` that reads the key from `authorization`
  // or from a query parameter never presents an `x-api-key` header, so the
  // gate's header check saw nothing and the whole refusal set was inert (a
  // key minted a key, created an org, rewrote the profile). The validator
  // is the one thing every recipe must pass, so the refusal lives there too.
  const recipe = (extra: Record<string, unknown>) =>
    makeAuth({
      apiKeyPlugin: apiKey({
        enableSessionForAPIKeys: true,
        customAPIKeyValidator: enterpriseApiKeyValidator,
        keyExpiration: { defaultExpiresIn: 90 * DAY_S, maxExpiresIn: 365 },
        ...extra,
      }),
    });

  async function attack(
    t: TestAuth,
    carry: (key: string) => { headers: Record<string, string>; qs: string },
  ) {
    const { cookie, userId: ownerId } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);
    await insertProvider(t, orgId, ownerId);
    const { body } = await createKey(t, cookie, orgId);
    const { headers, qs } = carry(body!.key);

    // The recipe itself works: the key authenticates its owner.
    const session = await t.api.get(`/get-session${qs}`, headers);
    expect(session.status).toBe(200);
    expect(((await session.json()) as { user: { id: string } }).user.id).toBe(ownerId);

    const refused: Array<[string, () => Promise<Response>]> = [
      [
        "/organization/create",
        () => t.api.post(`/organization/create${qs}`, { name: "viakey", slug: "viakey" }, headers),
      ],
      [
        "/api-key/create",
        () => t.api.post(`/api-key/create${qs}`, { name: "child", organizationId: orgId }, headers),
      ],
      ["/update-user", () => t.api.post(`/update-user${qs}`, { name: "pwned" }, headers)],
      [
        "/sso/update-provider",
        () =>
          t.api.post(
            `/sso/update-provider${qs}`,
            { providerId: "okta", domain: "evil.test" },
            headers,
          ),
      ],
    ];
    for (const [name, pending] of refused) {
      const res = await pending(); // sequential: see the SSO case
      expect(res.status, name).toBe(403);
      expect(await errorCode(res), name).toBe("API_KEY_NOT_ALLOWED_HERE");
    }
    expect((await t.client.execute(`SELECT id FROM organization`)).rows).toHaveLength(1);
    expect((await t.client.execute(`SELECT id FROM apikey`)).rows).toHaveLength(1);
    const owner = await t.client.execute({
      sql: `SELECT name FROM user WHERE id = ?`,
      args: [ownerId],
    });
    expect(owner.rows[0]!.name).not.toBe("pwned");
    expect((await providerRow(t))!.domain).toBe("acme.test");
  }

  it("apiKeyHeaders: ['authorization'] — every write is still refused, reads work", async () => {
    const t = await recipe({ apiKeyHeaders: ["authorization"] });
    await attack(t, (key) => ({ headers: { authorization: key }, qs: "" }));
  });

  it("customAPIKeyGetter reading ?api_key= — every write is still refused, reads work", async () => {
    const t = await recipe({
      customAPIKeyGetter: (ctx: { request?: Request }) =>
        ctx.request ? new URL(ctx.request.url).searchParams.get("api_key") : null,
    });
    await attack(t, (key) => ({ headers: {}, qs: `?api_key=${encodeURIComponent(key)}` }));
  });
});

describe("gap 1 — apiKeys.enableSessionForAPIKeys is the supported opt-in (verifier round 2, F5b)", () => {
  it("the preset builds the mock session with the validator, header list and expiry bound in place; off by default", async () => {
    const off = await makeAuth();
    const o = await signUpOwner(off);
    const { orgId: offOrg } = await createOrg(off, o.cookie);
    const offKey = await memberWithKey(off, offOrg);
    // Preset default: upstream ignores the header, so the key authenticates nobody.
    const anon = await off.api.get("/get-session", { "x-api-key": offKey.key });
    expect(anon.status).toBe(200);
    expect(await anon.json()).toBeNull();

    const t = await presetOptIn();
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);
    const { key, userId, expiresAt } = await memberWithKey(t, orgId);
    const session = await t.api.get("/get-session", { "x-api-key": key });
    expect(session.status).toBe(200);
    expect(((await session.json()) as { user: { id: string } }).user.id).toBe(userId);
    // Expiry bound kept (90 d), refusal set active, user binding active.
    const days = (new Date(expiresAt!).getTime() - Date.now()) / 86_400_000;
    expect(days).toBeGreaterThan(89.9);
    expect(days).toBeLessThanOrEqual(90);
    const mint = await t.api.post(
      "/api-key/create",
      { name: "child", organizationId: orgId },
      { "x-api-key": key },
    );
    expect(mint.status).toBe(403);
    expect(await errorCode(mint)).toBe("API_KEY_NOT_ALLOWED_HERE");
    await t.client.execute({ sql: `UPDATE user SET banned = 1 WHERE id = ?`, args: [userId] });
    const banned = await t.api.get("/get-session", { "x-api-key": key });
    expect(banned.status).toBe(401);
    expect(await errorCode(banned)).toBe("USER_BANNED");
  });
});

/** A product's own plugin: one session-bound endpoint, one anonymous one — neither known to this package. */
const productPlugin = (): BetterAuthPlugin => ({
  id: "zz-product",
  endpoints: {
    whoami: createAuthEndpoint(
      "/zz-product/whoami",
      { method: "GET", use: [sessionMiddleware] },
      async (ctx) => ctx.json({ userId: ctx.context.session.user.id }),
    ),
    ping: createAuthEndpoint("/zz-product/ping", { method: "GET" }, async (ctx) =>
      ctx.json({ ok: true }),
    ),
  },
});

async function storedSessionTokens(t: TestAuth, userId: string) {
  const res = await t.client.execute({
    sql: `SELECT token FROM session WHERE userId = ?`,
    args: [userId],
  });
  return res.rows.map((r) => String(r.token));
}

async function keyRateLimitRow(t: TestAuth, keyId: string) {
  const res = await t.client.execute({
    sql: `SELECT rateLimitMax, rateLimitTimeWindow, rateLimitEnabled FROM apikey WHERE id = ?`,
    args: [keyId],
  });
  const row = res.rows[0]!;
  return {
    max: Number(row.rateLimitMax),
    window: Number(row.rateLimitTimeWindow),
    enabled: Boolean(row.rateLimitEnabled),
  };
}

describe("gap 1 — a key reaches an allow-list only (verifier round 3, F6/F7; lead round 4)", () => {
  it("F6: /list-sessions is refused to a key, so no stored session token ever leaves via a key; with bearer() mounted the chain is dead; /get-session via key reports the key itself, never a stored token", async () => {
    // Round 3 verifier: `/list-sessions` (upstream `freshSessionMiddleware`,
    // satisfied by the mock session) answered a key with the owner's raw
    // session tokens; with the first-party `bearer()` plugin mounted —
    // which signs an unsigned token with the server secret by default —
    // that token then drove `/api-key/create`, `/sso/register`,
    // `/enterprise/policy/set` and `/organization/create`: the entire
    // refused surface. The path is simply not allow-listed now.
    const t = await makeAuth({ apiKeys: { enableSessionForAPIKeys: true }, plugins: [bearer()] });
    const { cookie, userId } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);
    const { body } = await createKey(t, cookie, orgId);
    const key = body!.key;
    const stored = await storedSessionTokens(t, userId);
    expect(stored.length).toBeGreaterThan(0);

    // Control: the owner's own (fresh) session lists them, tokens included —
    // upstream's behaviour for a browser session, untouched.
    const viaCookie = await t.api.get("/list-sessions", { cookie });
    expect(viaCookie.status).toBe(200);
    const listed = (await viaCookie.json()) as { token: string }[];
    expect(listed.map((s) => s.token)).toEqual(expect.arrayContaining(stored));

    const viaKey = await t.api.get("/list-sessions", { "x-api-key": key });
    expect(viaKey.status).toBe(403);
    expect(await errorCode(viaKey)).toBe("API_KEY_NOT_ALLOWED_HERE");

    // The one session a key can see is its own mock one: `session.token` is
    // the key, not any stored session token.
    const gs = await t.api.get("/get-session", { "x-api-key": key });
    expect(gs.status).toBe(200);
    const session = (await gs.json()) as { user: { id: string }; session: { token: string } };
    expect(session.user.id).toBe(userId);
    expect(session.session.token).toBe(key);
    expect(stored).not.toContain(session.session.token);

    // The key presented as a bearer token is not a session either.
    const asBearer = await t.api.get("/list-sessions", { authorization: `Bearer ${key}` });
    expect(asBearer.status).toBe(401);
    expect((await t.client.execute(`SELECT id FROM apikey`)).rows).toHaveLength(1);
    expect((await t.client.execute(`SELECT id FROM organization`)).rows).toHaveLength(1);
  });

  it("F7: jwt()'s /token is refused to a key (a key never mints a JWT); the owner's cookie still gets one; anonymous is 401", async () => {
    const t = await makeAuth({ apiKeys: { enableSessionForAPIKeys: true }, plugins: [jwt()] });
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);
    const { body } = await createKey(t, cookie, orgId);

    const viaKey = await t.api.get("/token", { "x-api-key": body!.key });
    expect(viaKey.status).toBe(403);
    expect(await errorCode(viaKey)).toBe("API_KEY_NOT_ALLOWED_HERE");

    const viaCookie = await t.api.get("/token", { cookie });
    expect(viaCookie.status).toBe(200);
    expect(((await viaCookie.json()) as { token: string }).token.split(".")).toHaveLength(3);
    expect((await t.api.get("/token")).status).toBe(401);
  });

  it("F7: oneTimeToken()'s /one-time-token/generate is refused to a key; the owner's cookie still gets one", async () => {
    const t = await makeAuth({
      apiKeys: { enableSessionForAPIKeys: true },
      plugins: [oneTimeToken()],
    });
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);
    const { body } = await createKey(t, cookie, orgId);

    const viaKey = await t.api.get("/one-time-token/generate", { "x-api-key": body!.key });
    expect(viaKey.status).toBe(403);
    expect(await errorCode(viaKey)).toBe("API_KEY_NOT_ALLOWED_HERE");

    const viaCookie = await t.api.get("/one-time-token/generate", { cookie });
    expect(viaCookie.status).toBe(200);
    expect(typeof ((await viaCookie.json()) as { token: string }).token).toBe("string");
  });

  it("F7: an endpoint of a product's own plugin — unknown to this package — is refused to a key and reachable with a cookie (or anonymously, where it allows that)", async () => {
    // Fail-closed by construction: the predicate never heard of
    // `/zz-product/*`, and that is exactly why it is refused.
    const t = await makeAuth({
      apiKeys: { enableSessionForAPIKeys: true },
      plugins: [productPlugin()],
    });
    const { cookie, userId } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);
    const { body } = await createKey(t, cookie, orgId);
    const headers = { "x-api-key": body!.key };

    for (const path of ["/zz-product/whoami", "/zz-product/ping"]) {
      const res = await t.api.get(path, headers); // sequential: see the SSO case
      expect(res.status, path).toBe(403);
      expect(await errorCode(res), path).toBe("API_KEY_NOT_ALLOWED_HERE");
    }
    const whoami = await t.api.get("/zz-product/whoami", { cookie });
    expect(whoami.status).toBe(200);
    expect(await whoami.json()).toEqual({ userId });
    expect((await t.api.get("/zz-product/whoami")).status).toBe(401);
    expect((await t.api.get("/zz-product/ping")).status).toBe(200);
  });

  it("preset default: the header alone is refused on /list-sessions, /organization/list and a product's own endpoint next to a valid cookie; /get-session with a stray header still answers the cookie's session", async () => {
    // Products forward the whole incoming request into
    // `auth.api.getSession({ headers })` (legacy `X-API-Key`
    // callers included), so `/get-session` must stay reachable with a
    // stray header — it is allow-listed. Everything else is not.
    const t = await makeAuth({ plugins: [productPlugin()] });
    const { cookie, userId } = await signUpOwner(t);
    const both = { cookie, "x-api-key": "legacy_or_anything" };
    for (const path of ["/list-sessions", "/organization/list", "/zz-product/whoami"]) {
      const res = await t.api.get(path, both);
      expect(res.status, path).toBe(403);
      expect(await errorCode(res), path).toBe("API_KEY_NOT_ALLOWED_HERE");
      expect((await t.api.get(path, { cookie })).status, path).toBe(200);
    }
    const gs = await t.api.get("/get-session", both);
    expect(gs.status).toBe(200);
    expect(((await gs.json()) as { user: { id: string } }).user.id).toBe(userId);
  });

  it("auth.api.verifyApiKey keeps working when a product forwards the incoming request's headers (x-api-key included), under the preset default and the opt-in; a path-less server-only call is refused for a key; there is no /api-key/verify HTTP route", async () => {
    // The verify path is the api-key plugin's own use path: recognised by
    // shape (`isApiKeyVerifyCall`), not by an HTTP path it does not have.
    for (const [mode, t] of [
      ["default", await makeAuth()],
      ["opt-in", await presetOptIn()],
    ] as const) {
      const { cookie, userId } = await signUpOwner(t);
      const { orgId } = await createOrg(t, cookie);
      const { body } = await createKey(t, cookie, orgId);
      const key = body!.key;
      const api = t.auth.api as unknown as {
        verifyApiKey: (input: {
          body: { key: string };
          headers?: Headers;
        }) => Promise<{ valid: boolean; error: { code?: string } | null }>;
        listUserAccounts: (input: { headers: Headers }) => Promise<unknown>;
        viewBackupCodes: (input: {
          body: { userId: string };
          headers: Headers;
        }) => Promise<unknown>;
      };
      const forwarded = new Headers({ "x-api-key": key, cookie });
      const bare = await api.verifyApiKey({ body: { key } });
      expect(bare.valid, mode).toBe(true);
      const withHeaders = await api.verifyApiKey({ body: { key }, headers: forwarded });
      expect(withHeaders.valid, mode).toBe(true);
      expect(
        (await api.verifyApiKey({ body: { key }, headers: new Headers({ "x-api-key": key }) }))
          .valid,
        mode,
      ).toBe(true);
      // A path-less server-only endpoint that is not the verify call
      // (`viewBackupCodes`, a credential-yielding read): with the mock
      // session on, the key does not authenticate it (403 before anything
      // runs); under the default the header is inert and upstream answers
      // on its own terms (here: the user has no 2FA enrolled).
      const view = () =>
        api.viewBackupCodes({ body: { userId }, headers: new Headers({ "x-api-key": key }) });
      if (mode === "opt-in") {
        await expect(view()).rejects.toMatchObject({ body: { code: "API_KEY_NOT_ALLOWED_HERE" } });
      } else {
        const outcome = await view().then(
          () => "ok",
          (e: { body?: { code?: string } }) => e.body?.code ?? "error",
        );
        expect(outcome, mode).not.toBe("API_KEY_NOT_ALLOWED_HERE");
      }
      // An HTTP-routable read with forwarded headers: the header alone is
      // refused (both modes) — the cookie next to it does not help.
      await expect(api.listUserAccounts({ headers: forwarded })).rejects.toMatchObject({
        body: { code: "API_KEY_NOT_ALLOWED_HERE" },
      });
      // Over HTTP there is no verify route at all, and nothing routes to
      // the server-only markers either (`/` is not a route).
      expect(
        (await t.api.post("/api-key/verify", { key }, { "x-api-key": key })).status,
        mode,
      ).toBe(404);
      expect((await t.api.post("/api-key/verify", { key }, { cookie })).status, mode).toBe(404);
      expect((await t.api.post("/", { key }, { "x-api-key": key })).status, mode).toBe(404);
      expect((await t.api.get("/", { "x-api-key": key })).status, mode).toBe(404);
      expect((await t.api.get("/virtual:", { "x-api-key": key })).status, mode).toBe(404);
      // And `/get-session` with the forwarded headers answers the owner in
      // both modes (the cookie under the default, the key under the opt-in).
      const gs = await t.api.get("/get-session", { "x-api-key": key, cookie });
      expect(gs.status, mode).toBe(200);
      expect(((await gs.json()) as { user: { id: string } }).user.id, mode).toBe(userId);
    }
  });

  it("apiKeys.rateLimit is forwarded to upstream: maxRequests/timeWindow are stamped on new keys and bound their uses (429 RATE_LIMITED); enabled:false lifts the bound; the default stays upstream's 10 per 24 h", async () => {
    // Round 3 verifier observation: under the preset opt-in the per-key
    // limit was upstream's default and unusable for a real product API.
    const bounded = await makeAuth({
      apiKeys: { enableSessionForAPIKeys: true, rateLimit: { maxRequests: 2, timeWindow: 60_000 } },
    });
    const b = await signUpOwner(bounded);
    const { orgId: bOrg } = await createOrg(bounded, b.cookie);
    const bk = await createKey(bounded, b.cookie, bOrg);
    expect(await keyRateLimitRow(bounded, bk.body!.id)).toEqual({
      max: 2,
      window: 60_000,
      enabled: true,
    });
    const headers = { "x-api-key": bk.body!.key };
    expect((await bounded.api.get("/get-session", headers)).status).toBe(200);
    expect((await bounded.api.get("/get-session", headers)).status).toBe(200);
    const third = await bounded.api.get("/get-session", headers);
    expect(third.status).toBe(429);
    expect(await errorCode(third)).toBe("RATE_LIMITED");
    // A refused request never counted: the bound was hit on the third
    // allow-listed use, not earlier, even though a refusal sits in between.
    const refused = await bounded.api.get("/organization/list", headers);
    expect(refused.status).toBe(403);
    expect(await errorCode(refused)).toBe("API_KEY_NOT_ALLOWED_HERE");

    const unbounded = await makeAuth({
      apiKeys: { enableSessionForAPIKeys: true, rateLimit: { enabled: false } },
    });
    const u = await signUpOwner(unbounded);
    const { orgId: uOrg } = await createOrg(unbounded, u.cookie);
    const uk = await createKey(unbounded, u.cookie, uOrg);
    expect((await keyRateLimitRow(unbounded, uk.body!.id)).enabled).toBe(false);
    for (let i = 0; i < 12; i++) {
      expect(
        (await unbounded.api.get("/get-session", { "x-api-key": uk.body!.key })).status,
        `use ${i + 1}`,
      ).toBe(200);
    }

    // Left out, upstream's own default applies — pinned so the docs' "10
    // per 24 h" tracks reality.
    const dflt = await presetOptIn();
    const d = await signUpOwner(dflt);
    const { orgId: dOrg } = await createOrg(dflt, d.cookie);
    const dk = await createKey(dflt, d.cookie, dOrg);
    expect(await keyRateLimitRow(dflt, dk.body!.id)).toEqual({
      max: 10,
      window: 24 * 60 * 60 * 1000,
      enabled: true,
    });
  });

  it("apiKeys.rateLimit is validated with the other options at preset build time", async () => {
    await expect(makeAuth({ apiKeys: { rateLimit: { maxRequests: 0 } } })).rejects.toThrow(
      /apiKeys\.rateLimit\.maxRequests/,
    );
    await expect(makeAuth({ apiKeys: { rateLimit: { timeWindow: -1 } } })).rejects.toThrow(
      /apiKeys\.rateLimit\.timeWindow/,
    );
    await expect(
      makeAuth({ apiKeys: { rateLimit: { enabled: "yes" as unknown as boolean } } }),
    ).rejects.toThrow(/apiKeys\.rateLimit\.enabled/);
    await expect(
      makeAuth({ apiKeys: { rateLimit: null as unknown as { enabled?: boolean } } }),
    ).rejects.toThrow(/apiKeys\.rateLimit/);
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
