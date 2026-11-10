// Staff-only entitlement store (spike security finding 1): entitlements were
// read from `organization.metadata`, which an organization's owner can write
// through better-auth, so an owner could grant itself SSO or SCIM. With
// `entitlements: { store: "table" }` the features come from `org_entitlement`,
// which only platform staff (non-impersonated) can write, audited and rate
// limited. Every test below attacks from the tenant's side first.

import { describe, expect, it, vi } from "vitest";
import { verifyDatabase } from "../../src/schema";
import { readEntitlementRow, setEntitlements } from "../../src/server/entitlement-store";
import type { Feature } from "../../src/server/types";
import { createOrg, makeAuth, signUpOwner, type TestAuth } from "../helpers/auth";
import { auditRows } from "./helpers";

// The staff route is rate limited per client (`test/security/entitlement-store-rate-limit.test.ts`
// pins that); the limiter's store is shared by every test of a file, so the
// tests here lift the limit the way the suite lifts the sign-in one.
async function makeTableAuth(overrides: Parameters<typeof makeAuth>[0] = {}) {
  return makeAuth({
    resolveEntitlements: undefined,
    entitlements: { store: "table" },
    rateLimitCustomRules: { "/enterprise/entitlements/set": { window: 10, max: 10_000 } },
    ...overrides,
  });
}

async function makeStaff(t: TestAuth, email = "staff@platform.test") {
  const staff = await signUpOwner(t, email);
  await t.client.execute({
    sql: `UPDATE user SET role = 'admin' WHERE id = ?`,
    args: [staff.userId],
  });
  return staff;
}

async function entitlementRows(t: TestAuth, orgId: string) {
  const result = await t.client.execute({
    sql: `SELECT * FROM org_entitlement WHERE org_id = ?`,
    args: [orgId],
  });
  return result.rows;
}

async function features(t: TestAuth, cookie: string, orgId: string): Promise<Feature[]> {
  const res = await t.api.get(`/enterprise/features?orgId=${orgId}`, { cookie });
  expect(res.status).toBe(200);
  return ((await res.json()) as { features: Feature[] }).features;
}

function setFeatures(t: TestAuth, cookie: string, orgId: string, list: unknown) {
  return t.api.post("/enterprise/entitlements/set", { orgId, features: list }, { cookie });
}

/** A session of `userId` that an admin impersonation would have minted (`session.impersonatedBy`). */
async function impersonationCookie(t: TestAuth, userId: string, staffId: string): Promise<string> {
  const token = `impersonation_token_${userId}_${Math.random().toString(36).slice(2)}`;
  const now = Date.now();
  await t.client.execute({
    sql: `INSERT INTO session (id, expiresAt, token, createdAt, updatedAt, userId, impersonatedBy) VALUES (?, ?, ?, ?, ?, ?, ?)`,
    args: [`sess_imp_${now}`, now + 3_600_000, token, now, now, userId, staffId],
  });
  const secret = (t.auth.options as { secret: string }).secret;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(token));
  const base64 = btoa(String.fromCharCode(...new Uint8Array(signature)));
  return `better-auth.session_token=${encodeURIComponent(`${token}.${base64}`)}`;
}

describe("an organization owner cannot write entitlements", () => {
  it("organization.metadata written through /organization/update grants nothing", async () => {
    const t = await makeTableAuth();
    const owner = await signUpOwner(t);
    const { orgId } = await createOrg(t, owner.cookie);

    const update = await t.api.post(
      "/organization/update",
      {
        organizationId: orgId,
        data: {
          metadata: {
            features: ["sso", "scim", "audit_log"],
            entitlements: ["sso", "scim"],
            plan: "enterprise",
          },
        },
      },
      { cookie: owner.cookie },
    );
    // The vector exists: the owner really can write the metadata ...
    expect(update.status).toBe(200);
    const row = await t.client.execute({
      sql: `SELECT metadata FROM organization WHERE id = ?`,
      args: [orgId],
    });
    expect(String(row.rows[0]!.metadata)).toContain("scim");

    // ... and it is never read for entitlements.
    expect(await features(t, owner.cookie, orgId)).toEqual([]);
    for (const path of [
      `/enterprise/sso/providers?orgId=${orgId}`,
      `/enterprise/scim/tokens?orgId=${orgId}`,
    ]) {
      const res = await t.api.get(path, { cookie: owner.cookie });
      expect(res.status, path).toBe(403);
      expect(((await res.json()) as { code: string }).code, path).toBe("FEATURE_NOT_ENTITLED");
    }
    expect(await entitlementRows(t, orgId)).toEqual([]);
  });

  it("organization.metadata set at creation grants nothing either", async () => {
    const t = await makeTableAuth();
    const owner = await signUpOwner(t);
    const res = await t.api.post(
      "/organization/create",
      { name: "meta", slug: "meta", metadata: { features: ["sso", "scim"] } },
      { cookie: owner.cookie },
    );
    expect(res.status).toBe(200);
    const { id } = (await res.json()) as { id: string };
    expect(await features(t, owner.cookie, id)).toEqual([]);
  });

  it("the staff endpoint answers 403 NOT_PLATFORM_STAFF and writes nothing", async () => {
    const t = await makeTableAuth();
    const owner = await signUpOwner(t);
    const { orgId } = await createOrg(t, owner.cookie);

    const res = await setFeatures(t, owner.cookie, orgId, ["sso", "scim"]);

    expect(res.status).toBe(403);
    expect(((await res.json()) as { code: string }).code).toBe("NOT_PLATFORM_STAFF");
    expect(await entitlementRows(t, orgId)).toEqual([]);
    expect(await features(t, owner.cookie, orgId)).toEqual([]);
    expect((await auditRows(t, orgId)).map((r) => r.action)).not.toContain("entitlement.changed");
  });

  it("an owner cannot make itself staff (update-user, admin/set-role) to reach the endpoint", async () => {
    const t = await makeTableAuth();
    const owner = await signUpOwner(t);
    const { orgId } = await createOrg(t, owner.cookie);

    // `role` is not an input field; whether upstream ignores it or refuses it,
    // the stored role must not change.
    await t.api.post("/update-user", { role: "admin", name: "Owner" }, { cookie: owner.cookie });
    const setRole = await t.api.post(
      "/admin/set-role",
      { userId: owner.userId, role: "admin" },
      { cookie: owner.cookie },
    );
    expect(setRole.status).toBe(403);
    const role = await t.client.execute({
      sql: `SELECT role FROM user WHERE id = ?`,
      args: [owner.userId],
    });
    expect(role.rows[0]!.role).not.toBe("admin");

    const res = await setFeatures(t, owner.cookie, orgId, ["sso"]);
    expect(res.status).toBe(403);
    expect(await entitlementRows(t, orgId)).toEqual([]);
  });

  it("an org admin or member (not staff) is refused the same way; anonymous gets 401", async () => {
    const t = await makeTableAuth();
    const owner = await signUpOwner(t);
    const { orgId } = await createOrg(t, owner.cookie);
    const other = await signUpOwner(t, "someone@acme.test");

    expect((await setFeatures(t, other.cookie, orgId, ["sso"])).status).toBe(403);
    const anonymous = await t.api.post("/enterprise/entitlements/set", {
      orgId,
      features: ["sso"],
    });
    expect(anonymous.status).toBe(401);
    expect(await entitlementRows(t, orgId)).toEqual([]);
  });

  it("a request carrying an x-api-key header is refused by the gate before the staff endpoint", async () => {
    const t = await makeTableAuth();
    const staff = await makeStaff(t);
    const owner = await signUpOwner(t);
    const { orgId } = await createOrg(t, owner.cookie);

    const res = await t.api.post(
      "/enterprise/entitlements/set",
      { orgId, features: ["sso"] },
      { cookie: staff.cookie, "x-api-key": "anything" },
    );
    expect(res.status).toBe(403);
    expect(((await res.json()) as { code: string }).code).toBe("API_KEY_NOT_ALLOWED_HERE");
    expect(await entitlementRows(t, orgId)).toEqual([]);
  });
});

describe("platform staff", () => {
  it("sets, replaces and revokes an organization's features; the gate follows", async () => {
    const t = await makeTableAuth();
    const staff = await makeStaff(t);
    const owner = await signUpOwner(t);
    const { orgId } = await createOrg(t, owner.cookie);

    // Unentitled org: 403 on SSO and SCIM routes.
    for (const path of [
      `/enterprise/sso/providers?orgId=${orgId}`,
      `/enterprise/scim/tokens?orgId=${orgId}`,
    ]) {
      const res = await t.api.get(path, { cookie: owner.cookie });
      expect(res.status, path).toBe(403);
      expect(((await res.json()) as { code: string }).code, path).toBe("FEATURE_NOT_ENTITLED");
    }
    const unentitledRegister = await t.api.post(
      "/sso/register",
      {
        providerId: "p",
        issuer: "https://idp.example",
        domain: "acme.test",
        organizationId: orgId,
      },
      { cookie: owner.cookie },
    );
    expect(unentitledRegister.status).toBe(403);
    expect(((await unentitledRegister.json()) as { code: string }).code).toBe(
      "FEATURE_NOT_ENTITLED",
    );

    // Entitle SSO only.
    const set = await setFeatures(t, staff.cookie, orgId, ["sso", "sso", "audit_log"]);
    expect(set.status).toBe(200);
    expect(await set.json()).toEqual({ orgId, features: ["sso", "audit_log"] });
    expect(await features(t, owner.cookie, orgId)).toEqual(["sso", "audit_log"]);
    expect(
      (await t.api.get(`/enterprise/sso/providers?orgId=${orgId}`, { cookie: owner.cookie }))
        .status,
    ).toBe(200);
    const scim = await t.api.get(`/enterprise/scim/tokens?orgId=${orgId}`, {
      cookie: owner.cookie,
    });
    expect(scim.status).toBe(403);

    // Replace (not merge), then revoke everything.
    expect((await setFeatures(t, staff.cookie, orgId, ["scim"])).status).toBe(200);
    expect(await features(t, owner.cookie, orgId)).toEqual(["scim"]);
    expect((await setFeatures(t, staff.cookie, orgId, [])).status).toBe(200);
    expect(await features(t, owner.cookie, orgId)).toEqual([]);
    expect(
      (await t.api.get(`/enterprise/scim/tokens?orgId=${orgId}`, { cookie: owner.cookie })).status,
    ).toBe(403);

    const rows = await entitlementRows(t, orgId);
    expect(rows).toHaveLength(1);
    expect(rows[0]!.updated_by).toBe(staff.userId);
  });

  it("audits every change as entitlement.changed in the org's hash chain, with the staff actor", async () => {
    const t = await makeTableAuth();
    const staff = await makeStaff(t);
    const owner = await signUpOwner(t);
    const { orgId } = await createOrg(t, owner.cookie);

    await setFeatures(t, staff.cookie, orgId, ["audit_log", "sso"]);
    await setFeatures(t, staff.cookie, orgId, ["audit_log"]);

    const changed = (await auditRows(t, orgId)).filter((r) => r.action === "entitlement.changed");
    expect(changed).toHaveLength(2);
    expect(changed[1]).toMatchObject({
      actor_type: "user",
      actor_id: staff.userId,
      target_type: "org_entitlement",
      target_id: orgId,
    });
    expect(JSON.parse(String(changed[1]!.metadata))).toEqual({
      features: ["audit_log"],
      previousFeatures: ["sso", "audit_log"],
    });
    const verify = await t.api.get(`/enterprise/audit/verify?orgId=${orgId}`, {
      cookie: owner.cookie,
    });
    expect(await verify.json()).toMatchObject({ ok: true });
  });

  it("is refused from an impersonation session, even when the impersonated user is staff", async () => {
    const t = await makeTableAuth();
    const staff = await makeStaff(t);
    const other = await makeStaff(t, "staff2@platform.test");
    const owner = await signUpOwner(t);
    const { orgId } = await createOrg(t, owner.cookie);

    const cookie = await impersonationCookie(t, other.userId, staff.userId);
    // The session is real: the impersonated user's own routes answer for it.
    expect((await t.api.get("/get-session", { cookie })).status).toBe(200);

    const res = await setFeatures(t, cookie, orgId, ["sso"]);
    expect(res.status).toBe(403);
    expect(((await res.json()) as { code: string }).code).toBe("IMPERSONATION_NOT_ALLOWED");
    expect(await entitlementRows(t, orgId)).toEqual([]);
  });

  it("a demoted staff user loses the ability at once (role is read from the database)", async () => {
    const t = await makeTableAuth();
    const staff = await makeStaff(t);
    const owner = await signUpOwner(t);
    const { orgId } = await createOrg(t, owner.cookie);
    expect((await setFeatures(t, staff.cookie, orgId, ["sso"])).status).toBe(200);

    await t.client.execute({
      sql: `UPDATE user SET role = 'user' WHERE id = ?`,
      args: [staff.userId],
    });

    const res = await setFeatures(t, staff.cookie, orgId, ["scim"]);
    expect(res.status).toBe(403);
    expect(await features(t, owner.cookie, orgId)).toEqual(["sso"]);
  });

  it("honours entitlements.staffRoles and comma-separated roles", async () => {
    const t = await makeTableAuth({ entitlements: { store: "table", staffRoles: ["platform"] } });
    const staff = await signUpOwner(t, "ops@platform.test");
    const owner = await signUpOwner(t);
    const { orgId } = await createOrg(t, owner.cookie);

    await t.client.execute({
      sql: `UPDATE user SET role = 'admin' WHERE id = ?`,
      args: [staff.userId],
    });
    expect((await setFeatures(t, staff.cookie, orgId, ["sso"])).status).toBe(403);

    await t.client.execute({
      sql: `UPDATE user SET role = 'admin,platform' WHERE id = ?`,
      args: [staff.userId],
    });
    expect((await setFeatures(t, staff.cookie, orgId, ["sso"])).status).toBe(200);
  });

  it("validates the request: unknown feature 400, unknown organization 404, no change either way", async () => {
    const t = await makeTableAuth();
    const staff = await makeStaff(t);
    const owner = await signUpOwner(t);
    const { orgId } = await createOrg(t, owner.cookie);

    expect((await setFeatures(t, staff.cookie, orgId, ["sso", "unlimited"])).status).toBe(400);
    expect((await setFeatures(t, staff.cookie, orgId, "sso")).status).toBe(400);
    const missing = await setFeatures(t, staff.cookie, "no_such_org", ["sso"]);
    expect(missing.status).toBe(404);
    expect(((await missing.json()) as { code: string }).code).toBe("ORG_NOT_FOUND");
    expect(await entitlementRows(t, orgId)).toEqual([]);
    expect(await entitlementRows(t, "no_such_org")).toEqual([]);
  });
});

describe("setEntitlements (server API)", () => {
  it("writes and audits for a staff actor, and refuses everyone else", async () => {
    const t = await makeTableAuth();
    const staff = await makeStaff(t);
    const owner = await signUpOwner(t);
    const { orgId } = await createOrg(t, owner.cookie);

    const result = await setEntitlements(t.auth, orgId, ["scim", "sso"], { userId: staff.userId });
    expect(result).toEqual({ features: ["sso", "scim"], previousFeatures: [] });
    expect(await features(t, owner.cookie, orgId)).toEqual(["sso", "scim"]);
    expect((await auditRows(t, orgId)).map((r) => r.action)).toContain("entitlement.changed");

    // The org owner, a user who does not exist, and a banned staff user.
    await expect(
      setEntitlements(t.auth, orgId, ["teams"], { userId: owner.userId }),
    ).rejects.toMatchObject({ body: { code: "NOT_PLATFORM_STAFF" } });
    await expect(
      setEntitlements(t.auth, orgId, ["teams"], { userId: "nobody" }),
    ).rejects.toMatchObject({ body: { code: "NOT_PLATFORM_STAFF" } });
    await t.client.execute({
      sql: `UPDATE user SET banned = 1 WHERE id = ?`,
      args: [staff.userId],
    });
    await expect(
      setEntitlements(t.auth, orgId, ["teams"], { userId: staff.userId }),
    ).rejects.toMatchObject({ body: { code: "NOT_PLATFORM_STAFF" } });
    expect(await features(t, owner.cookie, orgId)).toEqual(["sso", "scim"]);
  });

  it("refuses an unknown feature and an unknown organization", async () => {
    const t = await makeTableAuth();
    const staff = await makeStaff(t);

    await expect(
      setEntitlements(t.auth, "org", ["nope" as Feature], { userId: staff.userId }),
    ).rejects.toMatchObject({ body: { code: "UNKNOWN_FEATURE" } });
    await expect(
      setEntitlements(t.auth, "no_such_org", ["sso"], { userId: staff.userId }),
    ).rejects.toMatchObject({ body: { code: "ORG_NOT_FOUND" } });
  });

  it("is refused on a deployment without the table store", async () => {
    const t = await makeAuth();
    const staff = await makeStaff(t);
    await expect(
      setEntitlements(t.auth, "org", ["sso"], { userId: staff.userId }),
    ).rejects.toMatchObject({ body: { code: "ENTITLEMENT_STORE_DISABLED" } });
  });
});

describe("resolution", () => {
  it("fails closed: no row grants nothing; unknown names in a stored row are dropped", async () => {
    const t = await makeTableAuth();
    const owner = await signUpOwner(t);
    const { orgId } = await createOrg(t, owner.cookie);
    expect(await features(t, owner.cookie, orgId)).toEqual([]);

    await t.client.execute({
      sql: `INSERT INTO org_entitlement (id, org_id, features, updated_at) VALUES (?, ?, ?, ?)`,
      args: ["ent_1", orgId, '["scim","bogus"]', Date.now()],
    });
    expect(await features(t, owner.cookie, orgId)).toEqual(["scim"]);

    await t.client.execute({
      sql: `UPDATE org_entitlement SET features = 'not json' WHERE org_id = ?`,
      args: [orgId],
    });
    expect(await features(t, owner.cookie, orgId)).toEqual([]);
    expect(
      (await t.api.get(`/enterprise/scim/tokens?orgId=${orgId}`, { cookie: owner.cookie })).status,
    ).toBe(403);
  });

  it("a resolveEntitlements callback, when given, takes precedence over the table", async () => {
    const resolveEntitlements = vi.fn(async (): Promise<Feature[]> => ["teams"]);
    const t = await makeTableAuth({ resolveEntitlements });
    const staff = await makeStaff(t);
    const owner = await signUpOwner(t);
    const { orgId } = await createOrg(t, owner.cookie);

    expect((await setFeatures(t, staff.cookie, orgId, ["sso", "scim"])).status).toBe(200);

    expect(await features(t, owner.cookie, orgId)).toEqual(["teams"]);
    expect(
      (await t.api.get(`/enterprise/sso/providers?orgId=${orgId}`, { cookie: owner.cookie }))
        .status,
    ).toBe(403);
    expect(resolveEntitlements).toHaveBeenCalled();
  });

  it("/enterprise/features resolves once per request, through the gate's cache", async () => {
    const t = await makeTableAuth();
    const staff = await makeStaff(t);
    const owner = await signUpOwner(t);
    const { orgId } = await createOrg(t, owner.cookie);
    await setFeatures(t, staff.cookie, orgId, ["sso"]);

    const adapter = (await t.auth.$context).adapter;
    const findOne = vi.spyOn(adapter, "findOne");
    await features(t, owner.cookie, orgId);
    const reads = findOne.mock.calls.filter(
      ([query]) => (query as { model: string }).model === "orgEntitlement",
    );
    expect(reads).toHaveLength(1);
  });
});

describe("callback-only consumers are unchanged", () => {
  it("adds no table, no verify failure, and answers the staff endpoint 404 to staff", async () => {
    const entitled = new Set<Feature>(["sso"]);
    const t = await makeAuth({
      resolveEntitlements: async () => entitled,
      rateLimitCustomRules: { "/enterprise/entitlements/set": { window: 10, max: 10_000 } },
    });
    const staff = await makeStaff(t);
    const owner = await signUpOwner(t);
    const { orgId } = await createOrg(t, owner.cookie);

    expect(await verifyDatabase(t.client)).toEqual({ ok: true, missing: [] });
    const tables = await t.client.execute(
      `SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'org_entitlement'`,
    );
    expect(tables.rows).toEqual([]);

    expect(await features(t, owner.cookie, orgId)).toEqual(["sso"]);
    expect(
      (await t.api.get(`/enterprise/sso/providers?orgId=${orgId}`, { cookie: owner.cookie }))
        .status,
    ).toBe(200);
    expect(
      (await t.api.get(`/enterprise/scim/tokens?orgId=${orgId}`, { cookie: owner.cookie })).status,
    ).toBe(403);

    const asOwner = await setFeatures(t, owner.cookie, orgId, ["scim"]);
    expect(asOwner.status).toBe(403);
    const asStaff = await setFeatures(t, staff.cookie, orgId, ["scim"]);
    expect(asStaff.status).toBe(404);
    expect(((await asStaff.json()) as { code: string }).code).toBe("ENTITLEMENT_STORE_DISABLED");
    expect(await features(t, owner.cookie, orgId)).toEqual(["sso"]);
  });

  it("rejects options with no way to resolve entitlements", async () => {
    await expect(makeAuth({ resolveEntitlements: undefined })).rejects.toThrow(
      /resolveEntitlements.*entitlements/,
    );
    await expect(
      makeAuth({ entitlements: { store: "metadata" as unknown as "table" } }),
    ).rejects.toThrow(/entitlements\.store/);
  });
});

describe("a table store whose migration was never applied", () => {
  it("denies every gated route with a server error that names the migration", async () => {
    const t = await makeTableAuth();
    const owner = await signUpOwner(t);
    const { orgId } = await createOrg(t, owner.cookie);
    await t.client.execute("DROP TABLE org_entitlement");

    for (const path of [
      `/enterprise/sso/providers?orgId=${orgId}`,
      `/enterprise/scim/tokens?orgId=${orgId}`,
      `/enterprise/features?orgId=${orgId}`,
    ]) {
      const res = await t.api.get(path, { cookie: owner.cookie });
      expect(res.status, path).toBe(500);
    }

    const context = await t.auth.$context;
    const adapter = context.adapter as unknown as Parameters<typeof readEntitlementRow>[0];
    await expect(readEntitlementRow(adapter, orgId)).rejects.toThrow(
      /ab-enterprise migrate --entitlements/,
    );
  });
});
