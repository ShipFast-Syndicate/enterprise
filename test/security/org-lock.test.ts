// Staff-only organization creation and metadata write lock (spike security
// finding 1, second half): an organization's owner can write
// `organization.metadata` through `/organization/update` and at creation, so a
// product reading plans or flags from it trusts tenant-written data.
// `organization.creation` / `organization.metadata` lock both to platform staff
// and server-only calls. Every test attacks from the tenant's side first.

import { organization } from "better-auth/plugins";
import { describe, expect, it, vi } from "vitest";
import { enterprisePreset } from "../../src/server/preset";
import {
  ORG_CREATION_STAFF_ONLY,
  ORG_LOCK_PLUGIN_ID,
  ORG_METADATA_STAFF_ONLY,
  ORG_WRITE_REFUSED_ACTION,
} from "../../src/server/org-lock";
import type { EnterpriseOptions } from "../../src/server/types";
import { createOrg, makeAuth, signUpOwner, type TestAuth } from "../helpers/auth";
import { auditRows } from "./helpers";

type Orgs = NonNullable<EnterpriseOptions["organization"]>;

/** `auth.api` as a server-only caller sees it (the test auth is typed without the organization endpoints). */
function serverApi(t: TestAuth) {
  return t.auth.api as unknown as {
    createOrganization(input: {
      body: Record<string, unknown>;
      headers?: Headers;
    }): Promise<{ id: string }>;
  };
}

async function makeStaff(t: TestAuth, email = "staff@platform.test") {
  const staff = await signUpOwner(t, email);
  await t.client.execute({
    sql: `UPDATE user SET role = 'admin' WHERE id = ?`,
    args: [staff.userId],
  });
  return staff;
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

async function storedMetadata(t: TestAuth, orgId: string): Promise<string | null> {
  const row = await t.client.execute({
    sql: `SELECT metadata FROM organization WHERE id = ?`,
    args: [orgId],
  });
  const value = row.rows[0]?.metadata;
  return value === null || value === undefined ? null : String(value);
}

async function orgCount(t: TestAuth): Promise<number> {
  const result = await t.client.execute(`SELECT COUNT(*) AS n FROM organization`);
  return Number(result.rows[0]!.n);
}

function update(t: TestAuth, cookie: string, body: Record<string, unknown>) {
  return t.api.post("/organization/update", body, { cookie });
}

function create(t: TestAuth, cookie: string, body: Record<string, unknown>) {
  return t.api.post("/organization/create", body, { cookie });
}

async function codeOf(res: Response): Promise<string> {
  return ((await res.json()) as { code: string }).code;
}

async function refusedRows(t: TestAuth, orgId: string) {
  return (await auditRows(t, orgId)).filter((r) => r.action === ORG_WRITE_REFUSED_ACTION);
}

/** An organization the owner belongs to, made by a server-only call (works under any lock). */
async function serverCreateOrg(t: TestAuth, userId: string, slug = "acme") {
  const org = await serverApi(t).createOrganization({ body: { name: slug, slug, userId } });
  return org.id;
}

const LOCKED: Orgs = { metadata: "staff-only" };

describe("defaults are unchanged", () => {
  it("an owner still writes metadata at creation and through update; no lock plugin is mounted", async () => {
    const t = await makeAuth();
    const ids = (await t.auth.$context).options.plugins?.map((p) => p.id) ?? [];
    expect(ids).not.toContain(ORG_LOCK_PLUGIN_ID);

    const owner = await signUpOwner(t);
    const created = await create(t, owner.cookie, {
      name: "meta",
      slug: "meta",
      metadata: { plan: "x" },
    });
    expect(created.status).toBe(200);
    const { id } = (await created.json()) as { id: string };
    const res = await update(t, owner.cookie, {
      organizationId: id,
      data: { metadata: { plan: "y" } },
    });
    expect(res.status).toBe(200);
    expect(await storedMetadata(t, id)).toContain('"y"');
    expect(await refusedRows(t, id)).toEqual([]);
  });

  it("explicit defaults mount nothing either", async () => {
    const plugins = enterprisePreset({
      product: "test",
      secretsKey: "s".repeat(32),
      scimCredentialHashSecret: "catalog-test-key-".repeat(3),
      resolveEntitlements: async () => new Set(),
      organization: { creation: "self-service", metadata: "open" },
    });
    expect(plugins.map((p) => p.id)).not.toContain(ORG_LOCK_PLUGIN_ID);
  });

  it("rejects values outside the documented ones at construction", async () => {
    await expect(makeAuth({ organization: { creation: "nobody" as never } })).rejects.toThrow(
      /organization\.creation/,
    );
    await expect(makeAuth({ organization: { metadata: "closed" as never } })).rejects.toThrow(
      /organization\.metadata/,
    );
  });
});

describe("metadata: staff-only", () => {
  it("refuses an owner's PATCH of metadata, writes nothing, and audits the refusal in the org's chain", async () => {
    const t = await makeAuth({ organization: LOCKED });
    const owner = await signUpOwner(t);
    const { orgId } = await createOrg(t, owner.cookie);

    const res = await update(t, owner.cookie, {
      organizationId: orgId,
      data: { metadata: { features: ["sso", "scim"], plan: "enterprise" } },
    });

    expect(res.status).toBe(403);
    expect(await codeOf(res)).toBe(ORG_METADATA_STAFF_ONLY);
    expect(await storedMetadata(t, orgId)).toBeNull();

    const rows = await refusedRows(t, orgId);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      actor_type: "user",
      actor_id: owner.userId,
      target_type: "organization",
      target_id: orgId,
    });
    expect(JSON.parse(String(rows[0]!.metadata))).toEqual({
      code: ORG_METADATA_STAFF_ONLY,
      path: "/organization/update",
    });
    const verify = await t.api.get(`/enterprise/audit/verify?orgId=${orgId}`, {
      cookie: owner.cookie,
    });
    expect(await verify.json()).toMatchObject({ ok: true });
  });

  it("refuses metadata set to null and uses the active organization when none is named", async () => {
    const t = await makeAuth({ organization: LOCKED });
    const owner = await signUpOwner(t);
    const { orgId } = await createOrg(t, owner.cookie); // creation also makes it the active org

    const res = await update(t, owner.cookie, { data: { metadata: null } });
    expect(res.status).toBe(403);
    expect(await codeOf(res)).toBe(ORG_METADATA_STAFF_ONLY);
    expect((await refusedRows(t, orgId)).length).toBe(1);
  });

  it("refuses create-with-metadata and creates nothing; create without metadata still works", async () => {
    const t = await makeAuth({ organization: LOCKED });
    const owner = await signUpOwner(t);
    const before = await orgCount(t);

    const res = await create(t, owner.cookie, {
      name: "meta",
      slug: "meta",
      metadata: { features: ["sso"] },
    });
    expect(res.status).toBe(403);
    expect(await codeOf(res)).toBe(ORG_METADATA_STAFF_ONLY);
    expect(await orgCount(t)).toBe(before);

    const plain = await create(t, owner.cookie, { name: "plain", slug: "plain" });
    expect(plain.status).toBe(200);
  });

  it("leaves every other field of /organization/update open to the owner", async () => {
    const t = await makeAuth({ organization: LOCKED });
    const owner = await signUpOwner(t);
    const { orgId } = await createOrg(t, owner.cookie);

    const res = await update(t, owner.cookie, {
      organizationId: orgId,
      data: { name: "Renamed" },
    });
    expect(res.status).toBe(200);
    expect(await refusedRows(t, orgId)).toEqual([]);
  });

  it("does not let a non-member append rows to another organization's chain", async () => {
    const t = await makeAuth({ organization: LOCKED });
    const owner = await signUpOwner(t);
    const { orgId } = await createOrg(t, owner.cookie);
    const stranger = await signUpOwner(t, "stranger@else.test");

    const res = await update(t, stranger.cookie, {
      organizationId: orgId,
      data: { metadata: { plan: "free-for-all" } },
    });
    expect(res.status).toBe(403);
    expect(await codeOf(res)).toBe(ORG_METADATA_STAFF_ONLY);
    expect(await refusedRows(t, orgId)).toEqual([]);
    expect(await storedMetadata(t, orgId)).toBeNull();
  });

  it("allows platform staff, from the staff user's own session, and audits the write", async () => {
    const t = await makeAuth({ organization: LOCKED });
    const owner = await signUpOwner(t);
    const { orgId } = await createOrg(t, owner.cookie);
    const staff = await makeStaff(t);
    await t.client.execute({
      sql: `INSERT INTO member (id, organizationId, userId, role, createdAt) VALUES (?, ?, ?, ?, ?)`,
      args: ["member_staff", orgId, staff.userId, "admin", Date.now()],
    });

    const res = await update(t, staff.cookie, {
      organizationId: orgId,
      data: { metadata: { plan: "enterprise" } },
    });
    expect(res.status).toBe(200);
    expect(await storedMetadata(t, orgId)).toContain("enterprise");
    expect(await refusedRows(t, orgId)).toEqual([]);

    const created = await create(t, staff.cookie, {
      name: "staff-made",
      slug: "staff-made",
      metadata: { plan: "pro" },
    });
    expect(created.status).toBe(200);
  });

  it("allows a server-only call; a call that passes headers is judged as a session call", async () => {
    const t = await makeAuth({ organization: LOCKED });
    const owner = await signUpOwner(t);

    const org = await serverApi(t).createOrganization({
      body: { name: "srv", slug: "srv", userId: owner.userId, metadata: { plan: "pro" } },
    });
    expect(org.id).toBeTruthy();
    expect(await storedMetadata(t, org.id)).toContain("pro");

    await expect(
      serverApi(t).createOrganization({
        headers: new Headers({ cookie: owner.cookie }),
        body: { name: "hdr", slug: "hdr", metadata: { plan: "pro" } },
      }),
    ).rejects.toMatchObject({ body: { code: ORG_METADATA_STAFF_ONLY } });
  });

  it("refuses a staff member's impersonation session, even when the impersonated user is staff", async () => {
    const t = await makeAuth({ organization: LOCKED });
    const owner = await signUpOwner(t);
    const { orgId } = await createOrg(t, owner.cookie);
    const staff = await makeStaff(t);
    const other = await makeStaff(t, "staff2@platform.test");
    await t.client.execute({
      sql: `INSERT INTO member (id, organizationId, userId, role, createdAt) VALUES (?, ?, ?, ?, ?)`,
      args: ["member_other", orgId, other.userId, "owner", Date.now()],
    });

    const cookie = await impersonationCookie(t, other.userId, staff.userId);
    expect((await t.api.get("/get-session", { cookie })).status).toBe(200);

    const res = await update(t, cookie, {
      organizationId: orgId,
      data: { metadata: { plan: "enterprise" } },
    });
    expect(res.status).toBe(403);
    expect(await codeOf(res)).toBe(ORG_METADATA_STAFF_ONLY);
    expect(await storedMetadata(t, orgId)).toBeNull();

    // The row never reads as the impersonated user's own act.
    const rows = await refusedRows(t, orgId);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ actor_type: "impersonated", actor_id: other.userId });
    expect(JSON.parse(String(rows[0]!.metadata))).toMatchObject({ impersonatedBy: staff.userId });
  });

  it("a demoted staff user loses the ability at once; staffRoles is honoured", async () => {
    const t = await makeAuth({
      organization: LOCKED,
      entitlements: { store: "table", staffRoles: ["platform"] },
      resolveEntitlements: undefined,
    });
    const staff = await signUpOwner(t, "ops@platform.test");
    const { orgId } = await createOrg(t, staff.cookie);

    await t.client.execute({
      sql: `UPDATE user SET role = 'admin' WHERE id = ?`,
      args: [staff.userId],
    });
    expect(
      (await update(t, staff.cookie, { organizationId: orgId, data: { metadata: { a: 1 } } }))
        .status,
    ).toBe(403);

    await t.client.execute({
      sql: `UPDATE user SET role = 'admin,platform' WHERE id = ?`,
      args: [staff.userId],
    });
    expect(
      (await update(t, staff.cookie, { organizationId: orgId, data: { metadata: { a: 1 } } }))
        .status,
    ).toBe(200);

    await t.client.execute({
      sql: `UPDATE user SET role = 'user' WHERE id = ?`,
      args: [staff.userId],
    });
    expect(
      (await update(t, staff.cookie, { organizationId: orgId, data: { metadata: { a: 2 } } }))
        .status,
    ).toBe(403);
  });

  it("an anonymous request is left to upstream's 401", async () => {
    const t = await makeAuth({ organization: LOCKED });
    const res = await t.api.post("/organization/update", {
      organizationId: "x",
      data: { metadata: { a: 1 } },
    });
    expect(res.status).toBe(401);
  });

  it("a request carrying an x-api-key header is refused by the gate first", async () => {
    const t = await makeAuth({ organization: LOCKED });
    const owner = await signUpOwner(t);
    const { orgId } = await createOrg(t, owner.cookie);
    const res = await t.api.post(
      "/organization/update",
      { organizationId: orgId, data: { metadata: { a: 1 } } },
      { cookie: owner.cookie, "x-api-key": "anything" },
    );
    expect(res.status).toBe(403);
    expect(await codeOf(res)).toBe("API_KEY_NOT_ALLOWED_HERE");
  });
});

describe("creation: staff-only", () => {
  it("refuses an owner creating a second organization with a distinct code, and audits it in the owner's orgs", async () => {
    const t = await makeAuth({ organization: { creation: "staff-only" } });
    const owner = await signUpOwner(t);
    const orgId = await serverCreateOrg(t, owner.userId);
    const before = await orgCount(t);

    const res = await create(t, owner.cookie, { name: "second", slug: "second" });

    expect(res.status).toBe(403);
    expect(await codeOf(res)).toBe(ORG_CREATION_STAFF_ONLY);
    expect(await orgCount(t)).toBe(before);
    const rows = await refusedRows(t, orgId);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ actor_type: "user", actor_id: owner.userId });
    expect(JSON.parse(String(rows[0]!.metadata))).toEqual({
      code: ORG_CREATION_STAFF_ONLY,
      path: "/organization/create",
    });
  });

  it("a caller who belongs to no organization is refused, and no chain row is written (documented carve-out)", async () => {
    const t = await makeAuth({ organization: { creation: "staff-only" } });
    const loner = await signUpOwner(t);
    const before = await orgCount(t);

    const res = await create(t, loner.cookie, { name: "x", slug: "x" });
    expect(res.status).toBe(403);
    expect(await codeOf(res)).toBe(ORG_CREATION_STAFF_ONLY);
    expect(await orgCount(t)).toBe(before);
    // Chains are per organization: with none to land in, the refusal is only
    // logged at `warn` (docs/security.md), and nothing lands in another chain.
    const rows = await t.client.execute({
      sql: `SELECT COUNT(*) AS n FROM audit_event WHERE action = ?`,
      args: [ORG_WRITE_REFUSED_ACTION],
    });
    expect(Number(rows.rows[0]!.n)).toBe(0);
  });

  it("a creation function that throws is a refusal (audited, 403), not a 500", async () => {
    const t = await makeAuth({
      organization: {
        creation: async () => {
          throw new Error("predicate down");
        },
      },
    });
    const owner = await signUpOwner(t);
    const orgId = await serverCreateOrg(t, owner.userId);
    const before = await orgCount(t);

    const res = await create(t, owner.cookie, { name: "second", slug: "second" });
    expect(res.status).toBe(403);
    expect(await codeOf(res)).toBe(ORG_CREATION_STAFF_ONLY);
    expect(await orgCount(t)).toBe(before);
    expect(await refusedRows(t, orgId)).toHaveLength(1);
  });

  it("staff may create with metadata when only creation is staff-only", async () => {
    const t = await makeAuth({ organization: { creation: "staff-only" } });
    const staff = await makeStaff(t);
    const created = await create(t, staff.cookie, {
      name: "staff-made",
      slug: "staff-made",
      metadata: { plan: "pro" },
    });
    expect(created.status).toBe(200);
  });

  it("an owner still writes metadata through update when only creation is staff-only", async () => {
    const t = await makeAuth({ organization: { creation: "staff-only" } });
    const owner = await signUpOwner(t);
    const orgId = await serverCreateOrg(t, owner.userId);
    const res = await update(t, owner.cookie, {
      organizationId: orgId,
      data: { metadata: { plan: "y" } },
    });
    expect(res.status).toBe(200);
    expect(await storedMetadata(t, orgId)).toContain('"y"');
    expect(await refusedRows(t, orgId)).toEqual([]);
  });

  it("creation is judged first when both options are locked and both would fail", async () => {
    const both = await makeAuth({
      organization: { creation: "staff-only", metadata: "staff-only" },
    });
    const owner = await signUpOwner(both);
    const res = await create(both, owner.cookie, { name: "m", slug: "m", metadata: { a: 1 } });
    expect(await codeOf(res)).toBe(ORG_CREATION_STAFF_ONLY);
  });

  it("allows platform staff over HTTP and server-only calls", async () => {
    const t = await makeAuth({ organization: { creation: "staff-only" } });
    const staff = await makeStaff(t);
    const owner = await signUpOwner(t);

    expect((await create(t, staff.cookie, { name: "a", slug: "a" })).status).toBe(200);
    const org = await serverApi(t).createOrganization({
      body: { name: "b", slug: "b", userId: owner.userId },
    });
    expect(org.id).toBeTruthy();
  });

  it("refuses an impersonation session of a staff user", async () => {
    const t = await makeAuth({ organization: { creation: "staff-only" } });
    const staff = await makeStaff(t);
    const other = await makeStaff(t, "staff2@platform.test");
    const before = await orgCount(t);

    const cookie = await impersonationCookie(t, other.userId, staff.userId);
    const res = await create(t, cookie, { name: "imp", slug: "imp" });
    expect(res.status).toBe(403);
    expect(await codeOf(res)).toBe(ORG_CREATION_STAFF_ONLY);
    expect(await orgCount(t)).toBe(before);
  });

  it("a function decides for callers who are not staff; staff and server calls skip it", async () => {
    const predicate = vi.fn(async ({ user }: { user: { id: string; email: string } }) =>
      user.email.endsWith("@acme.test"),
    );
    const t = await makeAuth({ organization: { creation: predicate } });
    const insider = await signUpOwner(t, "insider@acme.test");
    const outsider = await signUpOwner(t, "outsider@else.test");
    const staff = await makeStaff(t);

    expect((await create(t, insider.cookie, { name: "in", slug: "in" })).status).toBe(200);
    const refused = await create(t, outsider.cookie, { name: "out", slug: "out" });
    expect(refused.status).toBe(403);
    expect(await codeOf(refused)).toBe(ORG_CREATION_STAFF_ONLY);

    predicate.mockClear();
    expect((await create(t, staff.cookie, { name: "st", slug: "st" })).status).toBe(200);
    await serverApi(t).createOrganization({
      body: { name: "srv", slug: "srv", userId: outsider.userId },
    });
    expect(predicate).not.toHaveBeenCalled();
  });

  it("does not affect /organization/update of other fields or metadata", async () => {
    const t = await makeAuth({ organization: { creation: "staff-only" } });
    const owner = await signUpOwner(t);
    const orgId = await serverCreateOrg(t, owner.userId);
    const res = await update(t, owner.cookie, {
      organizationId: orgId,
      data: { metadata: { plan: "x" } },
    });
    expect(res.status).toBe(200);
  });
});

describe("a product that replaces the organization plugin", () => {
  const own = () => organization({ teams: { enabled: true } });

  it("is unaffected by default", async () => {
    const t = await makeAuth({ organizationPlugin: own() });
    const owner = await signUpOwner(t);
    const created = await create(t, owner.cookie, {
      name: "meta",
      slug: "meta",
      metadata: { plan: "x" },
    });
    expect(created.status).toBe(200);
    const { id } = (await created.json()) as { id: string };
    expect(
      (await update(t, owner.cookie, { organizationId: id, data: { metadata: { plan: "y" } } }))
        .status,
    ).toBe(200);
  });

  it("is still locked when the options say so", async () => {
    const t = await makeAuth({
      organizationPlugin: own(),
      organization: { creation: "staff-only", metadata: "staff-only" },
    });
    const owner = await signUpOwner(t);
    const orgId = await serverCreateOrg(t, owner.userId);

    const made = await create(t, owner.cookie, { name: "second", slug: "second" });
    expect(made.status).toBe(403);
    expect(await codeOf(made)).toBe(ORG_CREATION_STAFF_ONLY);
    const patched = await update(t, owner.cookie, {
      organizationId: orgId,
      data: { metadata: { plan: "x" } },
    });
    expect(patched.status).toBe(403);
    expect(await codeOf(patched)).toBe(ORG_METADATA_STAFF_ONLY);
  });
});

describe("upstream allowUserToCreateOrganization: false, for reference", () => {
  it("refuses staff over HTTP as well, and lets only a sessionless server call with body.userId through", async () => {
    const t = await makeAuth({ organization: { allowUserToCreateOrganization: false } });
    const staff = await makeStaff(t);
    const owner = await signUpOwner(t);

    const res = await create(t, staff.cookie, { name: "a", slug: "a" });
    expect(res.status).toBe(403);
    expect(await codeOf(res)).toBe("YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_ORGANIZATION");

    const org = await serverApi(t).createOrganization({
      body: { name: "b", slug: "b", userId: owner.userId },
    });
    expect(org.id).toBeTruthy();
  });

  it("combined with staff-only creation, both apply", async () => {
    const t = await makeAuth({
      organization: { allowUserToCreateOrganization: false, creation: "staff-only" },
    });
    const staff = await makeStaff(t);
    const res = await create(t, staff.cookie, { name: "a", slug: "a" });
    expect(await codeOf(res)).toBe("YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_ORGANIZATION");
  });
});
