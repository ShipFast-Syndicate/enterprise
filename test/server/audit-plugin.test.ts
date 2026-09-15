import { describe, expect, it } from "vitest";
import { auditLog, AUDITED_PATHS } from "../../src/server/audit/plugin";
import { makeAuth, signUpOwner, createOrg, type TestAuth } from "../helpers/auth";

async function inviteMember(t: TestAuth, cookie: string, orgId: string, email: string) {
  const res = await t.api.post(
    "/organization/invite-member",
    { email, role: "member", organizationId: orgId },
    { cookie },
  );
  if (!res.ok) throw new Error(`invite-member failed: ${res.status} ${await res.text()}`);
  return (await res.json()) as { id: string; inviterId: string };
}

async function insertMemberRow(t: TestAuth, orgId: string, userId: string, role: string) {
  // better-auth's own `member` model has no `fieldName` overrides, so its
  // dynamically-generated table (`test/helpers/auth.ts`'s
  // `buildDynamicSchema`) uses the field keys themselves as column names —
  // camelCase, unlike this package's own snake_case tables.
  await t.client.execute({
    sql: `INSERT INTO member (id, organizationId, userId, role, createdAt) VALUES (?, ?, ?, ?, ?)`,
    args: [`member_${userId}`, orgId, userId, role, Date.now()],
  });
}

describe("AUDITED_PATHS", () => {
  it("covers the target types the brief lists, expanded to {action, targetType} objects", () => {
    const targetTypes = new Set(Object.values(AUDITED_PATHS).map((v) => v.targetType));
    expect(targetTypes).toEqual(
      new Set(["user", "member", "sso_provider", "scim_provider", "api_key", "org_policy"]),
    );
  });

  it("keys parameterised paths by better-auth's real registered pattern, not the brief's shorthand", () => {
    // @better-auth/scim registers its Users-by-id endpoints at
    // "/scim/v2/Users/:userId" (verified by grepping
    // node_modules/@better-auth/scim/dist/index.mjs), not "/scim/v2/Users/:id"
    // as the task brief's illustrative sketch wrote.
    expect(AUDITED_PATHS["/scim/v2/Users/:userId"]).toEqual({
      action: "scim.user_updated",
      targetType: "user",
      methods: ["PUT", "PATCH"],
    });
    expect(AUDITED_PATHS["/scim/v2/Users/:id"]).toBeUndefined();
    expect(AUDITED_PATHS["/sso/callback/:providerId"]).toEqual({
      action: "auth.sso_sign_in",
      targetType: "user",
    });
  });
});

describe("enterprise-audit hook matcher — parameterised path matching", () => {
  // `ctx.path` inside a `hooks.after` handler is the *route pattern* an
  // endpoint was registered with (e.g. "/scim/v2/Users/:userId"), never the
  // concrete resolved path with real param values substituted in — see
  // `./plugin.ts`'s header comment for the upstream dispatch code this was
  // verified against. The matcher must therefore match on the literal
  // pattern and must NOT match a concrete path that merely looks similar.
  const plugin = auditLog({
    product: "test",
    secretsKey: "s".repeat(32),
    resolveEntitlements: async () => new Set(),
  });
  const matcher = plugin.hooks!.after![0]!.matcher;

  it("matches the exact registered pattern (for a method the path is audited on)", () => {
    expect(matcher({ path: "/scim/v2/Users/:userId", request: { method: "PATCH" } } as never)).toBe(
      true,
    );
    expect(
      matcher({ path: "/sso/callback/:providerId", request: { method: "POST" } } as never),
    ).toBe(true);
  });

  it("does not match a concrete resolved path with a real id substituted in", () => {
    expect(
      matcher({ path: "/scim/v2/Users/usr_abc123", request: { method: "PATCH" } } as never),
    ).toBe(false);
    expect(matcher({ path: "/sso/callback/okta-prod", request: { method: "POST" } } as never)).toBe(
      false,
    );
  });

  it("does not match a read method on a path whose mutating siblings share the pattern", () => {
    // /scim/v2/Users/:userId is also GET (read) and DELETE (audited as a
    // different action, scim.user_deleted — see METHOD_ACTION_OVERRIDES);
    // GET must not match at all.
    expect(matcher({ path: "/scim/v2/Users/:userId", request: { method: "GET" } } as never)).toBe(
      false,
    );
  });

  it("matches DELETE on /scim/v2/Users/:userId via the method-action override, even though it's outside the base `methods` allow-list", () => {
    expect(
      matcher({ path: "/scim/v2/Users/:userId", request: { method: "DELETE" } } as never),
    ).toBe(true);
  });
});

describe("enterprise-audit hook — /organization/invite-member", () => {
  it("writes one member.invited row with actorId = owner and targetId = invitation id", async () => {
    const t = await makeAuth();
    const { cookie, userId: ownerId } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);

    const invitation = await inviteMember(t, cookie, orgId, "invitee@acme.test");

    const rows = await t.client.execute({
      sql: `SELECT * FROM audit_event WHERE org_id = ? AND action = 'member.invited'`,
      args: [orgId],
    });
    expect(rows.rows.length).toBe(1);
    const row = rows.rows[0]!;
    expect(row.actor_id).toBe(ownerId);
    expect(row.target_id).toBe(invitation.id);
    expect(row.target_type).toBe("member");
    expect(row.actor_type).toBe("user");
    expect(String(row.prev_hash)).toBe("GENESIS");
    expect(String(row.hash)).toMatch(/^[0-9a-f]{64}$/);
  });

  it("does not write an audit row for a failed call (no session)", async () => {
    const t = await makeAuth();
    const res = await t.api.post("/organization/invite-member", {
      email: "invitee@acme.test",
      role: "member",
      organizationId: "org_does_not_exist",
    });
    expect(res.status).toBe(401);

    const rows = await t.client.execute(`SELECT * FROM audit_event`);
    expect(rows.rows.length).toBe(0);
  });
});

describe("enterprise-audit hook — writeAudit failure handling (ruling e)", () => {
  it("admin path: a writeAudit failure throws 500 AUDIT_WRITE_FAILED, failing the call", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);
    // Force writeAudit to fail without touching plugin code, by removing
    // the table it writes to out from under it.
    await t.client.execute(`DROP TABLE audit_event`);

    const res = await t.api.post(
      "/organization/invite-member",
      { email: "invitee@acme.test", role: "member", organizationId: orgId },
      { cookie },
    );

    expect(res.status).toBe(500);
    expect((await res.json()).code).toBe("AUDIT_WRITE_FAILED");
  });

  it("sign-in path: a writeAudit failure is logged and swallowed — sign-in still succeeds", async () => {
    const t = await makeAuth();
    const email = "owner@acme.test";
    await signUpOwner(t, email);
    await t.client.execute(`DROP TABLE audit_event`);

    const res = await t.api.post("/sign-in/email", { email, password: "password1234" });

    expect(res.status).toBe(200);
    const body = (await res.json()) as { user: { email: string } };
    expect(body.user.email).toBe(email);
  });
});

describe("GET /enterprise/audit/list", () => {
  it("requires the audit_log feature (403 without it)", async () => {
    const t = await makeAuth({ resolveEntitlements: async () => [] });
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);

    const res = await t.api.get(`/enterprise/audit/list?orgId=${orgId}`, { cookie });

    expect(res.status).toBe(403);
    expect((await res.json()).code).toBe("FEATURE_NOT_ENTITLED");
  });

  it("requires an owner/admin membership (403 for a plain member)", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);
    const { cookie: memberCookie, userId: memberId } = await signUpOwner(t, "member@acme.test");
    await insertMemberRow(t, orgId, memberId, "member");

    const res = await t.api.get(`/enterprise/audit/list?orgId=${orgId}`, { cookie: memberCookie });

    expect(res.status).toBe(403);
    expect((await res.json()).code).toBe("NOT_ORG_ADMIN");
  });

  it("returns invite-member events for the owner", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);
    await inviteMember(t, cookie, orgId, "one@acme.test");
    await inviteMember(t, cookie, orgId, "two@acme.test");

    const res = await t.api.get(`/enterprise/audit/list?orgId=${orgId}`, { cookie });
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      items: Array<{ action: string }>;
      nextCursor: string | null;
    };
    expect(body.items).toHaveLength(2);
    expect(body.items.every((i) => i.action === "member.invited")).toBe(true);
    expect(body.nextCursor).toBeNull();
  });

  it("lazily purges rows older than audit.retentionDays on list (ruling g)", async () => {
    const t = await makeAuth({ audit: { retentionDays: 30 } });
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);

    const fortyDaysAgo = Date.now() - 40 * 24 * 60 * 60 * 1000;
    await t.client.execute({
      sql: `INSERT INTO audit_event (id, org_id, seq, actor_type, actor_id, action, target_type, target_id, metadata, created_at, prev_hash, hash) VALUES ('evt_old', ?, 1, 'user', 'u1', 'member.invited', 'member', 't1', '{}', ?, 'GENESIS', 'deadbeef')`,
      args: [orgId, fortyDaysAgo],
    });
    await inviteMember(t, cookie, orgId, "fresh@acme.test");

    const before = await t.client.execute({
      sql: `SELECT * FROM audit_event WHERE org_id = ?`,
      args: [orgId],
    });
    expect(before.rows.length).toBe(2); // old + fresh, purge hasn't run yet

    const res = await t.api.get(`/enterprise/audit/list?orgId=${orgId}`, { cookie });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { items: Array<{ id: string }> };
    expect(body.items.map((i) => i.id)).not.toContain("evt_old");

    const after = await t.client.execute({
      sql: `SELECT * FROM audit_event WHERE org_id = ?`,
      args: [orgId],
    });
    expect(after.rows.length).toBe(1);
    expect(after.rows[0]!.id).not.toBe("evt_old");
  });
});

describe("GET /enterprise/audit/export", () => {
  it("returns a CSV with the header and one row per audit event", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);
    await inviteMember(t, cookie, orgId, "one@acme.test");
    await inviteMember(t, cookie, orgId, "two@acme.test");
    await inviteMember(t, cookie, orgId, "three@acme.test");

    const res = await t.api.get(`/enterprise/audit/export?orgId=${orgId}`, { cookie });

    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toMatch(/text\/csv/);
    expect(res.headers.get("content-disposition")).toMatch(new RegExp(`audit-${orgId}`));

    const text = await res.text();
    const lines = text.trim().split("\r\n");
    expect(lines[0]).toBe(
      "id,seq,created_at,actor_type,actor_id,action,target_type,target_id,ip,user_agent,metadata,prev_hash,hash",
    );
    expect(lines.length).toBe(4); // header + 3 rows
  });

  it("RFC 4180-escapes a field containing a quote, a comma, and a raw newline", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);

    // `metadata` is always JSON round-tripped (`JSON.stringify` on export),
    // so an embedded newline in a metadata *value* always comes back out as
    // the two-character `\n` escape, never a raw newline byte — but its
    // JSON syntax still carries plenty of literal `"` and `,` characters
    // needing escaping (e.g. the comma inside the note text below, and the
    // quotes JSON uses for strings). `user_agent` is stored and exported as
    // a plain string with no such re-encoding, so a raw newline planted
    // there (e.g. a malformed/hostile User-Agent header) survives into the
    // CSV verbatim and is the one field here that genuinely needs
    // newline-triggered quoting.
    const metadata = { note: 'has "quotes", a comma, and a\nnewline (escaped in JSON)' };
    const userAgent = "Mozilla/5.0\nInjected-Header: evil";
    await t.client.execute({
      sql: `INSERT INTO audit_event (id, org_id, seq, actor_type, actor_id, action, target_type, target_id, user_agent, metadata, created_at, prev_hash, hash) VALUES ('evt_csv', ?, 1, 'user', 'u1', 'member.invited', 'member', 't1', ?, ?, ?, 'GENESIS', 'deadbeef')`,
      args: [orgId, userAgent, JSON.stringify(metadata), Date.now()],
    });

    const res = await t.api.get(`/enterprise/audit/export?orgId=${orgId}`, { cookie });
    expect(res.status).toBe(200);
    const text = await res.text();

    // The metadata field: wrapped in quotes, its own internal `"` doubled.
    expect(text).toContain(`"${JSON.stringify(metadata).replace(/"/g, '""')}"`);
    // The user_agent field: wrapped in quotes, the raw newline preserved
    // verbatim inside them (not stripped, not escaped to `\n` text) — proven
    // by there being more bare `\n` bytes than `\r\n` row separators (one
    // header + one data row = exactly one `\r\n`; the extra bare `\n` can
    // only be the one embedded inside the quoted user_agent field).
    expect(text).toContain(`"${userAgent}"`);
    const crlfCount = (text.match(/\r\n/g) ?? []).length;
    const bareLfCount = (text.match(/\n/g) ?? []).length;
    expect(crlfCount).toBe(1);
    expect(bareLfCount).toBeGreaterThan(crlfCount);
  });
});

describe("GET /enterprise/audit/verify", () => {
  it("is ok:true for an untampered chain, then ok:false after a raw-SQL tamper", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);
    await inviteMember(t, cookie, orgId, "one@acme.test");
    await inviteMember(t, cookie, orgId, "two@acme.test");

    const ok = await t.api.get(`/enterprise/audit/verify?orgId=${orgId}`, { cookie });
    expect(ok.status).toBe(200);
    expect(await ok.json()).toEqual({ ok: true });

    // Tamper with the metadata of the first row directly on the underlying
    // DB, bypassing the plugin entirely — this is what makes the chain a
    // tamper-evidence mechanism rather than just an audit trail.
    await t.client.execute({
      sql: `UPDATE audit_event SET metadata = ? WHERE org_id = ? AND seq = 1`,
      args: [JSON.stringify({ tampered: true }), orgId],
    });

    const broken = await t.api.get(`/enterprise/audit/verify?orgId=${orgId}`, { cookie });
    expect(broken.status).toBe(200);
    expect(await broken.json()).toEqual({ ok: false, brokenAtSeq: 1 });
  });
});

describe("enterprise-audit hook — SCIM bearer path (parameterised, live dispatch, method-aware)", () => {
  async function setUpScimUser(t: TestAuth, cookie: string, orgId: string) {
    const tokenRes = await t.api.post(
      "/scim/generate-token",
      { providerId: "okta", organizationId: orgId },
      { cookie },
    );
    expect(tokenRes.status).toBe(201);
    const { scimToken } = (await tokenRes.json()) as { scimToken: string };
    const bearer = { authorization: `Bearer ${scimToken}` };

    const createRes = await t.api.post(
      "/scim/v2/Users",
      {
        userName: "scim.user@acme.test",
        emails: [{ value: "scim.user@acme.test", primary: true }],
      },
      bearer,
    );
    expect(createRes.status).toBe(201);
    const created = (await createRes.json()) as { id: string };
    return { bearer, userId: created.id };
  }

  async function auditRowsFor(t: TestAuth, orgId: string, action: string) {
    return t.client.execute({
      sql: `SELECT * FROM audit_event WHERE org_id = ? AND action = ?`,
      args: [orgId, action],
    });
  }

  it("GET /scim/v2/Users/<id> (a read) still matches the :userId pattern but writes no audit row", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);
    const { bearer, userId } = await setUpScimUser(t, cookie, orgId);

    const getRes = await t.api.get(`/scim/v2/Users/${userId}`, bearer);
    expect(getRes.status).toBe(200);

    const all = await t.client.execute({
      sql: `SELECT * FROM audit_event WHERE org_id = ? AND target_id = ?`,
      args: [orgId, userId],
    });
    // Only the create (scim.user_created) — the GET wrote nothing.
    expect(all.rows.map((r) => r.action)).toEqual(["scim.user_created"]);
  });

  it("PATCH /scim/v2/Users/<id> {active:false} writes one scim.user_updated row", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);
    const { bearer, userId } = await setUpScimUser(t, cookie, orgId);

    const patchRes = await t.api.patch(
      `/scim/v2/Users/${userId}`,
      {
        schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        Operations: [{ op: "replace", path: "active", value: false }],
      },
      bearer,
    );
    expect(patchRes.status).toBe(204);

    const rows = await auditRowsFor(t, orgId, "scim.user_updated");
    expect(rows.rows.length).toBe(1);
    expect(rows.rows[0]!.actor_type).toBe("scim");
    expect(rows.rows[0]!.target_id).toBe(userId);
  });

  it("DELETE /scim/v2/Users/<id> writes one scim.user_deleted row (not scim.user_updated)", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);
    const { bearer, userId } = await setUpScimUser(t, cookie, orgId);

    const deleteRes = await t.api.delete(`/scim/v2/Users/${userId}`, bearer);
    expect(deleteRes.status).toBe(204);

    const deleted = await auditRowsFor(t, orgId, "scim.user_deleted");
    expect(deleted.rows.length).toBe(1);
    expect(deleted.rows[0]!.actor_type).toBe("scim");
    expect(deleted.rows[0]!.target_id).toBe(userId);

    const updated = await auditRowsFor(t, orgId, "scim.user_updated");
    expect(updated.rows.length).toBe(0);
  });
});
