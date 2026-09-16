import { describe, expect, it } from "vitest";
import { makeAuth, signUpOwner, createOrg, type TestAuth } from "../helpers/auth";

async function setUpScimUser(
  t: TestAuth,
  cookie: string,
  orgId: string,
  email = "scim.user@acme.test",
) {
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
    { userName: email, emails: [{ value: email, primary: true }] },
    bearer,
  );
  expect(createRes.status).toBe(201);
  const created = (await createRes.json()) as { id: string };
  return { bearer, userId: created.id };
}

/**
 * `setSessionCookie` (`node_modules/better-auth/dist/cookies/index.mjs`)
 * signs the session-token cookie with `ctx.setSignedCookie`
 * (`node_modules/better-call/dist/context.mjs`) — plain HMAC-SHA256 over the
 * token, base64-encoded, appended as `<token>.<signature>`
 * (`node_modules/better-call/dist/crypto.mjs`'s `signCookieValue`). The
 * SCIM-provisioned user in these tests has no password/magic-link account to
 * sign in with normally, so a session row is inserted directly (same spirit
 * as `test/server/audit-plugin.test.ts`'s `insertMemberRow`) and this
 * reproduces that signature so the forged cookie verifies.
 */
async function signCookieValue(value: string, secret: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value));
  const base64 = btoa(String.fromCharCode(...new Uint8Array(signature)));
  return encodeURIComponent(`${value}.${base64}`);
}

async function insertSessionCookie(t: TestAuth, userId: string): Promise<string> {
  const token = `test_session_token_${userId}_${Math.random().toString(36).slice(2)}`;
  const now = Date.now();
  await t.client.execute({
    sql: `INSERT INTO session (id, expiresAt, token, createdAt, updatedAt, userId) VALUES (?, ?, ?, ?, ?, ?)`,
    args: [`sess_${userId}`, now + 24 * 60 * 60 * 1000, token, now, now, userId],
  });
  const secret = (t.auth.options as { secret: string }).secret;
  const signedValue = await signCookieValue(token, secret);
  return `better-auth.session_token=${signedValue}`;
}

describe("SCIM deprovision cascade", () => {
  it("PATCH active:false deletes the user's api keys, leaves 0 sessions, and writes one scim.user_deactivated audit row", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);
    const { bearer, userId } = await setUpScimUser(t, cookie, orgId);

    const userCookie = await insertSessionCookie(t, userId);
    const apiKeyRes = await t.api.post(
      "/api-key/create",
      { name: "k1", organizationId: orgId },
      { cookie: userCookie },
    );
    expect(apiKeyRes.status).toBe(200);

    const keysBefore = await t.client.execute({
      sql: `SELECT * FROM apikey WHERE referenceId = ?`,
      args: [userId],
    });
    expect(keysBefore.rows.length).toBe(1);
    const sessionsBefore = await t.client.execute({
      sql: `SELECT * FROM session WHERE userId = ?`,
      args: [userId],
    });
    expect(sessionsBefore.rows.length).toBe(1); // the forged session, pre-deactivation

    const patchRes = await t.api.patch(
      `/scim/v2/Users/${userId}`,
      {
        schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        Operations: [{ op: "replace", path: "active", value: false }],
      },
      bearer,
    );
    expect(patchRes.status).toBe(204);

    // Sessions: not this hook's job — asserting upstream's own
    // `deleteUserSessions` (patchSCIMUser, `@better-auth/scim`) already ran,
    // per the brief ("sessions are already gone ... assert it in the test,
    // don't re-implement").
    const sessionsAfter = await t.client.execute({
      sql: `SELECT * FROM session WHERE userId = ?`,
      args: [userId],
    });
    expect(sessionsAfter.rows.length).toBe(0);

    const keysAfter = await t.client.execute({
      sql: `SELECT * FROM apikey WHERE referenceId = ?`,
      args: [userId],
    });
    expect(keysAfter.rows.length).toBe(0);

    const auditRows = await t.client.execute({
      sql: `SELECT * FROM audit_event WHERE org_id = ? AND action = 'scim.user_deactivated'`,
      args: [orgId],
    });
    expect(auditRows.rows.length).toBe(1);
    expect(auditRows.rows[0]!.target_type).toBe("user");
    expect(auditRows.rows[0]!.target_id).toBe(userId);
    expect(auditRows.rows[0]!.actor_type).toBe("scim");
    expect(auditRows.rows[0]!.actor_id).toBe("okta");

    // The generic audit hook (`../audit/plugin.ts`) still writes its own
    // `scim.user_updated` row for this same PATCH — a different action, not
    // a duplicate of `scim.user_deactivated` above.
    const updatedRows = await t.client.execute({
      sql: `SELECT * FROM audit_event WHERE org_id = ? AND action = 'scim.user_updated'`,
      args: [orgId],
    });
    expect(updatedRows.rows.length).toBe(1);
  });

  it("a PATCH that does not touch `active` does not run the cascade or write a scim.user_deactivated row", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);
    const { bearer, userId } = await setUpScimUser(t, cookie, orgId);
    const userCookie = await insertSessionCookie(t, userId);
    await t.api.post(
      "/api-key/create",
      { name: "k1", organizationId: orgId },
      { cookie: userCookie },
    );

    const patchRes = await t.api.patch(
      `/scim/v2/Users/${userId}`,
      {
        schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        Operations: [{ op: "replace", path: "name.givenName", value: "New" }],
      },
      bearer,
    );
    expect(patchRes.status).toBe(204);

    const keys = await t.client.execute({
      sql: `SELECT * FROM apikey WHERE referenceId = ?`,
      args: [userId],
    });
    expect(keys.rows.length).toBe(1); // untouched — not a deactivation

    const deactivated = await t.client.execute({
      sql: `SELECT * FROM audit_event WHERE org_id = ? AND action = 'scim.user_deactivated'`,
      args: [orgId],
    });
    expect(deactivated.rows.length).toBe(0);
  });

  it("DELETE deletes the user's api keys (relying on the existing scim.user_deleted audit row, not a duplicate)", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);
    const { bearer, userId } = await setUpScimUser(t, cookie, orgId);
    const userCookie = await insertSessionCookie(t, userId);
    await t.api.post(
      "/api-key/create",
      { name: "k1", organizationId: orgId },
      { cookie: userCookie },
    );

    const deleteRes = await t.api.delete(`/scim/v2/Users/${userId}`, bearer);
    expect(deleteRes.status).toBe(204);

    const keysAfter = await t.client.execute({
      sql: `SELECT * FROM apikey WHERE referenceId = ?`,
      args: [userId],
    });
    expect(keysAfter.rows.length).toBe(0);

    const deletedRows = await t.client.execute({
      sql: `SELECT * FROM audit_event WHERE org_id = ? AND action = 'scim.user_deleted'`,
      args: [orgId],
    });
    expect(deletedRows.rows.length).toBe(1); // exactly one — no duplicate from this hook

    const deactivatedRows = await t.client.execute({
      sql: `SELECT * FROM audit_event WHERE org_id = ? AND action = 'scim.user_deactivated'`,
      args: [orgId],
    });
    expect(deactivatedRows.rows.length).toBe(0);
  });
});
