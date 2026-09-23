// Shared fixtures for the security regression suite (`test/security/*.test.ts`).
//
// Every file here reproduces one finding from the 2026-09-15 code-level
// security audit (`.superpowers/sdd/2026-09-15-enterprise-v0.1/
// security-audit-part2-code.md`) as it was reproduced there — attacker-side
// first, so each test fails (RED) against the pre-fix code and passes
// (GREEN) after — and then asserts the fixed behaviour.

import type { TestAuth } from "../helpers/auth";

/** Inserts a raw `member` row (role can be anything, including a comma-joined multi-role value). */
export async function insertMemberRow(
  t: TestAuth,
  orgId: string,
  userId: string,
  role: string,
): Promise<void> {
  await t.client.execute({
    sql: `INSERT INTO member (id, organizationId, userId, role, createdAt) VALUES (?, ?, ?, ?, ?)`,
    args: [`member_${userId}_${orgId}`, orgId, userId, role, Date.now()],
  });
}

export async function mintScimToken(
  t: TestAuth,
  cookie: string,
  orgId: string,
  providerId = "okta",
): Promise<{ authorization: string }> {
  const res = await t.api.post("/enterprise/scim/tokens/create", { providerId, orgId }, { cookie });
  if (!res.ok) throw new Error(`generate-token failed: ${res.status} ${await res.text()}`);
  const { scimToken } = (await res.json()) as { scimToken: string };
  return { authorization: `Bearer ${scimToken}` };
}

export async function createScimUser(
  t: TestAuth,
  bearer: { authorization: string },
  email: string,
  externalId?: string,
): Promise<string> {
  const res = await t.api.post(
    "/scim/v2/Users",
    {
      schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
      userName: email,
      externalId,
      emails: [{ value: email, primary: true }],
    },
    bearer,
  );
  if (!res.ok) throw new Error(`SCIM create user failed: ${res.status} ${await res.text()}`);
  return ((await res.json()) as { id: string }).id;
}

export async function auditRows(
  t: TestAuth,
  orgId: string,
): Promise<Array<Record<string, unknown>>> {
  const res = await t.client.execute({
    sql: `SELECT * FROM audit_event WHERE org_id = ? ORDER BY seq ASC`,
    args: [orgId],
  });
  return res.rows as unknown as Array<Record<string, unknown>>;
}

export async function setPolicy(
  t: TestAuth,
  cookie: string,
  body: Record<string, unknown>,
): Promise<Response> {
  return t.api.post("/enterprise/policy/set", body, { cookie });
}

export async function coreUserId(t: TestAuth, scimUserId: string): Promise<string> {
  const result = await t.client.execute({
    sql: "SELECT userId FROM scimUser WHERE id = ?",
    args: [scimUserId],
  });
  return String(result.rows[0]!.userId);
}
