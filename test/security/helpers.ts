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

/** Flips the `user.twoFactorEnabled` flag directly — for tests that only need the *state*, not a real enrolment. */
export async function setTwoFactorEnabled(
  t: TestAuth,
  userId: string,
  enabled: boolean,
): Promise<void> {
  await t.client.execute({
    sql: `UPDATE user SET twoFactorEnabled = ? WHERE id = ?`,
    args: [enabled ? 1 : 0, userId],
  });
}

/** RFC 4648 base32 (no padding) → bytes, for the secret inside a `totpURI`. */
function base32Decode(input: string): Uint8Array<ArrayBuffer> {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = input.toUpperCase().replace(/=+$/, "");
  const bytes: number[] = [];
  let bits = 0;
  let value = 0;
  for (const char of clean) {
    const index = alphabet.indexOf(char);
    if (index === -1) throw new Error(`invalid base32 character ${JSON.stringify(char)}`);
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  const out = new Uint8Array(new ArrayBuffer(bytes.length));
  out.set(bytes);
  return out;
}

/** RFC 6238 TOTP (HMAC-SHA1, 6 digits, 30 s) — what `twoFactor()`'s default `createOTP` verifies. */
async function totpCode(secretBase32: string, digits = 6, period = 30): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    base32Decode(secretBase32),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );
  const counter = new DataView(new ArrayBuffer(8));
  counter.setBigUint64(0, BigInt(Math.floor(Date.now() / 1000 / period)));
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter.buffer));
  const offset = mac[mac.length - 1]! & 0x0f;
  const binary =
    ((mac[offset]! & 0x7f) << 24) |
    (mac[offset + 1]! << 16) |
    (mac[offset + 2]! << 8) |
    mac[offset + 3]!;
  return String(binary % 10 ** digits).padStart(digits, "0");
}

/**
 * Real TOTP enrolment through the preset's `twoFactor()` plugin:
 * `/two-factor/enable` (password re-auth) → parse the secret out of the
 * returned `totpURI` → `/two-factor/verify-totp` with a code computed from
 * it. Returns the post-enrolment session cookie (upstream re-issues the
 * session on verification) and a `totp()` generator for later challenges.
 */
export async function enrollTotp(
  t: TestAuth,
  cookie: string,
  password = "password1234",
): Promise<{ cookie: string; totp: () => Promise<string> }> {
  const enable = await t.api.post("/two-factor/enable", { password }, { cookie });
  if (!enable.ok) {
    throw new Error(`two-factor/enable failed: ${enable.status} ${await enable.text()}`);
  }
  const { totpURI } = (await enable.json()) as { totpURI: string };
  const secret = new URL(totpURI).searchParams.get("secret");
  if (!secret) throw new Error(`two-factor/enable returned no secret in ${totpURI}`);
  const totp = () => totpCode(secret);
  const verify = await t.api.post("/two-factor/verify-totp", { code: await totp() }, { cookie });
  if (!verify.ok) {
    throw new Error(`two-factor/verify-totp failed: ${verify.status} ${await verify.text()}`);
  }
  const setCookies = verify.headers.getSetCookie().map((raw) => raw.split(";")[0]);
  return { cookie: setCookies.length ? setCookies.join("; ") : cookie, totp };
}

/**
 * Forges a signed session cookie for a user who has no password/magic-link
 * account (a SCIM-provisioned user). Same signing as `setSignedCookie`
 * (HMAC-SHA256 over the token, base64, appended as `<token>.<sig>`) — see
 * `test/server/deprovision.test.ts` for the derivation.
 */
export async function insertSessionCookie(t: TestAuth, userId: string): Promise<string> {
  const token = `test_session_token_${userId}_${Math.random().toString(36).slice(2)}`;
  const now = Date.now();
  await t.client.execute({
    sql: `INSERT INTO session (id, expiresAt, token, createdAt, updatedAt, userId) VALUES (?, ?, ?, ?, ?, ?)`,
    args: [`sess_${userId}_${now}`, now + 24 * 60 * 60 * 1000, token, now, now, userId],
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
