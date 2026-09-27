// Audit log: what a caller can and cannot put into a tenant's chain, and
// what the audit layer costs the response.
//
// - A failure is recorded as a policy refusal (`auth.sign_in_refused`) only
//   when this package itself refused the request — never because a policy
//   code appears in a redirect URL or an IdP error response.
// - A retention anchor written under an impersonation session names the
//   staff member.
// - Values taken from the request are bounded: an address is recorded (and
//   used to find a subject's organizations) only when it is a valid e-mail
//   address; changed-key lists, user agents and codes are capped.
// - Rows about an address the caller chose are written off the response
//   path whatever the product configures, so response time does not depend
//   on whether the address has an account.
// - An `/enterprise/audit/list` cursor that is not a number is a 400.
//
// Every assertion states the fixed behaviour; against the parent commit each
// of these fails.

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { GenericEndpointContext } from "better-auth";
import { magicLink } from "better-auth/plugins";
import { createOrg, extractCookie, makeAuth, signUpOwner, type TestAuth } from "../helpers/auth";
import { startOidcIssuer, type OidcIssuer } from "../helpers/oidc-issuer";
import { insertProductMember, makeProductAuth } from "../helpers/product-auth";
import { flushAuditWrites } from "../../src/server/audit/background";
import { auditRefusal } from "../../src/server/audit/refusal";
import { twoTenants } from "./ghsa-sso-helpers";
import { insertMemberRow } from "./helpers";

type Row = Record<string, unknown> & { metadata: Record<string, unknown> };

async function rows(t: TestAuth, orgId: string, action?: string): Promise<Row[]> {
  const res = await t.client.execute({
    sql: action
      ? `SELECT * FROM audit_event WHERE org_id = ? AND action = ? ORDER BY seq`
      : `SELECT * FROM audit_event WHERE org_id = ? ORDER BY seq`,
    args: action ? [orgId, action] : [orgId],
  });
  return res.rows.map((r) => ({
    ...(r as unknown as Record<string, unknown>),
    metadata: JSON.parse(String(r.metadata)) as Record<string, unknown>,
  }));
}

async function allRows(t: TestAuth, action: string): Promise<Row[]> {
  const res = await t.client.execute({
    sql: `SELECT * FROM audit_event WHERE action = ? ORDER BY org_id, seq`,
    args: [action],
  });
  return res.rows.map((r) => ({
    ...(r as unknown as Record<string, unknown>),
    metadata: JSON.parse(String(r.metadata)) as Record<string, unknown>,
  }));
}

async function largestRowBytes(t: TestAuth): Promise<number> {
  const res = await t.client.execute(
    `SELECT max(length(metadata) + length(coalesce(user_agent, ''))) AS n FROM audit_event`,
  );
  return Number(res.rows[0]!.n ?? 0);
}

/** An owner with an org, plus a domain-verified provider row claiming `acme.test` for it. */
async function domainOrg(t: TestAuth) {
  const owner = await signUpOwner(t, "owner@claim.test");
  const { orgId } = await createOrg(t, owner.cookie, "claim");
  await t.client.execute({
    sql: `INSERT INTO "ssoProvider" (id, issuer, domain, domainVerified, organizationId, providerId, userId) VALUES (?, ?, ?, 1, ?, ?, ?)`,
    args: ["ssop_claim", "https://idp.test", "acme.test", orgId, "claim-okta", owner.userId],
  });
  return { owner, orgId };
}

/**
 * Starts an SSO sign-in for `providerId` as an anonymous caller would, with
 * the caller's own `errorCallbackURL`, and returns what the callback needs:
 * the state cookie and the `state` parameter.
 */
async function startSso(t: TestAuth, providerId: string, errorCallbackURL: string) {
  const res = await t.api.post("/sign-in/sso", { providerId, callbackURL: "/", errorCallbackURL });
  expect(res.status, await res.clone().text()).toBe(200);
  const { url } = (await res.json()) as { url: string };
  const state = new URL(url).searchParams.get("state");
  expect(state).toBeTruthy();
  return { cookie: extractCookie(res), state: state! };
}

function callback(t: TestAuth, providerId: string, query: string, cookie: string) {
  return t.auth.handler(
    new Request(`http://localhost:3000/api/auth/sso/callback/${providerId}?${query}`, {
      headers: { cookie, origin: "http://localhost:3000" },
    }),
  );
}

describe("a policy refusal is recorded only when this package refused the request", () => {
  let issuer: OidcIssuer;
  beforeAll(async () => {
    issuer = await startOidcIssuer();
  });
  afterAll(async () => {
    await issuer.close();
  });

  for (const errorCallbackURL of [
    "/x?error=SSO_DOMAIN_NOT_ALLOWED",
    "http://localhost:3000/x?error=SSO_REQUIRED",
    "/x?error=SCIM_USER_NOT_ACTIVE&",
    "/x?error=TWO_FACTOR_REQUIRED#frag",
  ]) {
    it(`an errorCallbackURL of ${JSON.stringify(errorCallbackURL)} and a bad code: one auth.sso_sign_in_failed {error: invalid_provider}, no auth.sign_in_refused`, async () => {
      const t = await makeAuth({ trustedOrigins: [issuer.issuerUrl] });
      const { acmeOrg } = await twoTenants(t, issuer);
      const { cookie, state } = await startSso(t, "acme-oidc", errorCallbackURL);
      const res = await callback(
        t,
        "acme-oidc",
        `code=garbage&state=${encodeURIComponent(state)}`,
        cookie,
      );
      expect(res.status).toBe(302);
      const location = res.headers.get("location") ?? "";
      expect(location).toContain("error=invalid_provider");

      expect(await allRows(t, "auth.sign_in_refused")).toHaveLength(0);
      const failed = await rows(t, acmeOrg, "auth.sso_sign_in_failed");
      expect(failed).toHaveLength(1);
      expect(failed[0]!.metadata).toEqual({ error: "invalid_provider" });
      expect(failed[0]).toMatchObject({ target_id: "acme-oidc", actor_type: "system" });
    });
  }

  it("an IdP error response naming a policy code is a failed SSO sign-in, not a refusal", async () => {
    const t = await makeAuth({ trustedOrigins: [issuer.issuerUrl] });
    const { acmeOrg, evilOrg } = await twoTenants(t, issuer);
    const { cookie, state } = await startSso(t, "acme-oidc", "/x");
    const res = await callback(
      t,
      "acme-oidc",
      `error=SSO_REQUIRED&state=${encodeURIComponent(state)}`,
      cookie,
    );
    expect(res.status).toBe(302);
    expect(res.headers.get("location") ?? "").toContain("error=SSO_REQUIRED");
    expect(await allRows(t, "auth.sign_in_refused")).toHaveLength(0);
    expect(await rows(t, acmeOrg, "auth.sso_sign_in_failed")).toHaveLength(1);
    expect(await rows(t, evilOrg, "auth.sso_sign_in_failed")).toHaveLength(0);
  });
});

describe("a retention anchor written under impersonation names the staff member", () => {
  async function impersonatedOwner(t: TestAuth) {
    const staff = await signUpOwner(t, "staff@vendor.test");
    await t.client.execute({
      sql: "UPDATE user SET role='admin' WHERE id=?",
      args: [staff.userId],
    });
    const owner = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, owner.cookie);
    await t.api.post(
      "/organization/invite-member",
      { email: "x@acme.test", role: "member", organizationId: orgId },
      { cookie: owner.cookie },
    );
    const imp = await t.api.post(
      "/admin/impersonate-user",
      { userId: owner.userId },
      { cookie: staff.cookie },
    );
    expect(imp.status).toBe(200);
    const jar = new Map<string, string>();
    for (const raw of imp.headers.getSetCookie()) {
      const kv = raw.split(";")[0]!;
      jar.set(kv.split("=")[0]!, kv);
    }
    await t.client.execute({
      sql: `UPDATE audit_event SET created_at = ? WHERE org_id = ?`,
      args: [Date.now() - 3 * 24 * 3600 * 1000, orgId],
    });
    return { staff, owner, orgId, impCookie: [...jar.values()].join("; ") };
  }

  it("POST /enterprise/audit/compact: actor impersonated, metadata.impersonatedBy = staff, and the chain still verifies", async () => {
    const t = await makeAuth({ audit: { retentionDays: 1 } });
    const { staff, owner, orgId, impCookie } = await impersonatedOwner(t);
    const res = await t.api.post("/enterprise/audit/compact", { orgId }, { cookie: impCookie });
    expect(await res.json()).toMatchObject({ compacted: true });
    const [anchor] = await rows(t, orgId, "audit.retention_compacted");
    expect(anchor).toMatchObject({ actor_type: "impersonated", actor_id: owner.userId });
    expect(anchor!.metadata).toMatchObject({ impersonatedBy: staff.userId });
    expect(anchor!.metadata).toHaveProperty("compactedThroughSeq");
    expect(anchor!.metadata).toHaveProperty("lastHash");
    const verify = await t.api.get(`/enterprise/audit/verify?orgId=${orgId}`, {
      cookie: owner.cookie,
    });
    expect(await verify.json()).toEqual({ ok: true, keyed: false });
  });

  it("the compaction GET /enterprise/audit/list triggers: same attribution", async () => {
    const t = await makeAuth({ audit: { retentionDays: 1 } });
    const { staff, owner, orgId, impCookie } = await impersonatedOwner(t);
    const res = await t.api.get(`/enterprise/audit/list?orgId=${orgId}`, { cookie: impCookie });
    expect(res.status).toBe(200);
    const [anchor] = await rows(t, orgId, "audit.retention_compacted");
    expect(anchor).toMatchObject({ actor_type: "impersonated", actor_id: owner.userId });
    expect(anchor!.metadata).toMatchObject({ impersonatedBy: staff.userId });
  });
});

describe("values taken from the request are bounded before they reach a chain", () => {
  const junk =
    "<script>alert(1)</script>\r\n=cmd|' /C calc'!A0" + "x".repeat(20_000) + "@acme.test";

  it("an invalid address at a claimed domain (400) names no subject: nothing reaches the domain org's chain", async () => {
    const t = await makeAuth();
    const { orgId } = await domainOrg(t);
    const before = (await rows(t, orgId)).length;
    const res = await t.api.post("/sign-in/email", { email: junk, password: "x" });
    expect(res.status).toBe(400);
    expect(await rows(t, orgId)).toHaveLength(before);
    expect(JSON.stringify(await rows(t, orgId))).not.toContain("<script>");
  });

  it("an over-long address that parses is not recorded either", async () => {
    const t = await makeAuth();
    const { orgId } = await domainOrg(t);
    const before = (await rows(t, orgId)).length;
    await t.api.post("/sign-in/email", { email: `${"a".repeat(300)}@acme.test`, password: "x" });
    expect(await rows(t, orgId)).toHaveLength(before);
  });

  it("auditRefusal with an invalid address and no user writes nothing; with a valid one it records the address lower-cased", async () => {
    const t = await makeAuth();
    const { orgId } = await domainOrg(t);
    const ctx = { context: await t.auth.$context } as unknown as GenericEndpointContext;
    await auditRefusal(ctx, {
      path: "/magic-link/verify",
      code: "SSO_REQUIRED",
      orgIds: [orgId],
      userId: null,
      email: junk,
    });
    await flushAuditWrites();
    expect(await rows(t, orgId, "auth.sign_in_refused")).toHaveLength(0);
    await auditRefusal(ctx, {
      path: "/magic-link/verify",
      code: "SSO_REQUIRED",
      orgIds: [orgId],
      userId: null,
      email: "Nobody@ACME.test",
    });
    await flushAuditWrites();
    const refused = await rows(t, orgId, "auth.sign_in_refused");
    expect(refused).toHaveLength(1);
    expect(refused[0]!.metadata).toMatchObject({ email: "nobody@acme.test" });
  });

  it("/update-user with thousands of keys: at most 64 well-formed names, the total in changedCount", async () => {
    const t = await makeAuth();
    const owner = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, owner.cookie);
    const body: Record<string, unknown> = { name: "Renamed" };
    for (let i = 0; i < 1500; i++) body[`k${i}`] = 1;
    for (let i = 0; i < 1500; i++) body[`long_${i}_${"y".repeat(80)}`] = 1;
    const res = await t.api.post("/update-user", body, { cookie: owner.cookie });
    expect(res.status, await res.clone().text()).toBe(200);
    const [row] = await rows(t, orgId, "user.updated");
    const changed = row!.metadata.changed as string[];
    expect(changed.length).toBe(64);
    expect(changed.every((k) => k.length <= 64)).toBe(true);
    expect(row!.metadata.changedCount).toBe(3001);
    expect(JSON.stringify(row!.metadata).length).toBeLessThan(4096);
  });

  it("an over-long user agent is cut to 512 characters", async () => {
    const t = await makeAuth();
    const owner = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, owner.cookie);
    await t.api.post(
      "/sign-in/email",
      { email: "owner@acme.test", password: "wrong-password-1" },
      { "user-agent": "=HYPERLINK(" + "u".repeat(20_000) },
    );
    const [row] = await rows(t, orgId, "auth.sign_in_failed");
    expect(String(row!.user_agent).length).toBe(512);
    expect(await largestRowBytes(t)).toBeLessThan(4096);
  });
});

describe("rows about an address the caller chose never hold up the response", () => {
  const DELAY_MS = 1500;

  /** A product-shaped deployment whose audit inserts take `DELAY_MS` each. */
  async function slowAudit() {
    const sent: string[] = [];
    const t = await makeProductAuth({
      plugins: [magicLink({ sendMagicLink: async ({ token }) => void sent.push(token) })],
    });
    const owner = await signUpOwner(t, "owner@acme.test");
    const orgs: string[] = [];
    for (const slug of ["one", "two", "three"]) {
      orgs.push((await createOrg(t, owner.cookie, slug)).orgId);
    }
    const member = await signUpOwner(t, "member@acme.test");
    for (const orgId of orgs) await insertProductMember(t, orgId, member.userId);
    // Every audit insert now takes DELAY_MS (at the database client, so the
    // whole write path — lock, read, insert — is what is being timed).
    const client = t.client as unknown as { execute: (stmt: unknown) => Promise<unknown> };
    const execute = client.execute.bind(client);
    client.execute = async (stmt) => {
      const sql = typeof stmt === "string" ? stmt : (stmt as { sql: string }).sql;
      if (/insert into "?audit_event"?/i.test(sql)) {
        await new Promise((resolve) => setTimeout(resolve, DELAY_MS));
      }
      return execute(stmt);
    };
    return { t, orgs };
  }

  async function timed(t: TestAuth, path: string, body: unknown) {
    const started = performance.now();
    const res = await t.rawHandler(
      new Request(`http://localhost:3000/api/auth${path}`, {
        method: "POST",
        headers: { "content-type": "application/json", origin: "http://localhost:3000" },
        body: JSON.stringify(body),
      }),
    );
    return { res, ms: performance.now() - started };
  }

  it("a wrong password for a member of three orgs answers as fast as for an unknown address; the rows land afterwards", async () => {
    const { t, orgs } = await slowAudit();
    const known = await timed(t, "/sign-in/email", {
      email: "member@acme.test",
      password: "wrong-password-1",
    });
    const unknown = await timed(t, "/sign-in/email", {
      email: "nobody@acme.test",
      password: "wrong-password-1",
    });
    expect(known.res.status).toBe(401);
    expect(unknown.res.status).toBe(401);
    expect(known.ms).toBeLessThan(DELAY_MS);
    expect(unknown.ms).toBeLessThan(DELAY_MS);
    await flushAuditWrites();
    for (const orgId of orgs) expect(await rows(t, orgId, "auth.sign_in_failed")).toHaveLength(1);
  }, 30_000);

  it("a magic-link request for a member of three orgs does not wait for its rows either", async () => {
    const { t, orgs } = await slowAudit();
    const known = await timed(t, "/sign-in/magic-link", { email: "member@acme.test" });
    const unknown = await timed(t, "/sign-in/magic-link", { email: "nobody@acme.test" });
    expect(known.res.status).toBe(200);
    expect(unknown.res.status).toBe(200);
    expect(known.ms).toBeLessThan(DELAY_MS);
    expect(unknown.ms).toBeLessThan(DELAY_MS);
    await flushAuditWrites();
    for (const orgId of orgs) {
      expect(await rows(t, orgId, "auth.magic_link_requested")).toHaveLength(1);
    }
  }, 30_000);
});

describe("/enterprise/audit/list cursor", () => {
  it("a cursor that is not a number is a 400, not a 500", async () => {
    const t = await makeAuth();
    const owner = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, owner.cookie);
    const member = await signUpOwner(t, "member@acme.test");
    await insertMemberRow(t, orgId, member.userId, "member");
    const res = await t.api.get(`/enterprise/audit/list?orgId=${orgId}&cursor=abc`, {
      cookie: owner.cookie,
    });
    expect(res.status).toBe(400);
  });
});

describe("the retention anchor keeps its own keys whatever the actor carries", () => {
  it("actor metadata cannot override compactedThroughSeq, compactedCount or lastHash", async () => {
    const { compactChain } = await import("../../src/server/audit/chain");
    const t = await makeAuth({ audit: { retentionDays: 1 } });
    const owner = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, owner.cookie);
    await t.api.post(
      "/organization/invite-member",
      { email: "x@acme.test", role: "member", organizationId: orgId },
      { cookie: owner.cookie },
    );
    await t.client.execute({
      sql: `UPDATE audit_event SET created_at = ? WHERE org_id = ?`,
      args: [Date.now() - 3 * 24 * 3600 * 1000, orgId],
    });
    const ctx = { context: await t.auth.$context } as unknown as Parameters<typeof compactChain>[0];
    const result = await compactChain(ctx, orgId, new Date(Date.now() - 24 * 3600 * 1000), {
      actor: {
        actorType: "user",
        actorId: owner.userId,
        metadata: { lastHash: "other", compactedThroughSeq: 999, compactedCount: 0, note: "x" },
      },
    });
    expect(result).not.toBeNull();
    const [anchor] = await rows(t, orgId, "audit.retention_compacted");
    expect(anchor!.metadata).toMatchObject({
      compactedThroughSeq: result!.compactedThroughSeq,
      compactedCount: result!.compactedCount,
      lastHash: result!.lastHash,
      note: "x",
    });
  });
});

describe("every policy refusal this package raises is marked for the audit log", () => {
  it("each `code: <policy code>` in src/server is built inside policyRefusal(), and no resolver rejects without notePolicyRefusal()", async () => {
    const { readdirSync, readFileSync, statSync } = await import("node:fs");
    const { join } = await import("node:path");
    const { POLICY_REFUSAL_CODES } = await import("../../src/server/audit/routes");
    const files: string[] = [];
    const walk = (dir: string) => {
      for (const name of readdirSync(dir)) {
        const path = join(dir, name);
        if (statSync(path).isDirectory()) walk(path);
        else if (path.endsWith(".ts")) files.push(path);
      }
    };
    walk(join(__dirname, "../../src/server"));
    const unmarked: string[] = [];
    let seen = 0;
    for (const file of files) {
      if (file.endsWith(join("audit", "routes.ts"))) continue;
      const source = readFileSync(file, "utf8");
      for (const match of source.matchAll(/code:\s*"([A-Z0-9_]+)"/g)) {
        if (!POLICY_REFUSAL_CODES.has(match[1]!)) continue;
        seen++;
        const before = source.slice(Math.max(0, match.index - 400), match.index);
        if (!before.includes("policyRefusal(")) unmarked.push(`${file}: ${match[1]}`);
      }
      for (const match of source.matchAll(/action:\s*"reject"/g)) {
        const around = source.slice(Math.max(0, match.index - 400), match.index);
        if (!around.includes("notePolicyRefusal(")) unmarked.push(`${file}: reject`);
      }
    }
    expect(seen).toBeGreaterThanOrEqual(10);
    expect(unmarked).toEqual([]);
  });
});
