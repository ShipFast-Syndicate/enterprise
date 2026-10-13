// Audit log: every writer's row is bounded, because `writeAudit` bounds it.
//
// The row backstop (`auditRowBounds`, `src/server/audit/bounds.ts`) used to
// run only in the audit plugin's own `writeRows`. The other writers — the
// refusal path, SCIM, API keys, the enterprise SCIM and SSO endpoints, the
// export row — called `writeAudit` directly and stored whatever they passed.
// `/enterprise/sso/test-login/finish` stored the `providerId` from its query
// string as `target_id`: a provider registered with a 50,000-character id
// left a 50,000-character value in the org's permanent chain and in every
// CSV export.
//
// - `writeAudit` itself now bounds every row, whoever calls it: a target id,
//   actor id or IP that is not a short value is recorded as `(unrecorded)`,
//   a user agent is cut, and metadata is capped.
// - No module other than `src/server/audit/chain.ts` creates or changes an
//   `auditEvent` row, so there is no path around `writeAudit`.
// - The self-audited endpoints, driven with oversized request values, store
//   only bounded rows; test-login finish with an oversized stored provider id
//   records the marker.
//
// Every assertion states the fixed behaviour; against the parent commit the
// direct write and the test-login row stored the values verbatim.

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { createOrg, makeAuth, signUpOwner, type TestAuth } from "../helpers/auth";
import { writeAudit, type AuditWriteContext } from "../../src/server/audit/chain";
import {
  AUDIT_METADATA_MAX_LENGTH,
  AUDIT_TOKEN_MAX_LENGTH,
  AUDIT_UNRECORDED,
  AUDIT_USER_AGENT_MAX_LENGTH,
} from "../../src/server/audit/bounds";

const BIG = "x".repeat(50_000);

async function largest(t: TestAuth) {
  const res = await t.client.execute(
    `SELECT count(*) AS n,
            coalesce(max(length(metadata)), 0) AS metadata,
            coalesce(max(length(target_id)), 0) AS target,
            coalesce(max(length(actor_id)), 0) AS actor,
            coalesce(max(length(user_agent)), 0) AS ua,
            coalesce(max(length(ip)), 0) AS ip
       FROM audit_event`,
  );
  const r = res.rows[0]!;
  return {
    rows: Number(r.n),
    metadata: Number(r.metadata),
    target: Number(r.target),
    actor: Number(r.actor),
    ua: Number(r.ua),
    ip: Number(r.ip),
  };
}

function expectBounded(max: Awaited<ReturnType<typeof largest>>) {
  expect(max.metadata).toBeLessThanOrEqual(AUDIT_METADATA_MAX_LENGTH);
  expect(max.target).toBeLessThanOrEqual(AUDIT_TOKEN_MAX_LENGTH);
  expect(max.actor).toBeLessThanOrEqual(AUDIT_TOKEN_MAX_LENGTH);
  expect(max.ua).toBeLessThanOrEqual(AUDIT_USER_AGENT_MAX_LENGTH);
  expect(max.ip).toBeLessThanOrEqual(AUDIT_TOKEN_MAX_LENGTH);
}

const OIDC = {
  clientId: "client",
  clientSecret: "secret-value-never-logged",
  skipDiscovery: true,
  authorizationEndpoint: "https://idp.test/authorize",
  tokenEndpoint: "https://idp.test/token",
  jwksEndpoint: "https://idp.test/jwks",
};

describe("writeAudit bounds every row, whoever writes it", () => {
  it("a direct write with oversized values stores the marker, a cut user agent and capped metadata", async () => {
    const t = await makeAuth();
    const owner = await signUpOwner(t);
    const { orgId } = await createOrg(t, owner.cookie);
    const ctx = await t.auth.$context;
    const row = await writeAudit({ context: ctx } as unknown as AuditWriteContext, {
      orgId,
      actorType: "user",
      actorId: BIG,
      action: "test.direct_write",
      targetType: "thing",
      targetId: BIG,
      ip: BIG,
      userAgent: BIG,
      metadata: { big: BIG, list: Array(20_000).fill("v"), small: "kept" },
    });
    expect(row).toMatchObject({
      actorId: AUDIT_UNRECORDED,
      targetId: AUDIT_UNRECORDED,
      ip: AUDIT_UNRECORDED,
    });
    expect(row.userAgent).toHaveLength(AUDIT_USER_AGENT_MAX_LENGTH);
    expect(row.metadata).toEqual({ big: AUDIT_UNRECORDED, list: AUDIT_UNRECORDED, small: "kept" });
    expectBounded(await largest(t));

    // The stored row is the hashed row: the chain still verifies.
    const verify = await t.api.get(`/enterprise/audit/verify?orgId=${orgId}`, {
      cookie: owner.cookie,
    });
    expect(await verify.json()).toMatchObject({ ok: true });
  });

  it("ordinary values are stored as they are", async () => {
    const t = await makeAuth();
    const owner = await signUpOwner(t);
    const { orgId } = await createOrg(t, owner.cookie);
    const ctx = await t.auth.$context;
    const row = await writeAudit({ context: ctx } as unknown as AuditWriteContext, {
      orgId,
      actorType: "user",
      actorId: owner.userId,
      action: "test.direct_write",
      targetType: "thing",
      targetId: "target-1",
      ip: "203.0.113.7",
      userAgent: "Mozilla/5.0",
      metadata: { role: "admin,member" },
    });
    expect(row).toMatchObject({
      actorId: owner.userId,
      targetId: "target-1",
      ip: "203.0.113.7",
      userAgent: "Mozilla/5.0",
      metadata: { role: "admin,member" },
    });
  });

  it("no module but src/server/audit/chain.ts creates or changes an auditEvent row", () => {
    const root = fileURLToPath(new URL("../../src", import.meta.url));
    const files: string[] = [];
    const walk = (dir: string) => {
      for (const name of readdirSync(dir)) {
        const path = join(dir, name);
        if (statSync(path).isDirectory()) walk(path);
        else if (/\.(ts|tsx|mts)$/.test(name)) files.push(path);
      }
    };
    walk(root);
    const writes =
      /\.(create|update|updateMany|upsert|insert)\s*(<[^>]*>)?\s*\(\s*\{\s*model:\s*["']auditEvent["']/;
    const writers = files
      .filter((file) => writes.test(readFileSync(file, "utf8")))
      .map((file) => relative(root, file));
    expect(writers).toEqual(["server/audit/chain.ts"]);
    const chain = readFileSync(join(root, "server/audit/chain.ts"), "utf8");
    // Inside chain.ts, the only row carrying caller values is the one
    // `insertNextRow` builds, and only `writeAudit` calls it — after bounding.
    expect(chain.match(/insertNextRow\(/g)?.length).toBe(3); // declaration + two calls
    const writeAuditBody = chain.slice(chain.indexOf("export async function writeAudit("));
    expect(writeAuditBody.indexOf("auditRowBounds(input)")).toBeGreaterThan(0);
    expect(writeAuditBody.indexOf("auditRowBounds(input)")).toBeLessThan(
      writeAuditBody.indexOf("insertNextRow("),
    );
  });
});

describe("self-audited endpoints with oversized request values store only bounded rows", () => {
  it("/enterprise/sso/test-login/finish with a 50,000-character stored providerId records the marker", async () => {
    const t = await makeAuth();
    const owner = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, owner.cookie);
    const providerId = "p".repeat(50_000);
    const registered = await t.api.post(
      "/sso/register",
      {
        providerId,
        issuer: "https://idp.test",
        domain: "acme.test",
        organizationId: orgId,
        oidcConfig: OIDC,
      },
      { cookie: owner.cookie },
    );
    expect(registered.status, await registered.clone().text()).toBe(200);
    const ctx = await t.auth.$context;
    await ctx.internalAdapter.createVerificationValue({
      identifier: `ab-sso-test:${providerId}`,
      value: owner.userId,
      expiresAt: new Date(Date.now() + 60_000),
    });

    const res = await t.api.get(
      `/enterprise/sso/test-login/finish?providerId=${encodeURIComponent(providerId)}`,
      { cookie: owner.cookie, "user-agent": BIG },
    );
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/?ab_sso_test=ok");

    const rows = await t.client.execute({
      sql: `SELECT target_id FROM audit_event WHERE org_id = ? AND action = 'sso.test_login_passed'`,
      args: [orgId],
    });
    expect(rows.rows.map((r) => r.target_id)).toEqual([AUDIT_UNRECORDED]);
    expectBounded(await largest(t));
  });

  it("SCIM token create/rotate/revoke, export and test-login with oversized headers and fields", async () => {
    const t = await makeAuth();
    const owner = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, owner.cookie);
    const headers = { cookie: owner.cookie, "user-agent": BIG, "x-forwarded-for": BIG };
    const registered = await t.api.post(
      "/sso/register",
      {
        providerId: "p1",
        issuer: "https://idp.test",
        domain: "acme.test",
        organizationId: orgId,
        oidcConfig: OIDC,
      },
      headers,
    );
    expect(registered.status).toBe(200);
    const before = (await largest(t)).rows;

    for (const path of [
      "/enterprise/scim/tokens/create",
      "/enterprise/scim/tokens/rotate",
      "/enterprise/scim/tokens/revoke",
    ]) {
      for (const body of [
        { orgId, providerId: "p1" },
        { orgId, providerId: BIG },
        { orgId, providerId: "p1", extra: BIG, name: BIG },
      ]) {
        await t.api.post(path, body, headers);
      }
    }
    await t.api.get(`/enterprise/audit/export?orgId=${orgId}`, headers);
    const ctx = await t.auth.$context;
    await ctx.internalAdapter.createVerificationValue({
      identifier: "ab-sso-test:p1",
      value: owner.userId,
      expiresAt: new Date(Date.now() + 60_000),
    });
    await t.api.get("/enterprise/sso/test-login/finish?providerId=p1", headers);

    const max = await largest(t);
    expect(max.rows - before).toBeGreaterThanOrEqual(5);
    expectBounded(max);
  });
});
