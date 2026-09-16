// M-05 … M-08 — the remaining Medium findings.
//
// M-05 `/enterprise/audit/export` was unbounded (whole table joined into one
//      in-memory string, twice).
// M-06 `breakGlassUserId` accepted any user id — no org-membership required —
//      and that outsider was then exempt from `allowedMethods` too.
// M-07 the entitlement check ran *before* any membership check, making
//      `/enterprise/*?orgId=<any string>` a cross-tenant plan/existence
//      oracle and a free amplifier into the product's billing lookup.
// M-08 plain members could read SSO provider configuration (including the
//      DNS verification token), SCIM token list and the security policy.

import { describe, expect, it } from "vitest";
import { makeAuth, signUpOwner, createOrg, type TestAuth } from "../helpers/auth";
import { DEFAULT_EXPORT_ROW_CAP } from "../../src/server/audit/plugin";
import { insertMemberRow, setPolicy } from "./helpers";

async function code(res: Response): Promise<string> {
  return ((await res.json()) as { code: string }).code;
}

async function seedAuditRows(t: TestAuth, orgId: string, count: number, offset = 0) {
  const now = Date.now();
  const statements = Array.from({ length: count }, (_, i) => ({
    sql: `INSERT INTO audit_event (id, org_id, seq, actor_type, actor_id, action, target_type, target_id, metadata, created_at, prev_hash, hash) VALUES (?, ?, ?, 'user', 'u1', 'member.invited', 'member', 't1', '{}', ?, 'GENESIS', ?)`,
    args: [`evt_${offset + i}`, orgId, offset + i + 1, now, `hash_${offset + i}`],
  }));
  await t.client.batch(statements, "write");
}

describe("M-05 — audit export is bounded", () => {
  it("413s past the row cap instead of materialising the whole table", async () => {
    // Exercising the shipped default would mean inserting 100 001 rows; the
    // behaviour under test is "one row over the cap ⇒ 413", so the cap is
    // lowered through the same option a product would use.
    const t = await makeAuth({ audit: { exportMaxRows: 3 } });
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);
    await seedAuditRows(t, orgId, 3);

    const ok = await t.api.get(`/enterprise/audit/export?orgId=${orgId}`, { cookie });
    expect(ok.status).toBe(200);
    expect(DEFAULT_EXPORT_ROW_CAP).toBe(100_000);

    await seedAuditRows(t, orgId, 4, 3); // now 7 rows total, over the cap of 3

    const tooBig = await t.api.get(`/enterprise/audit/export?orgId=${orgId}`, { cookie });
    expect(tooBig.status).toBe(413);
    expect(await code(tooBig)).toBe("AUDIT_EXPORT_TOO_LARGE");

    // A narrowed range is the documented way through.
    const narrowed = await t.api.get(
      `/enterprise/audit/export?orgId=${orgId}&from=${Date.now() + 60_000}`,
      { cookie },
    );
    expect(narrowed.status).toBe(200);
  });
});

describe("M-06 — breakGlassUserId must be an owner of the org, on every write", () => {
  it("rejects a user who is in no org at all, even with ssoEnforced false", async () => {
    const t = await makeAuth();
    const { cookie } = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, cookie);
    const outsider = await signUpOwner(t, "outsider@other.test");

    const res = await setPolicy(t, cookie, {
      orgId,
      breakGlassUserId: outsider.userId,
      allowedMethods: ["sso"],
    });
    expect(res.status).toBe(400);
    expect(await code(res)).toBe("BREAK_GLASS_NOT_OWNER");
  });

  it("rejects a plain member of the same org, and accepts an owner", async () => {
    const t = await makeAuth();
    const owner = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, owner.cookie);
    const member = await signUpOwner(t, "member@acme.test");
    await insertMemberRow(t, orgId, member.userId, "member");

    const refused = await setPolicy(t, owner.cookie, { orgId, breakGlassUserId: member.userId });
    expect(refused.status).toBe(400);
    expect(await code(refused)).toBe("BREAK_GLASS_NOT_OWNER");

    const accepted = await setPolicy(t, owner.cookie, { orgId, breakGlassUserId: owner.userId });
    expect(accepted.status).toBe(200);
  });
});

describe("M-07 — membership is checked before entitlement", () => {
  it("a non-member never reaches resolveEntitlements, and cannot tell orgs apart", async () => {
    const seen: string[] = [];
    const t = await makeAuth({
      resolveEntitlements: async (orgId) => {
        seen.push(orgId);
        return ["audit_log", "sso", "scim", "enforce_2fa", "api_keys", "teams"];
      },
    });
    const owner = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, owner.cookie);
    const outsider = await signUpOwner(t, "outsider@other.test");
    seen.length = 0;

    const real = await t.api.get(`/enterprise/audit/list?orgId=${orgId}`, {
      cookie: outsider.cookie,
    });
    const madeUp = await t.api.get(`/enterprise/audit/list?orgId=org_does_not_exist`, {
      cookie: outsider.cookie,
    });

    expect(real.status).toBe(403);
    expect(madeUp.status).toBe(403);
    expect(await code(real)).toBe(await code(madeUp)); // indistinguishable
    expect(seen).toEqual([]); // the billing lookup was never invoked
  });

  it("a member who lacks the plan still gets FEATURE_NOT_ENTITLED", async () => {
    const t = await makeAuth({ resolveEntitlements: async () => [] });
    const { cookie } = await signUpOwner(t);
    const { orgId } = await createOrg(t, cookie);

    const res = await t.api.get(`/enterprise/audit/list?orgId=${orgId}`, { cookie });
    expect(res.status).toBe(403);
    expect(await code(res)).toBe("FEATURE_NOT_ENTITLED");
  });
});

describe("M-08 — org security configuration is owner/admin only", () => {
  it("a plain member cannot read SSO providers, SCIM tokens or the policy", async () => {
    const t = await makeAuth();
    const owner = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, owner.cookie);
    const member = await signUpOwner(t, "member@acme.test");
    await insertMemberRow(t, orgId, member.userId, "member");

    for (const path of [
      `/enterprise/sso/providers?orgId=${orgId}`,
      `/enterprise/scim/tokens?orgId=${orgId}`,
      `/enterprise/policy?orgId=${orgId}`,
    ]) {
      const res = await t.api.get(path, { cookie: member.cookie });
      expect(res.status, path).toBe(403);
      expect(await code(res)).toBe("NOT_ORG_ADMIN");
    }
  });

  it("an admin still can", async () => {
    const t = await makeAuth();
    const owner = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, owner.cookie);
    const admin = await signUpOwner(t, "admin@acme.test");
    await insertMemberRow(t, orgId, admin.userId, "admin");

    for (const path of [
      `/enterprise/sso/providers?orgId=${orgId}`,
      `/enterprise/scim/tokens?orgId=${orgId}`,
      `/enterprise/policy?orgId=${orgId}`,
    ]) {
      const res = await t.api.get(path, { cookie: admin.cookie });
      expect(res.status, path).toBe(200);
    }
  });
});
