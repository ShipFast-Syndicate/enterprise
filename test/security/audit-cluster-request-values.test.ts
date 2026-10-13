// Audit log: no value a request carries reaches a chain unbounded, and the
// log's own read endpoints refuse out-of-range dates instead of failing.
//
// - Roles are recorded as a capped list of short names with the total count
//   (`/organization/update-member-role`, `/admin/set-role`); provider ids
//   and every other id from the request as a short token, else the marker
//   `(unrecorded)` (`/sso/register`).
// - A walk over every audited route, each with oversized strings and lists
//   in every field the audit layer reads and in the route parameters, finds
//   no stored row with an oversized target id or metadata. Each path whose
//   base request succeeds must have written rows: on gated paths the
//   oversized `?organizationId` is a request of its own, because the gate
//   refuses it before the endpoint runs (round 5).
// - With every audit insert failing, no audited change on a path whose
//   write failure is not soft answers success: SCIM `POST /scim/v2/Users`
//   answered 201 with `{"code":"AUDIT_WRITE_FAILED"}` (round 5).
// - `/enterprise/audit/list` and `/enterprise/audit/export` answer 400 for a
//   `from`/`to` that is not a whole number of milliseconds in the range a
//   `Date` can hold, and no query (or its SQL) reaches the error log.
//
// Every assertion states the fixed behaviour; against the parent commit the
// role and provider-id rows were stored verbatim (tens of kilobytes) and the
// out-of-range dates answered 500.

import { describe, expect, it, vi } from "vitest";
import { createOrg, makeAuth, signUpOwner, type TestAuth } from "../helpers/auth";
import { insertMemberRow, mintScimToken, createScimUser } from "./helpers";
import { AUDITED_PATHS, METHOD_ACTION_OVERRIDES } from "../../src/server/audit/routes";
import { GATED_PATHS } from "../../src/server/gate";
import * as auditPlugin from "../../src/server/audit/plugin";
import {
  AUDIT_METADATA_MAX_LENGTH,
  AUDIT_ROLES_MAX,
  AUDIT_TOKEN_MAX_LENGTH,
  AUDIT_UNRECORDED,
  AUDIT_USER_AGENT_MAX_LENGTH,
} from "../../src/server/audit/bounds";

type Row = Record<string, unknown> & { metadata: Record<string, unknown> };

async function rows(t: TestAuth, orgId: string, action: string): Promise<Row[]> {
  const res = await t.client.execute({
    sql: `SELECT * FROM audit_event WHERE org_id = ? AND action = ? ORDER BY seq`,
    args: [orgId, action],
  });
  return res.rows.map((r) => ({
    ...(r as unknown as Record<string, unknown>),
    metadata: JSON.parse(String(r.metadata)) as Record<string, unknown>,
  }));
}

/** The largest stored value per column across every row of every chain. */
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

async function ok(res: Response): Promise<Response> {
  expect(res.status, await res.clone().text()).toBe(200);
  return res;
}

async function makeStaff(t: TestAuth, email = "staff@vendor.test") {
  const staff = await signUpOwner(t, email);
  await t.client.execute({ sql: "UPDATE user SET role='admin' WHERE id=?", args: [staff.userId] });
  return staff;
}

const OIDC = {
  clientId: "client",
  clientSecret: "secret-value-never-logged",
  skipDiscovery: true,
  authorizationEndpoint: "https://idp.test/authorize",
  tokenEndpoint: "https://idp.test/token",
  jwksEndpoint: "https://idp.test/jwks",
};

async function orgWithMember(t: TestAuth) {
  const owner = await signUpOwner(t, "owner@acme.test");
  const { orgId } = await createOrg(t, owner.cookie);
  const member = await signUpOwner(t, "member@acme.test");
  await insertMemberRow(t, orgId, member.userId, "member");
  return { owner, orgId, member, memberId: `member_${member.userId}_${orgId}` };
}

describe("roles and provider ids from the request are bounded", () => {
  it("/organization/update-member-role with 5000 valid roles as a list: the row keeps the distinct names and the count", async () => {
    const t = await makeAuth();
    const { owner, orgId, memberId, member } = await orgWithMember(t);
    await ok(
      await t.api.post(
        "/organization/update-member-role",
        { memberId, role: Array(5000).fill("member"), organizationId: orgId },
        { cookie: owner.cookie },
      ),
    );
    const [row] = await rows(t, orgId, "member.role_changed");
    expect(row!.metadata).toEqual({ targetUserId: member.userId, role: "member", roleCount: 5000 });
    expect(JSON.stringify(row!.metadata).length).toBeLessThan(200);
  });

  it("/organization/update-member-role with 20000 roles comma-joined: same", async () => {
    const t = await makeAuth();
    const { owner, orgId, memberId } = await orgWithMember(t);
    await ok(
      await t.api.post(
        "/organization/update-member-role",
        { memberId, role: Array(20000).fill("admin").join(","), organizationId: orgId },
        { cookie: owner.cookie },
      ),
    );
    const [row] = await rows(t, orgId, "member.role_changed");
    expect(row!.metadata).toMatchObject({ role: "admin", roleCount: 20000 });
    expect(JSON.stringify(row!.metadata).length).toBeLessThan(200);
  });

  it("/organization/update-member-role with a short list: recorded as upstream stores it, no count", async () => {
    const t = await makeAuth();
    const { owner, orgId, memberId } = await orgWithMember(t);
    await ok(
      await t.api.post(
        "/organization/update-member-role",
        { memberId, role: ["admin", "member"], organizationId: orgId },
        { cookie: owner.cookie },
      ),
    );
    const [row] = await rows(t, orgId, "member.role_changed");
    expect(row!.metadata.role).toBe("admin,member");
    expect(row!.metadata).not.toHaveProperty("roleCount");
  });

  it("/admin/set-role with a 100,000-character role: recorded as the marker with the count", async () => {
    const t = await makeAuth();
    const { orgId, member } = await orgWithMember(t);
    const staff = await makeStaff(t);
    await ok(
      await t.api.post(
        "/admin/set-role",
        { userId: member.userId, role: "r".repeat(100_000) },
        { cookie: staff.cookie },
      ),
    );
    const [row] = await rows(t, orgId, "admin.user_role_changed");
    expect(row).toMatchObject({ actor_id: staff.userId, target_id: member.userId });
    expect(row!.metadata).toEqual({ role: AUDIT_UNRECORDED, roleCount: 1 });
  });

  it(`/admin/set-role with more than ${AUDIT_ROLES_MAX} distinct roles: the first ${AUDIT_ROLES_MAX} and the count`, async () => {
    const t = await makeAuth();
    const { orgId, member } = await orgWithMember(t);
    const staff = await makeStaff(t);
    const roles = Array.from({ length: 40 }, (_, i) => `role${i}`);
    await ok(
      await t.api.post(
        "/admin/set-role",
        { userId: member.userId, role: roles },
        { cookie: staff.cookie },
      ),
    );
    const [row] = await rows(t, orgId, "admin.user_role_changed");
    expect(row!.metadata).toEqual({
      role: roles.slice(0, AUDIT_ROLES_MAX).join(","),
      roleCount: 40,
    });
  });

  it("/sso/register with a 10,000-character providerId: target_id is the marker", async () => {
    const t = await makeAuth();
    const owner = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, owner.cookie);
    await ok(
      await t.api.post(
        "/sso/register",
        {
          providerId: "p".repeat(10_000),
          issuer: "https://idp.test",
          domain: "acme.test",
          organizationId: orgId,
          oidcConfig: OIDC,
        },
        { cookie: owner.cookie },
      ),
    );
    const [row] = await rows(t, orgId, "sso.provider_registered");
    expect(row).toMatchObject({ actor_id: owner.userId, target_id: AUDIT_UNRECORDED });
  });

  it("/sso/register with an ordinary providerId: recorded as it is", async () => {
    const t = await makeAuth();
    const owner = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, owner.cookie);
    await ok(
      await t.api.post(
        "/sso/register",
        {
          providerId: "acme-okta",
          issuer: "https://idp.test",
          domain: "acme.test",
          organizationId: orgId,
          oidcConfig: OIDC,
        },
        { cookie: owner.cookie },
      ),
    );
    const [row] = await rows(t, orgId, "sso.provider_registered");
    expect(row).toMatchObject({ target_id: "acme-okta" });
  });
});

// ---------------------------------------------------------------------------
// The generic walk.

const BIG = "x".repeat(100_000);
const BIG_LIST = Array<string>(20_000).fill("member");

/** Every body field the audit layer reads from a request, on any path. */
const READ_FIELDS = [
  "role",
  "providerId",
  "userId",
  "memberId",
  "memberIdOrEmail",
  "teamId",
  "invitationId",
  "keyId",
  "id",
  "name",
  "email",
  "data",
  "organizationId",
  "orgId",
  "sessionToken",
  "token",
] as const;

interface Walk {
  t: TestAuth;
  orgId: string;
  owner: { cookie: string; userId: string };
  staff: { cookie: string; userId: string };
  member: { cookie: string; userId: string };
  memberId: string;
  teamId: string;
  invitationId: string;
  scim?: { authorization: string; userId: string };
}

async function walkWorld(path: string): Promise<Walk> {
  const t = await makeAuth({ organization: { requireEmailVerificationOnInvitation: false } });
  const { owner, orgId, member, memberId } = await orgWithMember(t);
  await ok(
    await t.api.post(
      "/organization/set-active",
      { organizationId: orgId },
      { cookie: owner.cookie },
    ),
  );
  const staff = await makeStaff(t);
  const team = await ok(
    await t.api.post(
      "/organization/create-team",
      { name: "t1", organizationId: orgId },
      { cookie: owner.cookie },
    ),
  );
  const teamId = ((await team.json()) as { id: string }).id;
  const invitation = await ok(
    await t.api.post(
      "/organization/invite-member",
      { email: "new@acme.test", role: "member", organizationId: orgId },
      { cookie: owner.cookie },
    ),
  );
  const invitationId = ((await invitation.json()) as { id: string }).id;
  const w: Walk = { t, orgId, owner, staff, member, memberId, teamId, invitationId };
  if (path.startsWith("/sso/") || path.startsWith("/scim/")) {
    await ok(
      await t.api.post(
        "/sso/register",
        {
          providerId: "p1",
          issuer: "https://idp.test",
          domain: "acme.test",
          organizationId: orgId,
          oidcConfig: OIDC,
        },
        { cookie: owner.cookie },
      ),
    );
  }
  if (path.startsWith("/scim/")) {
    const bearer = await mintScimToken(t, owner.cookie, orgId, "p1");
    const userId = await createScimUser(t, bearer, "scim@acme.test", "ext-1");
    w.scim = { ...bearer, userId };
  }
  return w;
}

/** A body the endpoint would accept, so the oversized variants reach the audit layer on success too. */
function baseBody(path: string, w: Walk): Record<string, unknown> {
  const bases: Record<string, Record<string, unknown>> = {
    "/organization/update-member-role": {
      memberId: w.memberId,
      role: "member",
      organizationId: w.orgId,
    },
    "/organization/update": { data: { name: "renamed" }, organizationId: w.orgId },
    "/organization/invite-member": { email: "other@acme.test", role: "member" },
    "/organization/cancel-invitation": { invitationId: w.invitationId },
    "/organization/remove-member": { memberIdOrEmail: "member@acme.test" },
    "/organization/create-team": { name: "t2" },
    "/organization/update-team": { teamId: w.teamId, data: { name: "t1b" } },
    "/organization/add-team-member": { teamId: w.teamId, userId: w.member.userId },
    "/admin/set-role": { userId: w.member.userId, role: "admin" },
    "/admin/update-user": { userId: w.member.userId, data: { name: "renamed" } },
    "/admin/ban-user": { userId: w.member.userId },
    "/admin/unban-user": { userId: w.member.userId },
    "/admin/revoke-user-sessions": { userId: w.member.userId },
    "/admin/set-user-password": { userId: w.member.userId, newPassword: "a-new-password-1" },
    "/admin/create-user": { email: "made@acme.test", password: "password1234", name: "Made" },
    "/update-user": { name: "renamed" },
    "/api-key/create": { name: "k" },
    "/sso/register": {
      providerId: "p2",
      issuer: "https://idp.test",
      domain: "other.test",
      organizationId: w.orgId,
      oidcConfig: OIDC,
    },
    "/sso/update-provider": { providerId: "p1", oidcConfig: { clientId: "c2" } },
    "/sso/request-domain-verification": { providerId: "p1" },
    "/enterprise/policy/set": { orgId: w.orgId, auditRetentionDays: 400 },
    "/scim/v2/Users": {
      schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
      userName: "walk@acme.test",
      emails: [{ value: "walk@acme.test", primary: true }],
    },
  };
  return bases[path] ?? {};
}

/** The caller a path is meant for: staff for `/admin/*`, the SCIM bearer for `/scim/*`, else the org owner. */
function callerOf(path: string, w: Walk): Record<string, string> {
  if (path.startsWith("/scim/")) return { authorization: w.scim!.authorization };
  if (path.startsWith("/admin/")) return { cookie: w.staff.cookie };
  return { cookie: w.owner.cookie };
}

/** The route with each parameter filled with `value`. */
function concrete(path: string, value: string): string {
  return path.replace(/:[A-Za-z]+/g, encodeURIComponent(value));
}

function methodsOf(path: string): string[] {
  const entry = AUDITED_PATHS[path]!;
  const methods = new Set(entry.methods ?? ["POST"]);
  for (const method of Object.keys(METHOD_ACTION_OVERRIDES[path] ?? {})) methods.add(method);
  return [...methods];
}

/**
 * Each walk case sends a few dozen requests, and on the password paths each
 * valid variant hashes a password: about 4 s alone, but a case exceeded the
 * default 20 s once while the whole suite ran in parallel. The walk cases get
 * their own ceiling so load alone cannot fail them.
 */
const WALK_TIMEOUT_MS = 120_000;

/**
 * Gated paths whose base request the walk must see succeed and write a row.
 * Round 4 made the gate refuse an oversized org id in any field
 * (`400 ORG_ID_INVALID`, before the endpoint runs); the walk sent
 * `?organizationId=<100,000 characters>` with every request, so on these
 * paths every request was refused and the cases passed without reaching the
 * audit layer. The oversized query is now its own request on gated paths,
 * and the walk asserts per path that a successful base request wrote rows.
 */
const GATED_WALK_PATHS = [
  "/api-key/create",
  "/enterprise/policy/set",
  "/organization/create-team",
  "/sso/register",
  "/sso/request-domain-verification",
  "/sso/update-provider",
];

/**
 * Audited paths whose successful base request has no chain to write to in
 * the walk's world. `target-user` rows go to the target user's orgs, and the
 * user `/admin/create-user` creates belongs to none yet — the row is skipped
 * and logged at debug (`writeRows`, `expectOrg: false`).
 */
const NO_ORG_ON_SUCCESS = new Set(["/admin/create-user"]);

describe("every audited route, with oversized request values, stores only bounded rows", () => {
  const written = { rows: 0 };
  const rowsByPath = new Map<string, number>();
  const baseStatusByPath = new Map<string, number>();

  for (const path of Object.keys(AUDITED_PATHS).sort()) {
    it(
      path,
      async () => {
        const w = await walkWorld(path);
        const before = (await largest(w.t)).rows;
        const base = baseBody(path, w);
        const headers = {
          ...callerOf(path, w),
          "user-agent": BIG,
          "x-forwarded-for": BIG,
        };
        const variants: Record<string, unknown>[] = [base];
        for (const field of new Set<string>([...Object.keys(base), ...READ_FIELDS])) {
          variants.push({ ...base, [field]: BIG }, { ...base, [field]: BIG_LIST });
        }
        const params = path.includes(":")
          ? [path.includes(":userId") && w.scim ? w.scim.userId : "p1", BIG]
          : [""];
        const oversizedOrgQuery = `?organizationId=${encodeURIComponent(BIG)}`;
        const gated = path in GATED_PATHS;
        let baseStatus: number | undefined;
        for (const method of methodsOf(path)) {
          for (const param of params) {
            const plain = concrete(path, param);
            const bodies = method === "DELETE" ? [undefined] : variants;
            // A gated path refuses an oversized org id before the endpoint
            // runs, so there the oversized query goes on a request of its own
            // and every body variant is sent without it.
            const requests: Array<[string, Array<Record<string, unknown> | undefined>]> = gated
              ? [
                  [plain, bodies],
                  [`${plain}${oversizedOrgQuery}`, [bodies[0]]],
                ]
              : [[`${plain}${oversizedOrgQuery}`, bodies]];
            for (const [url, sent] of requests) {
              for (const body of sent) {
                const res = await w.t.api.request(method, url, body, headers);
                baseStatus ??= res.status;
              }
            }
          }
        }
        const max = await largest(w.t);
        written.rows += max.rows - before;
        rowsByPath.set(path, max.rows - before);
        baseStatusByPath.set(path, baseStatus!);
        // A base request the endpoint accepted is an audited change: the
        // walk reached the audit layer on this path, not only its refusals.
        if (baseStatus! >= 200 && baseStatus! < 300 && !NO_ORG_ON_SUCCESS.has(path)) {
          expect(max.rows - before, `${path}: rows written`).toBeGreaterThanOrEqual(1);
        }
        expect(max.metadata).toBeLessThanOrEqual(AUDIT_METADATA_MAX_LENGTH);
        expect(max.target).toBeLessThanOrEqual(AUDIT_TOKEN_MAX_LENGTH);
        expect(max.actor).toBeLessThanOrEqual(AUDIT_TOKEN_MAX_LENGTH);
        expect(max.ua).toBeLessThanOrEqual(AUDIT_USER_AGENT_MAX_LENGTH);
        expect(max.ip).toBeLessThanOrEqual(45);
      },
      WALK_TIMEOUT_MS,
    );
  }

  it("the walk reached the audit layer (rows were written, not only refused)", () => {
    expect(written.rows).toBeGreaterThan(40);
  });

  it("the gated paths are walked through the endpoint: each base request succeeds and writes rows", () => {
    for (const path of GATED_WALK_PATHS) {
      expect(path in GATED_PATHS, path).toBe(true);
      const status = baseStatusByPath.get(path);
      expect(status! >= 200 && status! < 300, `${path}: base request status ${status}`).toBe(true);
      expect(rowsByPath.get(path), `${path}: rows written`).toBeGreaterThanOrEqual(1);
    }
  });
});

// ---------------------------------------------------------------------------

/**
 * Paths where a failed audit write is logged and the request still succeeds
 * (docs/security.md, "Audit log coverage"): the sign-in family (every
 * `session` entry) and these unauthenticated account flows.
 */
const SOFT_WRITE_PATHS = new Set([
  "/sign-out",
  "/sign-in/magic-link",
  "/request-password-reset",
  "/reset-password",
  "/sso/saml2/logout/:providerId",
  "/sso/saml2/sp/slo/:providerId",
]);

function softWrite(path: string): boolean {
  return AUDITED_PATHS[path]!.kind === "session" || SOFT_WRITE_PATHS.has(path);
}

describe("an audited change whose row cannot be written never answers success", () => {
  it("the soft-path list above is the plugin's own", () => {
    const isSoft = (
      auditPlugin as {
        writeFailureIsSoft?: (path: string, entry: (typeof AUDITED_PATHS)[string]) => boolean;
      }
    ).writeFailureIsSoft;
    expect(typeof isSoft).toBe("function");
    for (const [path, entry] of Object.entries(AUDITED_PATHS)) {
      expect(isSoft!(path, entry), path).toBe(softWrite(path));
    }
  });

  // Every audit_event insert fails (a trigger, after the world is built).
  // The change itself is already committed when the after-hook runs, so
  // the answer must say the row is missing: never a 2xx or 3xx, whatever
  // status the endpoint set (SCIM `POST /scim/v2/Users` sets 201).
  const answers = new Map<string, number>();
  const failedWrites = new Set<string>();

  for (const path of Object.keys(AUDITED_PATHS).sort()) {
    if (softWrite(path) || NO_ORG_ON_SUCCESS.has(path)) continue;
    it(
      path,
      async () => {
        const w = await walkWorld(path);
        await w.t.client.execute(
          `CREATE TRIGGER audit_insert_fails BEFORE INSERT ON audit_event BEGIN SELECT RAISE(ABORT, 'audit insert refused'); END`,
        );
        const param = path.includes(":userId") && w.scim ? w.scim.userId : "p1";
        for (const method of methodsOf(path)) {
          const res = await w.t.api.request(
            method,
            concrete(path, param),
            method === "DELETE" ? undefined : baseBody(path, w),
            callerOf(path, w),
          );
          const text = await res.text();
          expect(
            res.status < 200 || res.status >= 400,
            `${method} ${path}: ${res.status} ${text}`,
          ).toBe(true);
          answers.set(`${method} ${path}`, res.status);
          if (text.includes("AUDIT_WRITE_FAILED")) failedWrites.add(`${method} ${path}`);
        }
      },
      WALK_TIMEOUT_MS,
    );
  }

  it("SCIM user create answers 500 AUDIT_WRITE_FAILED (was 201), and so do most audited changes", () => {
    expect(answers.get("POST /scim/v2/Users")).toBe(500);
    expect(failedWrites.has("POST /scim/v2/Users")).toBe(true);
    // SCIM delete writes its rows inside the endpoint and fails there.
    expect(answers.get("DELETE /scim/v2/Users/:userId")).toBeGreaterThanOrEqual(500);
    expect(failedWrites.size).toBeGreaterThan(20);
  });
});

// ---------------------------------------------------------------------------

describe("list/export: from/to are bounded to what a Date can hold", () => {
  async function owner(t: TestAuth) {
    const o = await signUpOwner(t, "owner@acme.test");
    const { orgId } = await createOrg(t, o.cookie);
    return { cookie: o.cookie, orgId };
  }

  for (const endpoint of ["/enterprise/audit/list", "/enterprise/audit/export"]) {
    for (const [param, value] of [
      ["from", "1e20"],
      ["to", "1e20"],
      ["from", "8640000000000001"],
      ["to", "-1"],
      ["from", "1.5"],
      ["to", "Infinity"],
    ] as const) {
      it(`${endpoint}?${param}=${value} → 400, and no query reaches the error log`, async () => {
        const t = await makeAuth();
        const { cookie, orgId } = await owner(t);
        const ctx = await t.auth.$context;
        const error = vi.spyOn(ctx.logger, "error");
        const res = await t.api.get(`${endpoint}?orgId=${orgId}&${param}=${value}`, { cookie });
        expect(res.status, await res.clone().text()).toBe(400);
        const body = await res.text();
        expect(body.toLowerCase()).not.toContain("select");
        expect(JSON.stringify(error.mock.calls).toLowerCase()).not.toContain("select");
        error.mockRestore();
      });
    }

    it(`${endpoint} with from=0 and to=8.64e15 (the bounds themselves) → 200`, async () => {
      const t = await makeAuth();
      const { cookie, orgId } = await owner(t);
      const res = await t.api.get(`${endpoint}?orgId=${orgId}&from=0&to=8640000000000000`, {
        cookie,
      });
      expect(res.status, await res.clone().text()).toBe(200);
    });
  }
});
