// Audit log: an organization endpoint's row goes to the org of the resource
// it acted on — read from that resource — never to an org the caller named.
//
// Upstream's organization endpoints resolve their org from
// `body.organizationId || session.activeOrganizationId` and never read the
// query string. A caller who belongs to two orgs, A (active) and B, and
// sends `?organizationId=<B>` still changes A's team — so the row must land
// in A's chain and nowhere else. Every assertion states the fixed
// behaviour; against the parent commit the three team endpoints whose
// response carries no organization id (add-team-member, remove-team-member,
// remove-team) wrote their row into B and none into A.

import { describe, expect, it } from "vitest";
import { createOrg, makeAuth, signUpOwner, type TestAuth } from "../helpers/auth";
import { insertMemberRow } from "./helpers";
import { AUDITED_PATHS } from "../../src/server/audit/routes";
import { RESOURCE_ORG_SOURCES } from "../../src/server/audit/plugin";

async function count(t: TestAuth, orgId: string, action: string): Promise<number> {
  const res = await t.client.execute({
    sql: `SELECT count(*) AS n FROM audit_event WHERE org_id = ? AND action = ?`,
    args: [orgId, action],
  });
  return Number(res.rows[0]!.n);
}

async function ok(res: Response): Promise<Response> {
  expect(res.status, await res.clone().text()).toBe(200);
  return res;
}

async function idOf(res: Response): Promise<string> {
  return ((await (await ok(res)).json()) as { id: string }).id;
}

interface World {
  t: TestAuth;
  owner: { cookie: string; userId: string };
  member: { cookie: string; userId: string };
  a: string;
  b: string;
  teamA: string;
  teamA2: string;
}

/**
 * An owner of two orgs A and B with A active, a plain member of A (not of
 * B), and two teams of A. The owner belonging to B is what makes B a
 * plausible org for them to name.
 */
async function world(): Promise<World> {
  const t = await makeAuth({ organization: { requireEmailVerificationOnInvitation: false } });
  const owner = await signUpOwner(t, "owner@acme.test");
  const { orgId: b } = await createOrg(t, owner.cookie, "bbb");
  const { orgId: a } = await createOrg(t, owner.cookie, "aaa");
  const member = await signUpOwner(t, "member@acme.test");
  await insertMemberRow(t, a, member.userId, "member");
  await ok(
    await t.api.post("/organization/set-active", { organizationId: a }, { cookie: owner.cookie }),
  );
  const teamA = await idOf(
    await t.api.post(
      "/organization/create-team",
      { name: "t1", organizationId: a },
      { cookie: owner.cookie },
    ),
  );
  const teamA2 = await idOf(
    await t.api.post(
      "/organization/create-team",
      { name: "t2", organizationId: a },
      { cookie: owner.cookie },
    ),
  );
  return { t, owner, member, a, b, teamA, teamA2 };
}

async function invite(w: World, email: string): Promise<string> {
  return idOf(
    await w.t.api.post(
      "/organization/invite-member",
      { email, role: "member", organizationId: w.a },
      { cookie: w.owner.cookie },
    ),
  );
}

type Case = {
  action: string;
  /** Runs the request (with `?organizationId=<B>`); returns the response. */
  run: (w: World, q: string) => Promise<Response>;
};

// One case per `resource`-scope path. Each request acts on a resource of A
// with A as the org upstream resolves, while the query names B.
const CASES: Record<string, Case> = {
  "/organization/update": {
    action: "org.updated",
    run: (w, q) =>
      w.t.api.post(
        `/organization/update${q}`,
        { data: { name: "A2" } },
        { cookie: w.owner.cookie },
      ),
  },
  "/organization/delete": {
    action: "org.deleted",
    run: (w, q) =>
      w.t.api.post(`/organization/delete${q}`, { organizationId: w.a }, { cookie: w.owner.cookie }),
  },
  "/organization/leave": {
    action: "member.left",
    run: (w, q) =>
      w.t.api.post(`/organization/leave${q}`, { organizationId: w.a }, { cookie: w.member.cookie }),
  },
  "/organization/invite-member": {
    action: "member.invited",
    run: (w, q) =>
      w.t.api.post(
        `/organization/invite-member${q}`,
        { email: "new@acme.test", role: "member" },
        { cookie: w.owner.cookie },
      ),
  },
  "/organization/cancel-invitation": {
    action: "member.invitation_canceled",
    run: async (w, q) => {
      const invitationId = await invite(w, "new@acme.test");
      return w.t.api.post(
        `/organization/cancel-invitation${q}`,
        { invitationId },
        { cookie: w.owner.cookie },
      );
    },
  },
  "/organization/reject-invitation": {
    action: "member.invitation_rejected",
    run: async (w, q) => {
      const invitationId = await invite(w, "new@acme.test");
      const invitee = await signUpOwner(w.t, "new@acme.test");
      await createOrg(w.t, invitee.cookie, "own");
      return w.t.api.post(
        `/organization/reject-invitation${q}`,
        { invitationId },
        { cookie: invitee.cookie },
      );
    },
  },
  "/organization/accept-invitation": {
    action: "member.joined",
    run: async (w, q) => {
      const invitationId = await invite(w, "new@acme.test");
      const invitee = await signUpOwner(w.t, "new@acme.test");
      await createOrg(w.t, invitee.cookie, "own");
      return w.t.api.post(
        `/organization/accept-invitation${q}`,
        { invitationId },
        { cookie: invitee.cookie },
      );
    },
  },
  "/organization/remove-member": {
    action: "member.removed",
    run: (w, q) =>
      w.t.api.post(
        `/organization/remove-member${q}`,
        { memberIdOrEmail: "member@acme.test" },
        { cookie: w.owner.cookie },
      ),
  },
  "/organization/update-member-role": {
    action: "member.role_changed",
    run: (w, q) =>
      w.t.api.post(
        `/organization/update-member-role${q}`,
        { memberId: `member_${w.member.userId}_${w.a}`, role: "admin" },
        { cookie: w.owner.cookie },
      ),
  },
  "/organization/create-team": {
    action: "team.created",
    run: (w, q) =>
      w.t.api.post(`/organization/create-team${q}`, { name: "t3" }, { cookie: w.owner.cookie }),
  },
  "/organization/update-team": {
    action: "team.updated",
    run: (w, q) =>
      w.t.api.post(
        `/organization/update-team${q}`,
        { teamId: w.teamA, data: { name: "t1b" } },
        { cookie: w.owner.cookie },
      ),
  },
  "/organization/remove-team": {
    action: "team.removed",
    run: (w, q) =>
      w.t.api.post(
        `/organization/remove-team${q}`,
        { teamId: w.teamA2 },
        { cookie: w.owner.cookie },
      ),
  },
  "/organization/add-team-member": {
    action: "team.member_added",
    run: (w, q) =>
      w.t.api.post(
        `/organization/add-team-member${q}`,
        { teamId: w.teamA, userId: w.member.userId },
        { cookie: w.owner.cookie },
      ),
  },
  "/organization/remove-team-member": {
    action: "team.member_removed",
    run: async (w, q) => {
      await ok(
        await w.t.api.post(
          "/organization/add-team-member",
          { teamId: w.teamA, userId: w.member.userId },
          { cookie: w.owner.cookie },
        ),
      );
      return w.t.api.post(
        `/organization/remove-team-member${q}`,
        { teamId: w.teamA, userId: w.member.userId },
        { cookie: w.owner.cookie },
      );
    },
  },
};

const RESOURCE_PATHS = Object.entries(AUDITED_PATHS)
  .filter(([, entry]) => entry.scope === "resource")
  .map(([path]) => path)
  .sort();

describe("resource-scope rows bind to the acted-on resource's org", () => {
  it("every resource-scope path has a resource-org source, and every case below covers one", () => {
    expect(Object.keys(RESOURCE_ORG_SOURCES).sort()).toEqual(RESOURCE_PATHS);
    expect(Object.keys(CASES).sort()).toEqual(RESOURCE_PATHS);
  });

  for (const path of Object.keys(CASES)) {
    it(`${path} with ?organizationId=<another org of the caller>: one row in the resource's org, none in the named one`, async () => {
      const w = await world();
      const { action, run } = CASES[path]!;
      const before = await count(w.t, w.a, action); // the fixture's own create-team rows
      await ok(await run(w, `?organizationId=${w.b}`));
      expect(await count(w.t, w.a, action)).toBe(before + 1);
      expect(await count(w.t, w.b, action)).toBe(0);
    });
  }

  for (const path of [
    "/organization/add-team-member",
    "/organization/remove-team-member",
    "/organization/remove-team",
  ]) {
    it(`${path}: the caller's active org is not the resource's org either — the row follows the team`, async () => {
      const w = await world();
      // B active; the body names A, which is the org upstream acts on.
      await ok(
        await w.t.api.post(
          "/organization/set-active",
          { organizationId: w.b },
          { cookie: w.owner.cookie },
        ),
      );
      const body =
        path === "/organization/remove-team"
          ? { teamId: w.teamA2, organizationId: w.a }
          : { teamId: w.teamA, userId: w.member.userId, organizationId: w.a };
      if (path === "/organization/remove-team-member") {
        await ok(
          await w.t.api.post("/organization/add-team-member", body, { cookie: w.owner.cookie }),
        );
      }
      await ok(
        await w.t.api.post(`${path}?organizationId=${w.b}`, body, { cookie: w.owner.cookie }),
      );
      const { action } = CASES[path]!;
      expect(await count(w.t, w.a, action)).toBe(1);
      expect(await count(w.t, w.b, action)).toBe(0);
    });
  }

  it("a team endpoint that fails writes no row anywhere (a team of A named under B)", async () => {
    const w = await world();
    const res = await w.t.api.post(
      "/organization/add-team-member",
      { teamId: w.teamA, userId: w.member.userId, organizationId: w.b },
      { cookie: w.owner.cookie },
    );
    expect(res.status).toBe(400);
    expect(await count(w.t, w.a, "team.member_added")).toBe(0);
    expect(await count(w.t, w.b, "team.member_added")).toBe(0);
  });
});
