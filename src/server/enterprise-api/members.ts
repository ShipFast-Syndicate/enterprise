// Alpha Bros enterprise layer — enterpriseApi plugin: members endpoint.
//
// `GET /enterprise/members?orgId` — basic org membership + pending
// invitations, for the admin portal's People tab. Deliberately *not* in
// `GATED_PATHS` (ruling: viewing your own org's roster is basic org
// management, not a licensed feature) — session + membership only, the same
// as `GET /enterprise/features` (`./plugin.ts`).
//
// `teams` is resolved via two extra queries (`team` rows for the org, then
// `teamMember` rows for those team ids) rather than one join, since
// `ctx.context.adapter` is better-auth's generic cross-database adapter —
// no join support to rely on (`../policy/store.ts`'s header comment makes
// the same call for the same reason).

import { createAuthEndpoint, sessionMiddleware } from "better-auth/api";
import type { GenericEndpointContext } from "better-auth";
import * as z from "zod";
import { requireOrgMember } from "../policy/store";

interface MemberRow {
  id: string;
  userId: string;
  role: string;
}

interface UserRow {
  id: string;
  email: string;
  name: string;
}

interface TeamRow {
  id: string;
  name: string;
}

interface TeamMemberRow {
  teamId: string;
  userId: string;
}

interface InvitationRow {
  id: string;
  email: string;
  role: string | null;
  status: string;
  expiresAt: Date;
}

const membersQuerySchema = z.object({ orgId: z.string() });

export function buildMembersEndpoint() {
  return createAuthEndpoint(
    "/enterprise/members",
    { method: "GET", use: [sessionMiddleware], query: membersQuerySchema },
    async (ctx) => {
      const fullCtx = ctx as unknown as GenericEndpointContext;
      const { orgId } = ctx.query;
      await requireOrgMember(fullCtx, orgId);

      const members = await ctx.context.adapter.findMany<MemberRow>({
        model: "member",
        where: [{ field: "organizationId", value: orgId }],
      });
      const userIds = members.map((m) => m.userId);
      const users = userIds.length
        ? await ctx.context.adapter.findMany<UserRow>({
            model: "user",
            where: [{ field: "id", value: userIds, operator: "in" }],
          })
        : [];
      const userById = new Map(users.map((u) => [u.id, u]));

      const teams = await ctx.context.adapter.findMany<TeamRow>({
        model: "team",
        where: [{ field: "organizationId", value: orgId }],
      });
      const teamNameById = new Map(teams.map((t) => [t.id, t.name]));
      const teamIds = teams.map((t) => t.id);
      const teamMembers = teamIds.length
        ? await ctx.context.adapter.findMany<TeamMemberRow>({
            model: "teamMember",
            where: [{ field: "teamId", value: teamIds, operator: "in" }],
          })
        : [];
      const teamNamesByUserId = new Map<string, string[]>();
      for (const tm of teamMembers) {
        const name = teamNameById.get(tm.teamId);
        if (!name) continue;
        const names = teamNamesByUserId.get(tm.userId) ?? [];
        names.push(name);
        teamNamesByUserId.set(tm.userId, names);
      }

      const invitations = await ctx.context.adapter.findMany<InvitationRow>({
        model: "invitation",
        where: [{ field: "organizationId", value: orgId }],
      });

      return ctx.json({
        members: members.map((m) => {
          const user = userById.get(m.userId);
          return {
            id: m.id,
            userId: m.userId,
            email: user?.email ?? null,
            name: user?.name ?? null,
            role: m.role,
            teams: teamNamesByUserId.get(m.userId) ?? [],
          };
        }),
        invitations: invitations.map((i) => ({
          id: i.id,
          email: i.email,
          role: i.role,
          status: i.status,
          expiresAt: new Date(i.expiresAt).toISOString(),
        })),
      });
    },
  );
}
