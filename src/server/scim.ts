import {
  scim,
  type SCIMPlugin,
  type SCIMProjectedUserState,
  type SCIMTransactionContext,
} from "@better-auth/scim";
import type { BetterAuthPlugin, GenericEndpointContext } from "better-auth";
import { createAuthMiddleware } from "better-auth/api";
import { requireFeature } from "./entitlements";
import { writeAudit } from "./audit/chain";
import { getOrgPolicy } from "./policy/store";
import type { EnterpriseOptions } from "./types";

const SCIM_BAN_REASON = "Enterprise SCIM deactivation";
interface ManagedMember {
  id: string;
  memberId: string;
  lastRole: string;
}
interface Member {
  id: string;
  role: string;
  organizationId: string;
  userId: string;
  createdAt: Date;
}

async function projectMembership(
  state: SCIMProjectedUserState,
  { database }: SCIMTransactionContext,
) {
  const where = [
    { field: "organizationId", value: state.provisioningDomainId },
    { field: "userId", value: state.userId },
  ];
  const member = await database.findOne<Member>({ model: "member", where });
  const managed = await database.findOne<ManagedMember>({
    model: "enterpriseScimMember",
    where: [
      { field: "orgId", value: state.provisioningDomainId },
      { field: "userId", value: state.userId },
    ],
  });
  // Only manage memberships this projector created. Manual roles and memberships
  // in another organization never become SCIM-owned implicitly.
  if (member && (!managed || managed.memberId !== member.id || member.role !== managed.lastRole)) {
    if (managed)
      await database.delete({
        model: "enterpriseScimMember",
        where: [{ field: "id", value: managed.id }],
      });
    return;
  }
  const role = state.grants.some((grant) => grant.role === "admin") ? "admin" : "member";
  if (!state.active) {
    if (managed)
      await writeAudit({ context: { adapter: database } } as unknown as GenericEndpointContext, {
        orgId: state.provisioningDomainId,
        actorType: "scim",
        actorId: null,
        action: "scim.user_deactivated",
        targetType: "user",
        targetId: state.userId,
      });
    if (member && managed)
      await database.delete({ model: "member", where: [{ field: "id", value: member.id }] });
    if (managed)
      await database.delete({
        model: "enterpriseScimMember",
        where: [{ field: "id", value: managed.id }],
      });
    return;
  }
  if (!member) {
    if (managed)
      await database.delete({
        model: "enterpriseScimMember",
        where: [{ field: "id", value: managed.id }],
      });
    const created = await database.create<Member>({
      model: "member",
      data: {
        organizationId: state.provisioningDomainId,
        userId: state.userId,
        role,
        createdAt: new Date(),
      },
    });
    await database.create({
      model: "enterpriseScimMember",
      data: {
        orgId: state.provisioningDomainId,
        userId: state.userId,
        memberId: created.id,
        lastRole: role,
      },
    });
  } else if (managed && member.role !== role) {
    await database.update({
      model: "member",
      where: [{ field: "id", value: member.id }],
      update: { role },
    });
    await database.update({
      model: "enterpriseScimMember",
      where: [{ field: "id", value: managed.id }],
      update: { lastRole: role },
    });
  }
}

export function enterpriseScim(opts: EnterpriseOptions): SCIMPlugin {
  const plugin = scim({
    connections: [],
    managedConnections: { credentialHashSecret: opts.scimCredentialHashSecret },
    identity: {
      async reconcileUser(state, { database }) {
        const user = await database.findOne<{ banned: boolean | null; banReason: string | null }>({
          model: "user",
          where: [{ field: "id", value: state.userId }],
        });
        if (!state.active) {
          await database.deleteMany({
            model: "apikey",
            where: [{ field: "referenceId", value: state.userId }],
          });
        }
        // Native SCIM revokes sessions; persist a ban to prevent a fresh login.
        // Reactivation must never clear an unrelated administrator ban.
        if (user && (!user.banned || user.banReason === SCIM_BAN_REASON)) {
          await database.update({
            model: "user",
            where: [{ field: "id", value: state.userId }],
            update: {
              banned: !state.active,
              banReason: state.active ? null : SCIM_BAN_REASON,
              banExpires: null,
            },
          });
        }
      },
    },
    projection: {
      roles: {
        async map(input, { database }) {
          const ctx = { context: { adapter: database } } as unknown as GenericEndpointContext;
          const policy = await getOrgPolicy(ctx, input.provisioningDomainId);
          const mapping = Object.keys(policy.groupRoleMap).length
            ? policy.groupRoleMap
            : (opts.scim?.groupRoleMap ?? {});
          const role = Object.hasOwn(mapping, input.source.displayName)
            ? mapping[input.source.displayName]
            : undefined;
          return role === "admin" || role === "member" ? [role] : [];
        },
        exists: ({ role }) => role === "admin" || role === "member",
      },
      reconcileUser: projectMembership,
    },
  });
  const gate = createAuthMiddleware(async (ctx) => {
    const connection = (
      ctx.context as unknown as { scimConnection: { provisioningDomainId: string } }
    ).scimConnection;
    await requireFeature(
      ctx as unknown as GenericEndpointContext,
      connection.provisioningDomainId,
      "scim",
    );
  });
  for (const endpoint of Object.values(plugin.endpoints)) {
    if (
      endpoint.path?.startsWith("/scim/v2/Users") ||
      endpoint.path?.startsWith("/scim/v2/Groups")
    ) {
      // Runs after native credential/scope authentication, before any mutation.
      const options = endpoint.options as { use?: (typeof gate)[] };
      options.use = [...(options.use ?? []), gate];
    }
  }
  return plugin;
}

export function scimMembershipSchema() {
  return {
    id: "enterprise-scim-membership",
    schema: {
      enterpriseScimMember: {
        modelName: "enterprise_scim_member",
        fields: {
          orgId: { type: "string", required: true, fieldName: "org_id" },
          userId: { type: "string", required: true, fieldName: "user_id" },
          memberId: { type: "string", required: true, unique: true, fieldName: "member_id" },
          lastRole: { type: "string", required: true, fieldName: "last_role" },
        },
      },
    },
  } satisfies BetterAuthPlugin;
}
