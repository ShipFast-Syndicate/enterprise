import {
  scim,
  type SCIMPlugin,
  type SCIMProjectedUserState,
  type SCIMTransactionContext,
} from "@better-auth/scim";
import type { BetterAuthPlugin, GenericEndpointContext } from "better-auth";
import { createAuthMiddleware } from "better-auth/api";
import { requireFeature } from "./entitlements";
import { writeAudit, type ChainWriteOptions } from "./audit/chain";
import { getOrgPolicy } from "./policy/store";
import { revokeUserApiKeys } from "./api-keys";
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

// Hand-off from the projection hook to the identity hook, keyed by the
// transaction adapter both receive (`trx` in every upstream flow: PATCH,
// DELETE, decommission replay). By the time `identity.reconcileUser` runs,
// nothing in the database still names the org whose feed deactivated a
// user: the projector removed the SCIM-owned membership, a DELETE removed the
// `scimUser` row (a tombstone exists only with an `externalId`) and a
// decommissioned connection's rows are filtered out of `state.sources`. The
// projection hook always knows `provisioningDomainId`, so it records it here
// and the identity hook consumes it. A `WeakMap` on the transaction object
// never outlives the transaction and never crosses requests.
const pendingProvisioningOrgs = new WeakMap<object, Map<string, Set<string>>>();

function recordProvisioningOrg(database: object, userId: string, orgId: string): void {
  let byUser = pendingProvisioningOrgs.get(database);
  if (!byUser) {
    byUser = new Map();
    pendingProvisioningOrgs.set(database, byUser);
  }
  let orgs = byUser.get(userId);
  if (!orgs) {
    orgs = new Set();
    byUser.set(userId, orgs);
  }
  orgs.add(orgId);
}

function takeProvisioningOrgs(database: object, userId: string): string[] {
  const byUser = pendingProvisioningOrgs.get(database);
  const orgs = byUser?.get(userId);
  byUser?.delete(userId);
  return orgs ? [...orgs] : [];
}

async function projectMembership(
  state: SCIMProjectedUserState,
  { database }: SCIMTransactionContext,
  chain: ChainWriteOptions,
) {
  recordProvisioningOrg(database, state.userId, state.provisioningDomainId);
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
      await writeAudit(
        { context: { adapter: database } } as unknown as GenericEndpointContext,
        {
          orgId: state.provisioningDomainId,
          actorType: "scim",
          actorId: null,
          action: "scim.user_deactivated",
          targetType: "user",
          targetId: state.userId,
        },
        chain,
      );
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

/** Whether the user holds an `owner` role in any organization (multi-role values are comma-joined). */
async function holdsOwnerMembership(
  database: SCIMTransactionContext["database"],
  userId: string,
): Promise<boolean> {
  const rows = await database.findMany<{ role: string }>({
    model: "member",
    where: [{ field: "userId", value: userId }],
  });
  return rows.some((row) =>
    String(row.role)
      .split(",")
      .map((r) => r.trim())
      .includes("owner"),
  );
}

export function enterpriseScim(opts: EnterpriseOptions): SCIMPlugin {
  const chain: ChainWriteOptions = { chainKey: opts.audit?.chainKey };
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
          // The orgs whose SCIM feeds provisioned this identity: the ones the
          // projector recorded for this transaction plus every source still
          // listed. `revokeUserApiKeys`'s own membership scan would miss
          // them (the SCIM-owned membership is already gone).
          const provisioningOrgIds = [
            ...new Set([
              ...takeProvisioningOrgs(database, state.userId),
              ...state.sources.map((source) => source.provisioningDomainId),
            ]),
          ];
          // Keys first, for every deactivated identity — owner or not. A key
          // is a live credential of an identity the IdP no longer vouches
          // for; an owner who is *not* banned (below) signs in again and
          // mints a new one, so nothing is irreversible for them. Audited
          // as `api_key.revoked` (actor `scim`, reason `scim.deactivate`)
          // into every org the user belonged to, the provisioning org(s)
          // included.
          await revokeUserApiKeys(
            { context: { adapter: database } },
            state.userId,
            { actorType: "scim", actorId: null },
            "scim.deactivate",
            { ...chain, orgIds: provisioningOrgIds },
          );
          // F-07: SCIM can never *produce* an owner (M-01), so an `owner`
          // membership is a manual grant — or, since self-serve org creation
          // stays on (`organization.allowUserToCreateOrganization`, default
          // `true`), an org the user created themselves. Neither an IdP
          // deactivation nor a connection decommission (which replays every
          // provisioned user as inactive) may turn that into a platform-wide
          // ban. Upstream still revokes the sessions; the SCIM-owned
          // memberships are still removed by `projectMembership`; the keys
          // are gone (above). The skipped ban is audited into the
          // provisioning org's chain so it is visible to the org that asked.
          if (await holdsOwnerMembership(database, state.userId)) {
            for (const orgId of provisioningOrgIds) {
              await writeAudit(
                { context: { adapter: database } } as unknown as GenericEndpointContext,
                {
                  orgId,
                  actorType: "scim",
                  actorId: null,
                  action: "scim.user_deactivation_skipped",
                  targetType: "user",
                  targetId: state.userId,
                  metadata: { reason: "owner_protected" },
                },
                chain,
              );
            }
            return;
          }
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
      reconcileUser: (state, context) => projectMembership(state, context, chain),
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
