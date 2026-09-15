// Alpha Bros enterprise layer — SCIM 2.0 Groups plugin.
//
// `scimGroups(opts)` (id `enterprise-scim-groups`) is the in-house
// replacement for the `/scim/v2/Groups` endpoints `@better-auth/scim` 1.6
// lacks (FDR-enterprise-0001) — appended by the preset (`../preset.ts`)
// right after `orgPolicy`. A SCIM "Group" maps 1:1 to an organization
// `team` (better-auth's own `organization({teams:{enabled:true}})` model,
// already registered by the preset): `id` = `team.id`, `displayName` =
// `team.name`, membership = `teamMember` rows. This plugin's own table,
// `scim_group` (declared below, `team_id` PK — see `../policy/store.ts`'s
// header comment for why a PK-aliased-to-a-non-`id`-column model omits an
// `id` field from its `schema` the same way `org_policy` does), only carries
// what `team` itself doesn't: `externalId` and this resource's own
// created/updated timestamps.
//
// Every endpoint here is a *plain* `createAuthEndpoint` — no
// `sessionMiddleware`, no upstream SCIM `authMiddleware` — authenticated
// instead by `./auth.ts`'s `authenticateScimBearer` (ruling (a)), called
// first thing in every handler. `runScim` (below) wraps every handler's body
// once so a thrown `ScimHttpError` (401 from auth, 400/404/409 from the
// handler body) becomes a `scimError(...)` response in one place rather than
// a repeated try/catch per endpoint.
//
// `ResourceTypes` (`GET /scim/v2/ResourceTypes`) is left exactly as
// `@better-auth/scim` registers it — Users only, per the controller ruling
// for this task — so an identity provider that reads that endpoint to
// discover supported resource types won't see Groups advertised there even
// though these endpoints exist; that's a known v0.1 gap, not an oversight.
//
// `GET /scim/v2/Groups/:groupId` is a separate `createAuthEndpoint`
// registration from `GET /scim/v2/Groups` (ruling (b)) — better-call routes
// on the literal path pattern, so the two can never cross-match; there's no
// shared handler branching on whether a groupId segment is present.

import type { BetterAuthPlugin, GenericEndpointContext } from "better-auth";
import { createAuthEndpoint } from "better-auth/api";
import type { Where } from "@better-auth/core/db/adapter";
import * as z from "zod";
import { writeAudit } from "../audit/chain";
import { getOrgPolicy } from "../policy/store";
import type { EnterpriseOptions } from "../types";
import { authenticateScimBearer } from "./auth";
import {
  applyGroupPatch,
  buildGroupResource,
  effectiveRole,
  locationFor,
  parseFilter,
  scimError,
  scimJson,
  ScimHttpError,
  type PatchOp,
  type ScimGroupResource,
} from "./scim";

// --- error-handling wrapper --------------------------------------------------

// A thunk (not a generic higher-order function over `ctx`) deliberately:
// each endpoint below still passes its own `async (ctx) => runScim(async ()
// => {...})` directly as `createAuthEndpoint`'s handler, so `ctx` keeps its
// endpoint-specific inferred type (body/query/params per that endpoint's own
// schema) instead of being widened through an intermediate generic wrapper.
async function runScim(fn: () => Promise<Response>): Promise<Response> {
  try {
    return await fn();
  } catch (err) {
    if (err instanceof ScimHttpError) return scimError(err.status, err.scimType, err.message);
    throw err;
  }
}

// --- row/model shapes ---------------------------------------------------

interface ScimGroupRow {
  teamId: string;
  orgId: string;
  externalId: string | null;
  createdAt: Date;
  updatedAt: Date;
}

interface TeamRow {
  id: string;
  name: string;
  organizationId: string;
  createdAt: Date;
  updatedAt: Date;
}

interface TeamMemberRow {
  teamId: string;
  userId: string;
}

interface MemberRow {
  id: string;
  organizationId: string;
  userId: string;
  role: string;
}

interface UserRow {
  id: string;
  email: string;
}

// --- shared helpers -----------------------------------------------------

async function findScimGroupRow(
  ctx: GenericEndpointContext,
  orgId: string,
  groupId: string,
): Promise<ScimGroupRow | null> {
  return ctx.context.adapter.findOne<ScimGroupRow>({
    model: "scimGroup",
    where: [
      { field: "teamId", value: groupId },
      { field: "orgId", value: orgId },
    ],
  });
}

async function loadGroupResource(
  ctx: GenericEndpointContext,
  row: ScimGroupRow,
): Promise<ScimGroupResource> {
  const [team, teamMembers] = await Promise.all([
    ctx.context.adapter.findOne<TeamRow>({
      model: "team",
      where: [{ field: "id", value: row.teamId }],
    }),
    ctx.context.adapter.findMany<TeamMemberRow>({
      model: "teamMember",
      where: [{ field: "teamId", value: row.teamId }],
    }),
  ]);
  const userIds = teamMembers.map((m) => m.userId);
  const users = userIds.length
    ? await ctx.context.adapter.findMany<UserRow>({
        model: "user",
        where: [{ field: "id", value: userIds, operator: "in" }],
      })
    : [];
  const members = teamMembers.map((tm) => ({
    value: tm.userId,
    display: users.find((u) => u.id === tm.userId)?.email,
  }));

  return buildGroupResource({
    id: row.teamId,
    externalId: row.externalId,
    displayName: team?.name ?? "",
    members,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
    location: locationFor(ctx.context.baseURL, row.teamId),
  });
}

async function assertDisplayNameAvailable(
  ctx: GenericEndpointContext,
  orgId: string,
  displayName: string,
  excludeTeamId?: string,
): Promise<void> {
  const existing = await ctx.context.adapter.findOne<{ id: string }>({
    model: "team",
    where: [
      { field: "organizationId", value: orgId },
      { field: "name", value: displayName },
    ],
  });
  if (existing && existing.id !== excludeTeamId) {
    throw new ScimHttpError(
      409,
      "uniqueness",
      `A group named "${displayName}" already exists in this organization.`,
    );
  }
}

/**
 * `scim_group_org_external` (`src/schema/sql/0001_enterprise.sql`) is a real
 * unique index on `(org_id, external_id)`, so a raw duplicate insert/update
 * would otherwise surface as an unhandled adapter/constraint error (a 500),
 * not a clean SCIM response. `externalId` is optional and nullable — SQLite
 * treats multiple `NULL`s in a unique index as distinct, so a missing
 * `externalId` never conflicts with anything and this check is a no-op for
 * it, matching the DB's own semantics.
 */
async function assertExternalIdAvailable(
  ctx: GenericEndpointContext,
  orgId: string,
  externalId: string | null | undefined,
  excludeTeamId?: string,
): Promise<void> {
  if (!externalId) return;
  const existing = await ctx.context.adapter.findOne<{ teamId: string }>({
    model: "scimGroup",
    where: [
      { field: "orgId", value: orgId },
      { field: "externalId", value: externalId },
    ],
  });
  if (existing && existing.teamId !== excludeTeamId) {
    throw new ScimHttpError(
      409,
      "uniqueness",
      `A group with externalId "${externalId}" already exists in this organization.`,
    );
  }
}

/** Members must hold a `member` row in the org (ruling (c)) — else 400 `invalidValue`. */
async function assertMembersExist(
  ctx: GenericEndpointContext,
  orgId: string,
  userIds: string[],
): Promise<void> {
  for (const userId of userIds) {
    const member = await ctx.context.adapter.findOne<MemberRow>({
      model: "member",
      where: [
        { field: "organizationId", value: orgId },
        { field: "userId", value: userId },
      ],
    });
    if (!member) {
      throw new ScimHttpError(
        400,
        "invalidValue",
        `"${userId}" is not a member of this organization.`,
      );
    }
  }
}

function diffMembers(previous: string[], next: string[]): { added: string[]; removed: string[] } {
  const prevSet = new Set(previous);
  const nextSet = new Set(next);
  return {
    added: next.filter((id) => !prevSet.has(id)),
    removed: previous.filter((id) => !nextSet.has(id)),
  };
}

async function applyMembershipDiff(
  ctx: GenericEndpointContext,
  teamId: string,
  added: string[],
  removed: string[],
): Promise<void> {
  for (const userId of removed) {
    await ctx.context.adapter.deleteMany({
      model: "teamMember",
      where: [
        { field: "teamId", value: teamId },
        { field: "userId", value: userId },
      ],
    });
  }
  for (const userId of added) {
    await ctx.context.adapter.create({
      model: "teamMember",
      data: { teamId, userId, createdAt: new Date() },
    });
  }
}

async function auditMembershipChanges(
  ctx: GenericEndpointContext,
  orgId: string,
  providerId: string,
  teamId: string,
  added: string[],
  removed: string[],
): Promise<void> {
  for (const userId of added) {
    await writeAudit(ctx, {
      orgId,
      actorType: "scim",
      actorId: providerId,
      action: "scim.group_member_added",
      targetType: "user",
      targetId: userId,
      metadata: { teamId },
    });
  }
  for (const userId of removed) {
    await writeAudit(ctx, {
      orgId,
      actorType: "scim",
      actorId: providerId,
      action: "scim.group_member_removed",
      targetType: "user",
      targetId: userId,
      metadata: { teamId },
    });
  }
}

/**
 * Recomputes one user's effective org role from their current team
 * memberships (ruling (d)): `effectiveRole(groupNames, policy.groupRoleMap
 * ?? opts.scim?.groupRoleMap ?? {})`. Never demotes the org's only owner —
 * skips the write and audits `scim.role_change_skipped` instead. A no-op
 * (role already correct) writes nothing at all, not even a skip row.
 */
async function recomputeRoleForUser(
  ctx: GenericEndpointContext,
  opts: EnterpriseOptions,
  orgId: string,
  userId: string,
  providerId: string,
): Promise<void> {
  const member = await ctx.context.adapter.findOne<MemberRow>({
    model: "member",
    where: [
      { field: "organizationId", value: orgId },
      { field: "userId", value: userId },
    ],
  });
  if (!member) return; // not (or no longer) an org member — nothing to recompute

  const teamMemberRows = await ctx.context.adapter.findMany<TeamMemberRow>({
    model: "teamMember",
    where: [{ field: "userId", value: userId }],
  });
  const teamIds = teamMemberRows.map((r) => r.teamId);
  const teams = teamIds.length
    ? await ctx.context.adapter.findMany<TeamRow>({
        model: "team",
        where: [
          { field: "id", value: teamIds, operator: "in" },
          { field: "organizationId", value: orgId },
        ],
      })
    : [];
  const groupNames = teams.map((t) => t.name);

  const policy = await getOrgPolicy(ctx, orgId);
  const role = effectiveRole(groupNames, policy.groupRoleMap ?? opts.scim?.groupRoleMap ?? {});

  if (member.role === role) return; // already correct — no write, no audit

  const currentRoles = member.role.split(",").map((r) => r.trim());
  if (currentRoles.includes("owner") && role !== "owner") {
    const orgMembers = await ctx.context.adapter.findMany<MemberRow>({
      model: "member",
      where: [{ field: "organizationId", value: orgId }],
    });
    const ownerCount = orgMembers.filter((m) =>
      m.role
        .split(",")
        .map((r) => r.trim())
        .includes("owner"),
    ).length;
    if (ownerCount <= 1) {
      await writeAudit(ctx, {
        orgId,
        actorType: "scim",
        actorId: providerId,
        action: "scim.role_change_skipped",
        targetType: "member",
        targetId: userId,
        metadata: { attemptedRole: role, currentRole: member.role, reason: "sole_owner" },
      });
      return;
    }
  }

  await ctx.context.adapter.update({
    model: "member",
    where: [{ field: "id", value: member.id }],
    update: { role },
  });
  await writeAudit(ctx, {
    orgId,
    actorType: "scim",
    actorId: providerId,
    action: "member.role_changed",
    targetType: "member",
    targetId: userId,
    metadata: { from: member.role, to: role },
  });
}

async function recomputeAffected(
  ctx: GenericEndpointContext,
  opts: EnterpriseOptions,
  orgId: string,
  providerId: string,
  userIds: string[],
): Promise<void> {
  for (const userId of [...new Set(userIds)]) {
    await recomputeRoleForUser(ctx, opts, orgId, userId, providerId);
  }
}

// --- request schemas ------------------------------------------------------

const memberInputSchema = z.object({ value: z.string() });

const createGroupBodySchema = z.object({
  displayName: z.string().min(1),
  externalId: z.string().optional(),
  members: z.array(memberInputSchema).optional(),
});

const replaceGroupBodySchema = createGroupBodySchema;

const patchOpSchema = z.object({
  op: z
    .string()
    .toLowerCase()
    .default("replace")
    .pipe(z.enum(["add", "remove", "replace"])),
  path: z.string().optional(),
  value: z.unknown().optional(),
});

const patchGroupBodySchema = z.object({
  schemas: z.array(z.string()).optional(),
  Operations: z.array(patchOpSchema),
});

const listGroupsQuerySchema = z
  .object({
    filter: z.string().optional(),
    startIndex: z.coerce.number().int().min(1).optional(),
    count: z.coerce.number().int().min(1).optional(),
  })
  .optional();

// --- endpoints --------------------------------------------------------

function buildListGroups() {
  return createAuthEndpoint(
    "/scim/v2/Groups",
    { method: "GET", query: listGroupsQuerySchema },
    (ctx) =>
      runScim(async () => {
        const fullCtx = ctx as unknown as GenericEndpointContext;
        const { organizationId } = await authenticateScimBearer(fullCtx);
        const query = ctx.query ?? {};
        const parsed = parseFilter(query.filter);
        const startIndex = query.startIndex ?? 1;
        const count = Math.min(query.count ?? 100, 100);

        const where: Where[] = [{ field: "orgId", value: organizationId }];
        if (parsed?.attr === "id") where.push({ field: "teamId", value: parsed.value });
        if (parsed?.attr === "externalId") where.push({ field: "externalId", value: parsed.value });
        if (parsed?.attr === "displayName") {
          const team = await fullCtx.context.adapter.findOne<{ id: string }>({
            model: "team",
            where: [
              { field: "organizationId", value: organizationId },
              { field: "name", value: parsed.value },
            ],
          });
          if (!team) {
            return scimJson(200, {
              schemas: ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
              totalResults: 0,
              startIndex,
              itemsPerPage: 0,
              Resources: [],
            });
          }
          where.push({ field: "teamId", value: team.id });
        }

        // `startIndex`/`count` slice this array, so its order must be
        // deterministic across calls — plain `findMany` with no `sortBy`
        // gives no such guarantee (adapter/index-dependent). `createdAt`
        // (not `team.name`) so this stays a single-table query — sorting by
        // display name would need a join with `team`.
        const rows = await fullCtx.context.adapter.findMany<ScimGroupRow>({
          model: "scimGroup",
          where,
          sortBy: { field: "createdAt", direction: "asc" },
        });
        const totalResults = rows.length;
        const sliceStart = Math.max(startIndex - 1, 0);
        const page = rows.slice(sliceStart, sliceStart + count);
        const resources = await Promise.all(page.map((row) => loadGroupResource(fullCtx, row)));

        return scimJson(200, {
          schemas: ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
          totalResults,
          startIndex,
          itemsPerPage: resources.length,
          Resources: resources,
        });
      }),
  );
}

function buildCreateGroup(opts: EnterpriseOptions) {
  return createAuthEndpoint(
    "/scim/v2/Groups",
    { method: "POST", body: createGroupBodySchema },
    (ctx) =>
      runScim(async () => {
        const fullCtx = ctx as unknown as GenericEndpointContext;
        const { providerId, organizationId } = await authenticateScimBearer(fullCtx);

        await assertDisplayNameAvailable(fullCtx, organizationId, ctx.body.displayName);
        await assertExternalIdAvailable(fullCtx, organizationId, ctx.body.externalId);
        const memberIds = [...new Set((ctx.body.members ?? []).map((m) => m.value))];
        await assertMembersExist(fullCtx, organizationId, memberIds);

        const now = new Date();
        const team = await fullCtx.context.adapter.create<TeamRow>({
          model: "team",
          data: { name: ctx.body.displayName, organizationId, createdAt: now, updatedAt: now },
        });
        await fullCtx.context.adapter.create({
          model: "scimGroup",
          data: {
            teamId: team.id,
            orgId: organizationId,
            externalId: ctx.body.externalId ?? null,
            createdAt: now,
            updatedAt: now,
          },
        });
        await applyMembershipDiff(fullCtx, team.id, memberIds, []);

        await writeAudit(fullCtx, {
          orgId: organizationId,
          actorType: "scim",
          actorId: providerId,
          action: "scim.group_created",
          targetType: "team",
          targetId: team.id,
        });
        await auditMembershipChanges(fullCtx, organizationId, providerId, team.id, memberIds, []);
        await recomputeAffected(fullCtx, opts, organizationId, providerId, memberIds);

        const resource = await loadGroupResource(fullCtx, {
          teamId: team.id,
          orgId: organizationId,
          externalId: ctx.body.externalId ?? null,
          createdAt: now,
          updatedAt: now,
        });
        return scimJson(201, resource, { location: resource.meta.location });
      }),
  );
}

function buildGetGroup() {
  return createAuthEndpoint("/scim/v2/Groups/:groupId", { method: "GET" }, (ctx) =>
    runScim(async () => {
      const fullCtx = ctx as unknown as GenericEndpointContext;
      const { organizationId } = await authenticateScimBearer(fullCtx);
      const row = await findScimGroupRow(fullCtx, organizationId, ctx.params.groupId);
      if (!row) throw new ScimHttpError(404, undefined, "Group not found");
      const resource = await loadGroupResource(fullCtx, row);
      return scimJson(200, resource);
    }),
  );
}

function buildReplaceGroup(opts: EnterpriseOptions) {
  return createAuthEndpoint(
    "/scim/v2/Groups/:groupId",
    { method: "PUT", body: replaceGroupBodySchema },
    (ctx) =>
      runScim(async () => {
        const fullCtx = ctx as unknown as GenericEndpointContext;
        const { providerId, organizationId } = await authenticateScimBearer(fullCtx);
        const groupId = ctx.params.groupId;

        const row = await findScimGroupRow(fullCtx, organizationId, groupId);
        if (!row) throw new ScimHttpError(404, undefined, "Group not found");

        await assertDisplayNameAvailable(fullCtx, organizationId, ctx.body.displayName, groupId);
        await assertExternalIdAvailable(fullCtx, organizationId, ctx.body.externalId, groupId);
        const nextMemberIds = [...new Set((ctx.body.members ?? []).map((m) => m.value))];
        await assertMembersExist(fullCtx, organizationId, nextMemberIds);

        const previousMembers = await fullCtx.context.adapter.findMany<TeamMemberRow>({
          model: "teamMember",
          where: [{ field: "teamId", value: groupId }],
        });
        const { added, removed } = diffMembers(
          previousMembers.map((m) => m.userId),
          nextMemberIds,
        );

        const now = new Date();
        await fullCtx.context.adapter.update({
          model: "team",
          where: [{ field: "id", value: groupId }],
          update: { name: ctx.body.displayName, updatedAt: now },
        });
        await fullCtx.context.adapter.update({
          model: "scimGroup",
          where: [{ field: "teamId", value: groupId }],
          update: { externalId: ctx.body.externalId ?? null, updatedAt: now },
        });
        await applyMembershipDiff(fullCtx, groupId, added, removed);

        await writeAudit(fullCtx, {
          orgId: organizationId,
          actorType: "scim",
          actorId: providerId,
          action: "scim.group_updated",
          targetType: "team",
          targetId: groupId,
        });
        await auditMembershipChanges(fullCtx, organizationId, providerId, groupId, added, removed);
        await recomputeAffected(fullCtx, opts, organizationId, providerId, [...added, ...removed]);

        const resource = await loadGroupResource(fullCtx, {
          teamId: groupId,
          orgId: organizationId,
          externalId: ctx.body.externalId ?? null,
          createdAt: row.createdAt,
          updatedAt: now,
        });
        return scimJson(200, resource);
      }),
  );
}

function buildPatchGroup(opts: EnterpriseOptions) {
  return createAuthEndpoint(
    "/scim/v2/Groups/:groupId",
    { method: "PATCH", body: patchGroupBodySchema },
    (ctx) =>
      runScim(async () => {
        const fullCtx = ctx as unknown as GenericEndpointContext;
        const { providerId, organizationId } = await authenticateScimBearer(fullCtx);
        const groupId = ctx.params.groupId;

        const row = await findScimGroupRow(fullCtx, organizationId, groupId);
        if (!row) throw new ScimHttpError(404, undefined, "Group not found");
        const team = await fullCtx.context.adapter.findOne<TeamRow>({
          model: "team",
          where: [{ field: "id", value: groupId }],
        });
        if (!team) throw new ScimHttpError(404, undefined, "Group not found");

        const previousMembers = await fullCtx.context.adapter.findMany<TeamMemberRow>({
          model: "teamMember",
          where: [{ field: "teamId", value: groupId }],
        });
        const previousMemberIds = previousMembers.map((m) => m.userId);

        const patched = applyGroupPatch(
          { displayName: team.name, members: previousMemberIds },
          ctx.body.Operations as PatchOp[],
        );

        const displayNameChanged = patched.displayName !== team.name;
        if (displayNameChanged) {
          await assertDisplayNameAvailable(fullCtx, organizationId, patched.displayName, groupId);
        }
        const nextMemberIds = [...new Set(patched.members)];
        const { added, removed } = diffMembers(previousMemberIds, nextMemberIds);
        if (added.length > 0) await assertMembersExist(fullCtx, organizationId, added);

        const now = new Date();
        if (displayNameChanged) {
          await fullCtx.context.adapter.update({
            model: "team",
            where: [{ field: "id", value: groupId }],
            update: { name: patched.displayName, updatedAt: now },
          });
        }
        await fullCtx.context.adapter.update({
          model: "scimGroup",
          where: [{ field: "teamId", value: groupId }],
          update: { updatedAt: now },
        });
        await applyMembershipDiff(fullCtx, groupId, added, removed);

        await writeAudit(fullCtx, {
          orgId: organizationId,
          actorType: "scim",
          actorId: providerId,
          action: "scim.group_updated",
          targetType: "team",
          targetId: groupId,
        });
        await auditMembershipChanges(fullCtx, organizationId, providerId, groupId, added, removed);
        await recomputeAffected(fullCtx, opts, organizationId, providerId, [...added, ...removed]);

        const resource = await loadGroupResource(fullCtx, {
          teamId: groupId,
          orgId: organizationId,
          externalId: row.externalId,
          createdAt: row.createdAt,
          updatedAt: now,
        });
        // Entra tolerates 200 or 204 for PATCH; this plugin always returns 200
        // + the resource (ruling (f)) — the more informative of the two, and
        // consistent with this plugin's PUT/POST responses.
        return scimJson(200, resource);
      }),
  );
}

function buildDeleteGroup(opts: EnterpriseOptions) {
  return createAuthEndpoint("/scim/v2/Groups/:groupId", { method: "DELETE" }, (ctx) =>
    runScim(async () => {
      const fullCtx = ctx as unknown as GenericEndpointContext;
      const { providerId, organizationId } = await authenticateScimBearer(fullCtx);
      const groupId = ctx.params.groupId;

      const row = await findScimGroupRow(fullCtx, organizationId, groupId);
      if (!row) throw new ScimHttpError(404, undefined, "Group not found");

      const members = await fullCtx.context.adapter.findMany<TeamMemberRow>({
        model: "teamMember",
        where: [{ field: "teamId", value: groupId }],
      });
      const memberIds = members.map((m) => m.userId);

      await fullCtx.context.adapter.deleteMany({
        model: "teamMember",
        where: [{ field: "teamId", value: groupId }],
      });
      await fullCtx.context.adapter.delete({
        model: "scimGroup",
        where: [{ field: "teamId", value: groupId }],
      });
      await fullCtx.context.adapter.delete({
        model: "team",
        where: [{ field: "id", value: groupId }],
      });

      await writeAudit(fullCtx, {
        orgId: organizationId,
        actorType: "scim",
        actorId: providerId,
        action: "scim.group_deleted",
        targetType: "team",
        targetId: groupId,
      });
      await recomputeAffected(fullCtx, opts, organizationId, providerId, memberIds);

      return scimJson(204, null);
    }),
  );
}

// --- plugin -------------------------------------------------------------

export function scimGroups(opts: EnterpriseOptions): BetterAuthPlugin {
  return {
    id: "enterprise-scim-groups",
    schema: {
      scimGroup: {
        modelName: "scim_group",
        fields: {
          teamId: { type: "string", required: true, fieldName: "team_id" },
          orgId: { type: "string", required: true, fieldName: "org_id" },
          externalId: { type: "string", required: false, fieldName: "external_id" },
          createdAt: { type: "date", required: true, fieldName: "created_at" },
          updatedAt: { type: "date", required: true, fieldName: "updated_at" },
        },
      },
    },
    endpoints: {
      scimListGroups: buildListGroups(),
      scimCreateGroup: buildCreateGroup(opts),
      scimGetGroup: buildGetGroup(),
      scimReplaceGroup: buildReplaceGroup(opts),
      scimPatchGroup: buildPatchGroup(opts),
      scimDeleteGroup: buildDeleteGroup(opts),
    },
  };
}
