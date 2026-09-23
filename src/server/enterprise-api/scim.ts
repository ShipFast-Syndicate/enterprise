// Tenant-authorized HTTP wrappers around the server-only 1.7 credential catalog.
import { APIError, createAuthEndpoint, getEndpoints, sessionMiddleware } from "better-auth/api";
import { runWithTransaction } from "@better-auth/core/context";
import type { GenericEndpointContext } from "better-auth";
import type { SCIMPlugin } from "@better-auth/scim";
import * as z from "zod";
import { requireFeature } from "../entitlements";
import { requireOwner, requireOwnerOrAdmin } from "../policy/store";
import { scimConnectionLabel as label } from "../scim-connection";
import { writeAudit } from "../audit/chain";

const orgIdSchema = z.string().min(1).max(100);
const body = z.object({ orgId: orgIdSchema, providerId: z.string().trim().min(1).max(64) });
const scopes = [
  "scim.users.read",
  "scim.users.write",
  "scim.groups.read",
  "scim.groups.write",
] as const;
function api(ctx: GenericEndpointContext) {
  return getEndpoints(ctx.context, ctx.context.options).api as unknown as SCIMPlugin["endpoints"];
}
async function authorize(ctx: GenericEndpointContext, orgId: string, owner = false) {
  if (owner) await requireOwner(ctx, orgId);
  else await requireOwnerOrAdmin(ctx, orgId);
  await requireFeature(ctx, orgId, "scim");
}
async function connections(ctx: GenericEndpointContext, orgId: string) {
  return (await api(ctx).listSCIMManagedConnections({ body: { provisioningDomainId: orgId } }))
    .connections;
}
async function findConnection(ctx: GenericEndpointContext, orgId: string, providerId: string) {
  const connection = (await connections(ctx, orgId)).find(
    (c) => c.status !== "decommissioned" && label(c) === providerId,
  );
  if (!connection) throw new APIError("NOT_FOUND", { message: "SCIM connection not found" });
  return connection;
}
function mintEndpoint(rotate: boolean) {
  return createAuthEndpoint(
    rotate ? "/enterprise/scim/tokens/rotate" : "/enterprise/scim/tokens/create",
    {
      method: "POST",
      use: [sessionMiddleware],
      body,
    },
    async (ctx) => {
      const full = ctx as unknown as GenericEndpointContext;
      const { orgId, providerId } = ctx.body;
      await authorize(full, orgId, true);
      // Credential changes and the audit row commit together. Failure cannot leave
      // an active credential whose one-time token was never delivered.
      const created = await runWithTransaction(ctx.context.adapter, async () => {
        const service = api(full);
        const policy = {
          provisioningDomainId: orgId,
          actorId: ctx.context.session.user.id,
          scopes,
          expiresAt: new Date(Date.now() + 365 * 86400_000),
        };
        let result;
        if (rotate) {
          const connection = await findConnection(full, orgId, providerId);
          const state = await service.getSCIMManagedConnection({
            body: { connectionId: connection.connectionId, provisioningDomainId: orgId },
          });
          for (const credential of state.credentials.filter((c) => c.status === "active")) {
            await service.revokeSCIMManagedCredential({
              body: {
                connectionId: connection.connectionId,
                provisioningDomainId: orgId,
                credentialId: credential.credentialId,
                actorId: policy.actorId,
              },
            });
          }
          result = await service.rotateSCIMManagedCredential({
            body: { ...policy, connectionId: connection.connectionId },
          });
        } else {
          if (
            (await connections(full, orgId)).some(
              (c) => c.status !== "decommissioned" && label(c) === providerId,
            )
          ) {
            throw new APIError("CONFLICT", {
              message: "This provider already has a connection. Rotate its token instead.",
            });
          }
          result = await service.createSCIMManagedConnection({
            body: {
              ...policy,
              creationRequestId: JSON.stringify([
                "enterprise",
                orgId,
                providerId,
                crypto.randomUUID(),
              ]),
            },
          });
        }
        await writeAudit(full, {
          orgId,
          actorType: "user",
          actorId: policy.actorId,
          action: rotate ? "scim.token_rotated" : "scim.token_created",
          targetType: "scim_connection",
          targetId: result.connection.connectionId,
        });
        return result;
      });
      ctx.setHeader("Cache-Control", "no-store");
      return ctx.json({
        scimToken: created.token,
        baseUrl: `${ctx.context.baseURL}/scim/v2`,
        expiresAt: created.credential.expiresAt.toISOString(),
      });
    },
  );
}
export function buildScimEndpoints() {
  return {
    enterpriseScimTokens: createAuthEndpoint(
      "/enterprise/scim/tokens",
      {
        method: "GET",
        use: [sessionMiddleware],
        query: z.object({ orgId: orgIdSchema }),
      },
      async (ctx) => {
        const full = ctx as unknown as GenericEndpointContext;
        await authorize(full, ctx.query.orgId);
        return ctx.json({
          tokens: (await connections(full, ctx.query.orgId))
            .filter((c) => c.status !== "decommissioned")
            .map((c) => ({
              providerId: label(c),
              connectionId: c.connectionId,
              createdAt: c.createdAt.toISOString(),
              lastUsedAt: null,
              status: c.status,
            })),
        });
      },
    ),
    enterpriseScimTokensCreate: mintEndpoint(false),
    enterpriseScimTokensRotate: mintEndpoint(true),
    enterpriseScimTokensRevoke: createAuthEndpoint(
      "/enterprise/scim/tokens/revoke",
      {
        method: "POST",
        use: [sessionMiddleware],
        body,
      },
      async (ctx) => {
        const full = ctx as unknown as GenericEndpointContext;
        const { orgId, providerId } = ctx.body;
        await authorize(full, orgId);
        const connection = await findConnection(full, orgId, providerId);
        const result = await api(full).decommissionSCIMManagedConnection({
          body: {
            connectionId: connection.connectionId,
            provisioningDomainId: orgId,
            actorId: ctx.context.session.user.id,
          },
        });
        // Native catalog events preserve the authoritative credential audit even
        // when this application audit write fails. Decommission can be retried.
        if (connection.status === "active")
          await writeAudit(full, {
            orgId,
            actorType: "user",
            actorId: ctx.context.session.user.id,
            action: "scim.token_revoked",
            targetType: "scim_connection",
            targetId: connection.connectionId,
          });
        if (result.decommission.status !== "complete") ctx.setStatus(202);
        return ctx.json({
          ok: result.decommission.status === "complete",
          status: result.decommission.status,
          retryAfter: result.decommission.retryAfter,
        });
      },
    ),
  };
}
