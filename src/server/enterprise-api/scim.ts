// Alpha Bros enterprise layer — enterpriseApi plugin: SCIM token endpoints.
//
// Portal-facing wrappers around `@better-auth/scim`'s token lifecycle,
// scoped to a single org: `GET .../tokens` (list — `providerId` only;
// `createdAt`/`lastUsedAt` are always `null` in v0.1, since `scimProvider`
// has neither column — verified against `node_modules/@better-auth/scim/
// dist/index.mjs`'s `schema.scimProvider.fields`, which declares only
// `providerId`/`scimToken`/`organizationId`/`userId`), `POST .../create`
// (forwards to upstream `/scim/generate-token` — the token is shown once,
// exactly as upstream returns it, never persisted by this layer), and
// `POST .../revoke` (forwards to upstream `/scim/delete-provider-
// connection`).
//
// `organizationId` is required explicitly in the forwarded body for both
// writes: `../gate.ts`'s `ORG_ID_REQUIRED_IN_BODY` demands it for these two
// upstream paths (GHSA-j8v8-g9cx-5qf4 — see that file's header comment), and
// won't fall back to the session's active org the way most gated paths do.

import { createAuthEndpoint, sessionMiddleware } from "better-auth/api";
import type { GenericEndpointContext } from "better-auth";
import * as z from "zod";
import { requireFeature } from "../entitlements";
import { requireOwner, requireOwnerOrAdmin } from "../policy/store";
import { forwardJson, relayStatus } from "./forward";

interface ScimProviderRow {
  providerId: string;
}

const tokensQuerySchema = z.object({ orgId: z.string() });

function buildTokensListEndpoint() {
  return createAuthEndpoint(
    "/enterprise/scim/tokens",
    { method: "GET", use: [sessionMiddleware], query: tokensQuerySchema },
    async (ctx) => {
      const fullCtx = ctx as unknown as GenericEndpointContext;
      const { orgId } = ctx.query;
      // Owner/admin, not any member (M-08); role before entitlement (M-07).
      // Admins may list (and revoke) tokens; only an owner may create one
      // (M-01, below).
      await requireOwnerOrAdmin(fullCtx, orgId);
      await requireFeature(fullCtx, orgId, "scim");

      const rows = await ctx.context.adapter.findMany<ScimProviderRow>({
        model: "scimProvider",
        where: [{ field: "organizationId", value: orgId }],
      });
      return ctx.json({
        tokens: rows.map((row) => ({
          providerId: row.providerId,
          createdAt: null as string | null,
          lastUsedAt: null as string | null,
        })),
      });
    },
  );
}

const tokensCreateBodySchema = z.object({ orgId: z.string(), providerId: z.string() });

function buildTokensCreateEndpoint() {
  return createAuthEndpoint(
    "/enterprise/scim/tokens/create",
    { method: "POST", use: [sessionMiddleware], body: tokensCreateBodySchema },
    async (ctx) => {
      const fullCtx = ctx as unknown as GenericEndpointContext;
      const { orgId, providerId } = ctx.body;
      // Owner only (M-01): a SCIM token is the second half of the
      // admin→owner escalation (write `groupRoleMap`, mint a token, add
      // yourself to the mapped group). `../gate.ts` enforces the same rule
      // on the upstream `/scim/generate-token` path this forwards to, so the
      // escalation is closed whether an attacker calls the wrapper or
      // upstream directly. Admins keep list/revoke.
      await requireOwner(fullCtx, orgId);
      await requireFeature(fullCtx, orgId, "scim");

      const { status, data } = await forwardJson(fullCtx, "POST", "/scim/generate-token", {
        providerId,
        organizationId: orgId,
      });
      if (status < 200 || status >= 300 || !data) {
        relayStatus(ctx, status);
        return ctx.json(data);
      }
      return ctx.json({ scimToken: data.scimToken, baseUrl: `${ctx.context.baseURL}/scim/v2` });
    },
  );
}

const tokensRevokeBodySchema = z.object({ orgId: z.string(), providerId: z.string() });

function buildTokensRevokeEndpoint() {
  return createAuthEndpoint(
    "/enterprise/scim/tokens/revoke",
    { method: "POST", use: [sessionMiddleware], body: tokensRevokeBodySchema },
    async (ctx) => {
      const fullCtx = ctx as unknown as GenericEndpointContext;
      const { orgId, providerId } = ctx.body;
      await requireOwnerOrAdmin(fullCtx, orgId);
      await requireFeature(fullCtx, orgId, "scim");

      const { status, data } = await forwardJson(
        fullCtx,
        "POST",
        "/scim/delete-provider-connection",
        {
          providerId,
          organizationId: orgId,
        },
      );
      if (status < 200 || status >= 300) {
        relayStatus(ctx, status);
        return ctx.json(data);
      }
      return ctx.json({ ok: true });
    },
  );
}

// No `EnterpriseOptions` parameter — see `./sso.ts`'s `buildSsoEndpoints`.
export function buildScimEndpoints() {
  return {
    enterpriseScimTokens: buildTokensListEndpoint(),
    enterpriseScimTokensCreate: buildTokensCreateEndpoint(),
    enterpriseScimTokensRevoke: buildTokensRevokeEndpoint(),
  };
}
