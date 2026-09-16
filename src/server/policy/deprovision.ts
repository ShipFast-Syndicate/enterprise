// Alpha Bros enterprise layer — SCIM deprovision cascade (controller ruling (f)).
//
// A leaf module: depends only on `../audit/chain`'s `writeAudit`, not on
// `./plugin.ts`/`./store.ts`/`./enforcement.ts`.

import type { GenericEndpointContext } from "better-auth";
import { createAuthMiddleware, isAPIError } from "better-auth/api";
import { writeAudit } from "../audit/chain";

const DEPROVISION_PATH = "/scim/v2/Users/:userId";
const DEPROVISION_METHODS = new Set(["PATCH", "PUT", "DELETE"]);

interface ScimPatchOperation {
  op?: unknown;
  path?: unknown;
  value?: unknown;
}

/**
 * Mirrors `@better-auth/scim`'s own PATCH `active` handling
 * (`userPatchMappings["/active"]`/`active()` in
 * `node_modules/@better-auth/scim/dist/index.mjs`): a PatchOp whose
 * (dot-or-slash, leading-slash-optional) normalized `path` is `/active`,
 * `op` is `add` or `replace` (the only ops SCIM patch application honors —
 * `remove` is a no-op for a boolean field upstream), and `value` is `false`
 * or the string `"false"`.
 */
function isScimDeactivatePatch(body: unknown): boolean {
  const operations = (body as { Operations?: ScimPatchOperation[] } | undefined)?.Operations;
  if (!Array.isArray(operations)) return false;
  return operations.some((operation) => {
    const op = typeof operation.op === "string" ? operation.op.toLowerCase() : "replace";
    if (op !== "replace" && op !== "add") return false;
    if (typeof operation.path !== "string") return false;
    const normalized =
      `/${operation.path.startsWith("/") ? operation.path.slice(1) : operation.path}`.replaceAll(
        ".",
        "/",
      );
    return normalized === "/active" && (operation.value === false || operation.value === "false");
  });
}

export function buildDeprovisionAfterHook() {
  return {
    matcher: (ctx: { path?: string; request?: { method?: string } }) =>
      ctx.path === DEPROVISION_PATH &&
      !!ctx.request?.method &&
      DEPROVISION_METHODS.has(ctx.request.method),
    handler: createAuthMiddleware(async (ctx) => {
      if (isAPIError(ctx.context.returned)) return; // only cascade on a successful SCIM call

      const method = ctx.request?.method;
      const userId = (ctx.params as { userId?: string } | undefined)?.userId;
      if (!userId) return;

      const deactivated =
        method === "DELETE"
          ? true
          : method === "PUT"
            ? (ctx.body as { active?: unknown } | undefined)?.active === false
            : isScimDeactivatePatch(ctx.body);
      if (!deactivated) return;

      const fullCtx = ctx as unknown as GenericEndpointContext;
      // `@better-auth/api-key`'s `apikey` model's owner field is literally
      // named `referenceId` (`node_modules/@better-auth/api-key/dist/
      // index.mjs`'s `apiKeySchema` — "The ID of the entity that owns this
      // key (userId or organizationId based on config's `references`
      // setting)"), not `userId` as the task brief's shorthand says; no
      // `fieldName` override remaps it, so `referenceId` is also the
      // physical column name. This preset never configures `references:
      // "organization"`, so it always holds a user id.
      await fullCtx.context.adapter.deleteMany({
        model: "apikey",
        where: [{ field: "referenceId", value: userId }],
      });

      // A DELETE on this path already gets a `scim.user_deleted` audit row
      // from `../audit/plugin.ts`'s generic `hooks.after`
      // (`METHOD_ACTION_OVERRIDES`) — that's the same action this hook would
      // otherwise write, so DELETE only runs the cascade above and skips a
      // second, redundant row. PATCH/PUT deactivation has no equivalent: the
      // generic hook writes `scim.user_updated` for *any* PATCH/PUT on this
      // path (deactivating or not), which doesn't capture deactivation
      // specifically, so `scim.user_deactivated` here is additional
      // information, not a duplicate.
      if (method === "DELETE") return;

      const scimProvider = (
        fullCtx.context as unknown as {
          scimProvider?: { providerId?: string; organizationId?: string };
        }
      ).scimProvider;
      if (!scimProvider?.organizationId) return;

      await writeAudit(fullCtx, {
        orgId: scimProvider.organizationId,
        actorType: "scim",
        actorId: scimProvider.providerId ?? null,
        action: "scim.user_deactivated",
        targetType: "user",
        targetId: userId,
      });
    }),
  };
}
