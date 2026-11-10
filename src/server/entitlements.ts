// Alpha Bros enterprise layer — entitlement resolution.
//
// `requireFeature` is the single choke point every gated endpoint (the
// enterprise-gate hook in `./gate.ts`, and — in later tasks — endpoints that
// need a finer-grained check than the path-level gate) calls to enforce
// plan entitlements. It reads `EnterpriseOptions` off `ctx.context` (via the
// `enterprise-gate` plugin's own `options`, the same convention better-auth's
// built-in plugins use — see e.g. `jwt`) rather than closing over a
// particular plugin instance, so it works from any endpoint context that
// belongs to an auth instance with `enterpriseGate()` registered.

import type { GenericEndpointContext } from "better-auth";
import { APIError } from "better-auth/api";
import {
  enterpriseOptionsOfContext,
  readEntitlementRow,
  usesEntitlementTable,
} from "./entitlement-store";
import type { EnterpriseOptions, Feature } from "./types";

export class FeatureNotEntitledError extends APIError {
  constructor(feature: Feature, orgId: string) {
    super("FORBIDDEN", {
      code: "FEATURE_NOT_ENTITLED",
      message: `Organization "${orgId}" is not entitled to the "${feature}" feature.`,
      feature,
      orgId,
    });
  }
}

function getEnterpriseOptions(ctx: GenericEndpointContext): EnterpriseOptions {
  return enterpriseOptionsOfContext(ctx.context);
}

// Per-request cache: ctx -> orgId -> the org's entitled features. Keyed by
// the ctx object itself (not ctx.context, which is shared/long-lived across
// requests) so entries are scoped to a single request and freed once it
// completes, and so two calls for the same org on the same request share one
// `resolveEntitlements` call.
const entitlementsCache = new WeakMap<object, Map<string, Set<Feature>>>();

async function getEntitledFeatures(
  ctx: GenericEndpointContext,
  opts: EnterpriseOptions,
  orgId: string,
): Promise<Set<Feature>> {
  let byOrg = entitlementsCache.get(ctx);
  if (!byOrg) {
    byOrg = new Map();
    entitlementsCache.set(ctx, byOrg);
  }
  let entitled = byOrg.get(orgId);
  if (!entitled) {
    entitled = new Set(await resolveFeatures(ctx, opts, orgId));
    byOrg.set(orgId, entitled);
  }
  return entitled;
}

// Where an organization's features come from. The product's callback decides
// when it is given; otherwise the staff-managed table (`entitlements: { store:
// "table" }`) — never `organization.metadata`, which an org owner can write.
// With neither there is nothing to resolve from, and nothing is granted.
async function resolveFeatures(
  ctx: GenericEndpointContext,
  opts: EnterpriseOptions,
  orgId: string,
): Promise<Iterable<Feature>> {
  if (opts.resolveEntitlements) return opts.resolveEntitlements(orgId);
  if (usesEntitlementTable(opts)) return readEntitlementRow(ctx.context.adapter, orgId);
  return [];
}

/**
 * The features `orgId` is entitled to, through the same per-request cache
 * `requireFeature` uses — so a gate check and the `/enterprise/features` read
 * of one request resolve once. `opts` defaults to the deployment's own.
 */
export async function resolveEntitledFeatures(
  ctx: GenericEndpointContext,
  orgId: string,
  opts: EnterpriseOptions = getEnterpriseOptions(ctx),
): Promise<Feature[]> {
  return [...(await getEntitledFeatures(ctx, opts, orgId))];
}

export async function requireFeature(
  ctx: GenericEndpointContext,
  orgId: string,
  feature: Feature,
): Promise<void> {
  const opts = getEnterpriseOptions(ctx);
  const entitled = await getEntitledFeatures(ctx, opts, orgId);
  if (!entitled.has(feature)) {
    throw new FeatureNotEntitledError(feature, orgId);
  }
}
