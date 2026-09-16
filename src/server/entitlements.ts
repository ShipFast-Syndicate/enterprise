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
import type { EnterpriseOptions, Feature } from "./types";

const ENTERPRISE_GATE_PLUGIN_ID = "enterprise-gate";

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
  const plugin = ctx.context.options.plugins?.find((p) => p.id === ENTERPRISE_GATE_PLUGIN_ID) as
    { options?: EnterpriseOptions } | undefined;
  if (!plugin?.options) {
    throw new Error(
      "requireFeature() requires the enterpriseGate() plugin to be registered on this auth instance.",
    );
  }
  return plugin.options;
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
    entitled = new Set(await opts.resolveEntitlements(orgId));
    byOrg.set(orgId, entitled);
  }
  return entitled;
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
