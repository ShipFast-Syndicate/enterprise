import { describe, expect, it, vi } from "vitest";
import type { GenericEndpointContext } from "better-auth";
import { requireFeature } from "../../src/server/entitlements";
import type { Feature } from "../../src/server/types";
import { makeAuth, type TestAuth } from "../helpers/auth";

// Per the task-2 ruling: `requireFeature` must only rely on `ctx.context`
// and a per-request cache stored on the ctx object itself, so a minimal
// fake endpoint context — not a real dispatched request — is enough to
// exercise it directly.
async function fakeCtx(t: TestAuth): Promise<GenericEndpointContext> {
  return {
    context: await t.auth.$context,
    path: "/test",
    request: new Request("http://localhost:3000/api/auth/test"),
  } as unknown as GenericEndpointContext;
}

describe("requireFeature", () => {
  it("throws 403 FEATURE_NOT_ENTITLED when the org lacks the feature", async () => {
    const t = await makeAuth({ resolveEntitlements: async () => ["teams"] });

    await expect(requireFeature(await fakeCtx(t), "org_1", "sso")).rejects.toMatchObject({
      status: "FORBIDDEN",
      body: { code: "FEATURE_NOT_ENTITLED", feature: "sso" },
    });
  });

  it("caches resolveEntitlements per request context", async () => {
    const resolveEntitlements = vi.fn(async (): Promise<Feature[]> => ["sso", "teams"]);
    const t = await makeAuth({ resolveEntitlements });
    const ctx = await fakeCtx(t);

    await requireFeature(ctx, "org_1", "sso");
    await requireFeature(ctx, "org_1", "teams");

    expect(resolveEntitlements).toHaveBeenCalledTimes(1);
  });

  it("resolves entitlements again for a different ctx (no cross-request leakage)", async () => {
    const resolveEntitlements = vi.fn(async (): Promise<Feature[]> => ["sso"]);
    const t = await makeAuth({ resolveEntitlements });

    await requireFeature(await fakeCtx(t), "org_1", "sso");
    await requireFeature(await fakeCtx(t), "org_1", "sso");

    expect(resolveEntitlements).toHaveBeenCalledTimes(2);
  });

  it("resolves entitlements again for a different org on the same ctx", async () => {
    const resolveEntitlements = vi.fn(async (): Promise<Feature[]> => ["sso"]);
    const t = await makeAuth({ resolveEntitlements });
    const ctx = await fakeCtx(t);

    await requireFeature(ctx, "org_1", "sso");
    await requireFeature(ctx, "org_2", "sso");

    expect(resolveEntitlements).toHaveBeenCalledTimes(2);
  });

  it("does not throw when the org is entitled to the feature", async () => {
    const t = await makeAuth({ resolveEntitlements: async () => ["sso"] });

    await expect(requireFeature(await fakeCtx(t), "org_1", "sso")).resolves.toBeUndefined();
  });
});
