// Hardening note routed to PR-6 (fix plan, round-4 follow-ups): the
// server-only sentinel `/` (the path a path-less `auth.api.*` call shows
// inside a hook) also matched a product HTTP endpoint declared at the
// literal path `/` — so a request carrying an API key in the header *and*
// in `body.key` passed as upstream's own `verifyApiKey` call, and the gate's
// header check skipped that route entirely. A server-only call has no
// `Request`; an HTTP request always does — that is now the test.

import { describe, expect, it } from "vitest";
import type { BetterAuthPlugin } from "better-auth";
import { createAuthEndpoint, sessionMiddleware } from "better-auth/api";
import * as z from "zod";
import { createOrg, makeAuth, signUpOwner, type TestAuth } from "../helpers/auth";
import { isApiKeyVerifyCall, isServerOnlyCall } from "../../src/server/api-keys";

const rootRoute = (): BetterAuthPlugin => ({
  id: "zz-root-route",
  endpoints: {
    root: createAuthEndpoint(
      "/",
      { method: "POST", use: [sessionMiddleware], body: z.object({ key: z.string().optional() }) },
      async (ctx) => ctx.json({ userId: ctx.context.session.user.id }),
    ),
  },
});

async function keyFor(t: TestAuth) {
  const owner = await signUpOwner(t);
  const { orgId } = await createOrg(t, owner.cookie);
  const res = await t.api.post(
    "/api-key/create",
    { name: "k", organizationId: orgId },
    {
      cookie: owner.cookie,
    },
  );
  expect(res.status).toBe(200);
  return { owner, key: ((await res.json()) as { key: string }).key };
}

async function code(res: Response) {
  return ((await res.clone().json()) as { code?: string }).code;
}

describe("the server-only `/` sentinel never matches an HTTP request", () => {
  it("opt-in mock session: a key in the header and body.key does not reach a product route declared at `/`", async () => {
    const t = await makeAuth({
      apiKeys: { enableSessionForAPIKeys: true },
      plugins: [rootRoute()],
    });
    const { key } = await keyFor(t);
    const res = await t.api.post("/", { key }, { "x-api-key": key });
    expect(res.status).toBe(403);
    expect(await code(res)).toBe("API_KEY_NOT_ALLOWED_HERE");
  });

  it("preset default: the gate's header check covers a `/` route too", async () => {
    const t = await makeAuth({ plugins: [rootRoute()] });
    const { owner, key } = await keyFor(t);
    const refused = await t.api.post("/", {}, { "x-api-key": key, cookie: owner.cookie });
    expect(refused.status).toBe(403);
    expect(await code(refused)).toBe("API_KEY_NOT_ALLOWED_HERE");
    // The route itself still works for a cookie session.
    const ok = await t.api.post("/", {}, { cookie: owner.cookie });
    expect(ok.status).toBe(200);
  });

  it("upstream's own server-side verifyApiKey call is still recognised (no Request)", async () => {
    const t = await makeAuth({ apiKeys: { enableSessionForAPIKeys: true } });
    const { key } = await keyFor(t);
    const api = t.auth.api as unknown as {
      verifyApiKey: (input: {
        body: { key: string };
        headers: Headers;
      }) => Promise<{ valid: boolean }>;
    };
    const verdict = await api.verifyApiKey({
      body: { key },
      headers: new Headers({ "x-api-key": key }),
    });
    expect(verdict.valid).toBe(true);
    expect(isServerOnlyCall({ path: "/" })).toBe(true);
    expect(isServerOnlyCall({ path: "/", request: new Request("http://x/") })).toBe(false);
    expect(isApiKeyVerifyCall({ path: "/", body: { key: "k" } }, "k")).toBe(true);
    expect(
      isApiKeyVerifyCall({ path: "/", body: { key: "k" }, request: new Request("http://x/") }, "k"),
    ).toBe(false);
  });
});
