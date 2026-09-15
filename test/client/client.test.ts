// Alpha Bros enterprise layer — `/client` entry (Task 9).
//
// These are pure unit tests against a mocked `fetch`: no real better-auth
// server is spun up (unlike test/server/**), matching the task-9 brief's
// note that this project needs no DOM and belongs in vitest's "server"
// (node-env) project. Each test asserts the *actual request shape* sent
// (URL, method, headers, credentials, body) rather than just the resolved
// value, per the task-9 self-review checklist ("tests verify real request
// shapes").

import { createAuthClient } from "better-auth/client";
import { describe, expect, expectTypeOf, it, vi } from "vitest";
import {
  discoverHomeRealm,
  EnterpriseClientError,
  enterpriseClient,
  homeRealmLogin,
  startSsoLogin,
} from "../../src/client";

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

/**
 * A `vi.fn` typed as `typeof fetch`, queued to resolve each call in order.
 * A call beyond the queued responses is a test bug (a helper under test
 * fetching more/fewer times than expected) — it fails loudly (a rejected
 * promise naming the unexpected request) rather than silently replaying
 * `responses[0]`, which would let such a bug pass unnoticed.
 */
function mockFetch(...responses: Response[]) {
  const fn = vi.fn<typeof fetch>(async (input, init) => {
    throw new Error(
      `mockFetch: unexpected call beyond the ${responses.length} queued response(s): ` +
        `${init?.method ?? "GET"} ${String(input)}`,
    );
  });
  for (const response of responses) fn.mockResolvedValueOnce(response);
  return fn;
}

describe("enterpriseClient", () => {
  it('has id "enterprise"', () => {
    expect(enterpriseClient().id).toBe("enterprise");
  });

  it("forces GET for every /enterprise/* read endpoint", () => {
    expect(enterpriseClient().pathMethods).toEqual({
      "/enterprise/features": "GET",
      "/enterprise/sso/providers": "GET",
      "/enterprise/scim/tokens": "GET",
      "/enterprise/members": "GET",
      "/enterprise/policy": "GET",
      "/enterprise/audit/list": "GET",
      "/enterprise/audit/export": "GET",
      "/enterprise/audit/verify": "GET",
      "/enterprise/sso/test-login/finish": "GET",
    });
  });

  // Type-level (fix round 1, controller ruling): `$InferServerPlugin`'s
  // three-plugin intersection is only useful if it actually makes
  // `authClient.enterprise.*` typed — this is `expectTypeOf`, not
  // `expect`: `pnpm typecheck` is what actually enforces it (a regression
  // here is a compile error, not a runtime assertion failure); vitest also
  // evaluates the file at runtime, where `expectTypeOf(...)` is a no-op, so
  // `createAuthClient` really does get constructed once as a smoke check
  // that wiring `enterpriseClient()` into `plugins: [...]` doesn't throw.
  it("types authClient.enterprise.* from PathToObject via $InferServerPlugin", () => {
    const client = createAuthClient({ plugins: [enterpriseClient()] });

    // "/enterprise/features" -> { enterprise: { features: Fn } }
    expectTypeOf(client.enterprise.features).toBeFunction();
    // "/enterprise/policy/set" -> { enterprise: { policy: { set: Fn } } }
    expectTypeOf(client.enterprise.policy.set).toBeFunction();

    expectTypeOf(client.enterprise.features).returns.not.toBeAny();
    expectTypeOf(client.enterprise.policy.set).returns.not.toBeAny();
  });
});

describe("discoverHomeRealm", () => {
  it("POSTs { email } as JSON to <basePath>/enterprise/home-realm with credentials included", async () => {
    const fetchMock = mockFetch(jsonResponse(200, { method: "local" }));

    await discoverHomeRealm("user@acme.test", { basePath: "/api/auth", fetch: fetchMock });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(String(url)).toBe("/api/auth/enterprise/home-realm");
    expect(init?.method).toBe("POST");
    expect(init?.credentials).toBe("include");
    expect(JSON.parse(init?.body as string)).toEqual({ email: "user@acme.test" });

    const headers = new Headers(init?.headers);
    expect(headers.get("content-type")).toBe("application/json");
    // Ruling (b): no custom `origin` header — browsers set it themselves,
    // and setting one explicitly would be rejected/overridden by a real
    // fetch implementation.
    expect(headers.has("origin")).toBe(false);
  });

  it("defaults basePath to /api/auth", async () => {
    const fetchMock = mockFetch(jsonResponse(200, { method: "local" }));

    await discoverHomeRealm("user@acme.test", { fetch: fetchMock });

    const [url] = fetchMock.mock.calls[0]!;
    expect(String(url)).toBe("/api/auth/enterprise/home-realm");
  });

  it('returns { method: "local" } verbatim', async () => {
    const fetchMock = mockFetch(jsonResponse(200, { method: "local" }));

    const result = await discoverHomeRealm("user@acme.test", { fetch: fetchMock });

    expect(result).toEqual({ method: "local" });
  });

  it('returns { method: "sso", providerId } verbatim', async () => {
    const fetchMock = mockFetch(jsonResponse(200, { method: "sso", providerId: "okta-acme" }));

    const result = await discoverHomeRealm("user@acme.test", { fetch: fetchMock });

    expect(result).toEqual({ method: "sso", providerId: "okta-acme" });
  });

  it("throws EnterpriseClientError with status/code/message on a non-2xx response", async () => {
    const fetchMock = mockFetch(
      jsonResponse(429, { code: "RATE_LIMITED", message: "Too many requests." }),
    );

    const err = await discoverHomeRealm("user@acme.test", { fetch: fetchMock }).catch((e) => e);

    expect(err).toBeInstanceOf(EnterpriseClientError);
    expect(err).toMatchObject({
      status: 429,
      code: "RATE_LIMITED",
      message: "Too many requests.",
    });
  });

  it("throws EnterpriseClientError even when the error body isn't JSON", async () => {
    const fetchMock = mockFetch(new Response("Internal Server Error", { status: 500 }));

    const err = await discoverHomeRealm("user@acme.test", { fetch: fetchMock }).catch((e) => e);

    expect(err).toBeInstanceOf(EnterpriseClientError);
    expect((err as EnterpriseClientError).status).toBe(500);
    expect((err as EnterpriseClientError).code).toBeUndefined();
  });
});

describe("startSsoLogin", () => {
  it("POSTs { providerId, callbackURL } to <basePath>/sign-in/sso and returns { url }", async () => {
    const fetchMock = mockFetch(jsonResponse(200, { url: "https://idp.test/authorize?state=abc" }));

    const result = await startSsoLogin("okta-acme", {
      basePath: "/api/auth",
      callbackURL: "/dashboard",
      fetch: fetchMock,
    });

    expect(result).toEqual({ url: "https://idp.test/authorize?state=abc" });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(String(url)).toBe("/api/auth/sign-in/sso");
    expect(init?.method).toBe("POST");
    expect(init?.credentials).toBe("include");
    expect(JSON.parse(init?.body as string)).toEqual({
      providerId: "okta-acme",
      callbackURL: "/dashboard",
    });
  });

  it('defaults callbackURL to "/"', async () => {
    const fetchMock = mockFetch(jsonResponse(200, { url: "https://idp.test/authorize" }));

    await startSsoLogin("okta-acme", { fetch: fetchMock });

    const [, init] = fetchMock.mock.calls[0]!;
    expect(JSON.parse(init?.body as string)).toEqual({
      providerId: "okta-acme",
      callbackURL: "/",
    });
  });

  it("throws EnterpriseClientError on a non-2xx response", async () => {
    const fetchMock = mockFetch(
      jsonResponse(404, { code: "PROVIDER_NOT_FOUND", message: "No such provider." }),
    );

    const err = await startSsoLogin("missing", { fetch: fetchMock }).catch((e) => e);

    expect(err).toBeInstanceOf(EnterpriseClientError);
    expect(err).toMatchObject({ status: 404, code: "PROVIDER_NOT_FOUND" });
  });
});

describe("homeRealmLogin", () => {
  it('discovers local and returns { method: "local" } without starting SSO', async () => {
    const fetchMock = mockFetch(jsonResponse(200, { method: "local" }));

    const result = await homeRealmLogin("user@acme.test", { fetch: fetchMock });

    expect(result).toEqual({ method: "local" });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('discovers sso and follows up with startSsoLogin, returning { method: "sso", url }', async () => {
    const fetchMock = mockFetch(
      jsonResponse(200, { method: "sso", providerId: "okta-acme" }),
      jsonResponse(200, { url: "https://idp.test/authorize" }),
    );

    const result = await homeRealmLogin("user@acme.test", { fetch: fetchMock });

    expect(result).toEqual({ method: "sso", url: "https://idp.test/authorize" });
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const [homeRealmUrl] = fetchMock.mock.calls[0]!;
    const [ssoUrl, ssoInit] = fetchMock.mock.calls[1]!;
    expect(String(homeRealmUrl)).toBe("/api/auth/enterprise/home-realm");
    expect(String(ssoUrl)).toBe("/api/auth/sign-in/sso");
    expect(JSON.parse(ssoInit?.body as string)).toMatchObject({ providerId: "okta-acme" });
  });
});
