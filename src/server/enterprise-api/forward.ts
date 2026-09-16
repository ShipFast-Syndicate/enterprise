// Alpha Bros enterprise layer — internal request forwarding for the
// enterpriseApi plugin's write-wrapper endpoints (SSO register, SSO test
// sign-in, SCIM token create/revoke).
//
// Why not a real network `fetch(ctx.context.baseURL + path)`: in this
// package's own test harness (`test/helpers/auth.ts`) nothing ever binds a
// listener to `baseURL` — tests drive every call through
// `auth.handler(request)` directly, in-process — so a literal network
// `fetch()` would ECONNREFUSED there. It would also be needless latency in
// production, where the upstream endpoint runs in the very same process
// anyway. `router` — the exact function `betterAuth()`'s own `handler`
// builds itself from on *every* call (`node_modules/better-auth/dist/auth/
// base.mjs`: `const { handler } = router(handlerCtx, options); return
// runWithAdapter(handlerCtx.adapter, () => handler(request));`) — is a
// public export of `better-auth/api` (verified against the pinned
// better-auth@1.6.33: `node_modules/better-auth/dist/api/index.mjs`'s
// export list includes `router`). Calling it here with `ctx.context` — the
// *same*, already-fully-resolved `AuthContext` for the current request, with
// the same `baseURL`/`trustedOrigins`/`adapter` `base.mjs`'s own `handlerCtx`
// would have — plus a freshly-built `Request`, reproduces the *exact*
// dispatch a real HTTP call to that path would get: same `hooks.before`/
// `hooks.after` chain (so the wrapped upstream path's own `AUDITED_PATHS`
// entry in `../audit/plugin.ts` fires for real — see that file's header
// comment for why this plugin's own `/enterprise/*` paths are deliberately
// *not* also added there, to avoid a double audit row), same validation,
// same side effects — with no real socket involved.
//
// Confirmed empirically (a throwaway smoke test against `/sso/register`,
// since deleted): forwarding this way creates the real `ssoProvider` row,
// resolves the actor from the caller's own session automatically, and
// writes exactly one audit row, not two. `dispatchAuthEndpoint`
// (`node_modules/better-auth/dist/api/dispatch.mjs`) shallow-copies
// `input.context` into a *new* object for every dispatch (`{...input.context,
// returned: void 0, responseHeaders: void 0, session: input.context.session
// ?? null}`) rather than mutating it, so the forwarded sub-request's own
// `ctx.context.returned` never leaks back into — or gets clobbered by — the
// outer request's `ctx.context` our own endpoint keeps using afterward.
//
// Headers are still forwarded explicitly (cookie, origin, content-type)
// rather than relying solely on the shared-context session: `origin` is
// required for `originCheckMiddleware` (wired into every `router()` call via
// `routerMiddleware`), and carrying the real cookie keeps the forwarded call
// correct even if a future refactor stops sharing `ctx.context` directly.

import { router } from "better-auth/api";
import type { GenericEndpointContext } from "better-auth";
import type { Status } from "better-call";

type ForwardingRouter = ReturnType<typeof router>;

// Cached per `ctx.context.options` — the one piece of `AuthContext` that's
// the exact same object reference across *every* request this auth instance
// ever handles, as long as `baseURL` is a plain string (every consumer of
// this package, and every test in this repo): `node_modules/better-auth/
// dist/auth/base.mjs`'s `handler` only ever replaces `ctx.options` with a
// new object when `baseURL` is a *dynamic* config. Building `router(...)`
// re-derives the entire merged endpoint table (every plugin's endpoints,
// each wrapped by `toAuthEndpoints`) and `better-call`'s route matcher from
// scratch — real, repeated work otherwise done on every forwarded call.
const routerCache = new WeakMap<object, ForwardingRouter>();

/**
 * Builds (once per auth instance) and reuses a `router()` for forwarding —
 * *never* keyed to, or built from, the current request's own `ctx.context`
 * object directly. That distinction is a correctness requirement, not just
 * style: by the time our endpoint runs, `sessionMiddleware` has already
 * written *this* caller's resolved session onto `ctx.context.session`, and
 * `getSessionFromCtx` (`node_modules/better-auth/dist/api/routes/
 * session.mjs`) short-circuits on it — `if (ctx.context.session) return
 * ctx.context.session;` — for *any* dispatch seeded from that object.
 * Caching a router bound to one request's `ctx.context` and reusing it for
 * a *different* real request later would silently leak the first caller's
 * session into the second caller's forwarded call. The snapshot below
 * strips `session`/`returned`/`responseHeaders` before the router is ever
 * cached, so every forwarded call instead re-derives its session fresh from
 * the `cookie` header `forwardToAuth` already carries on every call
 * regardless of caching — which is what we want either way.
 */
function getForwardingRouter(ctx: GenericEndpointContext): ForwardingRouter {
  const options = ctx.context.options;
  const cached = routerCache.get(options);
  if (cached) return cached;
  const snapshot = {
    ...ctx.context,
    session: null,
    returned: undefined,
    responseHeaders: undefined,
  } as GenericEndpointContext["context"];
  const built = router(snapshot, options);
  routerCache.set(options, built);
  return built;
}

/** Forwards `method path` through the same auth instance's own dispatch pipeline, carrying the caller's headers (cookie, origin). */
export async function forwardToAuth(
  ctx: GenericEndpointContext,
  method: "GET" | "POST",
  path: string,
  body?: unknown,
): Promise<Response> {
  const { handler } = getForwardingRouter(ctx);
  const headers = new Headers(ctx.headers ?? undefined);
  if (body !== undefined) headers.set("content-type", "application/json");
  const request = new Request(`${ctx.context.baseURL}${path}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  return handler(request);
}

/** `forwardToAuth`, parsed as JSON alongside the upstream status code. */
export async function forwardJson(
  ctx: GenericEndpointContext,
  method: "GET" | "POST",
  path: string,
  body?: unknown,
): Promise<{ status: number; data: Record<string, unknown> | null }> {
  const res = await forwardToAuth(ctx, method, path, body);
  const data = (await res.json().catch(() => null)) as Record<string, unknown> | null;
  return { status: res.status, data };
}

/**
 * Relays an upstream HTTP status code onto our own endpoint's response.
 * `better-call`'s `ctx.setStatus` only accepts its closed `Status` union of
 * specific literal codes, while `Response.status` (what `forwardJson`
 * returns) is a plain `number` — every status upstream can legally send us
 * is a member of that union, so the cast is safe.
 */
export function relayStatus(ctx: { setStatus: (status: Status) => void }, status: number): void {
  ctx.setStatus(status as Status);
}
