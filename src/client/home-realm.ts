// Alpha Bros enterprise layer — home-realm discovery client helpers.
//
// `discoverHomeRealm`/`startSsoLogin`/`homeRealmLogin` are plain fetch-based
// helpers, not better-auth client actions wired through `getActions` — a
// sign-in page needs to call home-realm discovery *before* an `authClient`
// even exists (there's no session, and often no org context yet), and the
// task-9 brief's controller ruling (e) requires this module to make no DOM
// assumptions so it also runs in SvelteKit/Next server code (a Node
// `fetch`/`Request`/`Response`, no `window`/`document`). Both defaults
// (`basePath = "/api/auth"`, and the injectable `fetch`) mirror how
// `better-auth/client`'s own `createAuthClient` defaults `basePath`
// (`node_modules/better-auth/dist/client/vanilla.mjs`).

/** `{ status, code?, message }` shape for a non-2xx `/enterprise/*` response. */
export interface EnterpriseClientErrorShape {
  status: number;
  code?: string;
  message: string;
}

/** Thrown by every helper in this module on a non-2xx HTTP response. */
export class EnterpriseClientError extends Error implements EnterpriseClientErrorShape {
  readonly status: number;
  readonly code?: string;

  constructor(input: EnterpriseClientErrorShape) {
    super(input.message);
    this.name = "EnterpriseClientError";
    this.status = input.status;
    this.code = input.code;
  }
}

export interface HomeRealmOptions {
  /** @default "/api/auth" — better-auth's own default mount path. */
  basePath?: string;
  /** @default globalThis.fetch */
  fetch?: typeof fetch;
}

export type HomeRealmResult = { method: "sso"; providerId: string } | { method: "local" };

/**
 * Best-effort JSON body of a failed response, for `EnterpriseClientError`'s
 * `code`/`message` — a non-JSON error body (e.g. a platform 502 HTML page)
 * must not itself throw and mask the original HTTP failure.
 */
async function readErrorBody(res: Response): Promise<{ code?: string; message?: string }> {
  try {
    const body: unknown = await res.json();
    if (body && typeof body === "object") {
      const { code, message } = body as { code?: unknown; message?: unknown };
      return {
        code: typeof code === "string" ? code : undefined,
        message: typeof message === "string" ? message : undefined,
      };
    }
  } catch {
    // fall through to the generic message below
  }
  return {};
}

async function throwOnError(res: Response): Promise<void> {
  if (res.ok) return;
  const { code, message } = await readErrorBody(res);
  throw new EnterpriseClientError({
    status: res.status,
    code,
    message: message ?? `Request failed with status ${res.status}`,
  });
}

/**
 * `POST <basePath>/enterprise/home-realm { email }` — home-realm discovery
 * for a sign-in page: does this email's domain belong to an org with a
 * verified SSO provider? Public/unauthenticated on the server side (see
 * `../server/policy/home-realm.ts`'s header comment), so this helper sends
 * no session-identifying header of its own beyond the request's own cookies
 * (`credentials: "include"`) — and, per ruling (b), no explicit `origin`
 * header: browsers set `Origin` themselves on cross-origin fetches, and a
 * caller-supplied one would either be dropped or rejected outright by a
 * real browser `fetch` (a "forbidden header name").
 */
export async function discoverHomeRealm(
  email: string,
  opts?: HomeRealmOptions,
): Promise<HomeRealmResult> {
  const basePath = opts?.basePath ?? "/api/auth";
  const doFetch = opts?.fetch ?? globalThis.fetch;
  const res = await doFetch(`${basePath}/enterprise/home-realm`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    credentials: "include",
    body: JSON.stringify({ email }),
  });
  await throwOnError(res);
  return (await res.json()) as HomeRealmResult;
}

export interface StartSsoLoginOptions {
  /** @default "/api/auth" */
  basePath?: string;
  /** @default "/" */
  callbackURL?: string;
  /** @default globalThis.fetch */
  fetch?: typeof fetch;
}

/**
 * `POST <basePath>/sign-in/sso { providerId, callbackURL }` — the upstream
 * `@better-auth/sso` sign-in endpoint (`node_modules/@better-auth/sso/dist/
 * index.mjs`'s `signInSSO`), called directly rather than through
 * `ssoClient()`'s inferred action so a sign-in page can kick off the
 * redirect immediately after `discoverHomeRealm` resolves `method: "sso"`,
 * without needing a full `authClient` instance in scope.
 */
export async function startSsoLogin(
  providerId: string,
  opts?: StartSsoLoginOptions,
): Promise<{ url: string }> {
  const basePath = opts?.basePath ?? "/api/auth";
  const doFetch = opts?.fetch ?? globalThis.fetch;
  const callbackURL = opts?.callbackURL ?? "/";
  const res = await doFetch(`${basePath}/sign-in/sso`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    credentials: "include",
    body: JSON.stringify({ providerId, callbackURL }),
  });
  await throwOnError(res);
  return (await res.json()) as { url: string };
}

export type HomeRealmLoginResult = { method: "sso"; url: string } | { method: "local" };

/**
 * Convenience wrapper: `discoverHomeRealm`, then — only when it resolves
 * `method: "sso"` — `startSsoLogin` for that provider. A sign-in page can
 * call this alone and either redirect to `.url` or fall back to rendering
 * its normal local sign-in form on `{ method: "local" }`.
 */
export async function homeRealmLogin(
  email: string,
  opts?: HomeRealmOptions & StartSsoLoginOptions,
): Promise<HomeRealmLoginResult> {
  const discovered = await discoverHomeRealm(email, opts);
  if (discovered.method === "local") return { method: "local" };
  const { url } = await startSsoLogin(discovered.providerId, opts);
  return { method: "sso", url };
}
