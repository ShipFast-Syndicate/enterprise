// Alpha Bros enterprise layer — admin portal fetch client (Task 10).
//
// `PortalApi` is the one thing every `AbElement` (`./base.ts`) talks to the
// server through: `GET`/`POST` against `<basePath>/enterprise/*` (and, for
// the upstream organization endpoints `<ab-members>` drives, plain
// `<basePath>/organization/*`), always `credentials: "include"` — the
// portal is embedded in the product's own admin UI, on the product's own
// origin, and relies on the session cookie `better-auth`'s own client
// already carries there — never an `Authorization` header of its own.
//
// Deliberately not built on `better-auth/client`'s own `createAuthClient`:
// this package's `./client` entry types `authClient.enterprise.*` for a
// product that already has a better-auth client instance in scope, but the
// portal components need to work for *any* embedder regardless of which
// client library (if any) renders the surrounding page — a plain `fetch`
// wrapper, mirroring `../client/home-realm.ts`'s own `EnterpriseClientError`/
// `throwOnError` shape (see that file's header comment) for the same reason:
// one non-2xx-response contract shared across this package's client-facing
// surfaces.

/** `{ status, code?, message }` shape for a non-2xx `/enterprise/*` response. */
export interface PortalErrorShape {
  status: number;
  code?: string;
  message: string;
}

/** Thrown by every `PortalApi` method on a non-2xx HTTP response. */
export class PortalError extends Error implements PortalErrorShape {
  readonly status: number;
  readonly code?: string;

  constructor(input: PortalErrorShape) {
    super(input.message);
    this.name = "PortalError";
    this.status = input.status;
    this.code = input.code;
  }
}

/**
 * Best-effort JSON body of a failed response, for `PortalError`'s
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
  throw new PortalError({
    status: res.status,
    code,
    message: message ?? `Request failed with status ${res.status}`,
  });
}

function buildQuery(query?: Record<string, string | undefined>): string {
  if (!query) return "";
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value !== undefined) params.set(key, value);
  }
  const qs = params.toString();
  return qs ? `?${qs}` : "";
}

/** Thin `fetch` wrapper every `AbElement` (`./base.ts`) constructs one of, scoped to a `basePath`. */
export class PortalApi {
  constructor(private readonly basePath: string) {}

  /** `GET <basePath><path>?<query>` — `query` values are URL-encoded via `URLSearchParams`. */
  async get<T>(path: string, query?: Record<string, string | undefined>): Promise<T> {
    const res = await fetch(`${this.basePath}${path}${buildQuery(query)}`, {
      method: "GET",
      credentials: "include",
    });
    await throwOnError(res);
    return (await res.json()) as T;
  }

  /** `POST <basePath><path>` with a JSON body. */
  async post<T>(path: string, body?: unknown): Promise<T> {
    const res = await fetch(`${this.basePath}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      credentials: "include",
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    await throwOnError(res);
    return (await res.json()) as T;
  }
}
