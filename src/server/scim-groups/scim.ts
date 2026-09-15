// Alpha Bros enterprise layer — SCIM 2.0 Groups pure helpers.
//
// No `ctx`/adapter access anywhere in this file — everything here is a pure
// function over plain data, mirroring the split `../audit/chain.ts` (pure
// hashing) vs. `../audit/plugin.ts` (DB/endpoint wiring) already established
// in this package. `./plugin.ts` is the wiring layer built on top of this
// file plus `./auth.ts` (bearer authentication).
//
// `ScimHttpError` is the one non-obvious piece: SCIM error responses need a
// `{status, scimType, detail}` triple (`scimError` below builds the actual
// `Response`), but `parseFilter`/`applyGroupPatch` are pure functions that
// can only signal failure by throwing — so they throw this carrier, and
// `./plugin.ts`'s endpoints (and `./auth.ts`'s `authenticateScimBearer`)
// catch it once, in one place, and turn it into a `scimError(...)` response.

export interface ScimGroupResource {
  schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"];
  id: string;
  externalId?: string;
  displayName: string;
  members: { value: string; display?: string; $ref?: string }[];
  meta: { resourceType: "Group"; created: string; lastModified: string; location: string };
}

/** Carries a SCIM error's `{status, scimType, detail}` through a `throw` — see header comment. */
export class ScimHttpError extends Error {
  constructor(
    public readonly status: number,
    public readonly scimType: string | undefined,
    detail: string,
  ) {
    super(detail);
  }
}

/**
 * SCIM-compliant error body (RFC 7644 §3.12), as a `Response` with
 * `content-type: application/scim+json` — per controller ruling (b), every
 * response this plugin returns (success or error) carries that content
 * type; returning a raw `Response` (rather than `ctx.json(...)`, which
 * better-call's `toResponse` unconditionally stamps back to
 * `application/json` — verified against `node_modules/better-call/dist/
 * to-response.mjs`'s `isJSONResponse` branch) is the only way to make that
 * stick, the same technique `../audit/plugin.ts`'s CSV export endpoint
 * already uses for its own non-`application/json` content type.
 */
export function scimError(status: number, scimType: string | undefined, detail: string): Response {
  const body = {
    schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
    status: String(status),
    detail,
    ...(scimType ? { scimType } : {}),
  };
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/scim+json" },
  });
}

/** A successful SCIM JSON response — same content-type rationale as `scimError` above. */
export function scimJson(
  status: number,
  body: unknown,
  headers?: Record<string, string>,
): Response {
  return new Response(body === null ? null : JSON.stringify(body), {
    status,
    headers: { "content-type": "application/scim+json", ...headers },
  });
}

// --- filter parsing (controller ruling (g)) --------------------------------

const FILTER_ATTRS = new Set(["displayName", "externalId", "id"]);

// Mirrors `@better-auth/scim`'s own `SCIMFilterRegex`
// (`node_modules/@better-auth/scim/dist/index.mjs`) shape — attribute, a
// SCIM comparison operator, and a quoted-or-bare value — but this plugin
// only ever supports `eq` on the 3 named attributes (ruling (g)); every
// other operator (`co`, `ne`, `sw`, ...) or attribute is rejected, not
// silently ignored.
const FILTER_REGEX =
  /^\s*(?<attr>[^\s]+)\s+(?<op>eq|ne|co|sw|ew|pr|gt|ge|lt|le)\s*(?<value>"(?:[^"\\]|\\.)*"|[^\s]+)?\s*$/i;

function unquote(raw: string): string {
  if (raw.startsWith('"') && raw.endsWith('"')) {
    return raw.slice(1, -1).replace(/\\(.)/g, "$1");
  }
  return raw;
}

/**
 * Parses a SCIM `filter` query param into `{attr, op: "eq", value}`, or
 * `null` when no filter was given at all (list-everything). Only
 * `displayName eq "x"` / `externalId eq "y"` / `id eq "z"` (case-sensitive
 * attribute names, case-insensitive `eq`) are supported; any other
 * attribute, any other operator (e.g. `co`), or a filter that doesn't parse
 * at all throws `ScimHttpError(400, "invalidFilter", ...)`.
 */
export function parseFilter(
  filter: string | undefined,
): { attr: "displayName" | "externalId" | "id"; op: "eq"; value: string } | null {
  if (filter === undefined) return null;

  const match = filter.match(FILTER_REGEX);
  const attr = match?.groups?.attr;
  const op = match?.groups?.op?.toLowerCase();
  const rawValue = match?.groups?.value;
  if (!match || !attr || !op || rawValue === undefined) {
    throw new ScimHttpError(400, "invalidFilter", `Invalid SCIM filter expression: ${filter}`);
  }
  if (op !== "eq") {
    throw new ScimHttpError(400, "invalidFilter", `Unsupported SCIM filter operator: ${op}`);
  }
  if (!FILTER_ATTRS.has(attr)) {
    throw new ScimHttpError(400, "invalidFilter", `Unsupported SCIM filter attribute: ${attr}`);
  }

  return { attr: attr as "displayName" | "externalId" | "id", op: "eq", value: unquote(rawValue) };
}

// --- PATCH application (controller ruling (f)) ------------------------------

export type PatchOp = { op: "add" | "remove" | "replace"; path?: string; value?: unknown };

const MEMBERS_FILTER_PATH = /^members\[\s*value\s+eq\s+"((?:[^"\\]|\\.)*)"\s*\]$/i;

function extractMemberIds(value: unknown): string[] {
  if (value === undefined || value === null) return [];
  const entries = Array.isArray(value) ? value : [value];
  const ids: string[] = [];
  for (const entry of entries) {
    if (typeof entry === "string") {
      ids.push(entry);
    } else if (
      entry &&
      typeof entry === "object" &&
      typeof (entry as { value?: unknown }).value === "string"
    ) {
      ids.push((entry as { value: string }).value);
    }
  }
  return ids;
}

/** Dedupes, keeping the first occurrence's position — "duplicates ignored" (ruling (f)). */
function dedupe(ids: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const id of ids) {
    if (!seen.has(id)) {
      seen.add(id);
      out.push(id);
    }
  }
  return out;
}

/**
 * Applies a SCIM PATCH `Operations` array to a group's `{displayName,
 * members}`. Supported `path`s (ruling (f)): `"displayName"`, `"members"`
 * (replace/add the whole set, or `remove` to clear it), and
 * `members[value eq "<id>"]` (add/remove one member by id). `op` is
 * expected already-lowercased (`./plugin.ts`'s zod body schema does this at
 * the request boundary, the same trick `@better-auth/scim`'s own
 * `patchSCIMUserBodySchema` uses for Entra's `"Add"`/`"Replace"`) but is
 * defensively re-lowered here too, so this function is correct standalone.
 * An unrecognized `path` throws `ScimHttpError(400, "invalidPath", ...)`.
 */
export function applyGroupPatch(
  current: { displayName: string; members: string[] },
  ops: PatchOp[],
): { displayName: string; members: string[] } {
  let displayName = current.displayName;
  let members = [...current.members];

  for (const rawOp of ops) {
    const op = String(rawOp.op).toLowerCase();
    const path = rawOp.path;

    if (path === "displayName") {
      if (op === "remove") continue; // displayName is required/single-valued — nothing to clear
      if (typeof rawOp.value !== "string" || rawOp.value.length === 0) {
        throw new ScimHttpError(
          400,
          "invalidValue",
          "displayName patch value must be a non-empty string",
        );
      }
      displayName = rawOp.value;
      continue;
    }

    if (path === "members") {
      if (op === "remove") {
        members = [];
        continue;
      }
      const ids = extractMemberIds(rawOp.value);
      members = op === "replace" ? dedupe(ids) : dedupe([...members, ...ids]);
      continue;
    }

    const filterMatch = path?.match(MEMBERS_FILTER_PATH);
    if (filterMatch) {
      const targetId = filterMatch[1]!.replace(/\\(.)/g, "$1");
      members =
        op === "remove" ? members.filter((id) => id !== targetId) : dedupe([...members, targetId]);
      continue;
    }

    throw new ScimHttpError(400, "invalidPath", `Unsupported SCIM patch path: ${path ?? "(none)"}`);
  }

  return { displayName, members };
}

// --- role mapping (controller ruling (d)) -----------------------------------

const ROLE_RANK: Record<"owner" | "admin" | "member", number> = { owner: 3, admin: 2, member: 1 };

/**
 * The highest-ranked role (`owner` > `admin` > `member`) any of `groupNames`
 * maps to in `map`; `"member"` if none of them are mapped (ruling (d)).
 */
export function effectiveRole(
  groupNames: string[],
  map: Record<string, "owner" | "admin" | "member">,
): "owner" | "admin" | "member" {
  let best: "owner" | "admin" | "member" = "member";
  for (const name of groupNames) {
    const role = map[name];
    if (role && ROLE_RANK[role] > ROLE_RANK[best]) best = role;
  }
  return best;
}

// --- resource shaping (controller ruling (c)) -------------------------------

/**
 * Builds the `Group` resource shape (ruling (c)): `id` = `team.id`,
 * `displayName` = `team.name`, `members[].value` = `user.id`,
 * `members[].display` = user email, `meta.location` = the absolute URL
 * `./plugin.ts` computed from `ctx.context.baseURL`.
 */
export function buildGroupResource(params: {
  id: string;
  externalId?: string | null;
  displayName: string;
  members: { value: string; display?: string }[];
  createdAt: Date;
  updatedAt: Date;
  location: string;
}): ScimGroupResource {
  return {
    schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"],
    id: params.id,
    ...(params.externalId ? { externalId: params.externalId } : {}),
    displayName: params.displayName,
    members: params.members,
    meta: {
      resourceType: "Group",
      created: params.createdAt.toISOString(),
      lastModified: params.updatedAt.toISOString(),
      location: params.location,
    },
  };
}

/** `${baseURL}/scim/v2/Groups/<id>` (ruling (c)) — a plain template, not a `URL`-joined path. */
export function locationFor(baseURL: string, groupId: string): string {
  return `${baseURL.replace(/\/+$/, "")}/scim/v2/Groups/${groupId}`;
}
