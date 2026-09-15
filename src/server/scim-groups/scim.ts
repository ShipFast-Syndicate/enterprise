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

const FILTER_OPS = new Set(["eq", "ne", "co", "sw", "ew", "pr", "gt", "ge", "lt", "le"]);

/**
 * Hard ceiling on a `filter` query parameter (M-04). Every filter this
 * plugin supports is `<attr> eq "<value>"`, so 512 characters is far more
 * than any real IdP sends, and it bounds the parser's work by construction.
 */
export const MAX_FILTER_LENGTH = 512;

const WHITESPACE = new Set([" ", "\t", "\n", "\r", "\f", "\v"]);

/**
 * Hand-written, single-pass tokenizer replacing the previous
 * `FILTER_REGEX` (M-04). That regex had two ambiguous `\s*` groups around an
 * optional capture, which made it catastrophically backtracking on trailing
 * whitespace: `displayName eq <64 000 spaces>x y` blocked the event loop for
 * **7.6 s** on a single request (8 k → 125 ms, 32 k → 2.3 s — quadratic).
 *
 * This scanner is strictly linear: it walks the string once, never re-reads
 * a character, and allocates only the three substrings it returns. A bare
 * value ends at the first whitespace; a quoted value consumes `\`-escapes
 * and must be terminated. Anything left over after the value (the `y` in the
 * example above) is a parse error, exactly as before.
 */
function tokenizeFilter(filter: string): { attr: string; op: string; value?: string } | null {
  let i = 0;
  const len = filter.length;
  const skipSpace = (): void => {
    while (i < len && WHITESPACE.has(filter[i]!)) i++;
  };
  const readBare = (): string => {
    const start = i;
    while (i < len && !WHITESPACE.has(filter[i]!)) i++;
    return filter.slice(start, i);
  };

  skipSpace();
  const attr = readBare();
  if (!attr) return null;

  skipSpace();
  const op = readBare();
  if (!op) return null;

  skipSpace();
  let value: string | undefined;
  if (i < len) {
    if (filter[i] === '"') {
      i++;
      let out = "";
      let closed = false;
      while (i < len) {
        const ch = filter[i]!;
        i++;
        if (ch === "\\") {
          if (i >= len) return null; // dangling escape
          out += filter[i]!;
          i++;
          continue;
        }
        if (ch === '"') {
          closed = true;
          break;
        }
        out += ch;
      }
      if (!closed) return null;
      value = out;
    } else {
      value = readBare();
    }
  }

  skipSpace();
  if (i !== len) return null; // trailing junk after the value
  return { attr, op, value };
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
  if (filter.length > MAX_FILTER_LENGTH) {
    throw new ScimHttpError(
      400,
      "invalidFilter",
      `SCIM filter expression exceeds ${MAX_FILTER_LENGTH} characters.`,
    );
  }

  const parsed = tokenizeFilter(filter);
  const attr = parsed?.attr;
  const op = parsed?.op.toLowerCase();
  const rawValue = parsed?.value;
  if (!parsed || !attr || !op || rawValue === undefined || !FILTER_OPS.has(op)) {
    throw new ScimHttpError(400, "invalidFilter", `Invalid SCIM filter expression: ${filter}`);
  }
  if (op !== "eq") {
    throw new ScimHttpError(400, "invalidFilter", `Unsupported SCIM filter operator: ${op}`);
  }
  if (!FILTER_ATTRS.has(attr)) {
    throw new ScimHttpError(400, "invalidFilter", `Unsupported SCIM filter attribute: ${attr}`);
  }

  return { attr: attr as "displayName" | "externalId" | "id", op: "eq", value: rawValue };
}

// --- PATCH application (controller ruling (f)) ------------------------------

export type PatchOp = { op: "add" | "remove" | "replace"; path?: string; value?: unknown };

/**
 * Hard ceiling on a PATCH `path` (M-04, same rationale as
 * `MAX_FILTER_LENGTH`): the only paths this plugin supports are
 * `displayName`, `members` and `members[value eq "<id>"]`.
 */
export const MAX_PATCH_PATH_LENGTH = 512;

/**
 * `members[value eq "<id>"]` → `<id>`, or `null` if `path` isn't that shape
 * (M-04). Hand-written for the same reason `tokenizeFilter` is: the previous
 * regex nested a quantified alternation inside another quantifier, which is
 * the shape that backtracks. This walks the string once.
 */
export function parseMembersFilterPath(path: string | undefined): string | null {
  if (!path || path.length > MAX_PATCH_PATH_LENGTH) return null;
  const lower = path.toLowerCase();
  if (!lower.startsWith("members[") || !path.endsWith("]")) return null;

  let i = "members[".length;
  const end = path.length - 1;
  const skipSpace = (): void => {
    while (i < end && WHITESPACE.has(path[i]!)) i++;
  };
  const expectWord = (word: string): boolean => {
    if (lower.startsWith(word, i)) {
      i += word.length;
      return true;
    }
    return false;
  };

  skipSpace();
  if (!expectWord("value")) return null;
  if (i >= end || !WHITESPACE.has(path[i]!)) return null;
  skipSpace();
  if (!expectWord("eq")) return null;
  if (i >= end || !WHITESPACE.has(path[i]!)) return null;
  skipSpace();
  if (path[i] !== '"') return null;
  i++;

  let value = "";
  let closed = false;
  while (i < end) {
    const ch = path[i]!;
    i++;
    if (ch === "\\") {
      if (i >= end) return null;
      value += path[i]!;
      i++;
      continue;
    }
    if (ch === '"') {
      closed = true;
      break;
    }
    value += ch;
  }
  if (!closed) return null;
  skipSpace();
  return i === end ? value : null;
}

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

    const targetId = parseMembersFilterPath(path);
    if (targetId !== null) {
      members =
        op === "remove" ? members.filter((id) => id !== targetId) : dedupe([...members, targetId]);
      continue;
    }

    throw new ScimHttpError(400, "invalidPath", `Unsupported SCIM patch path: ${path ?? "(none)"}`);
  }

  return { displayName, members };
}

// --- role mapping (controller ruling (d)) -----------------------------------

export type MappedRole = "owner" | "admin" | "member";

export const ROLE_RANK: Record<MappedRole, number> = { owner: 3, admin: 2, member: 1 };

/** Whether `role` is one of the three roles this package's role model knows about. */
export function isMappedRole(role: string): role is MappedRole {
  return role === "owner" || role === "admin" || role === "member";
}

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
