// Alpha Bros enterprise layer — bounds on request-derived audit values.
//
// Audit rows are hash-chained and cannot be removed without breaking the
// chain, and several of them (failed/refused sign-ins, magic-link and
// password-reset requests) are written for callers who hold no session.
// Every value such a row takes from the request therefore goes through one
// of these helpers first: an address is recorded only when it is a
// syntactically valid e-mail address, a code or identifier only when it is
// a short token (else `AUDIT_UNRECORDED`), a role list only as a capped list
// of short tokens with the total count, a user agent only up to a fixed
// length, and a list of changed keys only up to a fixed count. Anything else
// is dropped, truncated or replaced by the marker — never stored verbatim.
//
// `auditRowBounds` is the backstop `writeAudit` applies to every row, whoever
// writes it: a target id, actor id or IP that is not a short value and a
// metadata value too large to be a bounded one are replaced by the marker,
// and a user agent is cut, so a request value a writer forgot to bound still
// cannot grow a chain.

import * as z from "zod";

/** RFC 5321's path limit; longer strings are never addresses. */
export const AUDIT_EMAIL_MAX_LENGTH = 254;
/** Longest user agent an audit row keeps (the rest is cut). */
export const AUDIT_USER_AGENT_MAX_LENGTH = 512;
/** Longest error code / identifier an audit row keeps verbatim. */
export const AUDIT_TOKEN_MAX_LENGTH = 128;
/** Most changed keys `metadata.changed` lists; the total is in `metadata.changedCount`. */
export const AUDIT_CHANGED_KEYS_MAX = 64;
/** Longest key name `metadata.changed` lists. */
export const AUDIT_KEY_MAX_LENGTH = 64;
/** Most role names `metadata.role` lists; the total is in `metadata.roleCount`. */
export const AUDIT_ROLES_MAX = 16;
/** Longest role name `metadata.role` lists. */
export const AUDIT_ROLE_MAX_LENGTH = 64;
/** Longest serialized metadata value a row keeps (larger ones become `AUDIT_UNRECORDED`). */
export const AUDIT_METADATA_VALUE_MAX_LENGTH = 10_000;
/** Longest serialized metadata object a row keeps (the largest values become `AUDIT_UNRECORDED` until it fits). */
export const AUDIT_METADATA_MAX_LENGTH = 16_384;
/** Latest instant a JavaScript `Date` can hold (ms since the epoch); `from`/`to` filters are bounded to `[0, AUDIT_TIME_MAX]`. */
export const AUDIT_TIME_MAX = 8.64e15;
/**
 * What a request-derived value that cannot be recorded as it is (too long,
 * not a short token) is recorded as. Its parentheses are outside the token
 * alphabet, so it never equals a recorded identifier.
 */
export const AUDIT_UNRECORDED = "(unrecorded)";

const emailSchema = z.email();

/**
 * `value` lower-cased when it is a valid e-mail address of at most
 * `AUDIT_EMAIL_MAX_LENGTH` characters (the same `z.email()` check
 * better-auth's own endpoints apply), else `null`. A `null` here means the
 * request names no subject: no organization is resolved from it and no
 * row records it.
 */
export function auditEmail(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const email = value.trim().toLowerCase();
  if (email.length === 0 || email.length > AUDIT_EMAIL_MAX_LENGTH) return null;
  return emailSchema.safeParse(email).success ? email : null;
}

const TOKEN = /^[A-Za-z0-9_.:-]+$/;

/** An error code / identifier as recorded: the value when it is a short token, else `null`. */
export function auditToken(value: unknown): string | null {
  if (typeof value !== "string") return null;
  return value.length > 0 && value.length <= AUDIT_TOKEN_MAX_LENGTH && TOKEN.test(value)
    ? value
    : null;
}

/**
 * An identifier taken from the request (a provider, member, team,
 * invitation, key or user id) as recorded: the value when it is a short
 * token, `null` when the request carried none, else `AUDIT_UNRECORDED`.
 */
export function auditId(value: unknown): string | null {
  if (value === undefined || value === null || value === "") return null;
  return auditToken(value) ?? AUDIT_UNRECORDED;
}

/** An error code as recorded: the code when it is a short token, else `"UNRECOGNIZED_ERROR"`. */
export function auditCode(value: unknown): string {
  return auditToken(value) ?? "UNRECOGNIZED_ERROR";
}

/** A user agent as recorded: at most `AUDIT_USER_AGENT_MAX_LENGTH` characters. */
export function auditUserAgent(value: string | null | undefined): string | null {
  if (typeof value !== "string" || value.length === 0) return null;
  return value.length > AUDIT_USER_AGENT_MAX_LENGTH
    ? value.slice(0, AUDIT_USER_AGENT_MAX_LENGTH)
    : value;
}

const KEY = /^[A-Za-z0-9_$-]+$/;

/**
 * `metadata.changed` for a list of changed key paths: the first
 * `AUDIT_CHANGED_KEYS_MAX` well-formed names (sorted); when anything was
 * left out — more keys than that, or a name that is not a short identifier —
 * `changedCount` carries how many keys the request changed in total.
 */
export function auditChangedKeys(paths: readonly string[]): {
  changed: string[];
  changedCount?: number;
} {
  const wellFormed = paths.filter(
    (path) =>
      path.length <= AUDIT_KEY_MAX_LENGTH * 2 + 1 &&
      path
        .split(".")
        .every((segment) => segment.length <= AUDIT_KEY_MAX_LENGTH && KEY.test(segment)),
  );
  const changed = [...new Set(wellFormed)].sort().slice(0, AUDIT_CHANGED_KEYS_MAX);
  return changed.length === paths.length ? { changed } : { changed, changedCount: paths.length };
}

const ROLE = /^[A-Za-z0-9_.:-]+$/;

/**
 * `metadata.role` for a role value from the request — a string (upstream
 * splits it on `,`) or a list of strings: the first `AUDIT_ROLES_MAX`
 * distinct well-formed names, joined with `,` the way upstream stores a
 * member's role; `roleCount` carries how many names the request gave
 * whenever anything was left out. No value → `{ role: null }`; a value
 * with no recordable name → `AUDIT_UNRECORDED`.
 */
export function auditRoles(value: unknown): { role: string | null; roleCount?: number } {
  if (value === undefined || value === null) return { role: null };
  const names: unknown[] =
    typeof value === "string" ? value.split(",") : Array.isArray(value) ? value : [value];
  const wellFormed = names
    .map((name) => (typeof name === "string" ? name.trim() : ""))
    .filter((name) => name.length > 0 && name.length <= AUDIT_ROLE_MAX_LENGTH && ROLE.test(name));
  const kept = [...new Set(wellFormed)].slice(0, AUDIT_ROLES_MAX);
  const complete = kept.length === names.length;
  if (kept.length === 0) return { role: AUDIT_UNRECORDED, roleCount: names.length };
  return complete ? { role: kept.join(",") } : { role: kept.join(","), roleCount: names.length };
}

function hasControlCharacter(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) return true;
  }
  return false;
}

function serializedLength(value: unknown): number {
  try {
    return (JSON.stringify(value) ?? "").length;
  } catch {
    return Number.POSITIVE_INFINITY; // cyclic / unserializable: never stored
  }
}

/** A string column value as recorded: itself when short and free of control characters, else the marker. */
function boundedColumn(value: string | null | undefined): string | null | undefined {
  return typeof value === "string" &&
    (value.length > AUDIT_TOKEN_MAX_LENGTH || hasControlCharacter(value))
    ? AUDIT_UNRECORDED
    : value;
}

/**
 * The backstop every row goes through: `writeAudit` (`./chain.ts`) applies it
 * to whatever a writer passes, so no writer — the plugin, the refusal path,
 * SCIM, API keys, the enterprise endpoints, the export row — can store an
 * unbounded value. A `targetId`, `actorId` or `ip` that is not a short value
 * becomes `AUDIT_UNRECORDED`; a user agent is cut to
 * `AUDIT_USER_AGENT_MAX_LENGTH`; a metadata value whose JSON exceeds
 * `AUDIT_METADATA_VALUE_MAX_LENGTH` becomes `AUDIT_UNRECORDED`, and while the
 * whole metadata still exceeds `AUDIT_METADATA_MAX_LENGTH` the largest
 * remaining value does too. The per-path bounds above keep every value well
 * inside these limits; this only decides what happens to a value a writer
 * did not bound.
 */
export function auditRowBounds<
  T extends {
    targetId?: string | null;
    actorId?: string | null;
    ip?: string | null;
    userAgent?: string | null;
    metadata?: Record<string, unknown>;
  },
>(row: T): T {
  const metadata: Record<string, unknown> = {};
  const sizes = new Map<string, number>();
  for (const [key, value] of Object.entries(row.metadata ?? {})) {
    if (value === undefined) continue;
    const size = serializedLength(value);
    metadata[key] = size > AUDIT_METADATA_VALUE_MAX_LENGTH ? AUDIT_UNRECORDED : value;
    sizes.set(key, size > AUDIT_METADATA_VALUE_MAX_LENGTH ? AUDIT_UNRECORDED.length : size);
  }
  const bySize = [...sizes.entries()].sort((a, b) => b[1] - a[1]);
  while (serializedLength(metadata) > AUDIT_METADATA_MAX_LENGTH && bySize.length > 0) {
    const [key] = bySize.shift()!;
    metadata[key] = AUDIT_UNRECORDED;
  }
  const bounded = {
    ...row,
    targetId: boundedColumn(row.targetId),
    metadata,
  };
  if (row.actorId !== undefined) bounded.actorId = boundedColumn(row.actorId);
  if (row.ip !== undefined) bounded.ip = boundedColumn(row.ip);
  if (row.userAgent !== undefined) bounded.userAgent = auditUserAgent(row.userAgent);
  return bounded;
}
