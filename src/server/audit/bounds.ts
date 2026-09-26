// Alpha Bros enterprise layer — bounds on request-derived audit values.
//
// Audit rows are hash-chained and cannot be removed without breaking the
// chain, and several of them (failed/refused sign-ins, magic-link and
// password-reset requests) are written for callers who hold no session.
// Every value such a row takes from the request therefore goes through one
// of these helpers first: an address is recorded only when it is a
// syntactically valid e-mail address, a code or identifier only when it is
// a short token, a user agent only up to a fixed length, and a list of
// changed keys only up to a fixed count. Anything else is dropped (or, for
// the user agent, truncated) — never stored verbatim.

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
