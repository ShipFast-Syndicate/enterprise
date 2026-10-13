// Alpha Bros enterprise layer — organization ids taken from a request.
//
// An organization id that comes from a request (a body field, a query
// parameter) is used as a query value: the gate's membership lookup, the
// entitlement resolver, every enterprise endpoint's reads. Only a non-empty
// string of at most `ORG_ID_MAX_LENGTH` characters is ever used as one.
// Anything else — an array (a duplicated query parameter parses to one), an
// object, a number, a boolean, `null`, an oversized string — is refused with
// `400 ORG_ID_INVALID` before any query runs. A non-string used to reach the database driver, which refused to bind
// it: the request answered 500 and the failed query, with its parameters, was
// written to the error log.
//
// Every place that reads an org id from a request goes through this module:
// the gate (`./gate.ts`), each enterprise endpoint's zod schema
// (`orgIdSchema`), and the hooks that read an org id before validation runs.

import { APIError } from "better-auth/api";
import * as z from "zod";

/** Longest organization id accepted from a request. */
export const ORG_ID_MAX_LENGTH = 128;

/**
 * Whether `value` can be used as an organization id taken from a request: a
 * non-empty string of at most `ORG_ID_MAX_LENGTH` characters. Its characters
 * are not restricted — a product that generates its own ids decides their
 * alphabet, and every place that puts one in a header or a file name
 * escapes it there.
 */
export function isOrgId(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= ORG_ID_MAX_LENGTH;
}

/** The zod schema every enterprise endpoint declares for its `orgId` / `organizationId`. */
export const orgIdSchema = z.string().min(1).max(ORG_ID_MAX_LENGTH);

export function orgIdInvalidError(): APIError {
  return new APIError("BAD_REQUEST", {
    code: "ORG_ID_INVALID",
    message: `An organization id must be a non-empty string of at most ${ORG_ID_MAX_LENGTH} characters.`,
  });
}

/**
 * The organization id a request field carries: `undefined` when the field is
 * absent, `""` when it is empty (the caller decides whether that means "no
 * org"), the value when it is a valid id. Anything else throws
 * `400 ORG_ID_INVALID`.
 */
export function requestOrgId(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  if (value === "") return "";
  if (isOrgId(value)) return value;
  throw orgIdInvalidError();
}

/** Request fields that can carry an organization id, in the gate's order of precedence. */
export const ORG_ID_FIELDS = ["organizationId", "orgId"] as const;

/**
 * Checks every org-id field of a request's body and query string and returns
 * them. Throws `400 ORG_ID_INVALID` when any one of them is present and not
 * an id — including a field the gate would not have used, so no carrier of a
 * malformed id reaches a later hook or the endpoint.
 */
export function requestOrgIds(
  body: unknown,
  query: unknown,
): {
  body: Partial<Record<(typeof ORG_ID_FIELDS)[number], string>>;
  query: Partial<Record<(typeof ORG_ID_FIELDS)[number], string>>;
} {
  const pick = (source: unknown) => {
    const out: Partial<Record<(typeof ORG_ID_FIELDS)[number], string>> = {};
    if (!source || typeof source !== "object") return out;
    for (const field of ORG_ID_FIELDS) {
      const value = requestOrgId((source as Record<string, unknown>)[field]);
      if (value !== undefined) out[field] = value;
    }
    return out;
  };
  return { body: pick(body), query: pick(query) };
}
