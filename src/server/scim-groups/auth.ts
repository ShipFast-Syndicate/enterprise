// Alpha Bros enterprise layer — SCIM bearer authentication for scimGroups
// (controller ruling (a)).
//
// Replicates `@better-auth/scim`'s own `authMiddlewareFactory` bearer
// verification for the `storeSCIMToken: "hashed"` mode `../preset.ts`
// always configures: decode the base64url token into
// `${baseToken}:${providerId}[:${organizationId}]`
// (`node_modules/@better-auth/scim/dist/index.mjs`), look up `scimProvider`
// by `providerId` (+ `organizationId`), and compare `defaultKeyHasher
// (baseToken)` against the stored hash in constant time.
//
// `defaultKeyHasher` (SHA-256, base64url, unpadded) is reimplemented here
// via Web Crypto plus a small vendored base64url codec, rather than
// importing `@better-auth/utils` directly — that package is only a
// transitive dependency of `@better-auth/scim` (not declared in this
// package's own `package.json`), so reaching into it would be relying on
// node_modules hoisting rather than a real dependency. Same approach Task
// 5's `../policy/enforcement.ts`'s `hashMagicLinkToken` already uses for
// `magicLink`'s own default hasher. `constantTimeEqual`, by contrast, is a
// real subpath export of `better-auth` itself (`better-auth/crypto`, a
// declared peer dependency already used throughout this package via
// `better-auth/api`), so it's imported directly rather than reimplemented.
//
// Personal (non-org) SCIM providers are rejected here (401), not just
// disallowed at issuance (`../gate.ts`'s `ORG_ID_REQUIRED_IN_BODY` already
// requires `organizationId` for `/scim/generate-token`): every scimGroups
// endpoint is inherently org-scoped (a "Group" maps to an org's `team`), so
// a personal-provider token can never authenticate here even in the
// hypothetical case it reached this code some other way — belt-and-braces
// against GHSA-j8v8-g9cx-5qf4 (unpatched on `@better-auth/scim` below 1.7,
// mitigated elsewhere in this preset per `../gate.ts`'s header comment).

import type { GenericEndpointContext } from "better-auth";
import { constantTimeEqual } from "better-auth/crypto";
import { ScimHttpError } from "./scim";

const BASE64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

function base64UrlEncode(bytes: Uint8Array): string {
  let result = "";
  let buffer = 0;
  let shift = 0;
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    shift += 8;
    while (shift >= 6) {
      shift -= 6;
      result += BASE64URL_ALPHABET[(buffer >> shift) & 63];
    }
  }
  if (shift > 0) {
    result += BASE64URL_ALPHABET[(buffer << (6 - shift)) & 63];
  }
  return result; // unpadded, matching defaultKeyHasher's `base64Url.encode(hash, {padding: false})`
}

function base64UrlDecode(value: string): Uint8Array {
  const decodeMap = new Map<string, number>();
  for (let i = 0; i < BASE64URL_ALPHABET.length; i++) decodeMap.set(BASE64URL_ALPHABET[i]!, i);
  const bytes: number[] = [];
  let buffer = 0;
  let bitsCollected = 0;
  for (const char of value) {
    if (char === "=") break;
    const bits = decodeMap.get(char);
    if (bits === undefined) throw new Error(`Invalid base64url character: ${char}`);
    buffer = (buffer << 6) | bits;
    bitsCollected += 6;
    if (bitsCollected >= 8) {
      bitsCollected -= 8;
      bytes.push((buffer >> bitsCollected) & 255);
    }
  }
  return Uint8Array.from(bytes);
}

/** Web Crypto reimplementation of `@better-auth/scim`'s `defaultKeyHasher` — see header comment. */
async function defaultKeyHasher(token: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
  return base64UrlEncode(new Uint8Array(digest));
}

interface ScimProviderRow {
  id: string;
  providerId: string;
  organizationId: string | null;
  scimToken: string;
}

function scimUnauthorized(): ScimHttpError {
  return new ScimHttpError(401, undefined, "SCIM token is required or invalid");
}

/**
 * Authenticates a SCIM bearer token exactly like upstream for the hashed
 * token store, org-scoped only (ruling (a)). Throws `ScimHttpError(401, ...)`
 * — caught once, in one place, by `./plugin.ts`'s `withScimErrors` wrapper —
 * on a missing/malformed `Authorization` header, an unresolvable or
 * personal-provider token, or a hash mismatch.
 */
export async function authenticateScimBearer(
  ctx: GenericEndpointContext,
): Promise<{ providerId: string; organizationId: string }> {
  const header = ctx.headers?.get("authorization") ?? ctx.request?.headers.get("authorization");
  const token = header?.replace(/^Bearer\s+/i, "");
  if (!token) throw scimUnauthorized();

  let decoded: string;
  try {
    decoded = new TextDecoder().decode(base64UrlDecode(token));
  } catch {
    throw scimUnauthorized();
  }

  // Mirrors upstream's own split exactly: `scimToken` and `providerId` are
  // the first two colon-separated parts, `organizationId` is everything
  // after (rejoined on ":", so an organization id that itself contains a
  // colon — never the case for this preset's generated ids, but upstream
  // doesn't assume otherwise either — still round-trips).
  const parts = decoded.split(":");
  const [baseToken, providerId] = parts;
  const organizationId = parts.slice(2).join(":");
  if (!baseToken || !providerId || !organizationId) throw scimUnauthorized();

  const provider = await ctx.context.adapter.findOne<ScimProviderRow>({
    model: "scimProvider",
    where: [
      { field: "providerId", value: providerId },
      { field: "organizationId", value: organizationId },
    ],
  });
  if (!provider) throw scimUnauthorized();

  const expected = await defaultKeyHasher(baseToken);
  if (!constantTimeEqual(expected, provider.scimToken)) throw scimUnauthorized();

  return { providerId: provider.providerId, organizationId };
}
