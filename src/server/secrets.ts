// Alpha Bros enterprise layer — encryption at rest for IdP secrets (C-04).
//
// `EnterpriseOptions.secretsKey` used to be a *declared but entirely unused*
// option: `grep -rn secretsKey src/` found only its own declaration, while
// the design spec (§7.4) promises "IdP OIDC client secrets: encrypted in the
// DB with `secretsKey` from 1Password". A DB dump showed
// `ssoProvider.oidcConfig` holding `{"clientId":"cid","clientSecret":
// "SUPERSECRET",...}` verbatim — so anyone with database read (a backup, a
// replica, a logged query, a SQL injection elsewhere in the embedding
// product) got every tenant's IdP credentials. A required option that does
// nothing is worse than no option at all, because embedders assume §7.4 is
// implemented.
//
// Design:
//
// - **Where.** A transparent wrapper around `context.adapter`, installed
//   from `enterpriseGate`'s `init()` (`./gate.ts`). better-auth's
//   `runPluginInit` merges a plugin's returned `context` into the live
//   `AuthContext` and only *afterwards* builds `internalAdapter` from
//   `context.adapter` (`node_modules/better-auth/dist/context/helpers.mjs`),
//   so both access paths inherit the wrapper. Every `@better-auth/sso` read
//   and write of `ssoProvider` goes through `ctx.context.adapter`
//   (verified by grep over `@better-auth/sso@1.6.33`'s `dist/index.mjs` —
//   `adapter.create` at :2723, `adapter.findOne` at :1379/:2890/:2898/:3050,
//   `adapter.update` at :1525, `adapter.findMany` at :1359/:2905), so the
//   OIDC callback still receives a plaintext `clientSecret` while the row on
//   disk holds ciphertext.
// - **What.** `oidcConfig.clientSecret`, plus the SAML private-key material
//   in `samlConfig` (`privateKey`, `privateKeyPass`, `decryptionPvk`,
//   `encPrivateKey`, `encPrivateKeyPass`, and the same keys nested under
//   `spMetadata`). Public material (certs, endpoints, client ids) is left
//   readable so operators can still inspect a row.
// - **How.** AES-256-GCM via Web Crypto (no `node:crypto` — this package
//   must keep running on workerd), key = SHA-256 of `secretsKey`, a fresh
//   random 12-byte IV per value, output `enc:v1:<base64url(iv || ct||tag)>`.
// - **Migration.** A value that doesn't carry the `enc:v1:` prefix is
//   returned untouched on read, so existing plaintext rows keep working and
//   are re-encrypted the next time they're written.

import type { AuthContext } from "better-auth";

type Adapter = AuthContext["adapter"];

const PREFIX = "enc:v1:";
const IV_BYTES = 12;

/** Minimum `secretsKey` length the README/`types.ts` have always documented (L-08). */
export const MIN_SECRETS_KEY_LENGTH = 32;

/**
 * Throws if `secretsKey` is missing or shorter than 32 characters (L-08).
 * Until C-04 the rule was documented but never enforced anywhere — a product
 * could ship `secretsKey: "x"` and nothing complained, because nothing read
 * the value at all. Now that it is load-bearing, it is validated at
 * construction time (`enterprisePreset`) rather than on first use.
 */
export function assertSecretsKey(secretsKey: string): void {
  if (typeof secretsKey !== "string" || secretsKey.length < MIN_SECRETS_KEY_LENGTH) {
    throw new Error(
      `enterprisePreset: "secretsKey" must be a string of at least ${MIN_SECRETS_KEY_LENGTH} characters — it encrypts IdP client secrets and SAML private keys at rest.`,
    );
  }
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(value: string): Uint8Array {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded.padEnd(Math.ceil(padded.length / 4) * 4, "="));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

const keyCache = new Map<string, Promise<CryptoKey>>();

function importKey(secretsKey: string): Promise<CryptoKey> {
  let key = keyCache.get(secretsKey);
  if (!key) {
    key = (async () => {
      const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(secretsKey));
      return crypto.subtle.importKey("raw", digest, { name: "AES-GCM" }, false, [
        "encrypt",
        "decrypt",
      ]);
    })();
    keyCache.set(secretsKey, key);
  }
  return key;
}

/** `enc:v1:<base64url(iv || ciphertext||tag)>` — AES-256-GCM, fresh IV per call. */
export async function encryptSecret(plaintext: string, secretsKey: string): Promise<string> {
  const key = await importKey(secretsKey);
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(plaintext)),
  );
  const packed = new Uint8Array(iv.length + ciphertext.length);
  packed.set(iv, 0);
  packed.set(ciphertext, iv.length);
  return `${PREFIX}${toBase64Url(packed)}`;
}

export function isEncrypted(value: unknown): value is string {
  return typeof value === "string" && value.startsWith(PREFIX);
}

/**
 * Inverse of `encryptSecret`. A value without the `enc:v1:` prefix is
 * returned unchanged (migration-friendly: rows written before this shipped
 * are plaintext and must keep working). A prefixed value that fails to
 * decrypt throws — a wrong/rotated `secretsKey` must be loud, not silently
 * produce a garbage client secret that then fails at the IdP.
 */
export async function decryptSecret(value: string, secretsKey: string): Promise<string> {
  if (!isEncrypted(value)) return value;
  const key = await importKey(secretsKey);
  const packed = fromBase64Url(value.slice(PREFIX.length));
  const iv = packed.slice(0, IV_BYTES);
  const ciphertext = packed.slice(IV_BYTES);
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  return new TextDecoder().decode(plaintext);
}

// --- which fields of which model carry secret material ---------------------

const SECRET_MODEL = "ssoProvider";

/** JSON-string columns of `ssoProvider`, and the keys inside each that are secret. */
const SECRET_JSON_FIELDS: Record<string, { keys: string[]; nested?: string[] }> = {
  oidcConfig: { keys: ["clientSecret"] },
  samlConfig: {
    keys: ["privateKey", "privateKeyPass", "decryptionPvk", "encPrivateKey", "encPrivateKeyPass"],
    nested: ["spMetadata"],
  },
};

type Json = Record<string, unknown>;

async function mapSecretKeys(
  config: Json,
  spec: { keys: string[]; nested?: string[] },
  transform: (value: string) => Promise<string>,
): Promise<Json> {
  const out: Json = { ...config };
  for (const key of spec.keys) {
    const value = out[key];
    if (typeof value === "string" && value.length > 0) out[key] = await transform(value);
  }
  for (const key of spec.nested ?? []) {
    const nested = out[key];
    if (nested && typeof nested === "object" && !Array.isArray(nested)) {
      out[key] = await mapSecretKeys(nested as Json, { keys: spec.keys }, transform);
    }
  }
  return out;
}

/**
 * Applies `transform` to every secret key of every secret-bearing JSON field
 * of a `ssoProvider` row/payload, preserving whether that field was stored
 * as a JSON *string* (what `@better-auth/sso` writes) or already-parsed
 * object (what a `type: "json"` adapter may hand back). Anything that isn't
 * parseable JSON is left exactly as-is rather than destroyed.
 */
async function mapProviderSecrets(
  data: Json,
  transform: (value: string) => Promise<string>,
): Promise<Json> {
  let out = data;
  for (const [field, spec] of Object.entries(SECRET_JSON_FIELDS)) {
    const raw = out[field];
    if (raw === null || raw === undefined) continue;

    let parsed: Json | null = null;
    let wasString = false;
    if (typeof raw === "string") {
      wasString = true;
      try {
        const candidate: unknown = JSON.parse(raw);
        if (candidate && typeof candidate === "object" && !Array.isArray(candidate)) {
          parsed = candidate as Json;
        }
      } catch {
        parsed = null; // not JSON (or legacy/garbage) — leave the value alone
      }
    } else if (typeof raw === "object" && !Array.isArray(raw)) {
      parsed = raw as Json;
    }
    if (!parsed) continue;

    const mapped = await mapSecretKeys(parsed, spec, transform);
    if (out === data) out = { ...data };
    out[field] = wasString ? JSON.stringify(mapped) : mapped;
  }
  return out;
}

const encryptPayload = (data: unknown, secretsKey: string): Promise<unknown> =>
  data && typeof data === "object" && !Array.isArray(data)
    ? mapProviderSecrets(data as Json, (value) =>
        isEncrypted(value) ? Promise.resolve(value) : encryptSecret(value, secretsKey),
      )
    : Promise.resolve(data);

const decryptRow = async (row: unknown, secretsKey: string): Promise<unknown> =>
  row && typeof row === "object" && !Array.isArray(row)
    ? mapProviderSecrets(row as Json, (value) => decryptSecret(value, secretsKey))
    : row;

// --- the adapter wrapper ---------------------------------------------------

interface ModelParams {
  model?: unknown;
  data?: unknown;
  update?: unknown;
}

function isSecretModel(params: unknown): boolean {
  return (params as ModelParams | undefined)?.model === SECRET_MODEL;
}

/**
 * Returns `adapter` with transparent encrypt-on-write / decrypt-on-read for
 * `ssoProvider` secret material. Every other model, and every other adapter
 * method, is passed straight through untouched.
 *
 * A `Proxy` (rather than an object spread) so that adapter implementations
 * which add methods this package doesn't know about — or which rely on
 * `this` — keep working unchanged.
 */
export function withSecretEncryption(adapter: Adapter, secretsKey: string): Adapter {
  return new Proxy(adapter, {
    get(target, prop, receiver) {
      const value = Reflect.get(target, prop, receiver) as unknown;
      if (typeof value !== "function") return value;
      const call = value.bind(target) as (params: unknown) => Promise<unknown>;

      switch (prop) {
        case "create":
          return async (params: { data?: unknown }) => {
            if (!isSecretModel(params)) return call(params);
            const data = await encryptPayload(params.data, secretsKey);
            return decryptRow(await call({ ...params, data }), secretsKey);
          };
        case "update":
        case "updateMany":
          return async (params: { update?: unknown }) => {
            if (!isSecretModel(params)) return call(params);
            const update = await encryptPayload(params.update, secretsKey);
            return decryptRow(await call({ ...params, update }), secretsKey);
          };
        case "findOne":
          return async (params: unknown) => {
            const row = await call(params);
            return isSecretModel(params) ? decryptRow(row, secretsKey) : row;
          };
        case "findMany":
          return async (params: unknown) => {
            const rows = await call(params);
            if (!isSecretModel(params) || !Array.isArray(rows)) return rows;
            return Promise.all(rows.map((row) => decryptRow(row, secretsKey)));
          };
        default:
          return call;
      }
    },
  }) as Adapter;
}
